//! `SCRAM-SHA-256` from the client side, for the connection the daemon opens
//! upstream.
//!
//! The proxy authenticates to the real PostgreSQL server itself, with the
//! master password, so it needs a SCRAM client. This is that client and nothing
//! else: it has no server half, because briefcred is never the thing a password
//! is proved *to* — the token a subprocess presents is checked by
//! [`crate::proxy::issuer`], not here.
//!
//! # The exchange, and what each step proves
//!
//! ```text
//! →  n,,n=,r=<client nonce>                        client-first
//! ←  r=<client nonce><server nonce>,s=<salt>,i=<n>  server-first
//! →  c=biws,r=<nonce>,p=<client proof>              client-final
//! ←  v=<server signature>                           server-final
//! ```
//!
//! The proof shows the client knows the password without sending it. The
//! server's signature, checked in [`ScramClient::verify_server_final`], shows
//! the *server* knew it too — which is what stops a machine-in-the-middle from
//! accepting any password and then relaying an unauthenticated session back.
//! Skipping that check is the classic SCRAM implementation bug, so it is a hard
//! error here rather than a warning.
//!
//! # Two deliberate limits
//!
//! **No channel binding.** `SCRAM-SHA-256-PLUS` binds the exchange to the TLS
//! channel underneath it. briefcred does not implement it, and
//! [`select_mechanism`] refuses rather than silently downgrading a server that
//! offers only the bound variant — a downgrade is precisely what channel
//! binding exists to prevent.
//!
//! **No SASLprep.** RFC 5802 normalises the password with SASLprep before
//! hashing. briefcred does not, so a master password containing anything
//! outside printable ASCII is **refused** with [`ScramError::PasswordNotAscii`]
//! rather than hashed the wrong way and reported as a wrong password. For
//! printable ASCII, SASLprep is the identity, so every password briefcred does
//! accept is handled exactly as the RFC requires.

use base64::Engine as _;
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

/// The mechanism briefcred implements.
pub const MECHANISM: &str = "SCRAM-SHA-256";

/// The channel-bound mechanism briefcred does not implement.
pub const MECHANISM_PLUS: &str = "SCRAM-SHA-256-PLUS";

/// The GS2 header for "the client does not support channel binding", and its
/// base64, which is what `c=` carries in the client-final message.
const GS2_HEADER: &str = "n,,";
const GS2_HEADER_B64: &str = "biws";

/// Bytes of entropy in the client nonce, before base64.
const NONCE_BYTES: usize = 18;

/// The largest iteration count briefcred will spend PBKDF2 rounds on.
///
/// A server chooses this, so it is an input from the network. PostgreSQL uses
/// 4096; a million is far past anything real and still bounded, which is the
/// difference between a slow connection and a daemon wedged on one.
const MAX_ITERATIONS: u32 = 1_000_000;

/// Base64 with padding: the encoding SCRAM uses for salts, proofs and
/// signatures. Not the token module's URL-safe unpadded flavour.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Why an upstream SCRAM exchange could not be completed.
///
/// Nothing here carries the password or any material derived from it: these
/// are logged and audited as connection outcomes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScramError {
    /// The master password is not printable ASCII, so SASLprep would matter.
    #[error(
        "the master password is not printable ASCII; briefcred's SCRAM client does not \
         implement SASLprep and will not guess at the normalisation"
    )]
    PasswordNotAscii,

    /// A message from the server did not parse.
    #[error("the server's {0} message is malformed")]
    Malformed(&'static str),

    /// The server's nonce does not start with the one it was given.
    ///
    /// The whole point of the client nonce is that the client chose it; a
    /// server that replaces it is replaying somebody else's exchange.
    #[error("the server did not echo the nonce it was given")]
    WrongNonce,

    /// The iteration count is zero or past [`MAX_ITERATIONS`].
    #[error("the server asked for {0} PBKDF2 iterations, which briefcred will not do")]
    Iterations(u32),

    /// The server's signature does not verify against the password.
    #[error("the server's signature does not verify; it does not hold this password")]
    BadServerSignature,

    /// The server ended the exchange with an error instead of a signature.
    #[error("the server refused the SCRAM exchange: {0}")]
    Refused(String),

    /// No mechanism the server offered is one briefcred implements.
    #[error(
        "the server offers no SASL mechanism briefcred implements (it offered {offered}); \
         `{MECHANISM_PLUS}` is channel-bound and briefcred will not downgrade it"
    )]
    NoUsableMechanism {
        /// What the server listed, comma separated.
        offered: String,
    },
}

/// Choose a mechanism from the list the server offered.
///
/// Only [`MECHANISM`]. A server offering only [`MECHANISM_PLUS`] gets a
/// refusal, never a downgrade to the unbound variant: channel binding exists
/// to stop exactly that, and a client that "helpfully" falls back has removed
/// the protection the server asked for.
pub fn select_mechanism(offered: &[String]) -> Result<&'static str, ScramError> {
    if offered.iter().any(|name| name == MECHANISM) {
        return Ok(MECHANISM);
    }
    Err(ScramError::NoUsableMechanism {
        offered: offered.join(", "),
    })
}

/// One upstream SCRAM-SHA-256 exchange, from client-first to verification.
///
/// `Debug` is written by hand: the struct holds the master password and the
/// keys derived from it, and a derived implementation would put all of them in
/// whatever log line printed the connection state.
pub struct ScramClient {
    password: Zeroizing<String>,
    client_first_bare: String,
    client_nonce: String,
    /// The signature the server will have to produce, known once the client
    /// proof has been computed.
    expected_server_signature: Option<Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for ScramClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScramClient")
            .field("client_nonce", &self.client_nonce)
            .field("password", &"<redacted>")
            .field("proved", &self.expected_server_signature.is_some())
            .finish()
    }
}

impl ScramClient {
    /// Begin an exchange with a fresh random nonce.
    ///
    /// The SCRAM username is sent empty, which is what every PostgreSQL client
    /// does: the role travels in the startup packet, and the `n=` attribute
    /// only has to agree between the two ends of the exchange.
    pub fn new(password: &str) -> Result<ScramClient, ScramError> {
        ScramClient::begin("", password, random_nonce())
    }

    /// Begin an exchange with a caller-chosen username and nonce.
    ///
    /// Private, because a nonce a caller could repeat is a proof that could be
    /// replayed. The tests use it to replay the RFC 7677 vector exactly.
    fn begin(
        username: &str,
        password: &str,
        client_nonce: String,
    ) -> Result<ScramClient, ScramError> {
        // Checked before anything is derived from it: the failure is about the
        // password's shape, and reporting it here rather than as a wrong
        // password is the difference between a fixable message and a mystery.
        if !password.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(ScramError::PasswordNotAscii);
        }
        Ok(ScramClient {
            client_first_bare: format!("n={username},r={client_nonce}"),
            client_nonce,
            password: Zeroizing::new(password.to_string()),
            expected_server_signature: None,
        })
    }

    /// The client-first message, GS2 header included.
    pub fn client_first(&self) -> String {
        format!("{GS2_HEADER}{}", self.client_first_bare)
    }

    /// Answer the server-first message with the client proof.
    pub fn client_final(&mut self, server_first: &str) -> Result<String, ScramError> {
        let first = ServerFirst::parse(server_first)?;
        if !first.nonce.starts_with(&self.client_nonce) || first.nonce == self.client_nonce {
            return Err(ScramError::WrongNonce);
        }
        if first.iterations == 0 || first.iterations > MAX_ITERATIONS {
            return Err(ScramError::Iterations(first.iterations));
        }

        let mut salted = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha256>(
            self.password.as_bytes(),
            &first.salt,
            first.iterations,
            &mut *salted,
        );

        let client_key = hmac(&*salted, b"Client Key");
        let stored_key = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(*client_key)));

        let without_proof = format!("c={GS2_HEADER_B64},r={}", first.nonce);
        let auth_message = format!("{},{server_first},{without_proof}", self.client_first_bare);

        let client_signature = hmac(&*stored_key, auth_message.as_bytes());
        let mut proof = *client_key;
        for (byte, mask) in proof.iter_mut().zip(client_signature.iter()) {
            *byte ^= *mask;
        }
        let encoded = B64.encode(proof);
        proof.zeroize();

        let server_key = hmac(&*salted, b"Server Key");
        self.expected_server_signature = Some(hmac(&*server_key, auth_message.as_bytes()));

        Ok(format!("{without_proof},p={encoded}"))
    }

    /// Check the server-final message against the signature we expect.
    ///
    /// A mismatch means the server does not hold this password, which makes
    /// everything after it untrustworthy: the connection is abandoned rather
    /// than used.
    pub fn verify_server_final(&self, server_final: &str) -> Result<(), ScramError> {
        let Some(expected) = self.expected_server_signature.as_ref() else {
            return Err(ScramError::Malformed("server-final"));
        };
        if let Some(error) = field(server_final, 'e') {
            return Err(ScramError::Refused(error.to_string()));
        }
        let signature = field(server_final, 'v').ok_or(ScramError::Malformed("server-final"))?;
        let decoded = B64
            .decode(signature)
            .map_err(|_| ScramError::Malformed("server-final"))?;
        // Constant time, because a comparison that stops at the first wrong
        // byte tells a server how much of a forged signature it got right.
        if decoded.len() != expected.len() || !constant_time_eq(&decoded, &**expected) {
            return Err(ScramError::BadServerSignature);
        }
        Ok(())
    }
}

/// The parts of a server-first message.
struct ServerFirst {
    nonce: String,
    salt: Vec<u8>,
    iterations: u32,
}

impl ServerFirst {
    fn parse(message: &str) -> Result<ServerFirst, ScramError> {
        let malformed = || ScramError::Malformed("server-first");
        let nonce = field(message, 'r').ok_or_else(malformed)?.to_string();
        let salt = B64
            .decode(field(message, 's').ok_or_else(malformed)?)
            .map_err(|_| malformed())?;
        let iterations: u32 = field(message, 'i')
            .ok_or_else(malformed)?
            .parse()
            .map_err(|_| malformed())?;
        if nonce.is_empty() || salt.is_empty() {
            return Err(malformed());
        }
        Ok(ServerFirst {
            nonce,
            salt,
            iterations,
        })
    }
}

/// The value of the `<key>=<value>` attribute named `key`, if the message has
/// one. SCRAM messages are comma-separated single-letter attributes.
fn field(message: &str, key: char) -> Option<&str> {
    message
        .split(',')
        .find_map(|part| part.strip_prefix(key)?.strip_prefix('='))
}

/// HMAC-SHA-256, in the [`Zeroizing`] wrapper every key here lives in.
fn hmac(key: &[u8], message: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// Whether two equal-length byte strings match, without an early return.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |differences, (x, y)| differences | (x ^ y))
        == 0
}

/// A fresh client nonce, drawn from the OS CSPRNG.
///
/// The nonce is what makes one exchange's proof useless in another, so a
/// counter or a timestamp here would make every proof replayable.
fn random_nonce() -> String {
    let mut bytes = [0u8; NONCE_BYTES];
    getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7677 §3, the SCRAM-SHA-256 test vector, verbatim.
    const CLIENT_NONCE: &str = "rOprNGfwEbeRWgbNEkqO";
    const SERVER_NONCE: &str = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    const USERNAME: &str = "user";
    const PASSWORD: &str = "pencil";
    const SALT: &str = "W22ZaJ0SNY7soEsUEjb6gQ==";
    const RFC_CLIENT_PROOF: &str = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const RFC_SERVER_SIGNATURE: &str = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    fn server_first() -> String {
        format!("r={CLIENT_NONCE}{SERVER_NONCE},s={SALT},i=4096")
    }

    /// The RFC's exchange, carried to the point where the proof exists.
    fn rfc_exchange() -> (ScramClient, String) {
        let mut client = ScramClient::begin(USERNAME, PASSWORD, CLIENT_NONCE.to_string()).unwrap();
        let final_message = client.client_final(&server_first()).unwrap();
        (client, final_message)
    }

    #[test]
    fn the_client_first_message_is_the_one_rfc_7677_specifies() {
        let client = ScramClient::begin(USERNAME, PASSWORD, CLIENT_NONCE.to_string()).unwrap();
        assert_eq!(
            client.client_first(),
            format!("n,,n={USERNAME},r={CLIENT_NONCE}")
        );
    }

    #[test]
    fn the_client_final_message_is_the_one_rfc_7677_specifies() {
        // The whole of the SCRAM derivation — PBKDF2, the client and stored
        // keys, the auth message, the XOR — checked against a value briefcred
        // did not compute.
        let (_client, message) = rfc_exchange();
        assert_eq!(
            message,
            format!("c=biws,r={CLIENT_NONCE}{SERVER_NONCE},p={RFC_CLIENT_PROOF}")
        );
    }

    #[test]
    fn the_servers_signature_from_rfc_7677_verifies() {
        let (client, _) = rfc_exchange();
        client
            .verify_server_final(&format!("v={RFC_SERVER_SIGNATURE}"))
            .unwrap();
    }

    #[test]
    fn a_server_signature_that_is_not_the_expected_one_is_refused() {
        // The failure this guards against is the common one: implementations
        // that send the proof and then treat any server-final as success. A
        // server that cannot produce this value does not hold the password,
        // and everything it says after it is unauthenticated.
        let (client, _) = rfc_exchange();
        let mut wrong = RFC_SERVER_SIGNATURE.to_string();
        wrong.replace_range(0..1, "7");
        assert_eq!(
            client
                .verify_server_final(&format!("v={wrong}"))
                .unwrap_err(),
            ScramError::BadServerSignature
        );
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_refused_rather_than_compared_short() {
        let (client, _) = rfc_exchange();
        assert_eq!(
            client.verify_server_final("v=6rriTRBi23U=").unwrap_err(),
            ScramError::BadServerSignature
        );
    }

    #[test]
    fn the_exchange_postgres_actually_performs_sends_an_empty_username() {
        // PostgreSQL puts the role in the startup packet and sends `n=`; the
        // proof therefore differs from the RFC's, and this is that value,
        // computed independently from the same salt, nonces and password.
        let mut client = ScramClient::new(PASSWORD).unwrap();
        assert!(client.client_first().starts_with("n,,n=,r="));
        client.client_nonce = CLIENT_NONCE.to_string();
        client.client_first_bare = format!("n=,r={CLIENT_NONCE}");
        let message = client.client_final(&server_first()).unwrap();
        assert_eq!(
            message,
            format!(
                "c=biws,r={CLIENT_NONCE}{SERVER_NONCE},\
                 p=qvT2SWdEH5Q06albL+hjSYuUhCG7VndFyzIb7CK4n9k="
            )
        );
        client
            .verify_server_final("v=3HO6Qt1M4MKJrmlKaoOqLAI0/0TV0HZe7J9H3MBtSOg=")
            .unwrap();
    }

    #[test]
    fn a_server_final_that_is_an_error_reports_what_the_server_said() {
        let (client, _) = rfc_exchange();
        assert_eq!(
            client.verify_server_final("e=invalid-proof").unwrap_err(),
            ScramError::Refused("invalid-proof".to_string())
        );
    }

    #[test]
    fn a_server_final_with_no_signature_in_it_is_malformed() {
        let (client, _) = rfc_exchange();
        for message in ["nonsense", "v=not base64!!"] {
            assert_eq!(
                client.verify_server_final(message).unwrap_err(),
                ScramError::Malformed("server-final"),
                "{message}"
            );
        }
    }

    #[test]
    fn verifying_before_the_proof_was_sent_is_refused_rather_than_accepted() {
        let client = ScramClient::begin(USERNAME, PASSWORD, CLIENT_NONCE.to_string()).unwrap();
        assert_eq!(
            client
                .verify_server_final(&format!("v={RFC_SERVER_SIGNATURE}"))
                .unwrap_err(),
            ScramError::Malformed("server-final")
        );
    }

    #[test]
    fn a_server_that_replaces_the_client_nonce_is_refused() {
        let mut client = ScramClient::begin(USERNAME, PASSWORD, CLIENT_NONCE.to_string()).unwrap();
        assert_eq!(
            client
                .client_final(&format!("r=somethingelse{SERVER_NONCE},s={SALT},i=4096"))
                .unwrap_err(),
            ScramError::WrongNonce
        );
    }

    #[test]
    fn a_server_that_adds_nothing_to_the_nonce_is_refused() {
        // An extended nonce with no server contribution is a server that is not
        // participating in the freshness the nonce exists for.
        let mut client = ScramClient::begin(USERNAME, PASSWORD, CLIENT_NONCE.to_string()).unwrap();
        assert_eq!(
            client
                .client_final(&format!("r={CLIENT_NONCE},s={SALT},i=4096"))
                .unwrap_err(),
            ScramError::WrongNonce
        );
    }

    #[test]
    fn a_malformed_server_first_message_is_refused_by_name() {
        let mut client = ScramClient::begin(USERNAME, PASSWORD, CLIENT_NONCE.to_string()).unwrap();
        for message in [
            String::new(),
            format!("s={SALT},i=4096"),
            format!("r={CLIENT_NONCE}{SERVER_NONCE},i=4096"),
            format!("r={CLIENT_NONCE}{SERVER_NONCE},s={SALT}"),
            format!("r={CLIENT_NONCE}{SERVER_NONCE},s=!!!,i=4096"),
            format!("r={CLIENT_NONCE}{SERVER_NONCE},s={SALT},i=many"),
        ] {
            assert_eq!(
                client.client_final(&message).unwrap_err(),
                ScramError::Malformed("server-first"),
                "{message}"
            );
        }
    }

    #[test]
    fn an_iteration_count_briefcred_will_not_spend_is_refused() {
        let mut client = ScramClient::begin(USERNAME, PASSWORD, CLIENT_NONCE.to_string()).unwrap();
        for count in [0, MAX_ITERATIONS + 1] {
            assert_eq!(
                client
                    .client_final(&format!(
                        "r={CLIENT_NONCE}{SERVER_NONCE},s={SALT},i={count}"
                    ))
                    .unwrap_err(),
                ScramError::Iterations(count)
            );
        }
    }

    #[test]
    fn a_password_outside_printable_ascii_is_refused_rather_than_hashed_wrongly() {
        // SASLprep would normalise these; briefcred does not implement it, and
        // hashing them raw would produce a wrong-password error the operator
        // could never act on.
        for password in ["pass wörd", "pass word", "pen\tcil"] {
            assert_eq!(
                ScramClient::new(password).unwrap_err(),
                ScramError::PasswordNotAscii,
                "{password}"
            );
        }
        assert!(ScramClient::new("p3nc!l~").is_ok());
    }

    #[test]
    fn the_unbound_mechanism_is_chosen_and_the_bound_one_is_never_downgraded_to() {
        assert_eq!(
            select_mechanism(&[MECHANISM.to_string(), MECHANISM_PLUS.to_string()]).unwrap(),
            MECHANISM
        );
        let err = select_mechanism(&[MECHANISM_PLUS.to_string()]).unwrap_err();
        assert!(err.to_string().contains(MECHANISM_PLUS), "{err}");
        assert!(select_mechanism(&[]).is_err());
    }

    #[test]
    fn every_exchange_gets_a_nonce_of_its_own() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..32 {
            let client = ScramClient::new(PASSWORD).unwrap();
            let nonce = client.client_nonce.clone();
            assert!(!nonce.is_empty());
            assert!(!nonce.contains(','), "a nonce may not contain a comma");
            assert!(seen.insert(nonce), "nonces must not repeat");
        }
    }

    #[test]
    fn the_client_never_prints_the_password_it_holds() {
        let (client, _) = rfc_exchange();
        let rendered = format!("{client:?}");
        assert!(!rendered.contains(PASSWORD), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn a_comparison_of_equal_length_strings_is_only_true_when_they_match() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"bbc"));
    }
}
