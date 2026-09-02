//! The per-session key a client proves possession of.
//!
//! When `briefcred` opens a session it generates an Ed25519 pair, keeps the
//! private half for as long as the session lasts, and sends the public half.
//! The daemon puts a thumbprint of it into every synthetic token it signs for
//! that session, so a token says not only "this session" but "and here is the
//! key whoever holds me should be able to sign with".
//!
//! # What this does and does not buy today
//!
//! A client that can sign a request sends a `DPoP` header and the proxy checks
//! it against the token's `cnf.jkt`. `briefcred exec` cannot: the credential
//! reaches the subprocess as an environment variable and the subprocess is
//! `curl`, or a vendor SDK, and neither has any idea briefcred exists. So the
//! proxy also accepts a bare token, and on that path the token is a bearer
//! credential. `THREAT_MODEL.md` states the limit rather than dressing it up.
//!
//! The binding is still worth carrying. It costs one key generation per
//! session, it is what a first-party client will use the moment there is one,
//! and a token minted for a session with no key at all is distinguishable in
//! the daemon from one that simply was not proved.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use zeroize::Zeroizing;

/// One session's ephemeral key pair.
///
/// `Debug` is hand-written: the private half is a signing key, and a derived
/// implementation would put it in the first diagnostic anybody printed.
pub struct SessionKey {
    key: SigningKey,
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("public_key_base64", &self.public_key_base64())
            .finish()
    }
}

impl Default for SessionKey {
    fn default() -> SessionKey {
        SessionKey::generate()
    }
}

impl SessionKey {
    /// Draw a fresh pair from the operating system's CSPRNG.
    pub fn generate() -> SessionKey {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut seed[..]).expect("OS CSPRNG unavailable");
        SessionKey {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// The public half, base64 standard, exactly as `OpenSession` carries it.
    pub fn public_key_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.key.verifying_key().to_bytes())
    }

    /// A DPoP proof over `method` and `htu`, as a compact JWS.
    ///
    /// `htu` is the request URI with the query string already removed, which is
    /// the shape the proxy rebuilds from the request it received: a query
    /// string routinely carries a credential, and signing over one would put it
    /// in a header for no gain.
    pub fn dpop_proof(&self, method: &str, htu: &str, now: i64) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(r#"{"typ":"dpop+jwt","alg":"EdDSA"}"#);

        let mut jti = [0u8; 16];
        getrandom::fill(&mut jti).expect("OS CSPRNG unavailable");
        let payload = b64.encode(
            serde_json::json!({
                "htm": method,
                "htu": htu,
                "iat": now,
                "jti": b64.encode(jti),
            })
            .to_string(),
        );

        let signing_input = format!("{header}.{payload}");
        format!(
            "{signing_input}.{}",
            b64.encode(self.key.sign(signing_input.as_bytes()).to_bytes())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_key_reports_thirty_two_public_bytes() {
        let key = SessionKey::generate();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(key.public_key_base64())
            .unwrap();
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn two_sessions_never_share_a_key() {
        let keys: std::collections::BTreeSet<String> = (0..32)
            .map(|_| SessionKey::generate().public_key_base64())
            .collect();
        assert_eq!(keys.len(), 32);
    }

    #[test]
    fn a_proof_is_a_three_part_compact_jws() {
        let proof = SessionKey::generate().dpop_proof("GET", "https://a.test/x", 1_000);
        assert_eq!(proof.split('.').count(), 3, "{proof}");
    }

    #[test]
    fn two_proofs_for_the_same_request_differ_by_their_identifier() {
        let key = SessionKey::generate();
        let first = key.dpop_proof("GET", "https://a.test/x", 1_000);
        let second = key.dpop_proof("GET", "https://a.test/x", 1_000);
        assert_ne!(first, second, "each proof needs its own jti");
    }

    #[test]
    fn a_session_key_never_prints_its_private_half() {
        let key = SessionKey::generate();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("public_key_base64"), "{rendered}");
        assert!(!rendered.contains("SigningKey"), "{rendered}");
    }
}
