//! The synthetic token: what the subprocess gets instead of the real key.
//!
//! # The shape
//!
//! ```text
//! bc.<base64url(payload)>.<base64url(signature)>
//! ```
//!
//! The payload is JSON:
//!
//! ```json
//! { "sid": "…", "cred": "openai", "iat": 1, "exp": 901,
//!   "cnf": { "jkt": "…" } }
//! ```
//!
//! and the signature is Ed25519 over the ASCII bytes of everything before the
//! last dot, so the signed input is exactly what a verifier can reconstruct
//! from the token it was given.
//!
//! # Why it is signed at all
//!
//! The proxy has to answer "which session and which credential is this" from
//! nothing but a header. It could keep a table of issued tokens and look the
//! string up — but then a restart loses every live token, and the table is a
//! second place a mistake can hand out the wrong credential. A signed token
//! carries its own answer, and the daemon's key is the only thing that can
//! produce one.
//!
//! # `cnf`, and the honest limit
//!
//! `cnf.jkt` is the SHA-256 thumbprint of a per-session key the CLI generates
//! and keeps. A client that can prove possession of that key sends a `DPoP`
//! header and the proxy checks it. A client that cannot — anything whose only
//! channel is `OPENAI_API_KEY=<token>` in the environment, which is most of
//! them — sends the token bare and the proxy accepts it. The token is a bearer
//! credential on that path, and `THREAT_MODEL.md` says so plainly. What the
//! binding buys today is that a token stolen from one session's environment
//! cannot be *upgraded* by a client that does present a proof.

use std::fmt;

use base64::Engine as _;
use briefcred_core::keystore::{KeyStore, TOKEN_SIGNER_ITEM};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// The prefix that makes a synthetic token recognisable at a glance.
///
/// Deliberately short and deliberately not a vendor's prefix: a value starting
/// `bc.` is briefcred's and nothing else's, so the swap logic can tell a
/// synthetic token from a real key the user pasted in by hand.
pub const TOKEN_PREFIX: &str = "bc.";

/// How far apart the daemon's and the client's clocks may be.
///
/// Applied to `iat` in both directions and to `exp` in the forgiving one. A
/// minute: enough for the drift between two processes on one machine and for a
/// token generated a moment before a leap adjustment, and short enough that it
/// is not a meaningful extension of a credential's life.
pub const CLOCK_SKEW_SECS: i64 = 60;

/// How old a DPoP proof may be.
///
/// The proof is generated immediately before the request it covers, so this is
/// a network-and-scheduling allowance rather than a lifetime.
pub const DPOP_MAX_AGE_SECS: i64 = 300;

/// Base64url, no padding: the encoding every part of the token uses.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The claims a synthetic token carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// The session the token was issued to.
    pub sid: String,
    /// The credential's name within that session's profile.
    pub cred: String,
    /// When it was issued, in Unix seconds.
    pub iat: i64,
    /// When it stops being accepted, in Unix seconds.
    pub exp: i64,
    /// The key the holder can prove possession of, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
}

/// The `cnf` claim: what key a proof would have to be made with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    /// Base64url SHA-256 of the raw 32-byte Ed25519 public key.
    pub jkt: String,
}

/// The thumbprint of a raw Ed25519 public key.
///
/// SHA-256 of the 32 key bytes, base64url. Not the RFC 7638 JWK thumbprint:
/// there is no JWK here, both ends have the raw key, and hashing the key
/// itself has no JSON canonicalisation to get wrong.
pub fn thumbprint(public_key: &[u8; 32]) -> String {
    B64.encode(Sha256::digest(public_key))
}

/// Why a token was not accepted.
///
/// Every variant is a refusal the proxy turns into a 401 with the same body, so
/// the distinctions exist for the daemon's log and for tests rather than for
/// the client: telling a caller *which* check failed is telling an attacker
/// which half of the token to fix.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// Not three dot-separated parts starting `bc.`, or not decodable.
    #[error("not a briefcred token")]
    Malformed,

    /// The signature is not this daemon's over these claims.
    #[error("the token signature does not verify")]
    BadSignature,

    /// `exp` is in the past.
    #[error("the token expired")]
    Expired,

    /// `iat` is further in the future than [`CLOCK_SKEW_SECS`] allows.
    #[error("the token is not valid yet")]
    NotYetValid,

    /// The credential it names has been revoked.
    #[error("the credential has been revoked")]
    Revoked,
}

/// The per-machine Ed25519 key the proxy signs tokens with.
///
/// `Debug` is written by hand and prints nothing but the public half: the
/// signing key is a secret, and a struct that derived `Debug` would put it in
/// the first error anybody formatted.
pub struct TokenSigner {
    key: SigningKey,
}

impl fmt::Debug for TokenSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSigner")
            .field("public_key", &hex::encode(self.key.verifying_key()))
            .finish()
    }
}

impl TokenSigner {
    /// Load the signing key from `store`, generating and saving one if absent.
    ///
    /// Per machine rather than per run: a token has to stay verifiable for its
    /// whole lifetime, and a key regenerated at every daemon start would make
    /// every restart a mass revocation nobody asked for.
    pub fn load_or_create(store: &dyn KeyStore) -> briefcred_core::Result<TokenSigner> {
        if let Some(stored) = store.get(TOKEN_SIGNER_ITEM)? {
            return TokenSigner::from_hex(&stored);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut seed[..]).expect("OS CSPRNG unavailable");
        let encoded = Zeroizing::new(hex::encode(&seed[..]));
        store.put(TOKEN_SIGNER_ITEM, &encoded)?;
        Ok(TokenSigner {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Rebuild a signer from the hex form the key store holds.
    pub fn from_hex(encoded: &str) -> briefcred_core::Result<TokenSigner> {
        let bytes = Zeroizing::new(hex::decode(encoded.trim()).map_err(|_| {
            briefcred_core::Error::Keystore(format!("`{TOKEN_SIGNER_ITEM}` is not hex"))
        })?);
        let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            briefcred_core::Error::Keystore(format!(
                "`{TOKEN_SIGNER_ITEM}` is {} bytes, not 32",
                bytes.len()
            ))
        })?;
        Ok(TokenSigner {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Sign `claims` into a token.
    ///
    /// [`Zeroizing`] because the result is a credential: the subprocess will
    /// hold it, and no copy on the way there should outlive its scope.
    pub fn sign(&self, claims: &Claims) -> Zeroizing<String> {
        let payload = serde_json::to_vec(claims).expect("claims serialise");
        let signing_input = format!("{TOKEN_PREFIX}{}", B64.encode(payload));
        let signature = self.key.sign(signing_input.as_bytes());
        Zeroizing::new(format!(
            "{signing_input}.{}",
            B64.encode(signature.to_bytes())
        ))
    }

    /// Sign arbitrary bytes with the same key, for something that is not a
    /// token.
    ///
    /// The handoff blob is the one caller: it is not a credential and is never
    /// presented to anything, but it does have to be provably this machine's,
    /// and the token-signer key is already the daemon's answer to "prove you
    /// are the briefcred on this machine". Detached, because the bytes are
    /// carried alongside rather than embedded, and the signature has to cover
    /// exactly the bytes the receiver will parse.
    pub fn sign_detached(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }

    /// Whether `signature` is this key's over `message`.
    pub fn verify_detached(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.key
            .verifying_key()
            .verify(message, &Signature::from_bytes(signature))
            .is_ok()
    }

    /// Check `token` and return the claims it carries.
    ///
    /// `now` is Unix seconds, taken by the caller so the expiry rules can be
    /// tested without waiting.
    pub fn verify(&self, token: &str, now: i64) -> Result<Claims, TokenError> {
        let (signing_input, signature) = token.rsplit_once('.').ok_or(TokenError::Malformed)?;
        let encoded_payload = signing_input
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(TokenError::Malformed)?;

        let signature: [u8; 64] = B64
            .decode(signature)
            .map_err(|_| TokenError::Malformed)?
            .try_into()
            .map_err(|_| TokenError::Malformed)?;
        // The signature is checked before the payload is looked at, so a
        // forged token cannot reach the JSON parser at all.
        self.key
            .verifying_key()
            .verify(signing_input.as_bytes(), &Signature::from_bytes(&signature))
            .map_err(|_| TokenError::BadSignature)?;

        let payload = B64
            .decode(encoded_payload)
            .map_err(|_| TokenError::Malformed)?;
        let claims: Claims = serde_json::from_slice(&payload).map_err(|_| TokenError::Malformed)?;

        if now > claims.exp + CLOCK_SKEW_SECS {
            return Err(TokenError::Expired);
        }
        if claims.iat > now + CLOCK_SKEW_SECS {
            return Err(TokenError::NotYetValid);
        }
        Ok(claims)
    }
}

/// Whether `value` looks like one of our tokens.
///
/// A cheap prefix test, used to decide whether a header is worth parsing. It
/// says nothing about validity: [`TokenSigner::verify`] is the only thing that
/// does.
pub fn looks_synthetic(value: &str) -> bool {
    value.starts_with(TOKEN_PREFIX)
}

/// One DPoP proof, as the proxy checks it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DpopClaims {
    /// The HTTP method the proof covers.
    pub htm: String,
    /// The request URI the proof covers, without the query string.
    pub htu: String,
    /// When the proof was made, in Unix seconds.
    pub iat: i64,
    /// A unique identifier for this proof.
    pub jti: String,
}

/// The protected header of a DPoP proof.
#[derive(Debug, Deserialize)]
struct DpopHeader {
    alg: String,
}

/// Why a DPoP proof was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DpopError {
    /// Not a compact JWS, or not decodable.
    #[error("the DPoP header is not a compact JWS")]
    Malformed,

    /// The algorithm is not `EdDSA`.
    ///
    /// Refused rather than ignored: `alg: none` is the oldest JWS attack there
    /// is, and an algorithm the proxy does not implement must never be read as
    /// "no signature to check".
    #[error("a DPoP proof must be signed with EdDSA")]
    BadAlgorithm,

    /// The signature is not the session key's over this proof.
    #[error("the DPoP signature does not verify")]
    BadSignature,

    /// The token's `cnf.jkt` does not name the session key.
    #[error("the DPoP proof is not made with the key the token is bound to")]
    WrongKey,

    /// `htm` or `htu` does not describe the request it arrived on.
    #[error("the DPoP proof does not cover this request")]
    WrongRequest,

    /// `iat` is too far from now in either direction.
    #[error("the DPoP proof is stale")]
    Stale,
}

/// Verify a DPoP proof against the session key and the request it arrived on.
///
/// `htu` is built by the caller from the request the proxy actually received,
/// with the query string stripped — the same shape the client is told to sign,
/// and one that cannot carry a credential into the comparison.
pub fn verify_dpop(
    proof: &str,
    public_key: &[u8; 32],
    expected_jkt: &str,
    method: &str,
    htu: &str,
    now: i64,
) -> Result<DpopClaims, DpopError> {
    if thumbprint(public_key) != expected_jkt {
        return Err(DpopError::WrongKey);
    }

    let mut parts = proof.split('.');
    let (header, payload, signature) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return Err(DpopError::Malformed),
        };

    let decoded_header: DpopHeader =
        serde_json::from_slice(&B64.decode(header).map_err(|_| DpopError::Malformed)?)
            .map_err(|_| DpopError::Malformed)?;
    if decoded_header.alg != "EdDSA" {
        return Err(DpopError::BadAlgorithm);
    }

    let signature: [u8; 64] = B64
        .decode(signature)
        .map_err(|_| DpopError::Malformed)?
        .try_into()
        .map_err(|_| DpopError::Malformed)?;
    let verifying = VerifyingKey::from_bytes(public_key).map_err(|_| DpopError::WrongKey)?;
    verifying
        .verify(
            format!("{header}.{payload}").as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| DpopError::BadSignature)?;

    let claims: DpopClaims =
        serde_json::from_slice(&B64.decode(payload).map_err(|_| DpopError::Malformed)?)
            .map_err(|_| DpopError::Malformed)?;

    if !claims.htm.eq_ignore_ascii_case(method) || claims.htu != htu {
        return Err(DpopError::WrongRequest);
    }
    if (claims.iat - now).abs() > DPOP_MAX_AGE_SECS {
        return Err(DpopError::Stale);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use briefcred_core::keystore::FileKeyStore;

    fn signer() -> TokenSigner {
        TokenSigner::from_hex(&hex::encode([7u8; 32])).unwrap()
    }

    fn claims(sid: &str, cred: &str, now: i64) -> Claims {
        Claims {
            sid: sid.to_string(),
            cred: cred.to_string(),
            iat: now,
            exp: now + 900,
            cnf: None,
        }
    }

    #[test]
    fn a_signed_token_verifies_and_carries_its_claims_back() {
        let signer = signer();
        let token = signer.sign(&claims("s1", "openai", 1_000));
        assert!(token.starts_with(TOKEN_PREFIX), "{}", &*token);
        assert!(looks_synthetic(&token));

        let back = signer.verify(&token, 1_100).unwrap();
        assert_eq!(back.sid, "s1");
        assert_eq!(back.cred, "openai");
        assert_eq!(back.exp, 1_900);
    }

    #[test]
    fn the_token_has_the_documented_three_part_shape() {
        let token = signer().sign(&claims("s1", "openai", 0));
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "{}", *token);
        assert_eq!(parts[0], "bc");
        // Base64url, no padding, in both tail parts.
        for part in &parts[1..] {
            assert!(!part.contains('='), "{part}");
            assert!(!part.contains('+') && !part.contains('/'), "{part}");
        }
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let signer = signer();
        let token = signer.sign(&claims("s1", "openai", 1_000));
        let mut broken = token.to_string();
        let last = broken.pop().unwrap();
        broken.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(
            signer.verify(&broken, 1_100).unwrap_err(),
            TokenError::BadSignature
        );
    }

    #[test]
    fn a_tampered_payload_is_refused_before_it_is_even_parsed() {
        let signer = signer();
        let token = signer.sign(&claims("s1", "openai", 1_000));
        // Re-encode a payload naming a different session, keeping the
        // signature: this is the attack the signature exists to stop.
        let forged_payload =
            B64.encode(serde_json::to_vec(&claims("s2", "openai", 1_000)).unwrap());
        let signature = token.rsplit_once('.').unwrap().1;
        let forged = format!("{TOKEN_PREFIX}{forged_payload}.{signature}");
        assert_eq!(
            signer.verify(&forged, 1_100).unwrap_err(),
            TokenError::BadSignature
        );
    }

    #[test]
    fn a_token_from_another_daemons_key_is_refused() {
        let token = signer().sign(&claims("s1", "openai", 1_000));
        let other = TokenSigner::from_hex(&hex::encode([9u8; 32])).unwrap();
        assert_eq!(
            other.verify(&token, 1_100).unwrap_err(),
            TokenError::BadSignature
        );
    }

    #[test]
    fn an_expired_token_is_refused_once_the_skew_allowance_is_gone() {
        let signer = signer();
        let token = signer.sign(&claims("s1", "openai", 1_000));
        // exp is 1_900; the skew allowance carries it to 1_960.
        assert!(signer.verify(&token, 1_960).is_ok());
        assert_eq!(
            signer.verify(&token, 1_961).unwrap_err(),
            TokenError::Expired
        );
    }

    #[test]
    fn a_token_issued_in_the_future_is_refused() {
        let signer = signer();
        let token = signer.sign(&claims("s1", "openai", 10_000));
        assert!(signer.verify(&token, 9_940).is_ok(), "skew is allowed");
        assert_eq!(
            signer.verify(&token, 9_939).unwrap_err(),
            TokenError::NotYetValid
        );
    }

    #[test]
    fn something_that_is_not_a_token_at_all_is_malformed() {
        let signer = signer();
        for bad in [
            "",
            "sk-a-real-openai-key",
            "bc.",
            "bc.notbase64!.notbase64!",
            "xx.abc.def",
            "bc.YWJj.YWJj",
        ] {
            assert!(
                matches!(
                    signer.verify(bad, 0),
                    Err(TokenError::Malformed) | Err(TokenError::BadSignature)
                ),
                "`{bad}` was accepted"
            );
        }
        assert!(!looks_synthetic("sk-a-real-openai-key"));
    }

    #[test]
    fn a_token_carries_the_session_key_thumbprint_when_the_session_has_one() {
        let signer = signer();
        let public = [3u8; 32];
        let mut c = claims("s1", "openai", 0);
        c.cnf = Some(Confirmation {
            jkt: thumbprint(&public),
        });
        let back = signer.verify(&signer.sign(&c), 1).unwrap();
        assert_eq!(back.cnf.unwrap().jkt, thumbprint(&public));
    }

    #[test]
    fn a_thumbprint_is_the_base64url_sha256_of_the_raw_key() {
        let public = [3u8; 32];
        assert_eq!(thumbprint(&public), B64.encode(Sha256::digest(public)));
        assert_ne!(thumbprint(&public), thumbprint(&[4u8; 32]));
    }

    #[test]
    fn a_signer_is_created_once_and_then_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path());
        let first = TokenSigner::load_or_create(&store).unwrap();
        let second = TokenSigner::load_or_create(&store).unwrap();

        // The same key, proved by one verifying what the other signed.
        let token = first.sign(&claims("s1", "openai", 0));
        assert!(second.verify(&token, 1).is_ok());
    }

    #[test]
    fn a_corrupt_stored_key_is_an_error_rather_than_a_silent_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path());
        store
            .put(TOKEN_SIGNER_ITEM, &Zeroizing::new("not-hex".into()))
            .unwrap();
        assert!(TokenSigner::load_or_create(&store).is_err());

        store
            .put(TOKEN_SIGNER_ITEM, &Zeroizing::new(hex::encode([1u8; 16])))
            .unwrap();
        let err = TokenSigner::load_or_create(&store).unwrap_err();
        assert!(err.to_string().contains("32"), "{err}");
    }

    #[test]
    fn a_signer_never_prints_its_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path());
        let signer = TokenSigner::load_or_create(&store).unwrap();
        let stored = store.get(TOKEN_SIGNER_ITEM).unwrap().unwrap();
        let rendered = format!("{signer:?}");
        assert!(!rendered.contains(&*stored), "{rendered}");
        assert!(rendered.contains("public_key"), "{rendered}");
    }

    // --- DPoP ---

    fn session_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn proof(key: &SigningKey, alg: &str, htm: &str, htu: &str, iat: i64) -> String {
        let header = B64.encode(serde_json::json!({ "typ": "dpop+jwt", "alg": alg }).to_string());
        let payload = B64.encode(
            serde_json::json!({ "htm": htm, "htu": htu, "iat": iat, "jti": "abc" }).to_string(),
        );
        let signing_input = format!("{header}.{payload}");
        format!(
            "{signing_input}.{}",
            B64.encode(key.sign(signing_input.as_bytes()).to_bytes())
        )
    }

    fn public(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes()
    }

    #[test]
    fn a_well_formed_proof_for_this_request_verifies() {
        let key = session_key();
        let public = public(&key);
        let htu = "https://api.openai.com/v1/models";
        let token = proof(&key, "EdDSA", "GET", htu, 1_000);
        let claims = verify_dpop(&token, &public, &thumbprint(&public), "GET", htu, 1_000).unwrap();
        assert_eq!(claims.jti, "abc");
        assert_eq!(claims.htm, "GET");
    }

    #[test]
    fn a_proof_signed_by_another_key_is_refused() {
        let key = session_key();
        let public = public(&key);
        let other = SigningKey::from_bytes(&[43u8; 32]);
        let htu = "https://api.openai.com/v1/models";
        let token = proof(&other, "EdDSA", "GET", htu, 1_000);
        assert_eq!(
            verify_dpop(&token, &public, &thumbprint(&public), "GET", htu, 1_000).unwrap_err(),
            DpopError::BadSignature
        );
    }

    #[test]
    fn a_proof_whose_key_is_not_the_one_the_token_names_is_refused() {
        let key = session_key();
        let public = public(&key);
        let htu = "https://api.openai.com/v1/models";
        let token = proof(&key, "EdDSA", "GET", htu, 1_000);
        assert_eq!(
            verify_dpop(&token, &public, &thumbprint(&[9u8; 32]), "GET", htu, 1_000).unwrap_err(),
            DpopError::WrongKey
        );
    }

    #[test]
    fn a_proof_for_another_request_is_refused() {
        let key = session_key();
        let public = public(&key);
        let jkt = thumbprint(&public);
        let htu = "https://api.openai.com/v1/models";
        let token = proof(&key, "EdDSA", "GET", htu, 1_000);
        assert_eq!(
            verify_dpop(&token, &public, &jkt, "POST", htu, 1_000).unwrap_err(),
            DpopError::WrongRequest
        );
        assert_eq!(
            verify_dpop(
                &token,
                &public,
                &jkt,
                "GET",
                "https://api.openai.com/v1/chat/completions",
                1_000
            )
            .unwrap_err(),
            DpopError::WrongRequest
        );
    }

    #[test]
    fn a_proof_claiming_no_algorithm_is_refused_rather_than_trusted() {
        let key = session_key();
        let public = public(&key);
        let htu = "https://api.openai.com/v1/models";
        for alg in ["none", "HS256", "RS256"] {
            let token = proof(&key, alg, "GET", htu, 1_000);
            assert_eq!(
                verify_dpop(&token, &public, &thumbprint(&public), "GET", htu, 1_000).unwrap_err(),
                DpopError::BadAlgorithm,
                "alg {alg}"
            );
        }
    }

    #[test]
    fn a_stale_proof_is_refused_in_both_directions() {
        let key = session_key();
        let public = public(&key);
        let jkt = thumbprint(&public);
        let htu = "https://api.openai.com/v1/models";
        let token = proof(&key, "EdDSA", "GET", htu, 1_000);
        assert!(verify_dpop(&token, &public, &jkt, "GET", htu, 1_300).is_ok());
        assert_eq!(
            verify_dpop(&token, &public, &jkt, "GET", htu, 1_301).unwrap_err(),
            DpopError::Stale
        );
        assert_eq!(
            verify_dpop(&token, &public, &jkt, "GET", htu, 699).unwrap_err(),
            DpopError::Stale
        );
    }

    #[test]
    fn a_proof_that_is_not_a_compact_jws_is_refused() {
        let key = session_key();
        let public = public(&key);
        let jkt = thumbprint(&public);
        for bad in ["", "a.b", "a.b.c.d", "!!.!!.!!"] {
            assert!(
                verify_dpop(bad, &public, &jkt, "GET", "https://a.test/", 0).is_err(),
                "`{bad}` was accepted"
            );
        }
    }
}
