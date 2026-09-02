//! Minisign-compatible Ed25519 detached signatures.
//!
//! briefcred distributes profiles as files somebody else wrote, so a profile
//! that arrives over the network has to carry a signature briefcred can check
//! against a key the operator named. The format is minisign's, not one of our
//! own: an operator who already signs releases has the tooling, and a profile
//! author can sign with `minisign -S` and never install briefcred at all.
//!
//! Three files, all lines of text:
//!
//! - A **public key** is a comment line and one base64 line holding
//!   `"Ed" || key_id[8] || public_key[32]`.
//! - A **secret key** is a comment line and one base64 line holding the
//!   algorithm identifiers, the (unused, password-less) key-derivation
//!   parameters, and `key_id[8] || secret_key[64] || checksum[32]`.
//! - A **signature** is four lines: an untrusted comment, base64 of
//!   `"Ed" || key_id[8] || signature[64]`, a *trusted* comment, and base64 of
//!   a second signature over `signature[64] || trusted_comment`.
//!
//! The trusted comment is the point of the second signature. The first line's
//! comment is attacker-controlled — nothing signs it — so anything that must
//! survive the trip, a file name or a version, goes in the trusted comment,
//! which the global signature covers.
//!
//! briefcred writes password-less secret keys, because the thing signing a
//! profile in a release pipeline has no human to prompt. That is a real
//! trade-off and it is documented rather than hidden: the key file is `0600`
//! and its secrecy is the filesystem's job.

use std::fmt;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as _};
use ed25519_dalek::{Signature as DalekSignature, Signer as _, SigningKey, Verifier as _};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// The legacy (non-prehashed) minisign signature algorithm.
///
/// briefcred signs the file's bytes rather than a hash of them. Profiles are
/// kilobytes, so the prehashed variant buys nothing, and the legacy form is
/// what every minisign release since 0.1 can verify.
pub const SIG_ALG: [u8; 2] = *b"Ed";

/// The checksum algorithm identifier in a secret-key file: BLAKE2b.
const CKSUM_ALG: [u8; 2] = *b"B2";

/// The key-derivation algorithm identifier for a password-less secret key.
///
/// Two zero bytes, which is how minisign itself records "this key is not
/// encrypted"; the salt and the scrypt parameters that follow are then zeroes
/// too and the key material is stored in the clear.
const KDF_ALG_NONE: [u8; 2] = [0, 0];

/// Bytes in the base64 payload of a public-key line.
const PUBLIC_KEY_BYTES: usize = 2 + 8 + 32;

/// Bytes in the base64 payload of a secret-key line.
const SECRET_KEY_BYTES: usize = 2 + 2 + 2 + 32 + 8 + 8 + 8 + 64 + 32;

/// Bytes in the base64 payload of a signature's first line.
const SIGNATURE_BYTES: usize = 2 + 8 + 64;

/// The comment prefix minisign writes above a public key.
const PUBLIC_KEY_COMMENT: &str = "untrusted comment: minisign public key";

/// The comment prefix minisign writes above a secret key.
const SECRET_KEY_COMMENT: &str = "untrusted comment: minisign encrypted secret key";

/// The prefix of the third line of a signature file.
const TRUSTED_COMMENT_PREFIX: &str = "trusted comment: ";

fn bad(message: impl Into<String>) -> Error {
    Error::Signature(message.into())
}

/// Which key a signature says it came from.
///
/// Eight bytes chosen at random when the key is generated. It is a hint and
/// not a credential: it says which trust root to try, and the signature itself
/// is what decides whether the answer was right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId([u8; 8]);

impl KeyId {
    /// The raw eight bytes.
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Display for KeyId {
    /// Uppercase hex of the little-endian integer the bytes spell, which is
    /// how minisign prints a key id in its own comments and messages.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016X}", u64::from_le_bytes(self.0))
    }
}

/// A minisign public key: an Ed25519 verifying key and the id it answers to.
#[derive(Debug, Clone)]
pub struct PublicKey {
    key_id: KeyId,
    key: ed25519_dalek::VerifyingKey,
}

impl PublicKey {
    /// The key's id.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Parse the single base64 line that carries a public key.
    ///
    /// This is the form `daemon.toml` holds in `profiles.trust_roots`: one
    /// line, no comment, so a trust root is a value an operator can paste out
    /// of a `.pub` file without the surrounding file structure.
    pub fn parse_line(line: &str) -> Result<PublicKey> {
        let raw = BASE64
            .decode(line.trim())
            .map_err(|e| bad(format!("public key is not valid base64: {e}")))?;
        if raw.len() != PUBLIC_KEY_BYTES {
            return Err(bad(format!(
                "public key is {} bytes, expected {PUBLIC_KEY_BYTES}",
                raw.len()
            )));
        }
        if raw[..2] != SIG_ALG {
            return Err(bad(
                "public key is not an Ed25519 minisign key (bad algorithm tag)",
            ));
        }
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&raw[2..10]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw[10..]);
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|e| bad(format!("public key is not a valid Ed25519 point: {e}")))?;
        Ok(PublicKey {
            key_id: KeyId(key_id),
            key,
        })
    }

    /// Parse a whole `.pub` file: a comment line, then the key line.
    ///
    /// Blank lines and the comment are skipped, so a file with Windows line
    /// endings or a trailing newline parses the same as one without.
    pub fn parse_file(text: &str) -> Result<PublicKey> {
        let line = key_line(text).ok_or_else(|| bad("no key line in the public key file"))?;
        PublicKey::parse_line(line)
    }

    /// The single base64 line, as `daemon.toml` wants it.
    pub fn to_line(&self) -> String {
        let mut raw = Vec::with_capacity(PUBLIC_KEY_BYTES);
        raw.extend_from_slice(&SIG_ALG);
        raw.extend_from_slice(&self.key_id.0);
        raw.extend_from_slice(self.key.as_bytes());
        BASE64.encode(raw)
    }

    /// The whole `.pub` file, comment and all.
    pub fn to_file(&self) -> String {
        format!("{PUBLIC_KEY_COMMENT} {}\n{}\n", self.key_id, self.to_line())
    }
}

/// A minisign secret key, held only as long as something is signing with it.
///
/// No `Display`, no `Serialize`, and a hand-written `Debug` that prints the
/// key id and nothing else: the only way key material leaves this type is
/// [`SecretKey::to_file`], which returns [`Zeroizing`] text on its way to a
/// `0600` file.
pub struct SecretKey {
    key_id: KeyId,
    signing: SigningKey,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("key_id", &self.key_id)
            .field("signing", &"<redacted>")
            .finish()
    }
}

impl SecretKey {
    /// Generate a fresh key pair.
    pub fn generate() -> Result<(SecretKey, PublicKey)> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut())
            .map_err(|e| bad(format!("cannot read random bytes for a signing key: {e}")))?;
        let mut key_id = [0u8; 8];
        getrandom::fill(&mut key_id)
            .map_err(|e| bad(format!("cannot read random bytes for a key id: {e}")))?;
        let signing = SigningKey::from_bytes(&seed);
        let secret = SecretKey {
            key_id: KeyId(key_id),
            signing,
        };
        let public = secret.public();
        Ok((secret, public))
    }

    /// The key's id, shared with the public half.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The matching public key.
    pub fn public(&self) -> PublicKey {
        PublicKey {
            key_id: self.key_id,
            key: self.signing.verifying_key(),
        }
    }

    /// Render the password-less secret-key file.
    pub fn to_file(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new(Vec::with_capacity(SECRET_KEY_BYTES));
        raw.extend_from_slice(&SIG_ALG);
        raw.extend_from_slice(&KDF_ALG_NONE);
        raw.extend_from_slice(&CKSUM_ALG);
        // Salt, opslimit and memlimit. All zero: there is no password, so
        // there is no key derivation for them to parameterise.
        raw.extend_from_slice(&[0u8; 32 + 8 + 8]);
        raw.extend_from_slice(self.keynum_sk().as_slice());
        Zeroizing::new(format!(
            "{SECRET_KEY_COMMENT}\n{}\n",
            BASE64.encode(raw.as_slice())
        ))
    }

    /// Parse a password-less secret-key file.
    pub fn parse_file(text: &str) -> Result<SecretKey> {
        let line = key_line(text).ok_or_else(|| bad("no key line in the secret key file"))?;
        let raw = Zeroizing::new(
            BASE64
                .decode(line.trim())
                .map_err(|e| bad(format!("secret key is not valid base64: {e}")))?,
        );
        if raw.len() != SECRET_KEY_BYTES {
            return Err(bad(format!(
                "secret key is {} bytes, expected {SECRET_KEY_BYTES}",
                raw.len()
            )));
        }
        if raw[..2] != SIG_ALG {
            return Err(bad(
                "secret key is not an Ed25519 minisign key (bad algorithm tag)",
            ));
        }
        // A key with a key-derivation algorithm set is password-protected, and
        // briefcred has nowhere to prompt: it signs from a release pipeline.
        // Saying so beats decoding the encrypted bytes and failing the
        // checksum, which would read as "your key file is corrupt".
        if raw[2..4] != KDF_ALG_NONE {
            return Err(bad(
                "this secret key is password-protected; briefcred signs with password-less keys \
                 (generate one with `briefcred profile keygen`)",
            ));
        }
        if raw[4..6] != CKSUM_ALG {
            return Err(bad("secret key uses an unknown checksum algorithm"));
        }
        let keynum = &raw[6 + 48..];
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&keynum[..8]);
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&keynum[8..40]);
        let secret = SecretKey {
            key_id: KeyId(key_id),
            signing: SigningKey::from_bytes(&seed),
        };
        // The checksum catches a truncated or hand-edited file before a
        // signature made with the wrong key goes out the door.
        if keynum[72..] != secret.keynum_sk()[72..] {
            return Err(bad(
                "secret key checksum does not match; the file is damaged",
            ));
        }
        if keynum[8..72] != secret.keynum_sk()[8..72] {
            return Err(bad(
                "secret key's public half does not match its private half; the file is damaged",
            ));
        }
        Ok(secret)
    }

    /// Sign `content`, producing the text of a `.minisig` file.
    ///
    /// `trusted_comment` is covered by the global signature. Callers pass
    /// something that identifies what was signed — briefcred passes the file's
    /// name and the time — so a signature moved onto a different file is
    /// visible even when both files verify.
    pub fn sign(&self, content: &[u8], trusted_comment: &str) -> Result<String> {
        if trusted_comment.contains(['\r', '\n']) {
            return Err(bad("a trusted comment must be a single line"));
        }
        let signature = self.signing.sign(content);
        let mut global_input = Vec::with_capacity(64 + trusted_comment.len());
        global_input.extend_from_slice(&signature.to_bytes());
        global_input.extend_from_slice(trusted_comment.as_bytes());
        let global = self.signing.sign(&global_input);

        let mut first = Vec::with_capacity(SIGNATURE_BYTES);
        first.extend_from_slice(&SIG_ALG);
        first.extend_from_slice(&self.key_id.0);
        first.extend_from_slice(&signature.to_bytes());

        Ok(format!(
            "untrusted comment: signature from briefcred key {}\n{}\n\
             {TRUSTED_COMMENT_PREFIX}{trusted_comment}\n{}\n",
            self.key_id,
            BASE64.encode(first),
            BASE64.encode(global.to_bytes())
        ))
    }

    /// `key_id || secret_key || checksum`, the payload a secret-key file ends
    /// with. The secret key is libsodium's 64-byte form: seed then public key.
    fn keynum_sk(&self) -> Zeroizing<[u8; 104]> {
        let mut out = Zeroizing::new([0u8; 104]);
        out[..8].copy_from_slice(&self.key_id.0);
        out[8..40].copy_from_slice(self.signing.as_bytes());
        out[40..72].copy_from_slice(self.signing.verifying_key().as_bytes());

        let mut hasher = Blake2b::<U32>::new();
        hasher.update(SIG_ALG);
        hasher.update(&out[..72]);
        out[72..].copy_from_slice(&hasher.finalize());
        out
    }
}

/// A parsed `.minisig` file.
#[derive(Debug, Clone)]
pub struct Signature {
    key_id: KeyId,
    signature: [u8; 64],
    global: [u8; 64],
    trusted_comment: String,
}

impl Signature {
    /// Which key the signer claims to have used.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The trusted comment, which is only trustworthy after [`Signature::verify`].
    pub fn trusted_comment(&self) -> &str {
        &self.trusted_comment
    }

    /// Parse the four lines of a `.minisig` file.
    pub fn parse(text: &str) -> Result<Signature> {
        let mut lines = text.lines().filter(|line| !line.trim().is_empty());
        // The first line is an untrusted comment. Nothing signs it, so it is
        // skipped rather than read: believing it would be believing whoever
        // last touched the file.
        let _untrusted = lines.next().ok_or_else(|| bad("signature file is empty"))?;
        let first = lines
            .next()
            .ok_or_else(|| bad("signature file has no signature line"))?;
        let trusted = lines
            .next()
            .ok_or_else(|| bad("signature file has no trusted comment"))?;
        let global = lines
            .next()
            .ok_or_else(|| bad("signature file has no global signature"))?;

        let raw = BASE64
            .decode(first.trim())
            .map_err(|e| bad(format!("signature line is not valid base64: {e}")))?;
        if raw.len() != SIGNATURE_BYTES {
            return Err(bad(format!(
                "signature is {} bytes, expected {SIGNATURE_BYTES}",
                raw.len()
            )));
        }
        if raw[..2] != SIG_ALG {
            return Err(bad(
                "signature is not a legacy Ed25519 minisign signature (bad algorithm tag)",
            ));
        }
        let trusted_comment = trusted
            .strip_prefix(TRUSTED_COMMENT_PREFIX)
            .ok_or_else(|| bad("the third line is not a `trusted comment:` line"))?
            .to_string();
        let global_raw = BASE64
            .decode(global.trim())
            .map_err(|e| bad(format!("global signature is not valid base64: {e}")))?;
        if global_raw.len() != 64 {
            return Err(bad(format!(
                "global signature is {} bytes, expected 64",
                global_raw.len()
            )));
        }

        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&raw[2..10]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&raw[10..]);
        let mut global_bytes = [0u8; 64];
        global_bytes.copy_from_slice(&global_raw);
        Ok(Signature {
            key_id: KeyId(key_id),
            signature,
            global: global_bytes,
            trusted_comment,
        })
    }

    /// Check this signature over `content` against `key`.
    ///
    /// Both signatures are checked, not just the first: a file whose content
    /// signature verifies but whose global signature does not has had its
    /// trusted comment rewritten, and the comment is the part callers are
    /// entitled to believe.
    pub fn verify(&self, content: &[u8], key: &PublicKey) -> Result<()> {
        if self.key_id != key.key_id {
            return Err(bad(format!(
                "signature is from key {} but was checked against key {}",
                self.key_id, key.key_id
            )));
        }
        key.key
            .verify(content, &DalekSignature::from_bytes(&self.signature))
            .map_err(|_| bad("signature does not match the file"))?;
        let mut global_input = Vec::with_capacity(64 + self.trusted_comment.len());
        global_input.extend_from_slice(&self.signature);
        global_input.extend_from_slice(self.trusted_comment.as_bytes());
        key.key
            .verify(&global_input, &DalekSignature::from_bytes(&self.global))
            .map_err(|_| bad("the trusted comment does not match its signature"))?;
        Ok(())
    }
}

/// Verify `signature_text` over `content` against whichever of `roots` matches.
///
/// Returns the key that vouched for the file. An empty root list is a refusal
/// rather than a pass: "no trust roots configured" must never mean "everything
/// is trusted".
pub fn verify_with_any(
    content: &[u8],
    signature_text: &str,
    roots: &[PublicKey],
) -> Result<PublicKey> {
    let signature = Signature::parse(signature_text)?;
    if roots.is_empty() {
        return Err(bad(
            "no trust roots are configured, so no signature can be checked \
             (set `profiles.trust_roots` in daemon.toml)",
        ));
    }
    let mut matched = false;
    for root in roots {
        if root.key_id != signature.key_id {
            continue;
        }
        matched = true;
        if signature.verify(content, root).is_ok() {
            return Ok(root.clone());
        }
    }
    if matched {
        return Err(bad(format!(
            "signature from key {} does not match the file",
            signature.key_id
        )));
    }
    Err(bad(format!(
        "signature is from key {}, which is not a trust root",
        signature.key_id
    )))
}

/// The first line of a key file that is not blank and not a comment.
fn key_line(text: &str) -> Option<&str> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("untrusted comment:"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 section 7.1, TEST 3: the standard Ed25519 vector briefcred
    /// anchors its signature encoding to.
    ///
    /// This is the part of the minisign format that decides interoperability.
    /// A `.minisig` line is `"Ed"`, the key id, and *the raw Ed25519 signature
    /// of the file's bytes* — not of a hash, not of a length-prefixed blob. If
    /// briefcred ever signed something else, this vector is what notices,
    /// because the bytes it expects came from the standard rather than from
    /// briefcred's own output.
    const RFC8032_SEED: [u8; 32] = [
        0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7,
        0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44,
        0x58, 0xf7,
    ];
    const RFC8032_PUBLIC: [u8; 32] = [
        0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0,
        0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90,
        0x80, 0x25,
    ];
    const RFC8032_MESSAGE: [u8; 2] = [0xaf, 0x82];
    const RFC8032_SIGNATURE: [u8; 64] = [
        0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02, 0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe, 0x01,
        0xa3, 0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44, 0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a,
        0xc3, 0xac, 0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90, 0xae, 0x67, 0xf7, 0x60, 0x98,
        0x4d, 0xc6, 0x59, 0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d, 0xc0, 0x27, 0xbe, 0xce,
        0xea, 0x1e, 0xc4, 0x0a,
    ];

    /// A secret key built on the RFC vector, with a fixed key id so the test's
    /// expected bytes are stable.
    fn vector_key() -> SecretKey {
        SecretKey {
            key_id: KeyId([1, 2, 3, 4, 5, 6, 7, 8]),
            signing: SigningKey::from_bytes(&RFC8032_SEED),
        }
    }

    #[test]
    fn the_signature_line_carries_the_rfc_8032_signature_of_the_file() {
        let key = vector_key();
        let text = key.sign(&RFC8032_MESSAGE, "timestamp:0").unwrap();
        let parsed = Signature::parse(&text).unwrap();
        assert_eq!(
            parsed.signature, RFC8032_SIGNATURE,
            "the signature line must be the raw Ed25519 signature of the file's bytes"
        );
        assert_eq!(parsed.key_id, KeyId([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(parsed.trusted_comment(), "timestamp:0");
    }

    #[test]
    fn the_public_key_derived_from_the_vector_is_the_rfc_public_key() {
        let public = vector_key().public();
        assert_eq!(public.key.as_bytes(), &RFC8032_PUBLIC);
        assert_eq!(
            PublicKey::parse_line(&public.to_line())
                .unwrap()
                .key
                .as_bytes(),
            &RFC8032_PUBLIC
        );
    }

    #[test]
    fn the_signature_file_framing_is_the_documented_one() {
        let key = vector_key();
        let text = key.sign(&RFC8032_MESSAGE, "timestamp:0").unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "a minisig file is exactly four lines");
        assert!(lines[0].starts_with("untrusted comment: "), "{}", lines[0]);
        assert_eq!(lines[2], "trusted comment: timestamp:0");

        // The second line is `"Ed" || key_id || signature`, in that order,
        // standard base64. Built here from the RFC bytes rather than copied
        // from briefcred's own output, so a reordered or resized field fails.
        let mut expected = Vec::new();
        expected.extend_from_slice(b"Ed");
        expected.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        expected.extend_from_slice(&RFC8032_SIGNATURE);
        assert_eq!(lines[1], BASE64.encode(&expected));

        // The fourth line signs the signature and the trusted comment, which
        // is checked by verifying rather than by eye.
        Signature::parse(&text)
            .unwrap()
            .verify(&RFC8032_MESSAGE, &key.public())
            .expect("the file briefcred writes must verify against its own public key");
    }

    #[test]
    fn a_round_trip_verifies() {
        let (secret, public) = SecretKey::generate().unwrap();
        let content = b"name: alpha\n";
        let text = secret.sign(content, "profile alpha").unwrap();
        Signature::parse(&text)
            .unwrap()
            .verify(content, &public)
            .unwrap();
        assert_eq!(secret.key_id(), public.key_id());
    }

    #[test]
    fn a_tampered_byte_of_content_fails_verification() {
        let (secret, public) = SecretKey::generate().unwrap();
        let text = secret.sign(b"name: alpha\n", "profile alpha").unwrap();
        let err = Signature::parse(&text)
            .unwrap()
            .verify(b"name: alphb\n", &public)
            .unwrap_err();
        assert!(err.to_string().contains("does not match the file"), "{err}");
    }

    #[test]
    fn a_tampered_trusted_comment_fails_even_though_the_content_still_matches() {
        let (secret, public) = SecretKey::generate().unwrap();
        let content = b"name: alpha\n";
        let text = secret.sign(content, "profile alpha").unwrap().replace(
            "trusted comment: profile alpha",
            "trusted comment: profile root",
        );
        let err = Signature::parse(&text)
            .unwrap()
            .verify(content, &public)
            .unwrap_err();
        assert!(err.to_string().contains("trusted comment"), "{err}");
    }

    #[test]
    fn a_tampered_signature_byte_fails_verification() {
        let (secret, public) = SecretKey::generate().unwrap();
        let content = b"name: alpha\n";
        let text = secret.sign(content, "c").unwrap();
        let mut parsed = Signature::parse(&text).unwrap();
        parsed.signature[0] ^= 0x01;
        assert!(parsed.verify(content, &public).is_err());
    }

    #[test]
    fn a_signature_from_another_key_is_refused_rather_than_ignored() {
        let (alice, _) = SecretKey::generate().unwrap();
        let (_, bob) = SecretKey::generate().unwrap();
        let content = b"name: alpha\n";
        let text = alice.sign(content, "c").unwrap();
        let err = Signature::parse(&text)
            .unwrap()
            .verify(content, &bob)
            .unwrap_err();
        assert!(err.to_string().contains("checked against key"), "{err}");
    }

    #[test]
    fn a_secret_key_file_round_trips_and_keeps_its_key_id() {
        let (secret, public) = SecretKey::generate().unwrap();
        let text = secret.to_file();
        let parsed = SecretKey::parse_file(&text).unwrap();
        assert_eq!(parsed.key_id(), secret.key_id());
        let content = b"x";
        let signature = parsed.sign(content, "c").unwrap();
        Signature::parse(&signature)
            .unwrap()
            .verify(content, &public)
            .unwrap();
    }

    #[test]
    fn a_secret_key_file_never_renders_the_key_outside_zeroizing_text() {
        let (secret, _) = SecretKey::generate().unwrap();
        let text = secret.to_file();
        assert!(text.starts_with(SECRET_KEY_COMMENT));
        // Two lines and nothing else: no third line could carry a stray copy.
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn a_damaged_secret_key_file_is_refused() {
        let (secret, _) = SecretKey::generate().unwrap();
        let text = secret.to_file();
        let line = key_line(&text).unwrap();
        let mut raw = BASE64.decode(line).unwrap();
        // Flip a bit inside the private half; the checksum must catch it.
        raw[6 + 48 + 8] ^= 0x01;
        let damaged = format!("{SECRET_KEY_COMMENT}\n{}\n", BASE64.encode(raw));
        let err = SecretKey::parse_file(&damaged).unwrap_err();
        assert!(err.to_string().contains("damaged"), "{err}");
    }

    #[test]
    fn a_password_protected_secret_key_says_so_rather_than_looking_corrupt() {
        let (secret, _) = SecretKey::generate().unwrap();
        let line = key_line(&secret.to_file()).unwrap().to_string();
        let mut raw = BASE64.decode(&line).unwrap();
        raw[2..4].copy_from_slice(b"Sc");
        let encrypted = format!("{SECRET_KEY_COMMENT}\n{}\n", BASE64.encode(raw));
        let err = SecretKey::parse_file(&encrypted).unwrap_err();
        assert!(err.to_string().contains("password-protected"), "{err}");
    }

    #[test]
    fn a_public_key_file_round_trips() {
        let (_, public) = SecretKey::generate().unwrap();
        let file = public.to_file();
        assert!(file.starts_with(PUBLIC_KEY_COMMENT));
        let parsed = PublicKey::parse_file(&file).unwrap();
        assert_eq!(parsed.key_id(), public.key_id());
        assert_eq!(parsed.to_line(), public.to_line());
    }

    #[test]
    fn a_public_key_line_of_the_wrong_length_is_refused() {
        let err = PublicKey::parse_line(&BASE64.encode([0u8; 10])).unwrap_err();
        assert!(err.to_string().contains("expected 42"), "{err}");
        assert!(PublicKey::parse_line("not base64!").is_err());
    }

    #[test]
    fn verify_with_any_picks_the_matching_root_and_names_an_unknown_one() {
        let (alice, alice_pub) = SecretKey::generate().unwrap();
        let (_, bob_pub) = SecretKey::generate().unwrap();
        let (carol, _) = SecretKey::generate().unwrap();
        let content = b"name: alpha\n";

        let signed = alice.sign(content, "c").unwrap();
        let who = verify_with_any(content, &signed, &[bob_pub.clone(), alice_pub.clone()]).unwrap();
        assert_eq!(who.key_id(), alice_pub.key_id());

        let stranger = carol.sign(content, "c").unwrap();
        let err =
            verify_with_any(content, &stranger, std::slice::from_ref(&alice_pub)).unwrap_err();
        assert!(err.to_string().contains("not a trust root"), "{err}");
    }

    #[test]
    fn an_empty_trust_root_list_refuses_rather_than_trusting_everything() {
        let (alice, _) = SecretKey::generate().unwrap();
        let signed = alice.sign(b"x", "c").unwrap();
        let err = verify_with_any(b"x", &signed, &[]).unwrap_err();
        assert!(err.to_string().contains("no trust roots"), "{err}");
    }

    #[test]
    fn a_trusted_comment_with_a_newline_is_refused_rather_than_splitting_the_file() {
        let (secret, _) = SecretKey::generate().unwrap();
        let err = secret.sign(b"x", "a\nb").unwrap_err();
        assert!(err.to_string().contains("single line"), "{err}");
    }

    #[test]
    fn a_truncated_signature_file_names_the_missing_line() {
        let (secret, _) = SecretKey::generate().unwrap();
        let text = secret.sign(b"x", "c").unwrap();
        let three_lines: String = text.lines().take(3).collect::<Vec<_>>().join("\n");
        let err = Signature::parse(&three_lines).unwrap_err();
        assert!(err.to_string().contains("global signature"), "{err}");
    }
}
