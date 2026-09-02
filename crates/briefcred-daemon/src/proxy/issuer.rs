//! Issuing, retiring, and checking synthetic tokens.
//!
//! One object, held by the daemon for its whole life, that owns the three
//! things a synthetic token's lifecycle needs: the signing key, the set of
//! grants that have been revoked, and the address the token has to be sent
//! through. The mint path calls [`ProxyIssuer::issue`], the revoke queue calls
//! [`ProxyIssuer::revoke`], and the proxy calls [`ProxyIssuer::authorize`].
//!
//! Keeping them together is what makes "revoked" mean something: a token is
//! verifiable by anyone with the public key, so the only thing that can decide
//! it is *no longer* good is the daemon that issued it, and the check has to
//! live next to the verification rather than at some call site that might
//! forget it.
//!
//! # Why the key is loaded lazily
//!
//! The signing key lives in the platform key store, which on macOS is the login
//! keychain. Reading it at daemon start would make every briefcred install
//! prompt for keychain access at login, whether or not the user has a single
//! profile that uses the proxy. So it is read on the first token — issued or
//! presented — and a daemon nobody proxies through never touches the key store
//! at all.

use std::sync::{Arc, Mutex};

use briefcred_core::keystore::KeyStore;
use zeroize::Zeroizing;

use crate::proxy::revocation::RevocationSet;
use crate::proxy::token::{thumbprint, Claims, Confirmation, TokenError, TokenSigner};

/// One issued token: the value the subprocess gets, and when it dies.
pub struct IssuedToken {
    /// The token itself, `bc.<payload>.<signature>`.
    pub token: Zeroizing<String>,
    /// When it stops being accepted, in Unix seconds.
    pub expires_at: i64,
}

impl std::fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedToken")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// The daemon's synthetic-token authority.
pub struct ProxyIssuer {
    store: Box<dyn KeyStore>,
    signer: Mutex<Option<Arc<TokenSigner>>>,
    revocations: RevocationSet,
    proxy_url: String,
}

impl std::fmt::Debug for ProxyIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyIssuer")
            .field("proxy_url", &self.proxy_url)
            .field("keystore", &self.store.kind())
            .field("revoked", &self.revocations.len())
            .finish()
    }
}

impl ProxyIssuer {
    /// Bind an issuer to `store` and `proxy_url`, reading nothing yet.
    pub fn open(store: Box<dyn KeyStore>, proxy_url: impl Into<String>) -> Arc<ProxyIssuer> {
        Arc::new(ProxyIssuer {
            store,
            signer: Mutex::new(None),
            revocations: RevocationSet::new(),
            proxy_url: proxy_url.into(),
        })
    }

    /// The signing key, reading or creating it on the first call.
    ///
    /// A failure is not cached: a key store that was locked when the first
    /// token arrived may well be open by the next one, and permanently
    /// remembering the refusal would need a daemon restart to recover from.
    fn signer(&self) -> briefcred_core::Result<Arc<TokenSigner>> {
        let mut cached = self
            .signer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(signer) = cached.as_ref() {
            return Ok(Arc::clone(signer));
        }
        let signer = Arc::new(TokenSigner::load_or_create(self.store.as_ref())?);
        *cached = Some(Arc::clone(&signer));
        Ok(signer)
    }

    /// The `http://127.0.0.1:<port>` a token has to be presented through.
    pub fn proxy_url(&self) -> &str {
        &self.proxy_url
    }

    /// Sign a token for `credential` in session `sid`, good for `ttl_secs`.
    ///
    /// `session_pubkey` is the client's per-session key, when it offered one.
    /// Its thumbprint goes into `cnf`, so a client that can sign a `DPoP` proof
    /// has something to prove itself against; a session without one gets a
    /// token with no `cnf` at all rather than an empty one, so the two cases
    /// are distinguishable rather than merely unenforced.
    pub fn issue(
        &self,
        sid: &str,
        session_pubkey: Option<&[u8; 32]>,
        credential: &str,
        ttl_secs: u64,
        now: i64,
    ) -> briefcred_core::Result<IssuedToken> {
        let expires_at = now.saturating_add(ttl_secs as i64);
        let token = self.signer()?.sign(&Claims {
            sid: sid.to_string(),
            cred: credential.to_string(),
            iat: now,
            exp: expires_at,
            cnf: session_pubkey.map(|key| Confirmation {
                jkt: thumbprint(key),
            }),
        });
        Ok(IssuedToken { token, expires_at })
    }

    /// Stop honouring `credential` for `sid`, up to `expires_at`.
    pub fn revoke(&self, sid: &str, credential: &str, expires_at: i64) {
        self.revocations.revoke(sid, credential, expires_at);
    }

    /// Check a token and return its claims, or say why it is not acceptable.
    ///
    /// Signature and expiry first, revocation second: a forged token must never
    /// reach the revocation set, because "is this pair revoked" is a question
    /// about a grant briefcred made, and an unverified token has not shown that
    /// it names one.
    pub fn authorize(&self, token: &str, now: i64) -> Result<Claims, TokenError> {
        // A key store that will not open is a token that cannot be checked,
        // and an unchecked token is not a permission.
        let signer = self.signer().map_err(|err| {
            eprintln!("briefcred-daemon: the proxy cannot reach its signing key: {err}");
            TokenError::BadSignature
        })?;
        let claims = signer.verify(token, now)?;
        if self.revocations.is_revoked(&claims.sid, &claims.cred, now) {
            return Err(TokenError::Revoked);
        }
        Ok(claims)
    }

    /// Whether the grant for `credential` in `sid` has been retired.
    ///
    /// Separate from [`ProxyIssuer::authorize`] for the one caller that has
    /// already verified a token and needs to keep asking: the Postgres proxy
    /// re-checks a *live connection* on a timer, and it holds the session and
    /// credential from the claims rather than the token string, so that a
    /// long-running connection is not a reason to keep a token resident.
    pub fn is_revoked(&self, sid: &str, credential: &str, now: i64) -> bool {
        self.revocations.is_revoked(sid, credential, now)
    }

    /// How many grants are currently revoked. For tests and diagnostics.
    pub fn revoked_count(&self) -> usize {
        self.revocations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use briefcred_core::keystore::FileKeyStore;

    fn issuer() -> (tempfile::TempDir, Arc<ProxyIssuer>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Box::new(FileKeyStore::new(dir.path()));
        (dir, ProxyIssuer::open(store, "http://127.0.0.1:9318"))
    }

    #[test]
    fn an_issued_token_authorizes_for_the_session_and_credential_it_names() {
        let (_dir, issuer) = issuer();
        let issued = issuer.issue("s1", None, "openai", 900, 1_000).unwrap();
        assert_eq!(issued.expires_at, 1_900);

        let claims = issuer.authorize(&issued.token, 1_500).unwrap();
        assert_eq!(claims.sid, "s1");
        assert_eq!(claims.cred, "openai");
        assert_eq!(claims.cnf, None, "a session with no key gets no `cnf`");
    }

    #[test]
    fn a_session_that_offered_a_key_gets_a_token_bound_to_it() {
        let (_dir, issuer) = issuer();
        let public = [5u8; 32];
        let issued = issuer.issue("s1", Some(&public), "openai", 900, 0).unwrap();
        let claims = issuer.authorize(&issued.token, 1).unwrap();
        assert_eq!(claims.cnf.unwrap().jkt, thumbprint(&public));
    }

    #[test]
    fn a_revoked_grant_stops_authorizing_immediately() {
        let (_dir, issuer) = issuer();
        let issued = issuer.issue("s1", None, "openai", 900, 1_000).unwrap();
        assert!(issuer.authorize(&issued.token, 1_100).is_ok());

        issuer.revoke("s1", "openai", issued.expires_at);
        assert_eq!(
            issuer.authorize(&issued.token, 1_100).unwrap_err(),
            TokenError::Revoked
        );
    }

    #[test]
    fn revoking_one_grant_leaves_the_sessions_other_credentials_alone() {
        let (_dir, issuer) = issuer();
        let openai = issuer.issue("s1", None, "openai", 900, 1_000).unwrap();
        let stripe = issuer.issue("s1", None, "stripe", 900, 1_000).unwrap();
        issuer.revoke("s1", "openai", openai.expires_at);

        assert!(issuer.authorize(&openai.token, 1_100).is_err());
        assert!(issuer.authorize(&stripe.token, 1_100).is_ok());
    }

    #[test]
    fn a_revoked_grant_stays_refused_for_as_long_as_its_token_still_verifies() {
        // The regression this guards: the revocation sweep used to drop an
        // entry at the token's `exp`, while `verify` accepts for
        // `CLOCK_SKEW_SECS` past it. In that window the signature checked out
        // and the revocation was gone, so a grant `briefcred exec` had already
        // retired started working again.
        let (_dir, issuer) = issuer();
        let issued = issuer.issue("s1", None, "openai", 900, 1_000).unwrap();
        issuer.revoke("s1", "openai", issued.expires_at);

        for now in [
            issued.expires_at - 1,
            issued.expires_at,
            issued.expires_at + crate::proxy::token::CLOCK_SKEW_SECS,
        ] {
            assert_eq!(
                issuer.authorize(&issued.token, now).unwrap_err(),
                TokenError::Revoked,
                "at {now}"
            );
        }

        // Past the skew allowance the token stops verifying on its own, so the
        // entry has done its job and the refusal changes shape.
        assert_eq!(
            issuer
                .authorize(
                    &issued.token,
                    issued.expires_at + crate::proxy::token::CLOCK_SKEW_SECS + 1
                )
                .unwrap_err(),
            TokenError::Expired
        );
    }

    #[test]
    fn a_second_exec_in_a_revoked_session_is_a_new_grant_that_also_stops() {
        // The revocation is on the pair, not on the token string, so a token
        // issued after the revoke for the same pair is refused too — which is
        // what "this session may no longer use this credential" has to mean.
        let (_dir, issuer) = issuer();
        issuer.revoke("s1", "openai", 5_000);
        let later = issuer.issue("s1", None, "openai", 900, 1_000).unwrap();
        assert_eq!(
            issuer.authorize(&later.token, 1_100).unwrap_err(),
            TokenError::Revoked
        );
    }

    #[test]
    fn a_forged_token_is_refused_before_the_revocation_set_is_consulted() {
        // A well-formed token from another daemon's key, for a pair that is
        // revoked here: the signature check has to reach it first.
        let (_other_dir, other) = issuer();
        let (_dir, issuer) = issuer();
        let forged = other.issue("s1", None, "openai", 900, 1_000).unwrap();
        issuer.revoke("s1", "openai", 1_900);

        assert_eq!(
            issuer.authorize(&forged.token, 1_100).unwrap_err(),
            TokenError::BadSignature
        );
    }

    #[test]
    fn an_expired_token_is_refused_even_though_nothing_revoked_it() {
        let (_dir, issuer) = issuer();
        let issued = issuer.issue("s1", None, "openai", 900, 1_000).unwrap();
        assert_eq!(
            issuer.authorize(&issued.token, 10_000).unwrap_err(),
            TokenError::Expired
        );
    }

    #[test]
    fn an_issued_token_never_prints_itself() {
        let (_dir, issuer) = issuer();
        let issued = issuer.issue("s1", None, "openai", 900, 0).unwrap();
        let rendered = format!("{issued:?}");
        assert!(!rendered.contains(&*issued.token), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn the_issuer_reports_where_a_token_has_to_be_presented() {
        let (_dir, issuer) = issuer();
        assert_eq!(issuer.proxy_url(), "http://127.0.0.1:9318");
    }
}
