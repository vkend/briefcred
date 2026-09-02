//! Which synthetic tokens the proxy has stopped accepting.
//!
//! A synthetic token is self-describing and short-lived, which is most of what
//! makes it safe — but "short-lived" is not "revocable", and `briefcred exec`
//! finishing has to mean the token it handed out stops working *now* rather
//! than at its expiry.
//!
//! So the daemon keeps a set. It is in memory only, and that is correct rather
//! than a shortcut: every entry is discardable once the token it names has
//! stopped verifying anyway, so a daemon restart loses nothing a token could
//! still be used with. Entries are keyed on `(session, credential)` rather than
//! on the token string, because that is what a revoke actually means — this
//! session may no longer use this credential — and because two `briefcred exec`
//! runs in one session hold two different token strings for the same grant.
//!
//! # The window the sweep has to cover
//!
//! "Stopped verifying" is *not* the token's `exp`.
//! [`crate::proxy::token::TokenSigner::verify`] allows
//! [`CLOCK_SKEW_SECS`] past it, so an entry dropped at `exp` would leave a
//! revoked grant working again for the whole of that minute — the token still
//! verifies, and the revocation that should refuse it has been swept. The
//! sweep therefore holds every entry until `exp + CLOCK_SKEW_SECS`, which is
//! exactly as long as the verifier will accept the token it names.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::proxy::token::CLOCK_SKEW_SECS;

/// Every `(session, credential)` pair the proxy will no longer serve.
#[derive(Debug, Default)]
pub struct RevocationSet {
    /// The pair, and the Unix second after which the entry can be forgotten.
    entries: Mutex<HashMap<(String, String), i64>>,
}

impl RevocationSet {
    /// An empty set.
    pub fn new() -> RevocationSet {
        RevocationSet::default()
    }

    /// Stop serving `credential` for `sid`.
    ///
    /// `expires_at` is the token's own `exp`, in Unix seconds. The entry is
    /// held until [`CLOCK_SKEW_SECS`] past it — the point at which the verifier
    /// stops accepting the token anyway — which is what stops the set growing
    /// for the life of the daemon without opening a window where the token
    /// verifies and the revocation has gone.
    pub fn revoke(&self, sid: &str, credential: &str, expires_at: i64) {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert((sid.to_string(), credential.to_string()), expires_at);
    }

    /// Whether `credential` has been revoked for `sid` as of `now`.
    ///
    /// Sweeps entries whose tokens have stopped verifying as it goes, so the
    /// set is bounded by what is still live without needing a timer of its own.
    pub fn is_revoked(&self, sid: &str, credential: &str, now: i64) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // `now - CLOCK_SKEW_SECS`, not `now`: the verifier accepts a token for
        // that much longer than its `exp`, and an entry swept any earlier is a
        // revoked grant that works again.
        entries.retain(|_, expires_at| *expires_at >= now - CLOCK_SKEW_SECS);
        entries.contains_key(&(sid.to_string(), credential.to_string()))
    }

    /// How many entries are currently held. For tests and diagnostics.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Whether nothing is revoked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_nobody_revoked_is_served() {
        let set = RevocationSet::new();
        assert!(!set.is_revoked("s1", "openai", 100));
        assert!(set.is_empty());
    }

    #[test]
    fn a_revoked_credential_is_refused_for_that_session_only() {
        let set = RevocationSet::new();
        set.revoke("s1", "openai", 1_000);
        assert!(set.is_revoked("s1", "openai", 100));
        assert!(!set.is_revoked("s2", "openai", 100), "another session");
        assert!(!set.is_revoked("s1", "stripe", 100), "another credential");
    }

    #[test]
    fn an_entry_outlives_the_expiry_by_the_skew_the_verifier_allows() {
        // The sweep and `TokenSigner::verify` have to agree about when a token
        // stops existing. The verifier accepts until `exp + CLOCK_SKEW_SECS`,
        // so an entry dropped at `exp` would leave a revoked grant usable again
        // for the whole of that window.
        let set = RevocationSet::new();
        set.revoke("s1", "openai", 1_000);

        assert!(set.is_revoked("s1", "openai", 1_000), "still live");
        assert!(
            set.is_revoked("s1", "openai", 1_000 + CLOCK_SKEW_SECS),
            "a token this old still verifies, so it must still be refused"
        );
        assert!(!set.is_revoked("s1", "openai", 1_001 + CLOCK_SKEW_SECS));
        assert!(set.is_empty(), "the sweep must not leave the entry behind");
    }

    #[test]
    fn revoking_twice_is_the_same_as_revoking_once() {
        let set = RevocationSet::new();
        set.revoke("s1", "openai", 1_000);
        set.revoke("s1", "openai", 2_000);
        assert_eq!(set.len(), 1);
        assert!(
            set.is_revoked("s1", "openai", 1_500),
            "the later expiry wins"
        );
    }
}
