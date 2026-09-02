//! Identifiers and the value types that cross the minter boundary.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Prefix every briefcred-minted principal carries.
pub const MINT_ID_PREFIX: &str = "briefcred_t_";

/// Number of hex characters after the prefix.
pub const MINT_ID_HEX_LEN: usize = 12;

/// A minted credential's identifier, and the principal name used at the backend.
///
/// The form is `briefcred_t_<12 lowercase hex>` drawn from the operating
/// system CSPRNG: 24 characters, 48 bits of entropy.
///
/// # `NAMEDATALEN`
///
/// PostgreSQL identifiers are truncated to `NAMEDATALEN - 1` = **63 bytes** by
/// default. Anything longer is silently shortened, which would let two mints
/// collide on one role and make revoke ambiguous. At 24 characters a `MintId`
/// leaves 39 bytes of headroom, so a future prefix or suffix scheme still fits.
/// Any change to this format must keep the total under 63 bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MintId(String);

impl MintId {
    /// Draw a fresh identifier from the OS CSPRNG.
    pub fn generate() -> MintId {
        let mut bytes = [0u8; MINT_ID_HEX_LEN / 2];
        getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable");
        MintId(format!("{MINT_ID_PREFIX}{}", hex::encode(bytes)))
    }

    /// The identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MintId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for MintId {
    type Err = Error;

    fn from_str(s: &str) -> Result<MintId> {
        let hex = s.strip_prefix(MINT_ID_PREFIX).ok_or_else(|| {
            Error::MintId(format!("`{s}` does not start with `{MINT_ID_PREFIX}`"))
        })?;
        if hex.len() != MINT_ID_HEX_LEN {
            return Err(Error::MintId(format!(
                "`{s}` must have exactly {MINT_ID_HEX_LEN} hex characters after the prefix"
            )));
        }
        if !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::MintId(format!(
                "`{s}` must use lowercase hex after the prefix"
            )));
        }
        Ok(MintId(s.to_string()))
    }
}

impl serde::Serialize for MintId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for MintId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<MintId, D::Error> {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// Everything a minter needs to mint one credential.
///
/// `Debug` is written by hand: `master` must never reach a log line.
pub struct MintCtx {
    /// Identifier to use for the principal being created.
    pub mint_id: MintId,
    /// Profile that asked for the mint.
    pub profile: String,
    /// Credential name within that profile.
    pub credential: String,
    /// The credential spec's `config` block, as written in the profile.
    pub config: serde_yaml::Value,
    /// The master credential, fetched from a [`crate::MasterSource`].
    pub master: Zeroizing<String>,
    /// Requested lifetime.
    pub ttl: Duration,
}

impl fmt::Debug for MintCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintCtx")
            .field("mint_id", &self.mint_id)
            .field("profile", &self.profile)
            .field("credential", &self.credential)
            .field("config", &"<omitted>")
            .field("master", &"<redacted>")
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// Everything a minter needs to take one credential away again.
pub struct RevokeCtx {
    /// The principal to remove.
    pub mint_id: MintId,
    /// The same `config` block the mint ran against.
    pub config: serde_yaml::Value,
    /// The master credential.
    pub master: Zeroizing<String>,
    /// Opaque state the mint recorded so revoke can be exactly symmetric.
    pub revoke_token: String,
}

impl fmt::Debug for RevokeCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevokeCtx")
            .field("mint_id", &self.mint_id)
            .field("config", &"<omitted>")
            .field("master", &"<redacted>")
            .field("revoke_token", &"<redacted>")
            .finish()
    }
}

/// A successfully minted credential.
///
/// Deliberately not `Serialize`: the only legitimate exits for `fields` are the
/// subprocess environment and the proxy's substitution table.
pub struct MintedCredential {
    /// The identifier of the principal that was created.
    pub mint_id: MintId,
    /// Minter-defined fields, for example `PGUSER` and `PGPASSWORD`.
    pub fields: BTreeMap<String, Zeroizing<String>>,
    /// When the backend stops honouring this credential.
    pub expires_at: OffsetDateTime,
    /// Opaque state to hand back in a [`RevokeCtx`].
    pub revoke_token: String,
}

impl fmt::Debug for MintedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintedCredential")
            .field("mint_id", &self.mint_id)
            .field("fields", &self.fields.keys().collect::<Vec<_>>())
            .field("expires_at", &self.expires_at)
            .field("revoke_token", &"<redacted>")
            .finish()
    }
}

/// Everything a minter needs to sweep principals nothing is using any more.
///
/// Reconciliation is the answer to `SIGKILL`. A daemon killed mid-`exec` never
/// runs its revoke queue, so the principal it minted survives it. Nothing in
/// the daemon's own state can find that principal after a restart, but the
/// backend can: every briefcred principal is named [`MINT_ID_PREFIX`]`*` and
/// carries an expiry, so "expired and ours" is a complete description of what
/// to clean up.
pub struct ReconcileCtx {
    /// A `config` block naming the backend to sweep.
    pub config: serde_yaml::Value,
    /// The master credential.
    pub master: Zeroizing<String>,
}

impl fmt::Debug for ReconcileCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReconcileCtx")
            .field("config", &"<omitted>")
            .field("master", &"<redacted>")
            .finish()
    }
}

/// What one reconciliation sweep found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Principals the sweep removed, in the order it removed them.
    pub revoked: Vec<MintId>,
    /// Principals it found but could not remove, each with the reason.
    pub failed: Vec<(MintId, String)>,
}

impl ReconcileReport {
    /// Whether the sweep found nothing to do, which is the healthy steady state.
    pub fn is_clean(&self) -> bool {
        self.revoked.is_empty() && self.failed.is_empty()
    }
}

/// What happened when a minter tried to revoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// The credential is gone and the backend confirmed it.
    Revoked,
    /// The backend accepted the revoke but propagation is not immediate.
    EventuallyConsistent {
        /// How long the credential may still work for.
        propagation_estimate: Duration,
    },
    /// The revoke failed. `detail` is never empty — a failed audit row without
    /// one is a bug.
    Failed {
        /// Backend error text, including the SQLSTATE where there is one.
        detail: String,
    },
    /// The credential was already absent at the backend.
    AlreadyGone,
}

impl RevokeOutcome {
    /// Build a [`RevokeOutcome::Failed`], substituting a placeholder rather
    /// than emitting an empty detail.
    pub fn failed(detail: impl Into<String>) -> RevokeOutcome {
        let detail = detail.into();
        let detail = if detail.trim().is_empty() {
            "backend reported a failure with no detail".to_string()
        } else {
            detail
        };
        RevokeOutcome::Failed { detail }
    }

    /// Stable lowercase name for audit rows.
    pub fn label(&self) -> &'static str {
        match self {
            RevokeOutcome::Revoked => "revoked",
            RevokeOutcome::EventuallyConsistent { .. } => "eventually_consistent",
            RevokeOutcome::Failed { .. } => "failed",
            RevokeOutcome::AlreadyGone => "already_gone",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_have_the_documented_shape() {
        let id = MintId::generate();
        assert!(id.as_str().starts_with(MINT_ID_PREFIX));
        assert_eq!(id.as_str().len(), MINT_ID_PREFIX.len() + MINT_ID_HEX_LEN);
        assert_eq!(id.as_str().parse::<MintId>().unwrap(), id);
    }

    #[test]
    fn generated_ids_fit_within_namedatalen() {
        assert!(MintId::generate().as_str().len() < 63);
    }

    #[test]
    fn generated_ids_do_not_repeat() {
        let ids: std::collections::BTreeSet<_> = (0..256).map(|_| MintId::generate()).collect();
        assert_eq!(ids.len(), 256);
    }

    #[test]
    fn parsing_rejects_malformed_ids() {
        for bad in [
            "",
            "briefcred_t_",
            "briefcred_x_0123456789ab",
            "0123456789ab",
            "briefcred_t_0123456789abc",
            "briefcred_t_0123456789A",
            "briefcred_t_0123456789AB",
            "briefcred_t_0123456789gz",
            "briefcred_t_0123456789a;",
        ] {
            assert!(
                bad.parse::<MintId>().is_err(),
                "`{bad}` should not parse as a MintId"
            );
        }
    }

    #[test]
    fn contexts_never_debug_print_the_master_credential() {
        let mint = MintCtx {
            mint_id: MintId::generate(),
            profile: "dev".into(),
            credential: "db".into(),
            config: serde_yaml::from_str("password: hunter2").unwrap(),
            master: Zeroizing::new("s3cret-master".into()),
            ttl: Duration::from_secs(900),
        };
        let rendered = format!("{mint:?}");
        assert!(!rendered.contains("s3cret-master"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("<redacted>"));

        let revoke = RevokeCtx {
            mint_id: MintId::generate(),
            config: serde_yaml::Value::Null,
            master: Zeroizing::new("s3cret-master".into()),
            revoke_token: "tok-abc".into(),
        };
        let rendered = format!("{revoke:?}");
        assert!(!rendered.contains("s3cret-master"), "{rendered}");
        assert!(!rendered.contains("tok-abc"), "{rendered}");
    }

    #[test]
    fn minted_credential_debug_shows_field_names_only() {
        let minted = MintedCredential {
            mint_id: MintId::generate(),
            fields: BTreeMap::from([
                ("PGUSER".to_string(), Zeroizing::new("briefcred_t_1".into())),
                (
                    "PGPASSWORD".to_string(),
                    Zeroizing::new("t0p-s3cret".into()),
                ),
            ]),
            expires_at: OffsetDateTime::UNIX_EPOCH,
            revoke_token: "tok-abc".into(),
        };
        let rendered = format!("{minted:?}");
        assert!(rendered.contains("PGPASSWORD"), "{rendered}");
        assert!(!rendered.contains("t0p-s3cret"), "{rendered}");
        assert!(!rendered.contains("tok-abc"), "{rendered}");
    }

    #[test]
    fn a_failed_outcome_always_carries_a_detail() {
        let outcome = RevokeOutcome::failed("   ");
        match outcome {
            RevokeOutcome::Failed { detail } => assert!(!detail.trim().is_empty()),
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(RevokeOutcome::Revoked.label(), "revoked");
        assert_eq!(RevokeOutcome::AlreadyGone.label(), "already_gone");
    }
}
