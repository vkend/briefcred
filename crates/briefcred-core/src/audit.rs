//! Audit records.
//!
//! Audit rows are metadata only. They never carry headers, bodies, query
//! strings, connection strings, or credential material. Command arguments are
//! recorded as SHA-256 digests so an operator can correlate two runs without
//! the log becoming a secret store.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::types::{MintId, RevokeOutcome};

/// One append-only audit record.
///
/// Later phases add `ProxyRequest` and `PgConnection` variants; the enum is
/// tagged so adding one does not change how existing rows deserialise.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEntry {
    /// A credential was minted.
    Mint {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The principal that was created.
        mint_id: MintId,
        /// Profile that asked for it.
        profile: String,
        /// Credential name within that profile.
        credential: String,
        /// Minter kind that served it.
        kind: String,
        /// Requested lifetime.
        ttl_secs: u64,
    },
    /// A wrapped subprocess started.
    ExecStart {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The principal handed to the subprocess.
        mint_id: MintId,
        /// Profile that authorised it.
        profile: String,
        /// `argv[0]`, recorded verbatim because the allowlist is literal.
        argv0: String,
        /// SHA-256 of each remaining argument, in order.
        args_sha256: Vec<String>,
        /// Operating system process id.
        pid: u32,
    },
    /// A wrapped subprocess exited.
    ExecEnd {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The principal that was in use.
        mint_id: MintId,
        /// Profile that authorised it.
        profile: String,
        /// Exit status, absent when the child was killed by a signal.
        exit_code: Option<i32>,
        /// Wall-clock runtime.
        duration_ms: u64,
    },
    /// A revoke attempt finished.
    Revoke {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The principal that was being removed.
        mint_id: MintId,
        /// Minter kind that served it.
        kind: String,
        /// One of `revoked`, `eventually_consistent`, `failed`, `already_gone`.
        outcome: String,
        /// Backend error text. Always present when `outcome` is `failed`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        /// Propagation estimate, when the outcome was eventually consistent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        propagation_estimate_ms: Option<u64>,
    },
}

impl AuditEntry {
    /// Build a [`AuditEntry::Revoke`] row from an outcome, preserving detail.
    pub fn revoke(mint_id: MintId, kind: impl Into<String>, outcome: &RevokeOutcome) -> AuditEntry {
        let (detail, propagation_estimate_ms) = match outcome {
            RevokeOutcome::Failed { detail } => (Some(detail.clone()), None),
            RevokeOutcome::EventuallyConsistent {
                propagation_estimate,
            } => (None, Some(propagation_estimate.as_millis() as u64)),
            _ => (None, None),
        };
        AuditEntry::Revoke {
            ts: OffsetDateTime::now_utc(),
            mint_id,
            kind: kind.into(),
            outcome: outcome.label().to_string(),
            detail,
            propagation_estimate_ms,
        }
    }

    /// The identifier this row is about.
    pub fn mint_id(&self) -> &MintId {
        match self {
            AuditEntry::Mint { mint_id, .. }
            | AuditEntry::ExecStart { mint_id, .. }
            | AuditEntry::ExecEnd { mint_id, .. }
            | AuditEntry::Revoke { mint_id, .. } => mint_id,
        }
    }
}

/// SHA-256 of one command argument, lowercase hex.
///
/// Used so audit rows can show that two runs used the same arguments without
/// recording what those arguments were.
pub fn hash_arg(arg: &str) -> String {
    hex::encode(Sha256::digest(arg.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_failed_revoke_row_always_carries_a_detail() {
        let entry = AuditEntry::revoke(
            MintId::generate(),
            "postgres-dynamic",
            &RevokeOutcome::failed(""),
        );
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["outcome"], "failed");
        assert!(
            json["detail"]
                .as_str()
                .is_some_and(|d| !d.trim().is_empty()),
            "{json}"
        );
    }

    #[test]
    fn a_successful_revoke_row_omits_detail() {
        let entry = AuditEntry::revoke(
            MintId::generate(),
            "postgres-dynamic",
            &RevokeOutcome::Revoked,
        );
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["outcome"], "revoked");
        assert!(json.get("detail").is_none(), "{json}");
    }

    #[test]
    fn an_eventually_consistent_row_records_the_estimate() {
        let entry = AuditEntry::revoke(
            MintId::generate(),
            "aws-sts",
            &RevokeOutcome::EventuallyConsistent {
                propagation_estimate: Duration::from_secs(30),
            },
        );
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["outcome"], "eventually_consistent");
        assert_eq!(json["propagation_estimate_ms"], 30_000);
    }

    #[test]
    fn exec_rows_record_argument_digests_not_arguments() {
        let entry = AuditEntry::ExecStart {
            ts: OffsetDateTime::UNIX_EPOCH,
            mint_id: MintId::generate(),
            profile: "dev".into(),
            argv0: "psql".into(),
            args_sha256: vec![hash_arg("-c"), hash_arg("SELECT * FROM salaries")],
            pid: 42,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("salaries"), "{json}");
        assert!(!json.contains("SELECT"), "{json}");
        assert!(json.contains(&hash_arg("SELECT * FROM salaries")), "{json}");
        assert!(json.contains("\"argv0\":\"psql\""), "{json}");
    }

    #[test]
    fn hashing_is_stable_and_hex() {
        let digest = hash_arg("--dry-run");
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, hash_arg("--dry-run"));
        assert_ne!(digest, hash_arg("--dry-run "));
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn rows_round_trip_through_jsonl() {
        let entry = AuditEntry::Mint {
            ts: OffsetDateTime::UNIX_EPOCH,
            mint_id: MintId::generate(),
            profile: "dev".into(),
            credential: "db".into(),
            kind: "postgres-dynamic".into(),
            ttl_secs: 900,
        };
        let line = serde_json::to_string(&entry).unwrap();
        assert!(!line.contains('\n'));
        let back: AuditEntry = serde_json::from_str(&line).unwrap();
        assert_eq!(back, entry);
        assert_eq!(back.mint_id(), entry.mint_id());
    }
}
