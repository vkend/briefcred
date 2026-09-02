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
    ///
    /// One row per `briefcred exec`, not one per credential: a run may carry
    /// several mints, and splitting the row per mint would make one command
    /// look like several.
    ExecStart {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The session the run belongs to, so it can be tied to its unlock.
        session_id: String,
        /// The principals handed to the subprocess, in declaration order.
        mint_ids: Vec<MintId>,
        /// Profile that authorised it.
        profile: String,
        /// `argv[0]`, recorded verbatim because the allowlist is literal.
        argv0: String,
        /// SHA-256 of each remaining argument, in order.
        args_sha256: Vec<String>,
        /// The arguments themselves, only when `audit.raw_args` is on.
        ///
        /// Off by default, and the one place an audit row is allowed to hold
        /// text a user typed. An operator turns it on knowingly, and the
        /// digests stay alongside so the two are always correlatable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        args: Option<Vec<String>>,
        /// The pid of the `briefcred` process that spawned and owns the child.
        ///
        /// Not the child's own: the row is written when the credentials are
        /// minted, which is before the child exists. The wrapper is also the
        /// process an operator can act on, because killing it takes the child.
        pid: u32,
    },
    /// A wrapped subprocess exited.
    ExecEnd {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The session the run belonged to.
        session_id: String,
        /// The principals that were in use.
        mint_ids: Vec<MintId>,
        /// Profile that authorised it.
        profile: String,
        /// Exit status, absent when the child was killed by a signal.
        exit_code: Option<i32>,
        /// Wall-clock runtime.
        duration_ms: u64,
    },
    /// A Model Context Protocol tool call finished.
    ///
    /// The row an operator reads to answer "what did the agent ask for, and
    /// what did briefcred give it". `mcp_call_id` is what ties it to the
    /// `Mint`, `ExecStart` and `Revoke` rows the call caused: those name the
    /// mints, and this names the mints and the call together.
    ///
    /// The tool's *arguments* are not here. A `briefcred_db_query` carries SQL
    /// and a `briefcred_exec` carries a command line, and both are exactly the
    /// free-form text an audit row must never hold; the `ExecStart` row a
    /// `briefcred_exec` writes records `argv[0]` and digests of the rest on
    /// the same terms as every other exec.
    McpCall {
        /// When it finished.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// Identifier for this call, unique within the daemon's lifetime.
        mcp_call_id: String,
        /// The tool that was called, for example `briefcred_db_query`.
        tool: String,
        /// The profile it acted on, when it named one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile: Option<String>,
        /// The principals the call used, in declaration order.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        mint_ids: Vec<MintId>,
        /// `ok` or `error`.
        outcome: String,
        /// Why it failed. Present only when `outcome` is `error`, and never
        /// the caller's own text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        /// How long the call took.
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
    /// The daemon finished starting and is accepting connections.
    DaemonStart {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The daemon's process id.
        pid: u32,
        /// The daemon binary's crate version.
        version: String,
    },
    /// The daemon stopped accepting connections and is shutting down.
    DaemonStop {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The daemon's process id.
        pid: u32,
        /// How long it had been running.
        uptime_secs: u64,
        /// What asked it to stop: `sigterm`, `sigint`, or `request`.
        reason: String,
    },
    /// A profile directory failed to load; the previous set is still in force.
    ProfileLoadError {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The complaint, naming the offending file. Never file contents.
        message: String,
    },
    /// A session was opened after a successful unlock.
    SessionOpen {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The session handle, so open and close can be correlated.
        session_id: String,
        /// The profile it was opened for.
        profile: String,
        /// How many credentials the profile declares.
        credentials: usize,
    },
    /// A session ended, by request, by idle eviction, or at shutdown.
    SessionClose {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The session handle.
        session_id: String,
        /// The profile it belonged to.
        profile: String,
        /// One of `request`, `idle`, or `shutdown`.
        reason: String,
    },
    /// An unlock was refused, so nothing was opened and no master was read.
    UnlockDenied {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The profile that was being opened.
        profile: String,
        /// The policy that was asked for: `biometric`, `passcode`, or `none`.
        policy: String,
        /// One of `cancelled`, `failed`, `no_aqua_session`, `unsupported`.
        reason: String,
    },
    /// A reconciliation sweep ran against one minter kind.
    ///
    /// Written even when the sweep found nothing, because "the reconciler is
    /// alive and the backend is clean" is exactly what an operator needs to be
    /// able to see. Each principal it removed also gets its own `Revoke` row.
    Reconcile {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The minter kind that was swept.
        kind: String,
        /// The profile whose configuration named the backend.
        profile: String,
        /// How many stranded principals the sweep removed.
        revoked: usize,
        /// How many it found but could not remove.
        failed: usize,
    },
    /// A connection was refused because the peer is not the owning user.
    ///
    /// The socket lives in a `0700` directory at mode `0600`, so this row is
    /// evidence of something worth investigating rather than routine noise.
    AuthReject {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The uid the kernel reported for the connecting process.
        peer_uid: u32,
        /// The uid the daemon is running as, and the only one it serves.
        expected_uid: u32,
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

    /// Every principal this row is about, in the order the row records them.
    ///
    /// A `Mint` or a `Revoke` is about exactly one. An `ExecStart`, an
    /// `ExecEnd`, or an `McpCall` is about however many that run carried. Daemon-lifecycle,
    /// session, and authentication rows describe the daemon rather than a
    /// principal, so they are about none.
    pub fn mint_ids(&self) -> &[MintId] {
        match self {
            AuditEntry::Mint { mint_id, .. } | AuditEntry::Revoke { mint_id, .. } => {
                std::slice::from_ref(mint_id)
            }
            AuditEntry::ExecStart { mint_ids, .. }
            | AuditEntry::ExecEnd { mint_ids, .. }
            | AuditEntry::McpCall { mint_ids, .. } => mint_ids,
            AuditEntry::DaemonStart { .. }
            | AuditEntry::DaemonStop { .. }
            | AuditEntry::AuthReject { .. }
            | AuditEntry::ProfileLoadError { .. }
            | AuditEntry::Reconcile { .. }
            | AuditEntry::SessionOpen { .. }
            | AuditEntry::SessionClose { .. }
            | AuditEntry::UnlockDenied { .. } => &[],
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
            session_id: "s-1".into(),
            mint_ids: vec![MintId::generate()],
            profile: "dev".into(),
            argv0: "psql".into(),
            args_sha256: vec![hash_arg("-c"), hash_arg("SELECT * FROM salaries")],
            args: None,
            pid: 42,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("salaries"), "{json}");
        assert!(!json.contains("SELECT"), "{json}");
        assert!(json.contains(&hash_arg("SELECT * FROM salaries")), "{json}");
        assert!(json.contains("\"argv0\":\"psql\""), "{json}");
        // The raw-args field is absent, not null, when nobody opted in.
        assert!(!json.contains("\"args\""), "{json}");
    }

    #[test]
    fn raw_args_are_recorded_only_when_they_were_asked_for() {
        let entry = AuditEntry::ExecStart {
            ts: OffsetDateTime::UNIX_EPOCH,
            session_id: "s-1".into(),
            mint_ids: vec![],
            profile: "dev".into(),
            argv0: "psql".into(),
            args_sha256: vec![hash_arg("SELECT * FROM salaries")],
            args: Some(vec!["SELECT * FROM salaries".into()]),
            pid: 42,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("salaries"), "{json}");
        // The digests stay alongside, so a log with raw args on and one with it
        // off can still be correlated.
        assert!(json.contains(&hash_arg("SELECT * FROM salaries")), "{json}");
    }

    #[test]
    fn an_exec_row_is_about_every_principal_the_run_carried() {
        let ids = vec![MintId::generate(), MintId::generate()];
        let entry = AuditEntry::ExecEnd {
            ts: OffsetDateTime::UNIX_EPOCH,
            session_id: "s-1".into(),
            mint_ids: ids.clone(),
            profile: "dev".into(),
            exit_code: Some(0),
            duration_ms: 12,
        };
        assert_eq!(entry.mint_ids(), ids.as_slice());
        assert!(AuditEntry::Reconcile {
            ts: OffsetDateTime::UNIX_EPOCH,
            kind: "postgres-dynamic".into(),
            profile: "dev".into(),
            revoked: 0,
            failed: 0,
        }
        .mint_ids()
        .is_empty());
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
        assert_eq!(back.mint_ids(), entry.mint_ids());
    }

    #[test]
    fn an_auth_reject_row_records_both_uids_and_nothing_else() {
        let entry = AuditEntry::AuthReject {
            ts: OffsetDateTime::UNIX_EPOCH,
            peer_uid: 502,
            expected_uid: 501,
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["event"], "auth_reject");
        assert_eq!(json["peer_uid"], 502);
        assert_eq!(json["expected_uid"], 501);
        assert!(entry.mint_ids().is_empty());
    }

    #[test]
    fn daemon_lifecycle_rows_round_trip_and_carry_no_mint_id() {
        for entry in [
            AuditEntry::DaemonStart {
                ts: OffsetDateTime::UNIX_EPOCH,
                pid: 7,
                version: "0.1.0".into(),
            },
            AuditEntry::DaemonStop {
                ts: OffsetDateTime::UNIX_EPOCH,
                pid: 7,
                uptime_secs: 61,
                reason: "sigterm".into(),
            },
        ] {
            let line = serde_json::to_string(&entry).unwrap();
            assert!(!line.contains('\n'));
            let back: AuditEntry = serde_json::from_str(&line).unwrap();
            assert_eq!(back, entry);
            assert!(back.mint_ids().is_empty());
        }
    }

    #[test]
    fn credential_rows_still_expose_their_mint_id() {
        let entry = AuditEntry::Mint {
            ts: OffsetDateTime::UNIX_EPOCH,
            mint_id: MintId::generate(),
            profile: "dev".into(),
            credential: "db".into(),
            kind: "postgres-dynamic".into(),
            ttl_secs: 900,
        };
        assert_eq!(entry.mint_ids().len(), 1);
    }
}
