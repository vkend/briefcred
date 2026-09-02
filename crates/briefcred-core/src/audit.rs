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
/// The enum is tagged, so adding a variant does not change how existing rows
/// deserialise.
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
    /// One HTTP request crossed the proxy.
    ///
    /// Metadata only, and the omissions are the point. There are no headers
    /// here, because one of them is the credential; no body, because a body is
    /// whatever the agent decided to send; and **no query string**, because a
    /// query string routinely carries an API key and would turn the audit log
    /// into the secret store this row exists to make unnecessary.
    ProxyRequest {
        /// When the response finished.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The synthetic token's mint, tying the request to its `Mint` row.
        mint_id: MintId,
        /// The HTTP method, uppercase.
        method: String,
        /// The upstream host, without the port.
        host: String,
        /// The request path, with any query string already stripped.
        path: String,
        /// The upstream's status code, absent when the request never reached it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<u16>,
        /// Bytes of request body forwarded upstream.
        req_bytes: u64,
        /// Bytes of response body forwarded back.
        resp_bytes: u64,
        /// How long the whole exchange took.
        latency_ms: u64,
        /// What happened, and who decided it.
        ///
        /// `allow` and `would_deny` were forwarded; `deny` was refused by the
        /// policy or by a token that did not authorise. `swap_error` and
        /// `upstream_error` are **not** policy outcomes — the policy allowed
        /// those, and briefcred or the upstream failed afterwards — so an
        /// operator reading a rising count knows whether to widen a policy or
        /// to go and look at something.
        decision: String,
        /// The HTTP/2 connection this request was one stream of.
        ///
        /// Absent on HTTP/1.1, where a connection carries one request at a
        /// time and the row is already the whole story. Present on HTTP/2,
        /// where a hundred rows may belong to one connection and matching
        /// them up by host and timestamp would be guesswork. It matches the
        /// `connection_id` of exactly one
        /// [`AuditEntry::ProxyH2Connection`] row.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        connection_id: Option<String>,
    },
    /// One HTTP/2 connection from a wrapped subprocess closed.
    ///
    /// Written in addition to the [`AuditEntry::ProxyRequest`] row each of its
    /// streams already wrote, not instead of them. Every stream was authorised,
    /// charged, and decided on its own — HTTP/2 changes how requests are framed
    /// and nothing about what briefcred does with one — so this row carries no
    /// decision of its own. What it adds is the shape of the connection: how
    /// many streams a client multiplexed onto it, how long it held it open, and
    /// how much crossed it in each direction.
    ///
    /// Metadata only, on the same terms as every other proxy row. There is no
    /// path here, because a connection has many; no status, for the same
    /// reason; and nothing at all from a stream's headers, body, or trailers. A
    /// gRPC call's `grpc-status` trailer is relayed to the client untouched and
    /// is never read, so it could not appear here.
    ///
    /// `mint_id` is the mint of the first stream on the connection that
    /// resolved a session. A connection whose every stream was refused before
    /// one did — a run of bad tokens, say — gets no row, on the same terms as
    /// the request rows: a row names a grant, and nothing here named one.
    ProxyH2Connection {
        /// When the row was written, which is when the connection closed.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// Identifier for this connection, unique within the daemon's lifetime.
        ///
        /// What the `connection_id` on every [`AuditEntry::ProxyRequest`] and
        /// [`AuditEntry::ProxyStream`] row of this connection points back at.
        connection_id: String,
        /// The synthetic token's mint, tying the connection to its `Mint` row.
        mint_id: MintId,
        /// The upstream host the `CONNECT` named, without the port.
        host: String,
        /// When the connection's TLS handshake finished.
        #[serde(with = "time::serde::rfc3339")]
        started: OffsetDateTime,
        /// When the connection closed.
        #[serde(with = "time::serde::rfc3339")]
        ended: OffsetDateTime,
        /// Streams opened on it, counted whatever became of each.
        streams: u64,
        /// Bytes of request body forwarded upstream, across every stream.
        bytes_up: u64,
        /// Bytes of response body forwarded back, across every stream.
        bytes_down: u64,
    },
    /// One long-lived stream through the HTTP proxy ended.
    ///
    /// Written in addition to the [`AuditEntry::ProxyRequest`] row for the
    /// response that started it, not instead of it: the request row says a
    /// stream was authorised and opened, and this one says what went through it
    /// and for how long. A stream that lasts an hour would otherwise be a
    /// single row written at the start with nothing after it.
    ///
    /// Metadata only, on the same terms as every other proxy row and with one
    /// more omission that matters. `events_or_frames` is a count of framing —
    /// blank-line-terminated event blocks, or WebSocket frame headers — and no
    /// event's data and no frame's payload is read to produce it. A WebSocket
    /// payload is never unmasked, so this row could not carry one even if it
    /// wanted to.
    ProxyStream {
        /// When the row was written, which is when the stream ended.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The synthetic token's mint, tying the stream to its `Mint` row.
        mint_id: MintId,
        /// `sse` for an event stream, `ws` for a WebSocket.
        kind: String,
        /// The upstream host, without the port.
        host: String,
        /// The request path, with any query string already stripped.
        path: String,
        /// When the stream opened: the response head, or the `101`.
        #[serde(with = "time::serde::rfc3339")]
        started: OffsetDateTime,
        /// When either side closed, or briefcred ended it.
        #[serde(with = "time::serde::rfc3339")]
        ended: OffsetDateTime,
        /// Events dispatched, or frame headers seen in both directions.
        events_or_frames: u64,
        /// Bytes the client sent towards the upstream.
        bytes_up: u64,
        /// Bytes the upstream sent back to the client.
        bytes_down: u64,
        /// The HTTP/2 connection this stream was one stream of, if any.
        ///
        /// Absent on HTTP/1.1, and on the WebSocket streams that can only be
        /// HTTP/1.1. Present on an event stream a client opened over HTTP/2.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        connection_id: Option<String>,
    },
    /// One connection crossed the Postgres proxy.
    ///
    /// Metadata only, and here the omissions are almost the whole row. There is
    /// no query, no result, and no parameter, because after authentication the
    /// proxy copies bytes without parsing them and could not record a statement
    /// if it wanted to. What is left is who connected, as whom upstream, for how
    /// long, and how much moved — which is what an operator investigating "who
    /// was in the warehouse at four in the morning" actually needs.
    ///
    /// Written when the connection closes, because that is when the byte counts
    /// and the end time exist. A connection refused before its session was
    /// resolved gets no row at all: the row names a `mint_id`, and a client
    /// whose token did not verify has not named a grant briefcred made.
    PgConnection {
        /// When the row was written, which is when the connection closed.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The synthetic token's mint, tying the connection to its `Mint` row.
        mint_id: MintId,
        /// The real role the daemon authenticated as upstream.
        ///
        /// The name only. Its password is the master, and the master is the
        /// thing this row exists to prove the client never held.
        master_user: String,
        /// When the client was told it was authenticated.
        #[serde(with = "time::serde::rfc3339")]
        started: OffsetDateTime,
        /// When either side closed.
        #[serde(with = "time::serde::rfc3339")]
        ended: OffsetDateTime,
        /// Bytes the client sent towards the server.
        client_bytes: u64,
        /// Bytes the server sent back to the client.
        server_bytes: u64,
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
        /// What asked it to stop: `sigterm`, `sigint`, `request`, or
        /// `handoff` — the last being a daemon that gave its listeners and
        /// sessions to a successor and stood down. See
        /// [`AuditEntry::DaemonHandoff`].
        reason: String,
    },
    /// One daemon handed its listeners and sessions to another.
    ///
    /// Written by the daemon standing down and, with the pids the other way
    /// round, by the one taking over — so an investigator reading the log finds
    /// both halves of the swap and can tell which process was serving at any
    /// moment. A failed attempt is recorded too: an upgrade that did not happen
    /// is exactly the thing somebody will be asking about afterwards.
    DaemonHandoff {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The process that was serving before.
        from_pid: u32,
        /// The process serving after, absent when the handoff failed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_pid: Option<u32>,
        /// How many sessions moved across.
        sessions: usize,
        /// `handed_over`, `adopted`, or `failed`.
        outcome: String,
    },
    /// A profile directory failed to load; the previous set is still in force.
    ProfileLoadError {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The complaint, naming the offending file. Never file contents.
        message: String,
    },
    /// A registry profile could not be verified against any trust root.
    ///
    /// Written whether the file was dropped or loaded anyway: an operator who
    /// turns `dev_mode` on has to be able to find, afterwards, exactly which
    /// unverified profiles their daemon was running.
    ProfileTrustWarning {
        /// When it happened.
        #[serde(with = "time::serde::rfc3339")]
        ts: OffsetDateTime,
        /// The file, so the row names something an operator can go and look at.
        path: String,
        /// `dropped` when the profile was refused, `loaded_dev_mode` when
        /// `dev_mode` let it through anyway.
        action: String,
        /// Why it did not verify. Never file contents.
        reason: String,
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
        /// Why it ended. One of:
        ///
        /// | reason | what happened |
        /// | --- | --- |
        /// | `request` | a client sent `CloseSession` |
        /// | `idle` | nothing touched it for `session_idle_secs` |
        /// | `shutdown` | the daemon stopped |
        /// | `handoff` | it was handed to a successor daemon, and its mints go with it |
        /// | `mcp_disconnect` | the MCP connection holding it went away |
        /// | `quota` | the profile's quota refused the first call, so the session it had just opened was closed again |
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
            AuditEntry::Mint { mint_id, .. }
            | AuditEntry::Revoke { mint_id, .. }
            | AuditEntry::ProxyRequest { mint_id, .. }
            | AuditEntry::ProxyStream { mint_id, .. }
            | AuditEntry::ProxyH2Connection { mint_id, .. }
            | AuditEntry::PgConnection { mint_id, .. } => std::slice::from_ref(mint_id),
            AuditEntry::ExecStart { mint_ids, .. }
            | AuditEntry::ExecEnd { mint_ids, .. }
            | AuditEntry::McpCall { mint_ids, .. } => mint_ids,
            AuditEntry::DaemonStart { .. }
            | AuditEntry::DaemonStop { .. }
            | AuditEntry::DaemonHandoff { .. }
            | AuditEntry::AuthReject { .. }
            | AuditEntry::ProfileLoadError { .. }
            | AuditEntry::ProfileTrustWarning { .. }
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
    fn an_http2_connection_row_carries_a_shape_and_no_content() {
        let entry = AuditEntry::ProxyH2Connection {
            ts: OffsetDateTime::UNIX_EPOCH,
            connection_id: "h2-9f31c0a2b4de".into(),
            mint_id: MintId::generate(),
            host: "api.openai.com".into(),
            started: OffsetDateTime::UNIX_EPOCH,
            ended: OffsetDateTime::UNIX_EPOCH,
            streams: 140,
            bytes_up: 81_204,
            bytes_down: 2_140_338,
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["event"], "proxy_h2_connection");
        assert_eq!(json["connection_id"], "h2-9f31c0a2b4de");
        assert_eq!(json["streams"], 140);
        assert_eq!(entry.mint_ids().len(), 1);

        // The field list is the whole promise, as it is for every proxy row.
        // There is no path and no status because a connection has many of each,
        // and nothing from a stream's headers, body, or trailers because there
        // is nowhere here to put one.
        let mut fields: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
        fields.sort();
        assert_eq!(
            fields,
            [
                "bytes_down",
                "bytes_up",
                "connection_id",
                "ended",
                "event",
                "host",
                "mint_id",
                "started",
                "streams",
                "ts",
            ]
        );

        let back: AuditEntry =
            serde_json::from_str(&serde_json::to_string(&entry).unwrap()).unwrap();
        assert_eq!(back, entry);
    }

    #[test]
    fn a_request_row_names_its_connection_only_when_it_had_one() {
        let row = |connection_id: Option<String>| AuditEntry::ProxyRequest {
            ts: OffsetDateTime::UNIX_EPOCH,
            mint_id: MintId::generate(),
            method: "POST".into(),
            host: "api.openai.com".into(),
            path: "/v1/responses".into(),
            status: Some(200),
            req_bytes: 12,
            resp_bytes: 34,
            latency_ms: 5,
            decision: "allow".into(),
            connection_id,
        };
        // HTTP/1.1: the key is absent altogether, so a row is what it always
        // was and an older reader parses it unchanged.
        let http1 = serde_json::to_value(row(None)).unwrap();
        assert!(http1.get("connection_id").is_none(), "{http1}");

        let http2 = serde_json::to_value(row(Some("h2-9f31c0a2b4de".into()))).unwrap();
        assert_eq!(http2["connection_id"], "h2-9f31c0a2b4de");
    }

    #[test]
    fn a_stream_row_carries_framing_counts_and_no_content() {
        let entry = AuditEntry::ProxyStream {
            ts: OffsetDateTime::UNIX_EPOCH,
            mint_id: MintId::generate(),
            kind: "sse".into(),
            host: "api.openai.com".into(),
            path: "/v1/responses".into(),
            started: OffsetDateTime::UNIX_EPOCH,
            ended: OffsetDateTime::UNIX_EPOCH,
            events_or_frames: 100,
            connection_id: None,
            bytes_up: 40,
            bytes_down: 9_000,
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["event"], "proxy_stream");
        assert_eq!(json["kind"], "sse");
        assert_eq!(json["events_or_frames"], 100);
        assert_eq!(json["bytes_up"], 40);
        assert_eq!(json["bytes_down"], 9_000);
        assert_eq!(json["path"], "/v1/responses");
        assert_eq!(entry.mint_ids().len(), 1);

        // The field list is the whole promise: nothing here can hold a header,
        // a body, or a query string, because there is nowhere to put one.
        let mut fields: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
        fields.sort();
        assert_eq!(
            fields,
            [
                "bytes_down",
                "bytes_up",
                "ended",
                "event",
                "events_or_frames",
                "host",
                "kind",
                "mint_id",
                "path",
                "started",
                "ts",
            ]
        );

        let back: AuditEntry =
            serde_json::from_str(&serde_json::to_string(&entry).unwrap()).unwrap();
        assert_eq!(back, entry);
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
