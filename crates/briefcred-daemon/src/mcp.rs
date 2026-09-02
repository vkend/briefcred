//! The Model Context Protocol server, hosted inside the daemon.
//!
//! # Why in the daemon
//!
//! An agent that wants to query a database is normally handed a connection
//! string. That is the thing briefcred exists to stop: once the agent has the
//! credential, the credential is in a transcript, a log, a context window, and
//! a model provider's infrastructure, and briefcred's revoke is racing all of
//! them. So the tools here are deliberately *verbs rather than credentials*.
//! `briefcred_db_query` takes SQL and returns rows; `briefcred_exec` takes an
//! argv and returns output. The minted credential is created in the daemon,
//! used in the daemon, and revoked by the daemon, and at no point is there a
//! value for the agent to leak.
//!
//! # The session
//!
//! One briefcred session per MCP connection, and **one mint** within it. The
//! first tool call that needs a credential runs the profile's unlock gate,
//! opens a session, and mints; every later call on the same profile reuses it.
//! A call naming a *different* profile is refused rather than opening a second
//! session, because "this MCP connection is bound to one profile" is a
//! property an operator can hold in their head and check in an audit log, and
//! "it can reach anything you have a profile for" is not.
//!
//! When the connection closes, the session closes: the mints go on the revoke
//! queue and the helper processes stop. That is the same path a `briefcred
//! exec` whose wrapper was killed takes, and it is why an agent that
//! disappears mid-call does not strand a role.
//!
//! # What an operator is agreeing to
//!
//! This is the widest surface briefcred has. `briefcred_exec` runs commands
//! and `briefcred_db_query` runs SQL, both under the profile's own allowlists
//! but at the direction of a model. `THREAT_MODEL.md` states the exposure;
//! the short version is that an MCP profile should grant what an agent needs
//! and nothing more, and `exec.allow_argv0` is not optional on one.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use briefcred_core::audit::AuditEntry;
use briefcred_core::minters::postgres::{self, PostgresConfig};
use briefcred_core::profile::Profile;
use briefcred_proto::{MintSummary, SecretString};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServiceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::revoke::PendingRevoke;
use crate::server::State;

/// The most output `briefcred_exec` will carry back, per stream.
///
/// A megabyte each of stdout and stderr. The cap exists because the far end of
/// this is a model's context window: a command that prints a gigabyte would
/// not be *useful* at any size, and would take the daemon's memory with it on
/// the way to being useless. Output past the cap is dropped and the result
/// says so, rather than being silently truncated into something that looks
/// complete.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// The most rows `briefcred_db_query` will return when the caller asks for no
/// particular number.
pub const DEFAULT_MAX_ROWS: u32 = 100;

/// The ceiling on `max_rows`, whatever the caller asks for.
pub const MAX_MAX_ROWS: u32 = 10_000;

/// What one MCP connection has open.
struct Held {
    /// The profile this connection is bound to.
    profile: String,
    /// The briefcred session holding its masters and helpers.
    session_id: String,
    /// Minted fields, by credential name.
    fields: BTreeMap<String, BTreeMap<String, String>>,
    /// The composed environment, for `briefcred_exec`.
    env: BTreeMap<String, SecretString>,
    /// Variable names to copy from the daemon's own environment.
    passthrough: Vec<String>,
    /// What was minted, for the audit rows.
    mints: Vec<MintSummary>,
}

/// The MCP server for one connection.
///
/// Cloneable, and every clone is the same server: `rmcp`'s `serve` takes the
/// handler by value, and the cleanup after the connection ends needs the same
/// instance, because the briefcred session to close lives inside it.
#[derive(Clone)]
pub struct McpServer {
    inner: Arc<Inner>,
    tool_router: ToolRouter<Self>,
}

struct Inner {
    state: Arc<State>,
    held: tokio::sync::Mutex<Option<Held>>,
    calls: AtomicU64,
    connection: String,
}

impl std::fmt::Debug for McpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpServer")
            .field("connection", &self.inner.connection)
            .finish()
    }
}

/// Arguments to `briefcred_db_query`.
///
/// # The statement is rolled back
///
/// Bounding the fetch at the server needs a portal, a portal needs a
/// transaction, and a transaction that has fetched only part of a result set
/// must not be committed: a suspended `INSERT ... RETURNING` has inserted the
/// rows it produced and not the rest, and committing that would make the tool's
/// row cap silently decide how much of a write survived.
///
/// So the transaction is always rolled back and `briefcred_db_query` is a
/// **read**. This is stated in the tool's own description, so a model does not
/// discover it by having a write vanish; a profile that needs to write should
/// grant only `SELECT` and route writes through a command that owns its own
/// transaction.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbQueryArgs {
    /// The briefcred profile whose database credential to use.
    pub profile: String,
    /// The SQL to run. One statement, executed as the minted role in a
    /// transaction that is rolled back, so it must be a read.
    pub sql: String,
    /// The most rows to return. Defaults to 100 and is capped at 10000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rows: Option<u32>,
}

/// Arguments to `briefcred_exec`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExecArgs {
    /// The briefcred profile whose credentials the command runs with.
    pub profile: String,
    /// The command and its arguments. The first element is the program, and
    /// it must be one the profile's `exec.allow_argv0` permits.
    pub argv: Vec<String>,
}

/// One row of a `briefcred_db_query` result.
type Row = serde_json::Map<String, serde_json::Value>;

/// A tool call that failed, and the two different things to say about it.
///
/// These are not the same string and must not be allowed to become one. What
/// the *caller* is told may quote the caller's own input back — a database's
/// complaint names the table in the statement, and a refused command names the
/// argument that was refused, and both are what make the failure fixable. What
/// the *audit row* records may not: SQL and command lines are exactly the
/// free-form text `AuditEntry` forbids, and an audit log that accumulates them
/// is a log that has to be protected like the credentials it exists to
/// account for.
///
/// So every failure states both, and the `From` impl below is only for
/// failures whose message briefcred wrote itself out of metadata it already
/// records elsewhere.
struct ToolFailure {
    /// What the caller is told.
    reported: McpError,
    /// What the audit row records. Metadata only.
    audited: String,
}

impl From<McpError> for ToolFailure {
    /// For a message briefcred composed from a profile name, a credential
    /// name, or a kind — all of which the row already carries in a field.
    fn from(reported: McpError) -> ToolFailure {
        ToolFailure {
            audited: reported.message.to_string(),
            reported,
        }
    }
}

impl ToolFailure {
    /// A failure whose caller-facing message quotes something the caller sent.
    fn redacted(reported: McpError, audited: impl Into<String>) -> ToolFailure {
        ToolFailure {
            reported,
            audited: audited.into(),
        }
    }
}

#[tool_router]
impl McpServer {
    /// A server bound to the daemon's state, serving one connection.
    pub fn new(state: Arc<State>, connection: impl Into<String>) -> McpServer {
        McpServer {
            inner: Arc::new(Inner {
                state,
                held: tokio::sync::Mutex::new(None),
                calls: AtomicU64::new(0),
                connection: connection.into(),
            }),
            tool_router: Self::tool_router(),
        }
    }

    /// The profiles the daemon has loaded, and what each one mints.
    ///
    /// Deliberately the same reduction `briefcred profiles` shows: names,
    /// kinds, and lifetimes. Never a `config` block, which is where a
    /// hostname or a role ARN an agent has no business knowing would be.
    #[tool(
        name = "briefcred_list_profiles",
        description = "List the briefcred profiles available, with the credentials each one mints. \
                       Call this first to find out which profile to use."
    )]
    pub async fn list_profiles(&self) -> Result<CallToolResult, McpError> {
        let call_id = self.next_call_id();
        let started = std::time::Instant::now();

        let profiles: Vec<serde_json::Value> = self
            .inner
            .state
            .profiles()
            .list()
            .await
            .iter()
            .map(|profile| {
                serde_json::json!({
                    "name": profile.name,
                    "description": profile.description,
                    "unlock_policy": format!("{:?}", profile.unlock.policy).to_lowercase(),
                    "credentials": profile.credentials.iter().map(|spec| serde_json::json!({
                        "name": spec.name,
                        "kind": spec.kind,
                        "ttl_secs": spec.ttl_secs,
                    })).collect::<Vec<_>>(),
                    "allowed_commands": profile.exec.allow_argv0,
                })
            })
            .collect();

        self.audit(
            &call_id,
            "briefcred_list_profiles",
            None,
            &[],
            Ok(()),
            started,
        );
        json_result(&serde_json::json!({ "profiles": profiles }))
    }

    /// Run one SQL statement as a freshly minted database role.
    #[tool(
        name = "briefcred_db_query",
        description = "Run one read-only SQL statement against the database a briefcred profile \
                       mints a role for, and return the rows as JSON. The statement runs in a \
                       transaction that is rolled back, so it cannot write. The credential is \
                       created, used, and destroyed inside briefcred and is never returned."
    )]
    pub async fn db_query(
        &self,
        Parameters(args): Parameters<DbQueryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let call_id = self.next_call_id();
        let started = std::time::Instant::now();
        let outcome = self.db_query_inner(&args).await;
        let mint_ids = self.mint_ids().await;
        self.audit(
            &call_id,
            "briefcred_db_query",
            Some(&args.profile),
            &mint_ids,
            outcome.as_ref().map(|_| ()).map_err(|e| e.audited.clone()),
            started,
        );
        json_result(&outcome.map_err(|e| e.reported)?)
    }

    /// Run one command with the profile's credentials, inside the daemon.
    #[tool(
        name = "briefcred_exec",
        description = "Run a command with the credentials a briefcred profile mints, and return \
                       its output. The command must be one the profile permits. The credentials \
                       are placed in the child's environment by briefcred and are never returned."
    )]
    pub async fn exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let call_id = self.next_call_id();
        let started = std::time::Instant::now();
        let outcome = self.exec_inner(&args).await;
        let mint_ids = self.mint_ids().await;
        self.audit(
            &call_id,
            "briefcred_exec",
            Some(&args.profile),
            &mint_ids,
            outcome.as_ref().map(|_| ()).map_err(|e| e.audited.clone()),
            started,
        );
        json_result(&outcome.map_err(|e| e.reported)?)
    }
}

impl McpServer {
    async fn db_query_inner(&self, args: &DbQueryArgs) -> Result<serde_json::Value, ToolFailure> {
        let max_rows = args
            .max_rows
            .unwrap_or(DEFAULT_MAX_ROWS)
            .clamp(1, MAX_MAX_ROWS) as usize;

        let profile = self.profile(&args.profile).await?;
        // The credential is chosen before anything is minted, so a profile
        // with no database says so rather than minting and then failing.
        let spec = profile
            .credentials
            .iter()
            .find(|spec| spec.kind == postgres::KIND)
            .ok_or_else(|| {
                invalid(format!(
                    "profile `{}` declares no `{}` credential, so it has no database to query",
                    profile.name,
                    postgres::KIND
                ))
            })?;
        let config =
            PostgresConfig::from_value(&spec.config).map_err(|e| internal(e.to_string()))?;
        let credential = spec.name.clone();

        self.ensure_minted(&profile).await?;
        // Copied out of the lock rather than used under it: the connection and
        // the query below are network calls, and holding the session lock
        // across them would make two tool calls on one connection wait on each
        // other for no reason.
        let (user, password) = {
            let held = self.inner.held.lock().await;
            let held = held.as_ref().expect("ensure_minted leaves a session");
            let fields = held.fields.get(&credential).ok_or_else(|| {
                internal(format!(
                    "credential `{credential}` did not mint, so there is nothing to query with"
                ))
            })?;
            let user = fields
                .get("PGUSER")
                .ok_or_else(|| internal("the minted credential has no PGUSER"))?
                .clone();
            let password = zeroize::Zeroizing::new(
                fields
                    .get("PGPASSWORD")
                    .ok_or_else(|| internal("the minted credential has no PGPASSWORD"))?
                    .clone(),
            );
            (user, password)
        };

        let mut client = postgres::connect_as(&config, &user, &password)
            .await
            .map_err(|e| internal(e.to_string()))?;

        // A statement with no bound is a statement that holds a connection and
        // a minted role open for as long as it likes. The server enforces this
        // one, so a query that runs away is killed at the database rather than
        // waited out here.
        let timeout = self.inner.state.mcp_query_timeout();
        client
            .batch_execute(&format!(
                "SET statement_timeout = {}",
                timeout.as_millis().clamp(1, i32::MAX as u128)
            ))
            .await
            .map_err(|e| internal(describe_sql_error(&e)))?;

        // The row limit is enforced by the *server*, through a portal.
        //
        // Neither `query` nor `query_raw` does that. `query` collects the whole
        // result set before this code sees a row. `query_raw` looks like it
        // streams, and from this side it does — but the `Execute` it sends
        // carries no row limit, so the backend produces the entire result set
        // and pushes it down the connection whatever this code does with the
        // `RowStream`. Dropping the stream after five rows does not tell the
        // server to stop — only closing the connection does, which is what
        // eventually happens when `client` goes out of scope. So the cost is
        // not the rows asked for but however many the backend got through
        // before it was hung up on: measured at 5122 for a five-row request.
        // That is a bounded *read* of an unbounded fetch, not a bounded fetch.
        //
        // `bind` plus `query_portal(limit)` sends `Execute` with a row count.
        // The server sends at most that many and answers `PortalSuspended`. A
        // hundred-million-row generator costs the rows actually asked for.
        //
        // A portal only exists inside a transaction, which is why one is opened
        // here. It is **rolled back**, and that is a deliberate part of the
        // tool's contract rather than a consequence of the mechanism: see the
        // note on `DbQueryArgs`.
        let transaction = client
            .transaction()
            .await
            .map_err(|e| internal(describe_sql_error(&e)))?;

        // One past the cap, so "there was more" is observed rather than
        // guessed, and exactly one extra row is ever produced.
        let limit = i32::try_from(max_rows.saturating_add(1))
            .map_err(|_| internal("the row limit does not fit a portal fetch"))?;
        // Still the extended protocol rather than `simple_query`, so the
        // statement is one statement: the server refuses a second one after a
        // semicolon, which is what keeps a tool that takes SQL from a model out
        // of multi-statement territory.
        let no_params: [&(dyn tokio_postgres::types::ToSql + Sync); 0] = [];
        let portal = transaction
            .bind(args.sql.as_str(), &no_params)
            .await
            .map_err(|e| sql_failure(&e))?;
        let fetched = transaction
            .query_portal(&portal, limit)
            .await
            .map_err(|e| sql_failure(&e))?;

        // Rolling back is what makes this tool read-only, so it happens whether
        // the rows are used or not. A failure to roll back is not worth failing
        // the call over: dropping the client closes the connection, which ends
        // the transaction the same way.
        if let Err(err) = transaction.rollback().await {
            eprintln!("briefcred-daemon: an MCP query could not roll back: {err}");
        }

        let truncated = fetched.len() > max_rows;
        let columns: Vec<serde_json::Value> = fetched
            .first()
            .map(|row| {
                row.columns()
                    .iter()
                    .map(|c| serde_json::json!({ "name": c.name(), "type": c.type_().name() }))
                    .collect()
            })
            .unwrap_or_default();
        let json_rows: Vec<Row> = fetched.iter().take(max_rows).map(row_to_json).collect();

        Ok(serde_json::json!({
            "columns": columns,
            "rows": json_rows,
            "row_count": json_rows.len(),
            "truncated": truncated,
        }))
    }

    async fn exec_inner(&self, args: &ExecArgs) -> Result<serde_json::Value, ToolFailure> {
        let Some((argv0, rest)) = args.argv.split_first() else {
            return Err(invalid("`argv` must name a program to run").into());
        };
        let profile = self.profile(&args.profile).await?;

        // Before anything is minted, exactly as `briefcred exec` does it: a
        // command the profile forbids must not create a principal.
        // The refusal names the offending value, which for an `allow_args`
        // denial is an argument the caller sent. The caller needs it; the
        // audit row must not have it, so the row records `argv[0]` — which
        // every `exec_start` row already carries verbatim — and the fact of
        // the refusal.
        briefcred_core::exec::check_command(&profile, argv0, rest).map_err(|denied| {
            ToolFailure::redacted(
                invalid(denied.to_string()),
                format!(
                    "`{argv0}` was refused by profile `{}`'s exec policy",
                    profile.name
                ),
            )
        })?;

        self.ensure_minted(&profile).await?;
        let (env, passthrough, session_id) = {
            let held = self.inner.held.lock().await;
            let held = held.as_ref().expect("ensure_minted leaves a session");
            (
                held.env.clone(),
                held.passthrough.clone(),
                held.session_id.clone(),
            )
        };

        let mut command = tokio::process::Command::new(argv0);
        command
            .args(rest)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // The daemon's own environment is the only one there is here: an MCP
        // call has no calling shell, so `env_passthrough` is filled from the
        // daemon's, which is launchd's. Nothing is invented for it.
        for name in &passthrough {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        for (name, value) in &env {
            command.env(name, value.expose());
        }

        let started = std::time::Instant::now();
        let mint_ids = self.mint_ids().await;
        self.inner.state.audit(&AuditEntry::ExecStart {
            ts: OffsetDateTime::now_utc(),
            session_id: session_id.clone(),
            mint_ids: mint_ids.clone(),
            profile: profile.name.clone(),
            argv0: argv0.clone(),
            args_sha256: rest
                .iter()
                .map(|a| briefcred_core::audit::hash_arg(a))
                .collect(),
            args: None,
            pid: std::process::id(),
        });

        let output = run_capped(command)
            .await
            .map_err(|e| invalid(format!("cannot run `{argv0}`: {e}")))?;

        let duration_ms = started.elapsed().as_millis() as u64;
        self.inner.state.audit(&AuditEntry::ExecEnd {
            ts: OffsetDateTime::now_utc(),
            session_id,
            mint_ids,
            profile: profile.name.clone(),
            exit_code: output.exit_code,
            duration_ms,
        });

        Ok(serde_json::json!({
            "stdout": output.stdout,
            "stderr": output.stderr,
            "exit_code": output.exit_code,
            "truncated": output.truncated,
            "duration_ms": duration_ms,
        }))
    }

    /// The profile named, or a refusal a model can act on.
    async fn profile(&self, name: &str) -> Result<Profile, McpError> {
        self.inner.state.profiles().get(name).await.ok_or_else(|| {
            invalid(format!(
                "no profile `{name}`; call `briefcred_list_profiles` for the ones there are"
            ))
        })
    }

    /// Open the session and mint, once per connection.
    ///
    /// # Why the lock is held across the whole sequence
    ///
    /// `rmcp` dispatches every request as its own task, so two tool calls
    /// arriving together on a fresh connection run this concurrently. Checking
    /// the slot, releasing the lock, and then minting would have both find it
    /// empty, both prompt, both open a session, and both mint — and the second
    /// would overwrite the first in the slot. `close()` only closes the
    /// session it can see, so the first would be left open with a live
    /// credential nothing ever revokes, until the daemon's idle eviction found
    /// it.
    ///
    /// So the guard spans the check *and* the work. The cost is that a second
    /// tool call waits for the first connection's mint rather than starting
    /// its own, which is exactly what "one mint per MCP session" means.
    /// `briefcred_list_profiles` never takes this lock and is unaffected.
    async fn ensure_minted(&self, profile: &Profile) -> Result<(), McpError> {
        let mut held = self.inner.held.lock().await;
        if let Some(existing) = held.as_ref() {
            return if existing.profile == profile.name {
                Ok(())
            } else {
                Err(invalid(format!(
                    "this MCP connection is already using profile `{}`; one connection mints \
                     for one profile. Start a new connection to use `{}`.",
                    existing.profile, profile.name
                )))
            };
        }

        // The unlock gate first, then the masters, then the mint: the same
        // order `open_session` uses, so a refused prompt leaves nothing behind.
        // `client_headless` is false because the peer is a `briefcred mcp` on
        // this machine, which is as local as a `briefcred exec`.
        crate::server::prove_presence(&self.inner.state, profile, false)
            .await
            .map_err(locked_or_internal)?;

        let (session_id, _) = self
            .inner
            .state
            .sessions()
            .open(
                profile,
                self.inner.state.master_source().as_ref(),
                self.inner.state.helper_dirs().to_vec(),
                // The MCP server is in the daemon: there is no separate client
                // to hold a session key, and nothing it serves goes through the
                // proxy.
                None,
            )
            .await
            .map_err(|e| internal(e.to_string()))?;
        self.inner.state.audit(&AuditEntry::SessionOpen {
            ts: OffsetDateTime::now_utc(),
            session_id: session_id.clone(),
            profile: profile.name.clone(),
            credentials: profile.credentials.len(),
        });

        let specs: Vec<_> = profile.credentials.iter().collect();
        let (masters, helpers) = self
            .inner
            .state
            .sessions()
            .with_session(&session_id, |s| (s.masters.clone(), Arc::clone(&s.helpers)))
            .await
            .map_err(|e| internal(e.to_string()))?;
        let trust = briefcred_core::ca::trust_env(self.inner.state.paths(), profile);

        let minted = crate::exec::mint_only(
            profile,
            &specs,
            &masters,
            helpers.as_ref(),
            &trust,
            self.inner.state.metrics(),
            // No proxy grant: an MCP tool call runs inside the daemon and
            // spawns nothing, so there is no subprocess to hand a synthetic
            // token to. A profile mixing `http-*` credentials with an MCP tool
            // is told so rather than silently given a token it cannot use.
            None,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;

        self.inner
            .state
            .sessions()
            .record_mints(&session_id, minted.pending.clone())
            .await
            .map_err(|e| internal(e.to_string()))?;
        for row in &minted.rows {
            self.inner.state.audit(row);
        }

        let fields = minted
            .mints
            .iter()
            .map(|summary| {
                (
                    summary.credential.clone(),
                    summary
                        .fields
                        .iter()
                        .map(|(name, value)| (name.clone(), value.expose().to_string()))
                        .collect(),
                )
            })
            .collect();

        *held = Some(Held {
            profile: profile.name.clone(),
            session_id,
            fields,
            env: minted.env,
            passthrough: minted.passthrough,
            mints: minted.mints,
        });
        Ok(())
    }

    /// The principals this connection has minted, for an audit row.
    async fn mint_ids(&self) -> Vec<briefcred_core::types::MintId> {
        self.inner
            .held
            .lock()
            .await
            .as_ref()
            .map(|held| {
                held.mints
                    .iter()
                    .filter_map(|m| m.mint_id.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn next_call_id(&self) -> String {
        format!(
            "{}-{}",
            self.inner.connection,
            self.inner.calls.fetch_add(1, Ordering::SeqCst)
        )
    }

    fn audit(
        &self,
        call_id: &str,
        tool: &str,
        profile: Option<&str>,
        mint_ids: &[briefcred_core::types::MintId],
        outcome: Result<(), String>,
        started: std::time::Instant,
    ) {
        let (label, detail) = match outcome {
            Ok(()) => ("ok", None),
            Err(detail) => ("error", Some(detail)),
        };
        self.inner.state.audit(&AuditEntry::McpCall {
            ts: OffsetDateTime::now_utc(),
            mcp_call_id: call_id.to_string(),
            tool: tool.to_string(),
            profile: profile.map(str::to_string),
            mint_ids: mint_ids.to_vec(),
            outcome: label.to_string(),
            detail,
            duration_ms: started.elapsed().as_millis() as u64,
        });
    }

    /// Close the session this connection opened, if it opened one.
    ///
    /// Called when the stream ends, however it ends. Everything minted goes on
    /// the revoke queue and the helper processes stop, which is the same
    /// treatment a `briefcred exec` whose wrapper was killed gets.
    pub async fn close(&self) -> Vec<PendingRevoke> {
        let Some(held) = self.inner.held.lock().await.take() else {
            return Vec::new();
        };
        match self.inner.state.sessions().close(&held.session_id).await {
            Ok(session) => {
                let orphaned: Vec<_> = session.mints.values().cloned().collect();
                crate::server::retire(&self.inner.state, session, "mcp_disconnect").await;
                self.inner.state.audit(&AuditEntry::SessionClose {
                    ts: OffsetDateTime::now_utc(),
                    session_id: held.session_id,
                    profile: held.profile,
                    reason: "mcp_disconnect".to_string(),
                });
                orphaned
            }
            Err(err) => {
                eprintln!("briefcred-daemon: cannot close an MCP session: {err}");
                Vec::new()
            }
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl rmcp::ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(
            "briefcred mints short-lived credentials and uses them on your behalf. It never \
             returns a credential: ask it to run a query or a command instead. Call \
             briefcred_list_profiles first. One connection works with one profile."
                .to_string(),
        );
        info
    }
}

/// Serve the MCP protocol on `stream` until it closes, then clean up.
///
/// The caller has already written [`briefcred_proto::Response::McpReady`], so
/// everything from here is MCP's own newline-delimited JSON-RPC.
pub async fn serve<S>(stream: S, state: Arc<State>, connection: String)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let server = McpServer::new(state, connection);
    let cleanup = server.clone();
    match server.serve(stream).await {
        Ok(running) => {
            if let Err(err) = running.waiting().await {
                eprintln!("briefcred-daemon: the MCP connection ended: {err}");
            }
        }
        Err(err) => eprintln!("briefcred-daemon: cannot start the MCP server: {err}"),
    }
    // However the connection ended — clean shutdown, a killed client, a broken
    // pipe — the session it opened has to go, because the session is what
    // holds the masters and the mints.
    cleanup.close().await;
}

/// Wrap a JSON value as a tool result.
fn json_result(value: &serde_json::Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(|e| internal(e.to_string()))?,
    )]))
}

/// Turn a refused `prove_presence` into an error for the caller.
///
/// An exhaustive match rather than a `{:?}` fallback: `prove_presence`'s error
/// half is a `Response`, and debug-printing an unexpected one would put
/// whatever a future variant carries into a tool result. Only `Locked` is
/// reachable today, and anything else is briefcred's own bug.
fn locked_or_internal(response: briefcred_proto::Response) -> McpError {
    match response {
        briefcred_proto::Response::Locked { message, .. } => invalid(message),
        briefcred_proto::Response::Error { .. } => {
            internal("the unlock gate reported an error instead of a decision".to_string())
        }
        other => internal(format!(
            "internal error: the unlock gate answered `{}`",
            response_name(&other)
        )),
    }
}

/// A response's variant name, for a message that must carry no payload.
fn response_name(response: &briefcred_proto::Response) -> &'static str {
    use briefcred_proto::Response;
    match response {
        Response::Pong => "pong",
        Response::Status { .. } => "status",
        Response::ShuttingDown => "shutting_down",
        Response::Profiles { .. } => "profiles",
        Response::Profile { .. } => "profile",
        Response::SessionOpened { .. } => "session_opened",
        Response::SessionClosed { .. } => "session_closed",
        Response::Unlocked { .. } => "unlocked",
        Response::Minted { .. } => "minted",
        Response::ExecRecorded { .. } => "exec_recorded",
        Response::McpReady { .. } => "mcp_ready",
        Response::HookDecision { .. } => "hook_decision",
        Response::Denied { .. } => "denied",
        Response::Locked { .. } => "locked",
        Response::Error { .. } => "error",
        #[cfg(feature = "debug-heapscan")]
        Response::HeapScanned { .. } => "heap_scanned",
    }
}

/// The caller asked for something briefcred will not or cannot do.
fn invalid(message: impl Into<String>) -> McpError {
    McpError::invalid_params(message.into(), None)
}

/// briefcred could not do something it should have been able to.
fn internal(message: impl Into<String>) -> McpError {
    McpError::internal_error(message.into(), None)
}

/// What a child process produced, already bounded.
struct CappedOutput {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    truncated: bool,
}

/// Run `command`, reading at most [`MAX_OUTPUT_BYTES`] from each stream.
///
/// `Command::output` would collect everything the child writes before this
/// code saw any of it, so a command that prints without stopping — a `yes`, a
/// `cat` of something enormous, a log tail an agent thought was finite — would
/// take the daemon's memory whatever cap were applied afterwards. Here each
/// stream is read through a `take` that stops one byte past the cap, so the
/// allocation is bounded before the bytes arrive.
///
/// The two streams are read concurrently, which is not an optimisation: a
/// child that fills its stderr pipe while this code is only draining stdout
/// blocks forever, and so does the reverse.
///
/// A child that goes over the cap is **killed**. It has to be: this code has
/// stopped reading its pipe, so it would block on the next write and never
/// exit, and it is a process a model asked for. The output collected up to
/// that point is returned with `truncated` set.
async fn run_capped(mut command: tokio::process::Command) -> std::io::Result<CappedOutput> {
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    let mut out_task = tokio::spawn(read_capped(stdout));
    let mut err_task = tokio::spawn(read_capped(stderr));
    let mut out: Option<(Vec<u8>, bool)> = None;
    let mut err: Option<(Vec<u8>, bool)> = None;

    while out.is_none() || err.is_none() {
        tokio::select! {
            finished = &mut out_task, if out.is_none() => {
                let finished = finished.map_err(std::io::Error::other)??;
                if finished.1 {
                    let _ = child.start_kill();
                }
                out = Some(finished);
            }
            finished = &mut err_task, if err.is_none() => {
                let finished = finished.map_err(std::io::Error::other)??;
                if finished.1 {
                    let _ = child.start_kill();
                }
                err = Some(finished);
            }
        }
    }

    let status = child.wait().await?;
    let (stdout, stdout_over) = out.expect("the loop exits with both");
    let (stderr, stderr_over) = err.expect("the loop exits with both");
    let (stdout, stdout_cut) = capped(&stdout);
    let (stderr, stderr_cut) = capped(&stderr);
    Ok(CappedOutput {
        stdout,
        stderr,
        exit_code: status.code(),
        truncated: stdout_over || stderr_over || stdout_cut || stderr_cut,
    })
}

/// Read one stream to end-of-file, or to one byte past the cap.
///
/// The extra byte is how "there was more" is observed rather than guessed: a
/// stream that is exactly [`MAX_OUTPUT_BYTES`] long is complete, and one that
/// is a byte longer is not.
async fn read_capped<R>(stream: R) -> std::io::Result<(Vec<u8>, bool)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    let mut buffer = Vec::new();
    tokio::io::AsyncReadExt::take(stream, MAX_OUTPUT_BYTES as u64 + 1)
        .read_to_end(&mut buffer)
        .await?;
    let over = buffer.len() > MAX_OUTPUT_BYTES;
    Ok((buffer, over))
}

/// Truncate output to [`MAX_OUTPUT_BYTES`], saying whether it was truncated.
///
/// Cut on a character boundary: half a UTF-8 sequence at the end would make
/// the whole string unrepresentable in JSON, which is a worse failure than a
/// few missing bytes.
fn capped(bytes: &[u8]) -> (String, bool) {
    if bytes.len() <= MAX_OUTPUT_BYTES {
        return (String::from_utf8_lossy(bytes).into_owned(), false);
    }
    let mut end = MAX_OUTPUT_BYTES;
    while end > 0 && (bytes[end] & 0xC0) == 0x80 {
        end -= 1;
    }
    (String::from_utf8_lossy(&bytes[..end]).into_owned(), true)
}

/// A database error, reduced to its SQLSTATE and message.
fn describe_sql_error(error: &tokio_postgres::Error) -> String {
    match error.as_db_error() {
        Some(db) => format!("{}: {}", db.code().code(), db.message()),
        None => error.to_string(),
    }
}

/// A failed statement: the whole complaint to the caller, the SQLSTATE alone
/// to the audit log.
///
/// The server's message quotes the statement — `relation "orders" does not
/// exist` — which is the caller's own SQL coming back, and an audit row may
/// not hold it. The SQLSTATE is the part an operator acts on anyway: `42P01`
/// says "that table is not there" without saying which table somebody asked
/// for.
fn sql_failure(error: &tokio_postgres::Error) -> ToolFailure {
    let audited = match error.as_db_error() {
        Some(db) => format!("the database refused the statement: {}", db.code().code()),
        None => "the database connection failed".to_string(),
    };
    ToolFailure::redacted(invalid(describe_sql_error(error)), audited)
}

/// One result row as JSON.
///
/// Types briefcred cannot represent become a string saying so rather than
/// failing the whole query: one `numeric` column in a `SELECT *` should not
/// cost the caller the other nine, and the message tells them to cast it.
fn row_to_json(row: &tokio_postgres::Row) -> Row {
    use tokio_postgres::types::Type;

    let mut out = Row::new();
    for (index, column) in row.columns().iter().enumerate() {
        let value = match *column.type_() {
            Type::BOOL => json_of(row.try_get::<_, Option<bool>>(index)),
            Type::INT2 => json_of(row.try_get::<_, Option<i16>>(index)),
            Type::INT4 => json_of(row.try_get::<_, Option<i32>>(index)),
            Type::INT8 => json_of(row.try_get::<_, Option<i64>>(index)),
            Type::FLOAT4 => json_of(row.try_get::<_, Option<f32>>(index)),
            Type::FLOAT8 => json_of(row.try_get::<_, Option<f64>>(index)),
            Type::TEXT | Type::VARCHAR | Type::NAME | Type::BPCHAR | Type::CHAR => {
                json_of(row.try_get::<_, Option<String>>(index))
            }
            Type::JSON | Type::JSONB => json_of(row.try_get::<_, Option<serde_json::Value>>(index)),
            Type::TIMESTAMPTZ => json_of(
                row.try_get::<_, Option<time::OffsetDateTime>>(index)
                    .map(|v| v.map(|at| at.to_string())),
            ),
            Type::TIMESTAMP => json_of(
                row.try_get::<_, Option<time::PrimitiveDateTime>>(index)
                    .map(|v| v.map(|at| at.to_string())),
            ),
            Type::DATE => json_of(
                row.try_get::<_, Option<time::Date>>(index)
                    .map(|v| v.map(|at| at.to_string())),
            ),
            Type::BYTEA => json_of(
                row.try_get::<_, Option<Vec<u8>>>(index)
                    .map(|v| v.map(|bytes| format!("\\x{}", hex::encode(bytes)))),
            ),
            ref other => serde_json::Value::String(format!(
                "<briefcred cannot represent a `{other}`; cast it to text in your query>"
            )),
        };
        out.insert(column.name().to_string(), value);
    }
    out
}

/// A decoded column as JSON, or a note saying it would not decode.
fn json_of<T: Into<serde_json::Value>>(
    decoded: Result<Option<T>, tokio_postgres::Error>,
) -> serde_json::Value {
    match decoded {
        Ok(Some(value)) => value.into(),
        Ok(None) => serde_json::Value::Null,
        Err(e) => serde_json::Value::String(format!("<column did not decode: {e}>")),
    }
}

#[cfg(test)]
mod tests;
