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
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DbQueryArgs {
    /// The briefcred profile whose database credential to use.
    pub profile: String,
    /// The SQL to run. One statement, executed as the minted role.
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
        description = "Run one SQL statement against the database a briefcred profile mints a \
                       role for, and return the rows as JSON. The credential is created, used, \
                       and destroyed inside briefcred and is never returned."
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
            outcome
                .as_ref()
                .map(|_| ())
                .map_err(|e| e.message.to_string()),
            started,
        );
        json_result(&outcome?)
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
            outcome
                .as_ref()
                .map(|_| ())
                .map_err(|e| e.message.to_string()),
            started,
        );
        json_result(&outcome?)
    }
}

impl McpServer {
    async fn db_query_inner(&self, args: &DbQueryArgs) -> Result<serde_json::Value, McpError> {
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
        let held = self.inner.held.lock().await;
        let held = held.as_ref().expect("ensure_minted leaves a session");
        let fields = held.fields.get(&credential).ok_or_else(|| {
            internal(format!(
                "credential `{credential}` did not mint, so there is nothing to query with"
            ))
        })?;
        let user = fields
            .get("PGUSER")
            .ok_or_else(|| internal("the minted credential has no PGUSER"))?;
        let password = zeroize::Zeroizing::new(
            fields
                .get("PGPASSWORD")
                .ok_or_else(|| internal("the minted credential has no PGPASSWORD"))?
                .clone(),
        );

        let client = postgres::connect_as(&config, user, &password)
            .await
            .map_err(|e| internal(e.to_string()))?;
        // `query` and not `simple_query`: one statement, no multi-statement
        // batch, and the server refuses anything with a `;` in the middle of
        // it. An agent that wants two statements sends two calls, each of
        // which is one audit row.
        let rows = client
            .query(args.sql.as_str(), &[])
            .await
            .map_err(|e| invalid(describe_sql_error(&e)))?;

        let truncated = rows.len() > max_rows;
        let columns: Vec<serde_json::Value> = rows
            .first()
            .map(|row| {
                row.columns()
                    .iter()
                    .map(|c| serde_json::json!({ "name": c.name(), "type": c.type_().name() }))
                    .collect()
            })
            .unwrap_or_default();
        let json_rows: Vec<Row> = rows.iter().take(max_rows).map(row_to_json).collect();

        Ok(serde_json::json!({
            "columns": columns,
            "rows": json_rows,
            "row_count": json_rows.len(),
            "truncated": truncated,
        }))
    }

    async fn exec_inner(&self, args: &ExecArgs) -> Result<serde_json::Value, McpError> {
        let Some((argv0, rest)) = args.argv.split_first() else {
            return Err(invalid("`argv` must name a program to run"));
        };
        let profile = self.profile(&args.profile).await?;

        // Before anything is minted, exactly as `briefcred exec` does it: a
        // command the profile forbids must not create a principal.
        briefcred_core::exec::check_command(&profile, argv0, rest)
            .map_err(|denied| invalid(denied.to_string()))?;

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

        let output = command
            .output()
            .await
            .map_err(|e| invalid(format!("cannot run `{argv0}`: {e}")))?;

        let duration_ms = started.elapsed().as_millis() as u64;
        self.inner.state.audit(&AuditEntry::ExecEnd {
            ts: OffsetDateTime::now_utc(),
            session_id,
            mint_ids,
            profile: profile.name.clone(),
            exit_code: output.status.code(),
            duration_ms,
        });

        let (stdout, stdout_truncated) = capped(&output.stdout);
        let (stderr, stderr_truncated) = capped(&output.stderr);
        Ok(serde_json::json!({
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": output.status.code(),
            "truncated": stdout_truncated || stderr_truncated,
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
    async fn ensure_minted(&self, profile: &Profile) -> Result<(), McpError> {
        {
            let held = self.inner.held.lock().await;
            if let Some(held) = held.as_ref() {
                return if held.profile == profile.name {
                    Ok(())
                } else {
                    Err(invalid(format!(
                        "this MCP connection is already using profile `{}`; one connection mints \
                         for one profile. Start a new connection to use `{}`.",
                        held.profile, profile.name
                    )))
                };
            }
        }

        // The unlock gate first, then the masters, then the mint: the same
        // order `open_session` uses, so a refused prompt leaves nothing behind.
        // `client_headless` is false because the peer is a `briefcred mcp` on
        // this machine, which is as local as a `briefcred exec`.
        crate::server::prove_presence(&self.inner.state, profile, false)
            .await
            .map_err(|locked| match locked {
                briefcred_proto::Response::Locked { message, .. } => invalid(message),
                other => internal(format!("{other:?}")),
            })?;

        let (session_id, _) = self
            .inner
            .state
            .sessions()
            .open(
                profile,
                self.inner.state.master_source().as_ref(),
                self.inner.state.helper_dirs().to_vec(),
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

        *self.inner.held.lock().await = Some(Held {
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

/// The caller asked for something briefcred will not or cannot do.
fn invalid(message: impl Into<String>) -> McpError {
    McpError::invalid_params(message.into(), None)
}

/// briefcred could not do something it should have been able to.
fn internal(message: impl Into<String>) -> McpError {
    McpError::internal_error(message.into(), None)
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
