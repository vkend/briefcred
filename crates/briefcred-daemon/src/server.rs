//! The IPC listener, the dispatch table, and graceful shutdown.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use briefcred_core::audit::AuditEntry;
use briefcred_core::distribution::LoadedProfile;
use briefcred_core::paths::Paths;
use briefcred_core::types::MintId;
use briefcred_core::MasterSource;
use briefcred_proto::{
    read_frame, write_frame, CredentialSummary, ProfileSummary, Request, Response,
};
use time::OffsetDateTime;
use tokio::net::{UnixListener, UnixStream};

use crate::audit::AuditHandle;
use crate::error::{Error, Result};
use crate::metrics::Metrics;
use crate::profiles::ProfileStore;
use crate::revoke::RevokeQueue;
use crate::session::{Session, SessionError, SessionStore};
use crate::unlock::{UnlockCache, UnlockGate};

/// How long in-flight connections get to finish once shutdown begins.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// A handler's answer, boxed so the table can hold handlers of different shapes.
pub type BoxFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>;

/// One request handler.
///
/// Handlers take the deserialised [`Request`] because a request now carries a
/// payload — a profile name, a session id — and they are async because opening
/// a session prompts the user and reads a keychain. They take `Arc<State>`
/// rather than a reference so the returned future owns everything it needs.
pub type Handler = fn(Request, Arc<State>) -> BoxFuture;

/// Wrap an `async fn(Request, Arc<State>) -> Response` as a [`Handler`].
///
/// A macro rather than a closure because a [`Handler`] is a plain function
/// pointer, and a closure that captures nothing still cannot be named as one
/// without this shim.
macro_rules! handler {
    ($name:ident) => {{
        fn wrapper(request: Request, state: Arc<State>) -> BoxFuture {
            Box::pin($name(request, state))
        }
        wrapper as Handler
    }};
}

/// How many connections are still being served, and a way to wait for zero.
///
/// The IPC listener drains by counting its own connection tasks, which works
/// because every one of them is awaited by [`serve`]. The proxies cannot do
/// that: a `CONNECT` tunnel outlives the connection future that produced it, so
/// the task holding a live event stream is not the task the accept loop
/// spawned. A counter every such task holds a guard on is the one thing that
/// covers all of them, and it is what makes "drain before exiting" mean the
/// streams and not merely the sockets.
#[derive(Debug, Clone, Default)]
pub struct InFlight {
    open: Arc<std::sync::atomic::AtomicUsize>,
    idle: Arc<tokio::sync::Notify>,
}

impl InFlight {
    /// Count one piece of work until the returned guard is dropped.
    pub fn guard(&self) -> InFlightGuard {
        self.open.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        InFlightGuard {
            open: Arc::clone(&self.open),
            idle: Arc::clone(&self.idle),
        }
    }

    /// How much is still in flight.
    pub fn open(&self) -> usize {
        self.open.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Wait until nothing is in flight, or until `within` has passed.
    ///
    /// Reports what was still open when it gave up, so the caller can say so
    /// rather than exiting quietly on top of a stream somebody was reading.
    pub async fn drained(&self, within: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + within;
        while self.open() > 0 {
            let notified = self.idle.notified();
            if self.open() == 0 {
                break;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                break;
            }
        }
        self.open()
    }
}

/// One counted piece of work. Dropping it is what reports it finished.
#[derive(Debug)]
pub struct InFlightGuard {
    open: Arc<std::sync::atomic::AtomicUsize>,
    idle: Arc<tokio::sync::Notify>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.open.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
            self.idle.notify_waiters();
        }
    }
}

/// What one completed handoff moved, and to where.
#[derive(Debug, Clone)]
struct HandedOff {
    /// The process now serving.
    pid: u32,
    /// The identifiers of the sessions the blob carried.
    moved: std::collections::BTreeSet<String>,
}

/// What a client is told when it asks for something a handoff has closed off.
pub const HANDING_OFF: &str =
    "the daemon is handing off to a new one; retry, and the new daemon will answer";

/// Everything a handler needs, shared across every connection.
#[derive(Debug)]
pub struct State {
    started_at: OffsetDateTime,
    metrics: Arc<Metrics>,
    audit: AuditHandle,
    metrics_addr: Option<String>,
    proxy_addr: Option<String>,
    pg_proxy_addr: Option<String>,
    shutdown: tokio::sync::watch::Sender<bool>,
    shutdown_reason: Mutex<&'static str>,
    profiles: Arc<ProfileStore>,
    sessions: Arc<SessionStore>,
    unlock: Arc<dyn UnlockGate>,
    unlock_cache: UnlockCache,
    master_source: Arc<dyn MasterSource>,
    paths: Arc<Paths>,
    helper_dirs: Vec<PathBuf>,
    revokes: Arc<RevokeQueue>,
    raw_args: bool,
    mcp_query_timeout: Duration,
    mcp_exec_timeout: Duration,
    proxy: Option<Arc<crate::proxy::issuer::ProxyIssuer>>,
    keystore: Arc<dyn briefcred_core::keystore::KeyStore>,
    signer: Mutex<Option<Arc<crate::proxy::token::TokenSigner>>>,
    in_flight: InFlight,
    handed_off: Mutex<Option<HandedOff>>,
    handing_over: Arc<std::sync::atomic::AtomicBool>,
    drain: Duration,
    listener_fds: Vec<(crate::handoff::Slot, std::os::fd::RawFd)>,
}

/// Everything [`State::new`] needs, as a struct.
///
/// A struct rather than eleven positional parameters: the daemon's shared
/// state has grown a field per phase, and a call site of eleven `Arc`s is one
/// where two of them get swapped and nothing catches it.
pub struct StateParts {
    /// The audit writer's handle.
    pub audit: AuditHandle,
    /// The metrics registry.
    pub metrics: Arc<Metrics>,
    /// Where the Prometheus endpoint is listening, if it is.
    pub metrics_addr: Option<String>,
    /// Where the HTTP proxy is listening, if it is.
    pub proxy_addr: Option<String>,
    /// Where the Postgres proxy is listening, if it is.
    pub pg_proxy_addr: Option<String>,
    /// The shutdown signal's sending half.
    pub shutdown: tokio::sync::watch::Sender<bool>,
    /// The loaded profiles.
    pub profiles: Arc<ProfileStore>,
    /// The open sessions.
    pub sessions: Arc<SessionStore>,
    /// The presence gate.
    pub unlock: Arc<dyn UnlockGate>,
    /// The per-profile unlock cache.
    pub unlock_cache: UnlockCache,
    /// Where masters come from.
    pub master_source: Arc<dyn MasterSource>,
    /// The on-disk layout, for the trust environment.
    pub paths: Arc<Paths>,
    /// Where helper binaries are looked for.
    pub helper_dirs: Vec<PathBuf>,
    /// The persistent revoke queue.
    pub revokes: Arc<RevokeQueue>,
    /// Whether `ExecStart` rows carry raw arguments as well as digests.
    pub raw_args: bool,
    /// How long a `briefcred_db_query` statement may run.
    pub mcp_query_timeout: Duration,
    /// How long a `briefcred_exec` command may run.
    pub mcp_exec_timeout: Duration,
    /// The HTTP proxy's token authority, when the proxy is enabled.
    pub proxy: Option<Arc<crate::proxy::issuer::ProxyIssuer>>,
    /// Where the token-signer key lives, for signing a handoff blob.
    pub keystore: Arc<dyn briefcred_core::keystore::KeyStore>,
    /// Set while a handoff is under way, to hold the revoke queue off its file.
    ///
    /// Shared with [`crate::revoke::drain_loop`]: the daemon taking over opens
    /// the same queue file, and two processes rewriting it at once could lose
    /// an entry.
    pub handing_over: Arc<std::sync::atomic::AtomicBool>,
    /// How long in-flight proxy work gets to finish after a handoff.
    pub drain: Duration,
    /// The listening descriptors, so a handoff can pass them on.
    ///
    /// Raw descriptors rather than the listeners themselves: the accept loops
    /// own those, and a handoff only ever needs to name them to `sendmsg`. They
    /// stay valid for as long as this daemon is serving, which is exactly as
    /// long as a handoff can happen.
    pub listener_fds: Vec<(crate::handoff::Slot, std::os::fd::RawFd)>,
}

impl State {
    /// Assemble the shared state.
    pub fn new(parts: StateParts) -> State {
        State {
            started_at: OffsetDateTime::now_utc(),
            metrics: parts.metrics,
            audit: parts.audit,
            metrics_addr: parts.metrics_addr,
            proxy_addr: parts.proxy_addr,
            pg_proxy_addr: parts.pg_proxy_addr,
            shutdown: parts.shutdown,
            shutdown_reason: Mutex::new("unknown"),
            profiles: parts.profiles,
            sessions: parts.sessions,
            unlock: parts.unlock,
            unlock_cache: parts.unlock_cache,
            master_source: parts.master_source,
            paths: parts.paths,
            helper_dirs: parts.helper_dirs,
            revokes: parts.revokes,
            raw_args: parts.raw_args,
            mcp_query_timeout: parts.mcp_query_timeout,
            mcp_exec_timeout: parts.mcp_exec_timeout,
            proxy: parts.proxy,
            keystore: parts.keystore,
            signer: Mutex::new(None),
            in_flight: InFlight::default(),
            handed_off: Mutex::new(None),
            handing_over: parts.handing_over,
            drain: parts.drain,
            listener_fds: parts.listener_fds,
        }
    }

    /// The counter every proxy connection and tunnel holds a guard on.
    pub fn in_flight(&self) -> &InFlight {
        &self.in_flight
    }

    /// How long in-flight work gets to finish after a handoff.
    pub fn drain(&self) -> Duration {
        self.drain
    }

    /// The machine's token-signer key.
    ///
    /// Delegated to the proxy's issuer whenever there is one, so a daemon never
    /// holds two `TokenSigner`s: both would call `load_or_create`, and on a
    /// machine with no key yet the second would overwrite the first and every
    /// token the first signed would stop verifying. A daemon with the proxy
    /// switched off has no other reader, so it caches one of its own.
    pub fn token_signer(&self) -> briefcred_core::Result<Arc<crate::proxy::token::TokenSigner>> {
        if let Some(proxy) = &self.proxy {
            return proxy.token_signer();
        }
        let mut cached = self.signer.lock().expect("signer mutex");
        if let Some(signer) = cached.as_ref() {
            return Ok(Arc::clone(signer));
        }
        let signer = Arc::new(crate::proxy::token::TokenSigner::load_or_create(
            self.keystore.as_ref(),
        )?);
        *cached = Some(Arc::clone(&signer));
        Ok(signer)
    }

    /// Claim the right to hand over, or report that somebody already has.
    ///
    /// A compare-exchange rather than a read and a write: two `Handoff`
    /// requests can be accepted on two connections at the same instant, and
    /// two daemons each sending their descriptors to a different successor
    /// would leave four processes disagreeing about who owns the sockets.
    /// Exactly one caller gets `true`.
    pub fn begin_handoff(&self) -> bool {
        self.handing_over
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
    }

    /// Release the claim, for a handoff that did not happen.
    pub fn end_handoff(&self) {
        self.handing_over
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether a handoff is under way, so nothing new may be minted.
    ///
    /// Between the moment the blob is built and the moment this daemon stops
    /// accepting, the IPC listener is still answering. A session opened in that
    /// window is in no blob and will be adopted by nobody, so a credential
    /// minted against it would be one that no daemon has any record of and that
    /// nothing would ever revoke. Refusing is the honest answer: the client
    /// retries against the daemon that is about to own the socket.
    pub fn handing_over(&self) -> bool {
        self.handing_over.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Record that this daemon's listeners and sessions are now another's.
    ///
    /// Two things change once this is set, and both are about not undoing what
    /// the new daemon is relying on: the socket file is left alone rather than
    /// unlinked, and the sessions that *moved* are wiped without being retired
    /// — their mints belong to the daemon still serving them. `moved` names
    /// exactly those, so anything this daemon is still holding that the blob
    /// did not carry is retired normally.
    pub fn handed_off_to(&self, pid: u32, moved: std::collections::BTreeSet<String>) {
        *self.handed_off.lock().expect("handoff mutex") = Some(HandedOff { pid, moved });
    }

    /// The pid this daemon handed everything to, if it did.
    pub fn handed_off(&self) -> Option<u32> {
        self.handed_off
            .lock()
            .expect("handoff mutex")
            .as_ref()
            .map(|handed| handed.pid)
    }

    /// Whether `session_id` was one of the sessions the handoff carried.
    ///
    /// False for a session this daemon never handed anywhere, including one
    /// opened in the window between the blob being built and the listener
    /// closing — which is the case this exists for.
    pub fn was_handed_over(&self, session_id: &str) -> bool {
        self.handed_off
            .lock()
            .expect("handoff mutex")
            .as_ref()
            .is_some_and(|handed| handed.moved.contains(session_id))
    }

    /// The HTTP proxy's token authority, when the proxy is enabled.
    pub fn proxy(&self) -> Option<&Arc<crate::proxy::issuer::ProxyIssuer>> {
        self.proxy.as_ref()
    }

    /// Where the Postgres proxy is listening, when it is enabled.
    ///
    /// A `postgres-proxy` mint needs this to build the `DATABASE_URL` it hands
    /// the subprocess, so a daemon with the proxy switched off cannot serve one
    /// and says so rather than publishing a port nothing answers on.
    pub fn pg_proxy_addr(&self) -> Option<&str> {
        self.pg_proxy_addr.as_deref()
    }

    /// The open sessions.
    pub fn sessions(&self) -> &Arc<SessionStore> {
        &self.sessions
    }

    /// The persistent revoke queue.
    pub fn revokes(&self) -> &Arc<RevokeQueue> {
        &self.revokes
    }

    /// Where helper binaries are looked for.
    pub fn helper_dirs(&self) -> &[PathBuf] {
        &self.helper_dirs
    }

    /// How long a `briefcred_db_query` statement may run.
    pub fn mcp_exec_timeout(&self) -> Duration {
        self.mcp_exec_timeout
    }

    /// How long a `briefcred_db_query` statement may run.
    pub fn mcp_query_timeout(&self) -> Duration {
        self.mcp_query_timeout
    }

    /// The on-disk layout, for the trust environment.
    pub fn paths(&self) -> &Arc<Paths> {
        &self.paths
    }

    /// Where masters come from.
    pub fn master_source(&self) -> &Arc<dyn MasterSource> {
        &self.master_source
    }

    /// A clone of the audit writer's handle, for a background task.
    pub fn audit_handle(&self) -> AuditHandle {
        self.audit.clone()
    }

    /// The metrics registry, for the endpoint and for request counting.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// The loaded profiles.
    pub fn profiles(&self) -> &Arc<ProfileStore> {
        &self.profiles
    }

    /// The per-profile unlock cache, so a reload can invalidate it.
    pub fn unlock_cache(&self) -> &UnlockCache {
        &self.unlock_cache
    }

    /// Queue an audit row.
    ///
    /// Returns before the row reaches the disk. A daemon that stalls on its
    /// own log is worse than one that keeps serving with
    /// `briefcred_audit_write_errors_total` climbing, which is exactly what
    /// that counter is for. Use [`State::audit_flush`] where the row has to be
    /// durable before the next step.
    pub fn audit(&self, entry: &AuditEntry) {
        self.audit.append(entry);
    }

    /// Wait until every row queued so far is on the disk.
    pub async fn audit_flush(&self) {
        self.audit.flush().await;
    }

    /// The audit file rows are currently going to.
    pub async fn audit_path(&self) -> std::path::PathBuf {
        self.audit.path().await
    }

    /// Run the retention sweep, reporting failures without stopping.
    pub fn sweep(&self) {
        self.audit.sweep();
    }

    /// Ask the daemon to stop accepting and drain.
    ///
    /// `reason` is recorded on the `DaemonStop` audit row. The first caller
    /// wins, so a `SIGTERM` arriving during a requested shutdown does not
    /// rewrite history.
    pub fn request_shutdown(&self, reason: &'static str) {
        let mut current = self.shutdown_reason.lock().expect("shutdown mutex");
        if *current == "unknown" {
            *current = reason;
        }
        drop(current);
        // `send_replace`, not `send`: `send` fails and leaves the value alone
        // when no receiver happens to exist yet, which would lose a signal
        // that arrived during startup.
        self.shutdown.send_replace(true);
    }

    /// What asked the daemon to stop.
    pub fn shutdown_reason(&self) -> &'static str {
        *self.shutdown_reason.lock().expect("shutdown mutex")
    }

    /// A receiver that fires when shutdown has been requested.
    pub fn shutdown_signal(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    /// Seconds since the daemon finished starting.
    pub fn uptime_secs(&self) -> u64 {
        self.metrics.uptime_secs()
    }

    /// When the daemon finished starting.
    pub fn started_at(&self) -> OffsetDateTime {
        self.started_at
    }
}

/// Resolve as soon as shutdown has been requested, including when it already
/// has been.
///
/// This is deliberately not `Receiver::changed`. `changed` only reports a
/// change made *after* the receiver was created, so a connection accepted in
/// the same breath as the shutdown request would subscribe to an already-true
/// value and then wait forever, holding the drain open for its whole timeout.
/// `wait_for` inspects the current value first, which is the behaviour every
/// caller here actually wants.
pub async fn shutdown_requested(watcher: &mut tokio::sync::watch::Receiver<bool>) {
    // An error means the sender is gone, which only happens as the daemon is
    // being torn down: treat it as a shutdown too.
    let _ = watcher.wait_for(|requested| *requested).await;
}

/// An identifier for one upgraded connection, for its audit rows.
///
/// Random rather than a counter: a counter restarts with the daemon, and two
/// runs would then produce the same `mcp_call_id` for different work.
fn connection_id() -> String {
    let mut bytes = [0u8; 6];
    getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable");
    format!("mcp-{}", hex::encode(bytes))
}

/// The request-name to handler map.
///
/// A table rather than a `match` so a new request kind is one entry and one
/// function, and so [`dispatch_table`] can be asserted to cover the protocol.
/// It covers [`Request::NAMES`] minus [`Request::UPGRADE_NAMES`]: an upgrade
/// takes the connection over in [`serve_connection`] and can never reach a
/// handler that returns one `Response`.
pub fn dispatch_table() -> HashMap<&'static str, Handler> {
    let mut table: HashMap<&'static str, Handler> = HashMap::new();
    table.insert("ping", handler!(handle_ping));
    table.insert("status", handler!(handle_status));
    table.insert("shutdown", handler!(handle_shutdown));
    table.insert("list_profiles", handler!(handle_list_profiles));
    table.insert("show_profile", handler!(handle_show_profile));
    table.insert("open_session", handler!(handle_open_session));
    table.insert("close_session", handler!(handle_close_session));
    table.insert("unlock", handler!(handle_unlock));
    table.insert("exec", handler!(handle_exec));
    table.insert("exec_done", handler!(handle_exec_done));
    table.insert("hook_check", handler!(handle_hook_check));
    table.insert("handoff", handler!(handle_handoff));
    #[cfg(feature = "debug-heapscan")]
    table.insert("heap_scan", handler!(handle_heap_scan));
    table
}

async fn handle_ping(_request: Request, _state: Arc<State>) -> Response {
    Response::Pong
}

async fn handle_status(_request: Request, state: Arc<State>) -> Response {
    Response::Status {
        version: env!("CARGO_PKG_VERSION").to_string(),
        pid: std::process::id(),
        uptime_secs: state.uptime_secs(),
        started_at: state.started_at(),
        audit_path: state.audit_path().await,
        metrics_addr: state.metrics_addr.clone(),
        proxy_addr: state.proxy_addr.clone(),
        pg_proxy_addr: state.pg_proxy_addr.clone(),
        handing_over: state.handing_over(),
    }
}

async fn handle_shutdown(_request: Request, state: Arc<State>) -> Response {
    state.request_shutdown("request");
    Response::ShuttingDown
}

async fn handle_list_profiles(_request: Request, state: Arc<State>) -> Response {
    Response::Profiles {
        profiles: state
            .profiles
            .list_loaded()
            .await
            .iter()
            .map(summarise)
            .collect(),
    }
}

async fn handle_show_profile(request: Request, state: Arc<State>) -> Response {
    let Request::ShowProfile { name } = request else {
        return mismatched(&request);
    };
    match state.profiles.get_loaded(&name).await {
        Some(loaded) => Response::Profile {
            profile: summarise(&loaded),
        },
        None => Response::Error {
            message: SessionError::NoSuchProfile(name).to_string(),
        },
    }
}

/// Prove presence, then fetch the masters the profile needs.
///
/// The order matters and is the whole point: nothing reaches a keychain until
/// the unlock gate has said yes, so a refused prompt leaves no master in the
/// daemon's memory at all.
async fn handle_open_session(request: Request, state: Arc<State>) -> Response {
    let Request::OpenSession {
        profile: name,
        client_headless,
        session_pubkey,
    } = request
    else {
        return mismatched(&request);
    };
    // Nothing this daemon opens now would reach the blob, and no daemon would
    // ever have a record of what it minted. See `State::handing_over`.
    if state.handing_over() {
        return Response::Error {
            message: HANDING_OFF.to_string(),
        };
    }
    // A key the daemon cannot parse is refused rather than dropped: a client
    // that meant to bind its tokens and silently did not would believe it had
    // a guarantee it does not have.
    let pubkey = match decode_session_pubkey(session_pubkey.as_deref()) {
        Ok(pubkey) => pubkey,
        Err(message) => return Response::Error { message },
    };
    let Some(profile) = state.profiles.get(&name).await else {
        return Response::Error {
            message: SessionError::NoSuchProfile(name).to_string(),
        };
    };

    if let Err(locked) = prove_presence(&state, &profile, client_headless).await {
        return locked;
    }

    match state
        .sessions
        .open(
            &profile,
            state.master_source.as_ref(),
            state.helper_dirs.clone(),
            pubkey,
        )
        .await
    {
        Ok((session_id, expires_at)) => {
            state.audit(&AuditEntry::SessionOpen {
                ts: OffsetDateTime::now_utc(),
                session_id: session_id.clone(),
                profile: name,
                credentials: profile.credentials.len(),
            });
            Response::SessionOpened {
                session_id,
                expires_at,
            }
        }
        Err(err) => Response::Error {
            message: err.to_string(),
        },
    }
}

async fn handle_close_session(request: Request, state: Arc<State>) -> Response {
    let Request::CloseSession { session_id } = request else {
        return mismatched(&request);
    };
    match state.sessions.close(&session_id).await {
        Ok(session) => {
            let profile = session.profile.clone();
            retire(&state, session, "request").await;
            state.audit(&AuditEntry::SessionClose {
                ts: OffsetDateTime::now_utc(),
                session_id: session_id.clone(),
                profile,
                reason: "request".to_string(),
            });
            Response::SessionClosed { session_id }
        }
        Err(err) => Response::Error {
            message: err.to_string(),
        },
    }
}

/// Wind up a session that has been taken out of the store.
///
/// Anything it minted that no `ExecDone` accounted for goes on the revoke
/// queue, and its helper processes are stopped. Both matter: a wrapper that
/// was killed leaves mints behind, and a helper that outlives its session is a
/// process still holding a master.
pub async fn retire(state: &Arc<State>, session: Session, reason: &str) {
    // Every upstream connection the proxy was holding for this session, whether
    // or not it minted anything: a session that has ended will never send on
    // one again, and a connection nothing will use is a socket held open at a
    // vendor. The orphaned mints below revoke their own grants, which covers
    // the same connections a second time; this covers the sessions that had
    // nothing to revoke.
    if let Some(issuer) = state.proxy() {
        issuer.close_session(&session.id);
    }
    let orphaned: Vec<_> = session.mints.values().cloned().collect();
    if !orphaned.is_empty() {
        eprintln!(
            "briefcred-daemon: session {} closed ({reason}) with {} credential(s) still minted; queueing their revokes",
            session.id,
            orphaned.len()
        );
        if let Err(err) = state.revokes.enqueue(orphaned).await {
            eprintln!("briefcred-daemon: cannot queue an orphaned revoke: {err}");
        }
    }
    session.helpers.stop_all().await;
}

/// Let a handed-over session go without revoking anything it minted.
///
/// The mirror of [`retire`], for the one case where the mints are not orphaned:
/// another daemon is now holding this very session and will revoke them when
/// its own client says so. Queueing them here would kill credentials the
/// process that took over is still serving. The helpers are still stopped and
/// the masters are still wiped when `session` is dropped.
pub async fn release(session: Session) {
    session.helpers.stop_all().await;
}

/// Prove presence without opening anything.
async fn handle_unlock(request: Request, state: Arc<State>) -> Response {
    let Request::Unlock {
        profile: name,
        client_headless,
    } = request
    else {
        return mismatched(&request);
    };
    let Some(profile) = state.profiles.get(&name).await else {
        return Response::Error {
            message: SessionError::NoSuchProfile(name).to_string(),
        };
    };
    match prove_presence(&state, &profile, client_headless).await {
        Ok(()) => Response::Unlocked { profile: name },
        Err(locked) => locked,
    }
}

/// The unlock gate, the headless check, and the cache, in that order.
///
/// Factored out of [`handle_open_session`] so `Unlock` cannot drift away from
/// it: two code paths that both decide "may this profile be used now" would be
/// two chances to get the ordering wrong.
pub(crate) async fn prove_presence(
    state: &Arc<State>,
    profile: &briefcred_core::Profile,
    client_headless: bool,
) -> std::result::Result<(), Response> {
    use briefcred_core::profile::UnlockPolicy;

    if profile.unlock.policy != UnlockPolicy::None
        && (client_headless || crate::unlock::is_headless())
    {
        let err = crate::unlock::UnlockError::NoAquaSession;
        state.audit(&AuditEntry::UnlockDenied {
            ts: OffsetDateTime::now_utc(),
            profile: profile.name.clone(),
            policy: policy_name(profile.unlock.policy).to_string(),
            reason: err.reason().to_string(),
        });
        return Err(Response::Locked {
            reason: err.reason().to_string(),
            message: err.to_string(),
        });
    }

    let window = profile.unlock.cache_for();
    if !state.unlock_cache.is_fresh(&profile.name, window).await {
        let reason = format!("briefcred: unlock the `{}` profile", profile.name);
        if let Err(err) = state.unlock.unlock(profile.unlock.policy, &reason).await {
            state.audit(&AuditEntry::UnlockDenied {
                ts: OffsetDateTime::now_utc(),
                profile: profile.name.clone(),
                policy: policy_name(profile.unlock.policy).to_string(),
                reason: err.reason().to_string(),
            });
            return Err(Response::Locked {
                reason: err.reason().to_string(),
                message: err.to_string(),
            });
        }
        state.unlock_cache.record(&profile.name).await;
    }
    Ok(())
}

/// Check the command, mint, and compose the environment.
async fn handle_exec(request: Request, state: Arc<State>) -> Response {
    let Request::Exec {
        session_id,
        credentials,
        argv0,
        args,
        pid,
    } = request
    else {
        return mismatched(&request);
    };

    // Refused for the same reason `open_session` is, and it matters more here:
    // an `exec` accepted in the window creates a principal on a real backend
    // that neither daemon would hold a revoke for.
    if state.handing_over() {
        return Response::Error {
            message: HANDING_OFF.to_string(),
        };
    }

    if let Err(err) = state.sessions.touch(&session_id).await {
        return Response::Error {
            message: err.to_string(),
        };
    }
    let Ok(profile_name) = state
        .sessions
        .with_session(&session_id, |s| s.profile.clone())
        .await
    else {
        return Response::Error {
            message: SessionError::NoSuchSession(session_id).to_string(),
        };
    };
    let Some(profile) = state.profiles.get(&profile_name).await else {
        return Response::Error {
            message: SessionError::NoSuchProfile(profile_name).to_string(),
        };
    };

    // Before anything is minted. A refused command must leave no principal.
    if let Err(denied) = briefcred_core::exec::check_command(&profile, &argv0, &args) {
        return Response::Denied {
            message: denied.to_string(),
        };
    }
    let specs = match crate::exec::select(&profile, credentials.as_deref()) {
        Ok(specs) => specs,
        Err(err) => {
            return Response::Denied {
                message: err.to_string(),
            }
        }
    };

    // Before anything is minted, for the same reason the command check is: a
    // run the quota refuses must leave no principal behind. One token per run
    // rather than per credential, because what is being bounded is how often
    // the profile is used, not how many credentials it happens to declare.
    let quota = state
        .sessions
        .with_session(&session_id, |s| s.quota.clone())
        .await
        .ok()
        .flatten();
    if let Err(refusal) = crate::quota::charge(
        quota.as_deref(),
        &profile.name,
        crate::quota::SURFACE_EXEC,
        state.metrics(),
    ) {
        return Response::Error {
            message: quota_message(&profile.name, refusal),
        };
    }

    // Both taken out of the store before the mint, so the session map is not
    // held locked across a round trip to a database.
    let Ok((masters, helpers)) = state
        .sessions
        .with_session(&session_id, |s| {
            (s.masters.clone(), std::sync::Arc::clone(&s.helpers))
        })
        .await
    else {
        return Response::Error {
            message: SessionError::NoSuchSession(session_id).to_string(),
        };
    };
    let mut trust = briefcred_core::ca::trust_env(&state.paths, &profile);
    // The proxy variables ride in alongside the trust environment because they
    // are the same kind of thing: neither is a credential, both point the
    // subprocess at briefcred, and the profile's own `env` block is applied
    // afterwards so it can override either.
    if let Some(issuer) = state.proxy() {
        if profile.wants_proxy() {
            trust.extend(crate::proxy::proxy_env(issuer.proxy_url()));
        }
    }

    let session_pubkey = state
        .sessions
        .with_session(&session_id, |s| s.pubkey)
        .await
        .ok()
        .flatten();
    let grant = state.proxy().map(|issuer| crate::exec::ProxyGrant {
        issuer,
        session_id: &session_id,
        session_pubkey: session_pubkey.as_ref(),
        pg_proxy_addr: state.pg_proxy_addr(),
    });

    let minted = crate::exec::mint(
        &profile,
        &specs,
        &masters,
        helpers.as_ref(),
        &trust,
        &session_id,
        &argv0,
        &args,
        pid,
        state.raw_args,
        state.metrics(),
        grant,
    )
    .await;

    let minted = match minted {
        Ok(minted) => minted,
        Err(err) => {
            return Response::Error {
                message: err.to_string(),
            }
        }
    };

    // Recorded against the session before the client is told, so a client that
    // dies between the reply and its first instruction still leaves something
    // the session close can revoke.
    if let Err(err) = state
        .sessions
        .record_mints(&session_id, minted.pending.clone())
        .await
    {
        return Response::Error {
            message: err.to_string(),
        };
    }
    for row in &minted.rows {
        state.audit(row);
    }

    Response::Minted {
        mints: minted.mints,
        env: minted.env,
        passthrough: minted.passthrough,
    }
}

/// What a caller whose quota refused the run is told.
///
/// Names the profile and says which of the two limits was hit, because the
/// fixes are different: a rate that is too tight is a `quota.rate` to raise,
/// and a spent `total` is a session to close and reopen.
fn quota_message(profile: &str, refusal: crate::quota::Refusal) -> String {
    match refusal {
        crate::quota::Refusal::Refill { retry_after } => format!(
            "profile `{profile}` is over its quota; try again in {}s",
            retry_after.as_secs()
        ),
        crate::quota::Refusal::Exhausted => format!(
            "profile `{profile}` has spent its session quota (`quota.total`); \
             close the session and open a new one"
        ),
    }
}

/// The child has exited: queue its revokes and close the exec's audit rows.
async fn handle_exec_done(request: Request, state: Arc<State>) -> Response {
    let Request::ExecDone {
        session_id,
        mint_ids,
        exit_code,
        duration_ms,
        hold_until_expiry,
    } = request
    else {
        return mismatched(&request);
    };

    let _ = state.sessions.touch(&session_id).await;
    let parsed: Vec<MintId> = mint_ids.iter().filter_map(|id| id.parse().ok()).collect();
    let mut entries = match state.sessions.take_mints(&session_id, &parsed).await {
        Ok(entries) => entries,
        Err(err) => {
            return Response::Error {
                message: err.to_string(),
            }
        }
    };
    // `briefcred get` printed a value the caller is about to use, so the
    // credential has to outlive the command that fetched it. It is still
    // queued — just scheduled for its own expiry, so it is cleaned up promptly
    // once it stops being useful instead of being left to the reconciler.
    if hold_until_expiry {
        for entry in &mut entries {
            entry.hold_until_expiry();
        }
    }
    let profile = state
        .sessions
        .profile_of(&session_id)
        .await
        .unwrap_or_default();

    state.audit(&AuditEntry::ExecEnd {
        ts: OffsetDateTime::now_utc(),
        session_id: session_id.clone(),
        mint_ids: entries.iter().map(|e| e.mint_id.clone()).collect(),
        profile,
        exit_code,
        duration_ms,
    });

    match state.revokes.enqueue(entries).await {
        Ok(queued) => Response::ExecRecorded { queued },
        Err(err) => Response::Error {
            message: err.to_string(),
        },
    }
}

/// Would this command be allowed? Mints nothing either way.
/// Hand every listener and session to a daemon waiting on `socket`.
///
/// The order is the whole design. Nothing about this daemon changes until the
/// new one has said it is serving, so a handoff that fails at any step leaves a
/// daemon that is still listening, still holding its sessions, and still the
/// only owner of the sockets. Only after the confirmation does this one mark
/// itself handed off and ask for shutdown.
async fn handle_handoff(request: Request, state: Arc<State>) -> Response {
    let Request::Handoff { socket } = request else {
        return mismatched(&request);
    };
    if let Some(pid) = state.handed_off() {
        return Response::Error {
            message: format!("this daemon has already handed over to pid {pid}"),
        };
    }

    // The socket is the successor's address, and every master this daemon holds
    // is about to be sealed and written to it. A caller who could name a path
    // anywhere on the filesystem could name one it had a listener on, so only
    // the directory `Paths::handoff_socket` draws from is accepted.
    if let Err(message) = handoff_socket_is_ours(&state, &socket) {
        return Response::Error { message };
    }

    // Then presence. Exporting is the one operation that moves every resident
    // master at once, and it is reachable by anything running as this user, so
    // it is gated like the sessions it is moving — at the strictest policy any
    // open session asked for, because a handoff that prompted at the weakest
    // would let a `none` session lower the bar for a `biometric` one.
    if let Err(response) = prove_handoff_presence(&state).await {
        return response;
    }

    let signer = match state.token_signer() {
        Ok(signer) => signer,
        Err(err) => return handoff_failed(&state, format!("{err}")),
    };
    // Claimed once. The flag holds the revoke queue off its file, refuses new
    // sessions and mints, and — because it is taken with a compare-exchange —
    // is also what makes a second concurrent `Handoff` a refusal rather than a
    // second successor. It is released again below if the handoff fails.
    if !state.begin_handoff() {
        return Response::Error {
            message: "a handoff is already in progress on this daemon".to_string(),
        };
    }

    let moved: Arc<Mutex<std::collections::BTreeSet<String>>> = Arc::default();
    let build_state = Arc::clone(&state);
    let build_moved = Arc::clone(&moved);
    let handed = crate::handoff::hand_over(
        std::path::Path::new(&socket),
        &signer,
        async |sealer: &crate::handoff::Sealer| {
            let sessions = build_state.sessions().export(sealer).await?;
            *build_moved.lock().expect("moved mutex") =
                sessions.iter().map(|s| s.id.clone()).collect();
            Ok(crate::handoff::Outgoing {
                sessions,
                revocations: build_state
                    .proxy()
                    .map(|proxy| proxy.export_revocations())
                    .unwrap_or_default()
                    .into_iter()
                    .map(
                        |(session_id, credential, expires_at)| crate::handoff::RevocationBlob {
                            session_id,
                            credential,
                            expires_at,
                        },
                    )
                    .collect(),
                listeners: build_state.listener_fds.clone(),
            })
        },
    )
    .await;

    let to_pid = match handed {
        Ok(pid) => pid,
        Err(err) => return handoff_failed(&state, err.to_string()),
    };

    let moved = moved.lock().expect("moved mutex").clone();
    let sessions = moved.len();
    state.metrics().record_handoff("handed_over");
    state.audit(&AuditEntry::DaemonHandoff {
        ts: OffsetDateTime::now_utc(),
        from_pid: std::process::id(),
        to_pid: Some(to_pid),
        sessions,
        outcome: "handed_over".to_string(),
    });
    state.handed_off_to(to_pid, moved);
    eprintln!("briefcred-daemon: handed {sessions} session(s) to pid {to_pid}; draining");
    state.request_shutdown("handoff");
    Response::HandoffComplete { to_pid, sessions }
}

/// Refuse a handoff socket that is not one this daemon would ever have named.
///
/// The path is compared after resolving the directory it sits in, so a
/// `../../tmp/x.sock` or a symlinked parent cannot dress itself up as a state
/// directory. The file itself is not resolved: it does not exist yet from this
/// daemon's point of view, and a successor's socket that *was* a symlink is
/// exactly what this is refusing.
fn handoff_socket_is_ours(state: &Arc<State>, socket: &str) -> std::result::Result<(), String> {
    let path = std::path::Path::new(socket);
    let refuse = || {
        format!(
            "a handoff socket must be a file directly under {}; `{socket}` is not",
            state.paths().state_dir().display()
        )
    };
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(refuse());
    };
    if name.as_encoded_bytes().is_empty() {
        return Err(refuse());
    }
    let state_dir = state
        .paths()
        .state_dir()
        .canonicalize()
        .map_err(|e| format!("cannot resolve the state directory: {e}"))?;
    let parent = parent.canonicalize().map_err(|_| refuse())?;
    if parent != state_dir {
        return Err(refuse());
    }
    Ok(())
}

/// Prove presence for a handoff, at the strictest policy any session asked for.
///
/// `biometric` beats `passcode` beats `none`, and a daemon with no open
/// sessions has nothing to protect, so it prompts for nothing. The unlock cache
/// is deliberately not consulted: a cached unlock was granted for one profile's
/// own use, and moving every master in the daemon to another process is not
/// that use.
async fn prove_handoff_presence(state: &Arc<State>) -> std::result::Result<(), Response> {
    use briefcred_core::profile::UnlockPolicy;

    let rank = |policy: UnlockPolicy| match policy {
        UnlockPolicy::None => 0,
        UnlockPolicy::Passcode => 1,
        UnlockPolicy::Biometric => 2,
    };

    let mut strictest = UnlockPolicy::None;
    for (_, profile_name) in state.sessions().open_sessions().await {
        if let Some(profile) = state.profiles().get(&profile_name).await {
            if rank(profile.unlock.policy) > rank(strictest) {
                strictest = profile.unlock.policy;
            }
        }
    }
    if strictest == UnlockPolicy::None {
        return Ok(());
    }

    if crate::unlock::is_headless() {
        let err = crate::unlock::UnlockError::NoAquaSession;
        state.audit(&AuditEntry::UnlockDenied {
            ts: OffsetDateTime::now_utc(),
            profile: HANDOFF_UNLOCK_PROFILE.to_string(),
            policy: policy_name(strictest).to_string(),
            reason: err.reason().to_string(),
        });
        return Err(Response::Locked {
            reason: err.reason().to_string(),
            message: err.to_string(),
        });
    }

    if let Err(err) = state.unlock.unlock(strictest, HANDOFF_UNLOCK_REASON).await {
        state.audit(&AuditEntry::UnlockDenied {
            ts: OffsetDateTime::now_utc(),
            profile: HANDOFF_UNLOCK_PROFILE.to_string(),
            policy: policy_name(strictest).to_string(),
            reason: err.reason().to_string(),
        });
        return Err(Response::Locked {
            reason: err.reason().to_string(),
            message: err.to_string(),
        });
    }
    Ok(())
}

/// What the prompt says when a handoff asks for presence.
const HANDOFF_UNLOCK_REASON: &str = "daemon upgrade";

/// The `profile` an `UnlockDenied` row carries for a handoff.
///
/// A handoff is not for one profile — it moves every session at once — so the
/// row names the operation instead. The leading `@` cannot collide with a
/// profile name, which are file stems.
const HANDOFF_UNLOCK_PROFILE: &str = "@handoff";

/// Record a handoff that did not happen, and say so without stopping.
///
/// The daemon keeps running: it still owns the sockets, and an upgrade that
/// could not be completed must leave the machine working rather than empty.
fn handoff_failed(state: &Arc<State>, message: String) -> Response {
    state.end_handoff();
    state.metrics().record_handoff("failed");
    state.audit(&AuditEntry::DaemonHandoff {
        ts: OffsetDateTime::now_utc(),
        from_pid: std::process::id(),
        to_pid: None,
        sessions: 0,
        outcome: "failed".to_string(),
    });
    eprintln!("briefcred-daemon: the handoff failed, so this daemon keeps running: {message}");
    Response::Error { message }
}

async fn handle_hook_check(request: Request, state: Arc<State>) -> Response {
    let Request::HookCheck {
        profile: name,
        argv0,
        args,
    } = request
    else {
        return mismatched(&request);
    };
    let Some(profile) = state.profiles.get(&name).await else {
        // An unknown profile is a denial with a reason rather than an error:
        // the hook has to turn every answer into a decision, and "briefcred
        // does not know that profile" is a perfectly good reason to say no.
        return Response::HookDecision {
            allowed: false,
            reason: SessionError::NoSuchProfile(name).to_string(),
        };
    };
    match briefcred_core::exec::check_command(&profile, &argv0, &args) {
        Ok(()) => Response::HookDecision {
            allowed: true,
            reason: format!("profile `{}` permits `{argv0}`", profile.name),
        },
        Err(denied) => Response::HookDecision {
            allowed: false,
            reason: denied.to_string(),
        },
    }
}

/// Debug-only self-scan. See [`crate::heapscan`].
#[cfg(feature = "debug-heapscan")]
async fn handle_heap_scan(request: Request, _state: Arc<State>) -> Response {
    let Request::HeapScan { needle_sha256 } = request else {
        return mismatched(&request);
    };
    // On a blocking thread: the scan hashes tens of millions of windows and
    // would otherwise park an async worker for the whole of it.
    let found = tokio::task::spawn_blocking(move || crate::heapscan::scan_self(&needle_sha256))
        .await
        .unwrap_or(crate::heapscan::ScanResult {
            present: false,
            regions_scanned: 0,
            bytes_scanned: 0,
        });
    Response::HeapScanned {
        present: found.present,
        regions_scanned: found.regions_scanned,
        bytes_scanned: found.bytes_scanned,
    }
}

/// Decode the base64 session public key a client offered.
///
/// `Ok(None)` is a client that offered none, which is normal. `Err` is one that
/// offered something that is not a 32-byte Ed25519 key.
fn decode_session_pubkey(encoded: Option<&str>) -> std::result::Result<Option<[u8; 32]>, String> {
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    let raw = <base64::engine::general_purpose::GeneralPurpose as base64::Engine>::decode(
        &base64::engine::general_purpose::STANDARD,
        encoded,
    )
    .map_err(|_| "`session_pubkey` is not base64".to_string())?;
    let key: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
        format!(
            "`session_pubkey` is {} bytes; an Ed25519 public key is 32",
            raw.len()
        )
    })?;
    Ok(Some(key))
}

/// Reduce a loaded profile to the shape a client is allowed to see.
///
/// Provenance travels with it: where the profile came from, what its signature
/// was worth, and what it shadows. A client deciding whether to run a profile
/// is asking who chose its allowlist, and that is the answer.
fn summarise(loaded: &LoadedProfile) -> ProfileSummary {
    let profile = &loaded.profile;
    ProfileSummary {
        name: profile.name.clone(),
        description: profile.description.clone(),
        unlock_policy: policy_name(profile.unlock.policy).to_string(),
        unlock_cache_secs: profile.unlock.cache_secs,
        source: loaded.source.to_string(),
        signature: loaded.signature.to_string(),
        signer_key_id: loaded.signer_key_id.clone(),
        overrides: loaded.overrides.clone(),
        path: loaded.path.clone(),
        credentials: profile
            .credentials
            .iter()
            .map(|spec| CredentialSummary {
                name: spec.name.clone(),
                kind: spec.kind.clone(),
                ttl_secs: spec.ttl_secs,
                source_key: spec.source_key().to_string(),
            })
            .collect(),
    }
}

/// The wire name of an unlock policy, matching the profile schema's spelling.
fn policy_name(policy: briefcred_core::profile::UnlockPolicy) -> &'static str {
    use briefcred_core::profile::UnlockPolicy;
    match policy {
        UnlockPolicy::Biometric => "biometric",
        UnlockPolicy::Passcode => "passcode",
        UnlockPolicy::None => "none",
    }
}

/// A handler was reached by a request of another kind.
///
/// Unreachable while [`dispatch_table`] is keyed on [`Request::name`], and kept
/// as an error rather than a panic so a future table edit is a bad reply rather
/// than a dead daemon.
fn mismatched(request: &Request) -> Response {
    Response::Error {
        message: format!(
            "internal error: `{}` reached the wrong handler",
            request.name()
        ),
    }
}

/// Bind the listener, clearing a socket a dead daemon left behind.
///
/// A socket file that still has a live peer means another daemon owns this
/// home, which is an error rather than something to stomp on.
pub fn bind(sock: &Path) -> Result<UnixListener> {
    let parent = sock.parent().ok_or_else(|| {
        Error::io(
            "find the parent of",
            sock,
            std::io::ErrorKind::NotFound.into(),
        )
    })?;
    briefcred_core::paths::ensure_private_dir(parent)?;

    if std::fs::symlink_metadata(sock).is_ok() {
        match std::os::unix::net::UnixStream::connect(sock) {
            Ok(_) => return Err(Error::AlreadyRunning(sock.to_path_buf())),
            Err(_) => std::fs::remove_file(sock)
                .map_err(|e| Error::io("remove the stale socket", sock, e))?,
        }
    }

    let listener = UnixListener::bind(sock).map_err(|e| Error::io("bind", sock, e))?;
    std::fs::set_permissions(
        sock,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .map_err(|e| Error::io("set the mode of", sock, e))?;
    Ok(listener)
}

/// Accept and serve connections until shutdown is requested, then drain.
pub async fn serve(listener: UnixListener, state: Arc<State>) {
    let table = Arc::new(dispatch_table());
    let mut shutdown = state.shutdown_signal();
    // Every connection task holds a clone. When the last one drops, the
    // receiver below returns `None`, which is how the drain knows it is done.
    let (in_flight, mut drained) = tokio::sync::mpsc::channel::<()>(1);

    loop {
        let stream = tokio::select! {
            biased;
            _ = shutdown_requested(&mut shutdown) => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(err) => {
                    eprintln!("briefcred-daemon: accept failed: {err}");
                    continue;
                }
            },
        };

        let state = Arc::clone(&state);
        let table = Arc::clone(&table);
        let guard = in_flight.clone();
        let closing = state.shutdown_signal();
        tokio::spawn(async move {
            serve_connection(stream, state, table, closing).await;
            drop(guard);
        });
    }

    // Stop accepting: dropping the listener unlinks nothing, but it does close
    // the fd so no further connection is established while we drain.
    drop(listener);
    drop(in_flight);
    if tokio::time::timeout(DRAIN_TIMEOUT, drained.recv())
        .await
        .is_err()
    {
        eprintln!(
            "briefcred-daemon: {} s drain timeout expired with connections still open",
            DRAIN_TIMEOUT.as_secs()
        );
    }
}

async fn serve_connection(
    mut stream: UnixStream,
    state: Arc<State>,
    table: Arc<HashMap<&'static str, Handler>>,
    mut closing: tokio::sync::watch::Receiver<bool>,
) {
    let expected_uid = own_uid();
    match stream.peer_cred() {
        Ok(cred) if cred.uid() == expected_uid => {}
        Ok(cred) => {
            state.audit(&AuditEntry::AuthReject {
                ts: OffsetDateTime::now_utc(),
                peer_uid: cred.uid(),
                expected_uid,
            });
            return;
        }
        Err(err) => {
            eprintln!("briefcred-daemon: cannot read peer credentials: {err}");
            return;
        }
    }

    loop {
        // Once shutdown is under way there is nothing more to serve, so an
        // idle connection must not hold the drain open for its full timeout.
        // A client that has just been answered `ShuttingDown` is exactly this
        // case, so without the select the common path always waits five
        // seconds.
        let next = tokio::select! {
            biased;
            _ = shutdown_requested(&mut closing) => return,
            next = read_frame(&mut stream) => next,
        };

        let request: Request = match next {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(err) => {
                eprintln!("briefcred-daemon: dropping connection: {err}");
                return;
            }
        };

        let name = request.name();
        state.metrics().record_request(name);

        // An upgrade is answered once and then owns the connection: the
        // dispatch table's handlers return a `Response` and have no way to
        // reach the stream, which is exactly the shape a protocol that is not
        // request/response cannot fit into.
        if request.is_upgrade() {
            let ready = Response::McpReady {
                version: env!("CARGO_PKG_VERSION").to_string(),
            };
            if let Err(err) = write_frame(&mut stream, &ready).await {
                eprintln!("briefcred-daemon: cannot acknowledge an upgrade: {err}");
                return;
            }
            crate::mcp::serve(stream, state, connection_id()).await;
            return;
        }

        // The table is asserted to cover `Request::NAMES`, so the `None` arm
        // is unreachable in a build whose tests pass. It stays because a
        // daemon that answers "I do not know that request" is better than one
        // that panics a connection task.
        let response = match table.get(name) {
            Some(handler) => handler(request, Arc::clone(&state)).await,
            None => Response::Error {
                message: format!("no handler for request `{name}`"),
            },
        };

        if let Err(err) = write_frame(&mut stream, &response).await {
            eprintln!("briefcred-daemon: cannot reply: {err}");
            return;
        }
    }
}

/// The uid this process is running as, and the only one it serves.
#[allow(unsafe_code)]
fn own_uid() -> u32 {
    // SAFETY: `getuid` takes no arguments, touches no memory, and is
    // documented as always succeeding.
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_state;
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn only_the_first_caller_claims_a_handoff() {
        let (_home, state, _prompts) = test_state(GUARDED).await;

        assert!(state.begin_handoff(), "the first caller claims it");
        assert!(!state.begin_handoff(), "the second is refused");
        assert!(state.handing_over());

        // A handoff that failed releases the claim, so a retry can be made
        // against a daemon that is still perfectly capable of handing over.
        state.end_handoff();
        assert!(!state.handing_over());
        assert!(state.begin_handoff());
    }

    #[tokio::test]
    async fn a_handoff_refuses_new_sessions_and_new_mints() {
        let (_home, state, _prompts) = test_state("name: dev\nunlock:\n  policy: none\n").await;

        let opened = handle_open_session(
            Request::OpenSession {
                profile: "dev".into(),
                client_headless: true,
                session_pubkey: None,
            },
            Arc::clone(&state),
        )
        .await;
        let Response::SessionOpened { session_id, .. } = opened else {
            panic!("the session should have opened: {opened:?}");
        };

        assert!(state.begin_handoff());

        // Nothing opened now would reach the blob, so it is refused rather
        // than handed masters no daemon will account for.
        let refused = handle_open_session(
            Request::OpenSession {
                profile: "dev".into(),
                client_headless: true,
                session_pubkey: None,
            },
            Arc::clone(&state),
        )
        .await;
        assert!(
            matches!(&refused, Response::Error { message } if message.contains("handing off")),
            "{refused:?}"
        );

        // And an `exec` against the session that *is* in the blob is refused
        // too: the mint would happen on this daemon and be recorded on neither.
        let refused = handle_exec(
            Request::Exec {
                session_id,
                credentials: None,
                argv0: "curl".into(),
                args: Vec::new(),
                pid: 1,
            },
            Arc::clone(&state),
        )
        .await;
        assert!(
            matches!(&refused, Response::Error { message } if message.contains("handing off")),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn only_the_sessions_the_blob_carried_count_as_handed_over() {
        // The discrimination the shutdown path turns into "release" or
        // "retire". A session the handoff did not carry was adopted by nobody,
        // so its mints are orphaned exactly as on an ordinary shutdown.
        let (_home, state, _prompts) = test_state(GUARDED).await;
        assert!(!state.was_handed_over("moved"), "before any handoff");

        state.handed_off_to(99, std::collections::BTreeSet::from(["moved".to_string()]));
        assert_eq!(state.handed_off(), Some(99));
        assert!(state.was_handed_over("moved"));
        assert!(
            !state.was_handed_over("opened-in-the-window"),
            "a session the blob never carried was not handed anywhere"
        );
    }

    #[tokio::test]
    async fn a_handoff_prompts_once_at_the_strictest_policy_any_session_holds() {
        let (_home, state, prompts) = test_state(GUARDED).await;

        // No sessions: there is nothing resident to protect, so nobody is asked.
        prove_handoff_presence(&state)
            .await
            .expect("an empty daemon hands over without a prompt");
        assert_eq!(prompts.load(Ordering::SeqCst), 0);

        let opened = handle_open_session(
            Request::OpenSession {
                profile: "dev".into(),
                client_headless: false,
                session_pubkey: None,
            },
            Arc::clone(&state),
        )
        .await;
        assert!(
            matches!(opened, Response::SessionOpened { .. }),
            "{opened:?}"
        );
        let after_open = prompts.load(Ordering::SeqCst);

        // One session, and its profile is guarded: exactly one prompt, and it
        // is not served by the unlock the session itself already paid for.
        prove_handoff_presence(&state)
            .await
            .expect("the gate answers yes in this test");
        assert_eq!(
            prompts.load(Ordering::SeqCst),
            after_open + 1,
            "a handoff asks for presence itself rather than riding the cache"
        );
    }

    #[tokio::test]
    async fn a_handoff_socket_outside_the_state_directory_is_refused() {
        let (home, state, _prompts) = test_state(GUARDED).await;
        let state_dir = state.paths().state_dir();
        std::fs::create_dir_all(&state_dir).unwrap();

        let ours = state.paths().handoff_socket();
        handoff_socket_is_ours(&state, &ours.display().to_string())
            .expect("the path this daemon would name itself");

        for outside in [
            home.path().join("elsewhere.sock"),
            state_dir.join("nested").join("x.sock"),
            std::path::PathBuf::from("/tmp/briefcred-handoff.sock"),
            state_dir.join("..").join("evil.sock"),
        ] {
            assert!(
                handoff_socket_is_ours(&state, &outside.display().to_string()).is_err(),
                "{} must not be accepted as a handoff socket",
                outside.display()
            );
        }
    }

    const GUARDED: &str = "name: dev\ncredentials:\n  - name: db\n    kind: postgres-dynamic\n    config:\n      host: 127.0.0.1\n      dbname: app\n      user: m\n      sslmode: disable\n      role_template: {}\n";

    #[tokio::test]
    async fn a_headless_client_is_refused_without_the_gate_being_asked() {
        let (_home, state, prompts) = test_state(GUARDED).await;

        let response = handle_open_session(
            Request::OpenSession {
                profile: "dev".into(),
                client_headless: true,
                session_pubkey: None,
            },
            Arc::clone(&state),
        )
        .await;

        assert!(
            matches!(&response, Response::Locked { reason, .. } if reason == "no_aqua_session"),
            "{response:?}"
        );
        assert_eq!(
            prompts.load(Ordering::SeqCst),
            0,
            "the gate must not be consulted for a client with no screen"
        );
        assert!(state.sessions.is_empty().await, "nothing may be opened");
    }

    #[tokio::test]
    async fn a_warm_cache_does_not_rescue_a_headless_client() {
        let (_home, state, prompts) = test_state(GUARDED).await;

        // A local caller opens a session, warming the cache.
        let first = handle_open_session(
            Request::OpenSession {
                profile: "dev".into(),
                client_headless: false,
                session_pubkey: None,
            },
            Arc::clone(&state),
        )
        .await;
        assert!(matches!(first, Response::SessionOpened { .. }), "{first:?}");
        assert_eq!(prompts.load(Ordering::SeqCst), 1);

        // A headless caller must still be refused, even though the cache is
        // warm. The cache records that somebody was once at a screen; it says
        // nothing about whether this caller has one.
        let second = handle_open_session(
            Request::OpenSession {
                profile: "dev".into(),
                client_headless: true,
                session_pubkey: None,
            },
            Arc::clone(&state),
        )
        .await;
        assert!(
            matches!(&second, Response::Locked { reason, .. } if reason == "no_aqua_session"),
            "{second:?}"
        );
        assert_eq!(state.sessions.len().await, 1, "only the first may exist");
    }

    #[tokio::test]
    async fn an_unattended_profile_opens_for_a_headless_client_without_a_prompt() {
        let (_home, state, prompts) = test_state("name: dev\nunlock:\n  policy: none\n").await;

        let response = handle_open_session(
            Request::OpenSession {
                profile: "dev".into(),
                client_headless: true,
                session_pubkey: None,
            },
            Arc::clone(&state),
        )
        .await;

        assert!(
            matches!(response, Response::SessionOpened { .. }),
            "{response:?}"
        );
        assert_eq!(prompts.load(Ordering::SeqCst), 0, "`none` prompts nobody");
    }

    #[tokio::test]
    async fn an_exec_over_the_session_quota_is_refused_by_name() {
        // A profile with no credentials, so the run reaches the quota and
        // nothing else: `burst: 1` means the second `exec` has no token.
        let (_home, state, _) =
            test_state("name: dev\nunlock:\n  policy: none\nquota:\n  rate: 0.1\n  burst: 1\n")
                .await;
        let Response::SessionOpened { session_id, .. } = handle_open_session(
            Request::OpenSession {
                profile: "dev".into(),
                client_headless: true,
                session_pubkey: None,
            },
            Arc::clone(&state),
        )
        .await
        else {
            panic!("the session must open");
        };

        let exec = |state: Arc<State>, session_id: String| async move {
            handle_exec(
                Request::Exec {
                    session_id,
                    credentials: None,
                    argv0: "true".into(),
                    args: Vec::new(),
                    pid: std::process::id(),
                },
                state,
            )
            .await
        };

        let first = exec(Arc::clone(&state), session_id.clone()).await;
        assert!(matches!(first, Response::Minted { .. }), "{first:?}");

        let second = exec(Arc::clone(&state), session_id).await;
        let Response::Error { message } = second else {
            panic!("the second exec must be refused: {second:?}");
        };
        assert!(message.contains("quota"), "{message}");
        assert!(message.contains("dev"), "{message}");
    }

    #[test]
    fn a_quota_refusal_names_the_profile_and_the_way_out_of_it() {
        let refill = crate::quota::Refusal::Refill {
            retry_after: Duration::from_secs(12),
        };
        let message = quota_message("openai", refill);
        assert!(message.contains("openai"), "{message}");
        assert!(message.contains("12s"), "{message}");

        // A spent `total` must not tell anybody to wait: no wait would help.
        let spent = quota_message("openai", crate::quota::Refusal::Exhausted);
        assert!(spent.contains("quota.total"), "{spent}");
        assert!(spent.contains("new one"), "{spent}");
        assert!(!spent.contains("try again in"), "{spent}");
    }

    #[test]
    fn the_table_covers_every_request_the_protocol_defines() {
        let table = dispatch_table();
        for name in Request::NAMES {
            if Request::UPGRADE_NAMES.contains(name) {
                assert!(
                    !table.contains_key(name),
                    "`{name}` takes the connection over; a handler for it could never run"
                );
                continue;
            }
            assert!(table.contains_key(name), "no handler for `{name}`");
        }
        assert_eq!(
            table.len(),
            Request::NAMES.len() - Request::UPGRADE_NAMES.len(),
            "the table has handlers the protocol does not define"
        );
    }

    #[test]
    fn a_connection_id_is_unique_per_connection() {
        let ids: std::collections::BTreeSet<_> = (0..128).map(|_| connection_id()).collect();
        assert_eq!(ids.len(), 128);
        assert!(ids.iter().all(|id| id.starts_with("mcp-")));
    }

    #[tokio::test]
    async fn a_watcher_created_after_the_request_still_sees_the_shutdown() {
        let (tx, _) = tokio::sync::watch::channel(false);
        tx.send_replace(true);
        // Subscribing now records `true` as already seen, so `changed()` would
        // never fire. This is the connection that is accepted in the same
        // breath as the shutdown request, and before the fix it sat in
        // `read_frame` until the drain timed out.
        let mut late = tx.subscribe();

        tokio::time::timeout(Duration::from_secs(5), shutdown_requested(&mut late))
            .await
            .expect("a watcher created after the request must resolve at once");
    }

    #[tokio::test]
    async fn a_watcher_created_before_the_request_waits_for_it() {
        let (tx, _) = tokio::sync::watch::channel(false);
        let mut early = tx.subscribe();

        assert!(
            tokio::time::timeout(Duration::from_millis(50), shutdown_requested(&mut early))
                .await
                .is_err(),
            "nothing has asked for shutdown yet"
        );

        tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), shutdown_requested(&mut early))
            .await
            .expect("the request must wake the watcher");
    }

    #[tokio::test]
    async fn a_dropped_sender_counts_as_a_shutdown() {
        let (tx, _) = tokio::sync::watch::channel(false);
        let mut watcher = tx.subscribe();
        drop(tx);

        tokio::time::timeout(Duration::from_secs(5), shutdown_requested(&mut watcher))
            .await
            .expect("a gone sender means the daemon is going away");
    }

    #[test]
    fn every_variant_reaches_a_handler_through_its_own_name() {
        let table = dispatch_table();
        for request in [Request::Ping, Request::Status, Request::Shutdown] {
            assert!(table.contains_key(request.name()), "{request:?}");
        }
    }
}
