//! The IPC listener, the dispatch table, and graceful shutdown.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use briefcred_core::audit::AuditEntry;
use briefcred_core::MasterSource;
use briefcred_proto::{
    read_frame, write_frame, CredentialSummary, ProfileSummary, Request, Response,
};
use time::OffsetDateTime;
use tokio::net::{UnixListener, UnixStream};

use crate::audit::AuditLog;
use crate::error::{Error, Result};
use crate::metrics::Metrics;
use crate::profiles::ProfileStore;
use crate::session::{SessionError, SessionStore};
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

/// Everything a handler needs, shared across every connection.
#[derive(Debug)]
pub struct State {
    started_at: OffsetDateTime,
    metrics: Arc<Metrics>,
    audit: Mutex<AuditLog>,
    metrics_addr: Option<String>,
    shutdown: tokio::sync::watch::Sender<bool>,
    shutdown_reason: Mutex<&'static str>,
    profiles: Arc<ProfileStore>,
    sessions: Arc<SessionStore>,
    unlock: Arc<dyn UnlockGate>,
    unlock_cache: UnlockCache,
    master_source: Arc<dyn MasterSource>,
}

impl State {
    /// Assemble the shared state. Takes ownership of the audit log.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        audit: AuditLog,
        metrics: Arc<Metrics>,
        metrics_addr: Option<String>,
        shutdown: tokio::sync::watch::Sender<bool>,
        profiles: Arc<ProfileStore>,
        sessions: Arc<SessionStore>,
        unlock: Arc<dyn UnlockGate>,
        unlock_cache: UnlockCache,
        master_source: Arc<dyn MasterSource>,
    ) -> State {
        State {
            started_at: OffsetDateTime::now_utc(),
            metrics,
            audit: Mutex::new(audit),
            metrics_addr,
            shutdown,
            shutdown_reason: Mutex::new("unknown"),
            profiles,
            sessions,
            unlock,
            unlock_cache,
            master_source,
        }
    }

    /// The metrics registry, for the endpoint and for request counting.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// The loaded profiles.
    pub fn profiles(&self) -> &Arc<ProfileStore> {
        &self.profiles
    }

    /// The open sessions.
    pub fn sessions(&self) -> &Arc<SessionStore> {
        &self.sessions
    }

    /// The per-profile unlock cache, so a reload can invalidate it.
    pub fn unlock_cache(&self) -> &UnlockCache {
        &self.unlock_cache
    }

    /// Append an audit row, counting rather than propagating a failure.
    ///
    /// A daemon that dies because it could not write its log is worse than one
    /// that keeps serving with `briefcred_audit_write_errors_total` climbing,
    /// which is exactly what that counter is for.
    pub fn audit(&self, entry: &AuditEntry) {
        let mut log = self.audit.lock().expect("audit mutex");
        if let Err(err) = log.append(entry) {
            eprintln!("briefcred-daemon: audit write failed: {err}");
        }
    }

    /// The audit file rows are currently going to.
    pub fn audit_path(&self) -> std::path::PathBuf {
        self.audit.lock().expect("audit mutex").current_path()
    }

    /// Run the retention sweep, reporting failures without stopping.
    pub fn sweep(&self) {
        let log = self.audit.lock().expect("audit mutex");
        if let Err(err) = log.sweep() {
            eprintln!("briefcred-daemon: audit retention sweep failed: {err}");
        }
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

/// The request-name to handler map.
///
/// A table rather than a `match` so a new request kind is one entry and one
/// function, and so [`dispatch_table`] can be asserted to cover the protocol.
pub fn dispatch_table() -> HashMap<&'static str, Handler> {
    let mut table: HashMap<&'static str, Handler> = HashMap::new();
    table.insert("ping", handler!(handle_ping));
    table.insert("status", handler!(handle_status));
    table.insert("shutdown", handler!(handle_shutdown));
    table.insert("list_profiles", handler!(handle_list_profiles));
    table.insert("show_profile", handler!(handle_show_profile));
    table.insert("open_session", handler!(handle_open_session));
    table.insert("close_session", handler!(handle_close_session));
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
        audit_path: state.audit_path(),
        metrics_addr: state.metrics_addr.clone(),
    }
}

async fn handle_shutdown(_request: Request, state: Arc<State>) -> Response {
    state.request_shutdown("request");
    Response::ShuttingDown
}

async fn handle_list_profiles(_request: Request, state: Arc<State>) -> Response {
    Response::Profiles {
        profiles: state.profiles.list().await.iter().map(summarise).collect(),
    }
}

async fn handle_show_profile(request: Request, state: Arc<State>) -> Response {
    let Request::ShowProfile { name } = request else {
        return mismatched(&request);
    };
    match state.profiles.get(&name).await {
        Some(profile) => Response::Profile {
            profile: summarise(&profile),
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
    let Request::OpenSession { profile: name } = request else {
        return mismatched(&request);
    };
    let Some(profile) = state.profiles.get(&name).await else {
        return Response::Error {
            message: SessionError::NoSuchProfile(name).to_string(),
        };
    };

    let window = profile.unlock.cache_for();
    if !state.unlock_cache.is_fresh(&name, window).await {
        let reason = format!("briefcred: unlock the `{name}` profile");
        if let Err(err) = state.unlock.unlock(profile.unlock.policy, &reason).await {
            state.audit(&AuditEntry::UnlockDenied {
                ts: OffsetDateTime::now_utc(),
                profile: name,
                policy: policy_name(profile.unlock.policy).to_string(),
                reason: err.reason().to_string(),
            });
            return Response::Locked {
                reason: err.reason().to_string(),
                message: err.to_string(),
            };
        }
        state.unlock_cache.record(&name).await;
    }

    match state
        .sessions
        .open(&profile, state.master_source.as_ref())
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
        Ok(profile) => {
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

/// Reduce a loaded profile to the shape a client is allowed to see.
fn summarise(profile: &briefcred_core::Profile) -> ProfileSummary {
    ProfileSummary {
        name: profile.name.clone(),
        description: profile.description.clone(),
        unlock_policy: policy_name(profile.unlock.policy).to_string(),
        unlock_cache_secs: profile.unlock.cache_secs,
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

    #[test]
    fn the_table_covers_every_request_the_protocol_defines() {
        let table = dispatch_table();
        for name in Request::NAMES {
            assert!(table.contains_key(name), "no handler for `{name}`");
        }
        assert_eq!(
            table.len(),
            Request::NAMES.len(),
            "the table has handlers the protocol does not define"
        );
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
