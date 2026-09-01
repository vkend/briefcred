//! The IPC listener, the dispatch table, and graceful shutdown.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use briefcred_core::audit::AuditEntry;
use briefcred_proto::{read_frame, write_frame, Request, Response};
use time::OffsetDateTime;
use tokio::net::{UnixListener, UnixStream};

use crate::audit::AuditLog;
use crate::error::{Error, Result};
use crate::metrics::Metrics;

/// How long in-flight connections get to finish once shutdown begins.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// One request handler.
///
/// Handlers are synchronous because every Phase 1 request is a memory read or
/// a single appended audit row. When a handler needs to do real work, this
/// becomes a boxed future and the table keeps its shape.
pub type Handler = fn(&State) -> Response;

/// Everything a handler needs, shared across every connection.
#[derive(Debug)]
pub struct State {
    started_at: OffsetDateTime,
    metrics: Arc<Metrics>,
    audit: Mutex<AuditLog>,
    metrics_addr: Option<String>,
    shutdown: tokio::sync::watch::Sender<bool>,
    shutdown_reason: Mutex<&'static str>,
}

impl State {
    /// Assemble the shared state. Takes ownership of the audit log.
    pub fn new(
        audit: AuditLog,
        metrics: Arc<Metrics>,
        metrics_addr: Option<String>,
        shutdown: tokio::sync::watch::Sender<bool>,
    ) -> State {
        State {
            started_at: OffsetDateTime::now_utc(),
            metrics,
            audit: Mutex::new(audit),
            metrics_addr,
            shutdown,
            shutdown_reason: Mutex::new("unknown"),
        }
    }

    /// The metrics registry, for the endpoint and for request counting.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
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
        let _ = self.shutdown.send(true);
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

/// The request-name to handler map.
///
/// A table rather than a `match` so a new request kind is one entry and one
/// function, and so [`dispatch_table`] can be asserted to cover the protocol.
pub fn dispatch_table() -> HashMap<&'static str, Handler> {
    let mut table: HashMap<&'static str, Handler> = HashMap::new();
    table.insert("ping", handle_ping);
    table.insert("status", handle_status);
    table.insert("shutdown", handle_shutdown);
    table
}

fn handle_ping(_state: &State) -> Response {
    Response::Pong
}

fn handle_status(state: &State) -> Response {
    Response::Status {
        version: env!("CARGO_PKG_VERSION").to_string(),
        pid: std::process::id(),
        uptime_secs: state.uptime_secs(),
        started_at: state.started_at(),
        audit_path: state.audit_path(),
        metrics_addr: state.metrics_addr.clone(),
    }
}

fn handle_shutdown(state: &State) -> Response {
    state.request_shutdown("request");
    Response::ShuttingDown
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
            _ = shutdown.changed() => break,
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
        tokio::spawn(async move {
            serve_connection(stream, state, table).await;
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
        let request: Request = match read_frame(&mut stream).await {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(err) => {
                eprintln!("briefcred-daemon: dropping connection: {err}");
                return;
            }
        };

        let name = request.name();
        state.metrics().record_request(name);
        let response = match table.get(name) {
            Some(handler) => handler(&state),
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

    #[test]
    fn every_variant_reaches_a_handler_through_its_own_name() {
        let table = dispatch_table();
        for request in [Request::Ping, Request::Status, Request::Shutdown] {
            assert!(table.contains_key(request.name()), "{request:?}");
        }
    }
}
