//! The briefcred per-user daemon: IPC, lifecycle, audit, and metrics.
//!
//! Phase 1 does no credential work. The daemon exists so that later phases
//! have somewhere to put it: a process that starts with the login session,
//! owns a private socket only its own user can reach, writes an append-only
//! audit log, and is observable while it does so.

#![deny(unsafe_code)]

pub mod audit;
pub mod clock;
pub mod config;
pub mod error;
pub mod exec;
pub mod handoff;
#[cfg(feature = "debug-heapscan")]
pub mod heapscan;
pub mod helper;
pub mod inproc;
pub mod mcp;
pub mod metrics;
pub mod pgproxy;
pub mod profiles;
pub mod proxy;
pub mod quota;
pub mod reconcile;
pub mod revoke;
pub mod server;
pub mod session;
pub mod unlock;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use briefcred_core::audit::AuditEntry;
use briefcred_core::paths::Paths;
use time::OffsetDateTime;

use crate::audit::AuditLog;
use crate::clock::{Clock, SystemClock};
use crate::config::Config;
use crate::error::{Error, Result};
use crate::handoff::Slot;
use crate::metrics::Metrics;
use crate::profiles::{ProfileStore, Reload};
use crate::server::{State, StateParts};
use crate::session::SessionStore;
use crate::unlock::{SystemUnlockGate, UnlockCache};

/// How often the retention sweep runs after the one at startup.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Where this daemon's listeners come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup {
    /// Bind them, or adopt what systemd passed. The ordinary start.
    Fresh,
    /// Wait on a handoff socket for the daemon this one is replacing.
    Takeover(PathBuf),
}

impl Startup {
    /// Read the one flag the daemon takes.
    ///
    /// Deliberately hand-rolled rather than a `clap` derive: the daemon is
    /// started by a service manager and takes exactly one option, and an
    /// argument parser that accepted anything else would be a surface an
    /// operator could get wrong at the one moment — an upgrade — when getting
    /// it wrong means two daemons.
    pub fn from_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<Startup> {
        let mut args = args.into_iter();
        let Some(first) = args.next() else {
            return Ok(Startup::Fresh);
        };
        let first = first.to_string_lossy().into_owned();
        let socket = match first.strip_prefix(&format!("{}=", crate::handoff::TAKEOVER_FLAG)) {
            Some(inline) => PathBuf::from(inline),
            None if first == crate::handoff::TAKEOVER_FLAG => match args.next() {
                Some(path) => PathBuf::from(path),
                None => {
                    return Err(Error::Handoff(format!(
                        "{} needs the path of the handoff socket",
                        crate::handoff::TAKEOVER_FLAG
                    )))
                }
            },
            None => return Err(Error::Handoff(format!("unknown argument `{first}`"))),
        };
        match args.next() {
            None => Ok(Startup::Takeover(socket)),
            Some(extra) => Err(Error::Handoff(format!(
                "unknown argument `{}`",
                extra.to_string_lossy()
            ))),
        }
    }
}

/// Run the daemon until it is asked to stop.
pub async fn run() -> Result<()> {
    run_with(Startup::from_args(std::env::args_os().skip(1))?).await
}

/// Run the daemon, told where its listeners come from.
pub async fn run_with(startup: Startup) -> Result<()> {
    let paths = Paths::discover()?;
    paths.ensure_layout()?;

    let config = Config::load(&paths.daemon_toml())?;
    let audit = crate::audit::spawn(AuditLog::open(&paths.audit_dir(), config.retention_days)?);
    let metrics = Arc::new(Metrics::new(audit.write_errors_handle()));

    // Opened, not read: constructing a key store touches neither the keychain
    // nor a file, so a daemon nobody upgrades and nobody proxies through still
    // never prompts. See `ProxyIssuer` for the same reasoning about the key.
    let keystore: Arc<dyn briefcred_core::keystore::KeyStore> =
        Arc::from(config.ca.open_keystore(&paths)?);

    // Register the signal handlers before any socket exists. `signal` installs
    // the handler when it is called, not when the future is first polled, so
    // doing this after `bind` would leave a window where the daemon is
    // reachable but a SIGTERM still hits the default disposition and kills it.
    let signals = install_signal_handlers()?;

    // Descriptors this daemon did not bind: systemd's, on an activated start,
    // or the outgoing daemon's, on an upgrade. Whatever is left in here once
    // every listener has been decided is closed, which is what happens to a
    // proxy socket handed to a daemon whose `daemon.toml` turns the proxy off.
    let mut adopted: BTreeMap<Slot, OwnedFd> = crate::handoff::socket_activation();
    let mut accepted = match &startup {
        Startup::Fresh => None,
        Startup::Takeover(socket) => {
            let takeover = crate::handoff::Takeover::bind(socket)?;
            eprintln!(
                "briefcred-daemon: waiting to take over on {}",
                socket.display()
            );
            takeover_delay().await;
            let signer = crate::proxy::token::TokenSigner::load_or_create(keystore.as_ref())?;
            let mut accepted = takeover.accept(&signer).await?;
            // A descriptor from a handoff wins over one from socket
            // activation: this process was started to replace a running
            // daemon, and the sockets that matter are the ones it is serving.
            adopted.extend(std::mem::take(&mut accepted.listeners));
            Some(accepted)
        }
    };

    // Backdated when there is a handoff, so every session's age survives it.
    let clock: Arc<dyn Clock> = match &accepted {
        Some(accepted) => Arc::new(SystemClock::started_ago(crate::handoff::oldest_age(
            &accepted.blob,
        ))),
        None => Arc::new(SystemClock::new()),
    };

    let bound_metrics = if config.metrics_enabled {
        Some(match adopted.remove(&Slot::Metrics) {
            Some(fd) => adopt_tcp(fd, "metrics")?,
            None => metrics::bind(config.metrics_port)
                .map_err(|e| Error::io("bind the metrics listener on", paths.root(), e))?,
        })
    } else {
        None
    };
    let metrics_addr = bound_metrics.as_ref().map(|(_, addr)| addr.to_string());

    // Fail to start rather than start without a way to read masters: a daemon
    // that cannot fetch a master is a daemon whose every session fails, and
    // finding that out at the first `briefcred exec` is far more confusing
    // than being told now.
    let master_source: Arc<dyn briefcred_core::MasterSource> =
        briefcred_core::source::open(config.master_source(paths.platform()), &paths)?.into();

    let profiles = Arc::new(ProfileStore::new(
        paths.profiles_dir(),
        briefcred_core::Registry::discover(),
        config.profiles.trust()?,
    ));
    let sessions = Arc::new(SessionStore::new(clock.clone(), config.session_idle()));

    // Next to this binary first, then `BRIEFCRED_HELPER_DIR`. See
    // `helper::search_path` for why that order and not the other one.
    let helper_dirs = helper::search_path(helper::own_dir().as_deref());
    let revokes = Arc::new(revoke::RevokeQueue::open(
        paths.state_dir().join(revoke::QUEUE_FILE),
    )?);
    let outstanding = revokes.len().await;
    if outstanding > 0 {
        eprintln!("briefcred-daemon: resuming {outstanding} revoke(s) left by an earlier run");
    }

    // The proxy is bound before the socket, for the same reason the metrics
    // listener is: a daemon that is answering `exec` but has no proxy to send
    // the token it just issued through is worse than one that failed to start.
    let bound_proxy = if config.proxy_enabled {
        let (listener, addr) = match adopted.remove(&Slot::Proxy) {
            Some(fd) => adopt_tcp(fd, "proxy")?,
            None => proxy::listener::bind(config.proxy_port)
                .map_err(|e| Error::io("bind the proxy listener on", paths.root(), e))?,
        };
        // The key store is opened but not read: see `ProxyIssuer`, which loads
        // the signing key on the first token rather than at startup, so a
        // daemon nobody proxies through never prompts for keychain access.
        let store = config.ca.open_keystore(&paths)?;
        let issuer = proxy::issuer::ProxyIssuer::open(store, format!("http://{addr}"));
        let upstream = proxy::tls::client_config(config.upstream_roots.as_deref())?;
        Some((listener, addr, issuer, upstream))
    } else {
        None
    };
    let issuer = bound_proxy
        .as_ref()
        .map(|(_, _, issuer, _)| Arc::clone(issuer));
    let proxy_addr = bound_proxy.as_ref().map(|(_, addr, _, _)| addr.to_string());

    // The Postgres proxy signs its synthetic tokens with the *same* issuer as
    // the HTTP proxy: one signing key per daemon, one revocation set, one place
    // that decides a token is no longer good. Two issuers would mean a `Revoke`
    // that retired a grant in one of them and not the other.
    //
    // So it can only run where that issuer exists. A `daemon.toml` that turns
    // the HTTP proxy off and leaves this one on is refused rather than started
    // half-working, because the failure would otherwise appear as every
    // `postgres-proxy` credential silently failing to mint.
    if config.pg_proxy_enabled && issuer.is_none() {
        return Err(Error::Config {
            path: paths.daemon_toml(),
            message: "`pg_proxy_enabled` needs `proxy_enabled`: the Postgres proxy verifies \
                      synthetic tokens with the HTTP proxy's signing key"
                .to_string(),
        });
    }
    let bound_pg_proxy = match (config.pg_proxy_enabled, issuer.as_ref()) {
        (true, Some(issuer)) => {
            let (listener, addr) = match adopted.remove(&Slot::PgProxy) {
                Some(fd) => adopt_tcp(fd, "pg_proxy")?,
                None => pgproxy::listener::bind(config.pg_proxy_port).map_err(|e| {
                    Error::io("bind the postgres proxy listener on", paths.root(), e)
                })?,
            };
            Some((listener, addr, Arc::clone(issuer)))
        }
        _ => None,
    };
    let pg_proxy_addr = bound_pg_proxy.as_ref().map(|(_, addr, _)| addr.to_string());

    let paths = Arc::new(paths);
    let listener = match adopted.remove(&Slot::Ipc) {
        // Adopted rather than rebound, and the socket file is deliberately
        // left alone: unlinking and rebinding it would give a client
        // connecting at that instant "no such file", which is precisely the
        // downtime an in-place upgrade exists to avoid.
        Some(fd) => adopt_unix(fd)?,
        None => server::bind(paths.sock())?,
    };
    for (slot, _) in std::mem::take(&mut adopted) {
        eprintln!(
            "briefcred-daemon: closing the handed-over {} listener; this daemon's \
             configuration does not run it",
            slot.as_str()
        );
    }

    // Loaded before the sessions are rebuilt, because a handed-over session's
    // quota comes from its profile as *this* daemon has it.
    let reloaded = profiles.reload().await;

    let (shutdown, _) = tokio::sync::watch::channel(false);
    let handing_over = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let listener_fds = crate::handoff::listener_fds(
        &listener,
        bound_metrics.as_ref().map(|(listener, _)| listener),
        bound_proxy.as_ref().map(|(listener, _, _, _)| listener),
        bound_pg_proxy.as_ref().map(|(listener, _, _)| listener),
    );
    let state = Arc::new(State::new(StateParts {
        audit,
        metrics: Arc::clone(&metrics),
        metrics_addr,
        proxy_addr,
        pg_proxy_addr: pg_proxy_addr.clone(),
        shutdown,
        profiles: Arc::clone(&profiles),
        sessions: Arc::clone(&sessions),
        unlock: Arc::new(SystemUnlockGate::new()),
        unlock_cache: UnlockCache::new(Arc::clone(&clock)),
        master_source: Arc::clone(&master_source),
        paths: Arc::clone(&paths),
        helper_dirs: helper_dirs.clone(),
        revokes: Arc::clone(&revokes),
        raw_args: config.audit.raw_args,
        mcp_query_timeout: config.mcp_query_timeout(),
        proxy: issuer.clone(),
        keystore,
        handing_over: Arc::clone(&handing_over),
        drain: config.handoff_drain(),
        listener_fds,
    }));

    // Sweep before the first row is written, so a log left behind by a much
    // older run is gone before today's file is even opened.
    state.sweep();

    // Reported here rather than where it was loaded, because the report is
    // written to the audit log and the audit log lives on `State`.
    report_reload(&state, reloaded);
    state.audit(&AuditEntry::DaemonStart {
        ts: OffsetDateTime::now_utc(),
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    });

    // Rebuilt before a single listener starts accepting, so the first request
    // that arrives on an adopted socket already finds its session open. A
    // failure here is reported back to the daemon still holding the sockets,
    // which then keeps running rather than standing down.
    if let Some(accepted) = accepted.as_mut() {
        let sessions = match crate::handoff::rebuild_sessions(
            &accepted.blob,
            &accepted.unsealer,
            &clock,
            &profiles,
            &helper_dirs,
        )
        .await
        {
            Ok(sessions) => sessions,
            Err(err) => {
                metrics.record_handoff("failed");
                state.audit(&AuditEntry::DaemonHandoff {
                    ts: OffsetDateTime::now_utc(),
                    from_pid: accepted.blob.from_pid,
                    to_pid: None,
                    sessions: 0,
                    outcome: "failed".to_string(),
                });
                state.audit_flush().await;
                accepted.refused(err.to_string()).await;
                return Err(err);
            }
        };
        let adopted_count = sessions.len();
        state.sessions().adopt(sessions).await;
        if let Some(issuer) = &issuer {
            for entry in &accepted.blob.revocations {
                issuer.revoke(&entry.session_id, &entry.credential, entry.expires_at);
            }
        }
        metrics.record_handoff("adopted");
        state.audit(&AuditEntry::DaemonHandoff {
            ts: OffsetDateTime::now_utc(),
            from_pid: accepted.blob.from_pid,
            to_pid: Some(std::process::id()),
            sessions: adopted_count,
            outcome: "adopted".to_string(),
        });
        eprintln!(
            "briefcred-daemon: adopted {adopted_count} session(s) and {} listener(s) from pid {}",
            accepted.blob.listeners.len(),
            accepted.blob.from_pid
        );
    }

    if let Some((metrics_listener, addr)) = bound_metrics {
        eprintln!("briefcred-daemon: metrics on http://{addr}/metrics");
        tokio::spawn(metrics::serve(
            metrics_listener,
            Arc::clone(&metrics),
            state.shutdown_signal(),
        ));
    }
    if let Some((proxy_listener, addr, issuer, upstream)) = bound_proxy {
        eprintln!("briefcred-daemon: http proxy on http://{addr}");
        tokio::spawn(proxy::listener::serve(
            proxy_listener,
            proxy::listener::Proxy::new(Arc::clone(&state), issuer, upstream),
            state.shutdown_signal(),
        ));
    }
    if let Some((pg_listener, addr, issuer)) = bound_pg_proxy {
        eprintln!("briefcred-daemon: postgres proxy on postgresql://{addr}");
        tokio::spawn(pgproxy::listener::serve(
            pg_listener,
            pgproxy::listener::PgProxy::new(
                Arc::clone(&state),
                issuer,
                config.pgproxy.tls,
                config.pgproxy.allow_md5,
            ),
            state.shutdown_signal(),
        ));
    }
    tokio::spawn(sweep_loop(Arc::clone(&state)));
    tokio::spawn(watch_signals(Arc::clone(&state), signals));

    // A reloaded profile may have had its unlock policy tightened, so the
    // cached unlock for the file that used to be there must not carry over.
    let reload_state = Arc::clone(&state);
    tokio::spawn(profiles::watch(
        Arc::clone(&profiles),
        state.shutdown_signal(),
        move |outcome| {
            let state = Arc::clone(&reload_state);
            report_reload(&state, outcome);
            tokio::spawn(async move { state.unlock_cache().clear().await });
        },
    ));

    let evict_state = Arc::clone(&state);
    tokio::spawn(session::evict_loop(
        Arc::clone(&sessions),
        state.shutdown_signal(),
        move |session: session::Session| {
            let state = Arc::clone(&evict_state);
            async move {
                state.audit(&AuditEntry::SessionClose {
                    ts: OffsetDateTime::now_utc(),
                    session_id: session.id.clone(),
                    profile: session.profile.clone(),
                    reason: "idle".to_string(),
                });
                server::retire(&state, session, "idle").await;
            }
        },
    ));

    // The revoke queue and the reconciler each get their own helper set: both
    // outlive every session, and the whole point of the reconciler is that it
    // runs when no session exists.
    tokio::spawn(revoke::drain_loop(
        Arc::clone(&revokes),
        Arc::new(QueueRevoker {
            helpers: Arc::new(helper::MinterSet::new(helper_dirs.clone())),
            masters: Arc::clone(&master_source),
            proxy: issuer,
        }),
        state.audit_handle(),
        Arc::clone(&metrics),
        handing_over,
        state.shutdown_signal(),
    ));
    tokio::spawn(reconcile::reconcile_loop(
        Arc::clone(&profiles),
        reconcile::helpers_for(helper_dirs),
        Arc::clone(&master_source),
        state.audit_handle(),
        config.reconcile_interval(),
        state.shutdown_signal(),
    ));

    eprintln!(
        "briefcred-daemon: listening on {} (pid {})",
        paths.sock().display(),
        std::process::id()
    );
    // The last thing before this daemon starts accepting, and the thing that
    // lets the old one stand down: every listener is live, every session is
    // rebuilt, so there is no instant in which neither process is serving.
    if let Some(accepted) = accepted.take() {
        let open = state.sessions().len().await;
        accepted.accepted(open).await?;
    }
    server::serve(listener, Arc::clone(&state)).await;

    // In-flight proxy work outlives the accept loops: a `CONNECT` tunnel
    // carrying an event stream is a task of its own, and exiting on top of one
    // is the dropped bytes an in-place upgrade is supposed to make impossible.
    let handed_off = state.handed_off();
    if handed_off.is_some() {
        let left = state.in_flight().drained(state.drain()).await;
        if left > 0 {
            eprintln!(
                "briefcred-daemon: {} s drain expired with {left} connection(s) still open",
                state.drain().as_secs()
            );
        }
    }

    // The socket file outlives the listener, so remove it explicitly. A client
    // that finds no socket is told to start the daemon; one that finds a stale
    // socket gets a confusing connection refused instead.
    //
    // Never after a handoff: the file is the new daemon's listener, and
    // removing it would take the machine's briefcred away at the end of a
    // successful upgrade.
    if handed_off.is_none() {
        if let Err(err) = std::fs::remove_file(paths.sock()) {
            if err.kind() != std::io::ErrorKind::NotFound {
                eprintln!("briefcred-daemon: cannot remove the socket: {err}");
            }
        }
    }

    // Wipe every master still resident before the process exits. The audit
    // rows come first, because after `close_all` there is nothing left to
    // name — and a session that vanished without a row is a session an
    // investigator cannot account for.
    for session in sessions.close_all().await {
        // Per session, not per daemon. A session the blob carried was *moved*:
        // the daemon that took it over holds its mints, and queueing their
        // revokes here would kill credentials it is still serving. A session
        // this daemon is holding that the blob did not carry was not moved —
        // nobody adopted it, and its mints are orphaned exactly as they would
        // be on an ordinary shutdown.
        let moved = state.was_handed_over(&session.id);
        let reason = if moved { "handoff" } else { "shutdown" };
        state.audit(&AuditEntry::SessionClose {
            ts: OffsetDateTime::now_utc(),
            session_id: session.id.clone(),
            profile: session.profile.clone(),
            reason: reason.to_string(),
        });
        if moved {
            server::release(session).await;
        } else {
            server::retire(&state, session, reason).await;
        }
    }

    state.audit(&AuditEntry::DaemonStop {
        ts: OffsetDateTime::now_utc(),
        pid: std::process::id(),
        uptime_secs: state.uptime_secs(),
        reason: state.shutdown_reason().to_string(),
    });
    // The last row has to be on the disk before the process exits, or a clean
    // shutdown looks exactly like a crash to whoever reads the log.
    state.audit_flush().await;
    Ok(())
}

/// Widen the handoff window, for a test that needs to act inside it.
///
/// The socket is already bound, so the daemon being replaced connects and then
/// waits here for the hello — which is exactly the interval in which it is
/// still accepting IPC and its blob does not yet exist. Nothing outside a test
/// sets the variable, and a daemon that ignores it behaves as it always did.
async fn takeover_delay() {
    let Some(millis) = std::env::var("BRIEFCRED_TEST_TAKEOVER_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return;
    };
    eprintln!("briefcred-daemon: BRIEFCRED_TEST_TAKEOVER_DELAY_MS is set; waiting {millis} ms");
    tokio::time::sleep(Duration::from_millis(millis)).await;
}

/// Turn an adopted descriptor into a listening TCP socket.
fn adopt_tcp(fd: OwnedFd, what: &'static str) -> Result<(tokio::net::TcpListener, SocketAddr)> {
    let listener = std::net::TcpListener::from(fd);
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::Handoff(format!("cannot adopt the {what} listener: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| Error::Handoff(format!("cannot read the {what} listener's address: {e}")))?;
    let listener = tokio::net::TcpListener::from_std(listener)
        .map_err(|e| Error::Handoff(format!("cannot adopt the {what} listener: {e}")))?;
    Ok((listener, addr))
}

/// Turn an adopted descriptor into the listening IPC socket.
fn adopt_unix(fd: OwnedFd) -> Result<tokio::net::UnixListener> {
    let listener = crate::handoff::adopt_fd(fd);
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::Handoff(format!("cannot adopt the ipc listener: {e}")))?;
    tokio::net::UnixListener::from_std(listener)
        .map_err(|e| Error::Handoff(format!("cannot adopt the ipc listener: {e}")))
}

/// The revoke queue's back end: a helper call with a freshly fetched master.
///
/// The master is fetched per attempt rather than carried on the queue, so the
/// queue file never holds one and a revoke that outlives its session still
/// works. See `revoke::PendingRevoke`.
#[derive(Debug)]
struct QueueRevoker {
    helpers: Arc<helper::MinterSet>,
    masters: Arc<dyn briefcred_core::MasterSource>,
    /// The proxy's token authority, when the proxy is running.
    ///
    /// Revoking an `http-*` credential is the daemon deciding to stop
    /// honouring a token it signed, so it happens here rather than at a
    /// backend. A queue entry for one that outlives a proxy-less restart is
    /// reported as failed rather than silently dropped — see
    /// [`crate::exec::revoke_one`].
    proxy: Option<Arc<proxy::issuer::ProxyIssuer>>,
}

#[async_trait::async_trait]
impl revoke::Revoker for QueueRevoker {
    async fn revoke(&self, entry: &revoke::PendingRevoke) -> briefcred_core::RevokeOutcome {
        // The proxy's own kinds need no master: retiring one is the daemon
        // deciding to stop honouring a token it signed. Fetching a master
        // anyway would make a revoke that cannot fail depend on a key store
        // that can, and on a secret whose file the user may have deleted along
        // with the profile.
        if briefcred_core::Registry::discover().is_proxy(&entry.kind) {
            return crate::exec::revoke_one(
                &self.helpers,
                entry,
                &zeroize::Zeroizing::new(String::new()),
                self.proxy.as_deref(),
            )
            .await;
        }
        let master = match self.masters.fetch(&entry.source_key).await {
            Ok(master) => master,
            Err(err) => return briefcred_core::RevokeOutcome::failed(err.to_string()),
        };
        crate::exec::revoke_one(&self.helpers, entry, &master, self.proxy.as_deref()).await
    }

    /// Stop every helper this pass started, so none holds a master while the
    /// queue waits for its next one.
    async fn end_of_pass(&self) {
        self.helpers.stop_all().await;
    }
}

/// Log a reload, and audit it when it failed.
///
/// A failed reload is the one profile event an operator has to be able to find
/// after the fact: the daemon carried on with stale profiles, and the audit
/// row is the only record that it did.
fn report_reload(state: &State, outcome: Reload) {
    match outcome {
        Reload::Loaded { count, warnings } => {
            eprintln!("briefcred-daemon: loaded {count} profile(s)");
            for warning in warnings {
                // Printed for whoever is watching the daemon start; audited
                // for whoever asks, next month, what this daemon was actually
                // running. The action comes from the loader rather than from
                // reading the message back, so the audit row and the decision
                // cannot drift apart.
                if warning.action.is_trust_failure() {
                    eprintln!("briefcred-daemon: !! PROFILE NOT VERIFIED: {warning}");
                } else {
                    eprintln!("briefcred-daemon: {warning}");
                }
                if !warning.action.is_trust_failure() {
                    continue;
                }
                state.audit(&AuditEntry::ProfileTrustWarning {
                    ts: OffsetDateTime::now_utc(),
                    path: warning.path.display().to_string(),
                    action: warning.action.as_str().to_string(),
                    reason: warning.reason.clone(),
                });
            }
        }
        Reload::Failed { message } => {
            eprintln!("briefcred-daemon: keeping the last good profiles: {message}");
            state.audit(&AuditEntry::ProfileLoadError {
                ts: OffsetDateTime::now_utc(),
                message,
            });
        }
    }
}

async fn sweep_loop(state: Arc<State>) {
    let mut shutdown = state.shutdown_signal();
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    // `interval` fires immediately; the startup sweep already covered that.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = server::shutdown_requested(&mut shutdown) => return,
            _ = ticker.tick() => state.sweep(),
        }
    }
}

/// The signal streams the daemon shuts down on, registered eagerly.
struct Signals {
    terminate: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

fn install_signal_handlers() -> Result<Signals> {
    use tokio::signal::unix::{signal, SignalKind};

    let handler = |kind, name: &'static str| {
        signal(kind).map_err(|source| Error::io("install a signal handler for", name, source))
    };
    Ok(Signals {
        terminate: handler(SignalKind::terminate(), "SIGTERM")?,
        interrupt: handler(SignalKind::interrupt(), "SIGINT")?,
    })
}

async fn watch_signals(state: Arc<State>, mut signals: Signals) {
    tokio::select! {
        _ = signals.terminate.recv() => state.request_shutdown("sigterm"),
        _ = signals.interrupt.recv() => state.request_shutdown("sigint"),
    }
}
