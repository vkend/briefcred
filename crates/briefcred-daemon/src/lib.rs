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
#[cfg(feature = "debug-heapscan")]
pub mod heapscan;
pub mod helper;
pub mod metrics;
pub mod profiles;
pub mod reconcile;
pub mod revoke;
pub mod server;
pub mod session;
pub mod unlock;

use std::sync::Arc;
use std::time::Duration;

use briefcred_core::audit::AuditEntry;
use briefcred_core::paths::Paths;
use time::OffsetDateTime;

use crate::audit::AuditLog;
use crate::clock::SystemClock;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::metrics::Metrics;
use crate::profiles::{ProfileStore, Reload};
use crate::server::{State, StateParts};
use crate::session::SessionStore;
use crate::unlock::{SystemUnlockGate, UnlockCache};

/// How often the retention sweep runs after the one at startup.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Run the daemon until it is asked to stop.
pub async fn run() -> Result<()> {
    let paths = Paths::discover()?;
    paths.ensure_layout()?;

    let config = Config::load(&paths.daemon_toml())?;
    let audit = crate::audit::spawn(AuditLog::open(&paths.audit_dir(), config.retention_days)?);
    let metrics = Arc::new(Metrics::new(audit.write_errors_handle()));

    let bound_metrics = if config.metrics_enabled {
        let (listener, addr) = metrics::bind(config.metrics_port)
            .map_err(|e| Error::io("bind the metrics listener on", paths.root(), e))?;
        Some((listener, addr))
    } else {
        None
    };
    let metrics_addr = bound_metrics.as_ref().map(|(_, addr)| addr.to_string());

    // Register the signal handlers before the socket exists. `signal` installs
    // the handler when it is called, not when the future is first polled, so
    // doing this after `bind` would leave a window where the daemon is
    // reachable but a SIGTERM still hits the default disposition and kills it.
    let signals = install_signal_handlers()?;

    // Fail to start rather than start without a way to read masters: a daemon
    // that cannot fetch a master is a daemon whose every session fails, and
    // finding that out at the first `briefcred exec` is far more confusing
    // than being told now.
    let master_source: Arc<dyn briefcred_core::MasterSource> =
        briefcred_core::source::open(config.master_source(paths.platform()), &paths)?.into();

    let clock = Arc::new(SystemClock::new());
    let profiles = Arc::new(ProfileStore::new(
        paths.profiles_dir(),
        briefcred_core::Registry::discover(),
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

    let paths = Arc::new(paths);
    let listener = server::bind(paths.sock())?;
    let (shutdown, _) = tokio::sync::watch::channel(false);
    let state = Arc::new(State::new(StateParts {
        audit,
        metrics: Arc::clone(&metrics),
        metrics_addr,
        shutdown,
        profiles: Arc::clone(&profiles),
        sessions: Arc::clone(&sessions),
        unlock: Arc::new(SystemUnlockGate::new()),
        unlock_cache: UnlockCache::new(clock),
        master_source: Arc::clone(&master_source),
        paths: Arc::clone(&paths),
        helper_dirs: helper_dirs.clone(),
        revokes: Arc::clone(&revokes),
        raw_args: config.audit.raw_args,
    }));

    // Sweep before the first row is written, so a log left behind by a much
    // older run is gone before today's file is even opened.
    state.sweep();

    // Load once here rather than leaving it to the watcher, so the daemon is
    // already answering `list_profiles` correctly by the time it accepts its
    // first connection.
    report_reload(&state, profiles.reload().await);
    state.audit(&AuditEntry::DaemonStart {
        ts: OffsetDateTime::now_utc(),
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    });

    if let Some((metrics_listener, addr)) = bound_metrics {
        eprintln!("briefcred-daemon: metrics on http://{addr}/metrics");
        tokio::spawn(metrics::serve(
            metrics_listener,
            Arc::clone(&metrics),
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
            helpers: Arc::new(helper::HelperSet::new(helper_dirs.clone())),
            masters: Arc::clone(&master_source),
        }),
        state.audit_handle(),
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
    server::serve(listener, Arc::clone(&state)).await;

    // The socket file outlives the listener, so remove it explicitly. A client
    // that finds no socket is told to start the daemon; one that finds a stale
    // socket gets a confusing connection refused instead.
    if let Err(err) = std::fs::remove_file(paths.sock()) {
        if err.kind() != std::io::ErrorKind::NotFound {
            eprintln!("briefcred-daemon: cannot remove the socket: {err}");
        }
    }

    // Wipe every master still resident before the process exits. The audit
    // rows come first, because after `close_all` there is nothing left to
    // name — and a session that vanished without a row is a session an
    // investigator cannot account for.
    for session in sessions.close_all().await {
        state.audit(&AuditEntry::SessionClose {
            ts: OffsetDateTime::now_utc(),
            session_id: session.id.clone(),
            profile: session.profile.clone(),
            reason: "shutdown".to_string(),
        });
        server::retire(&state, session, "shutdown").await;
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

/// The revoke queue's back end: a helper call with a freshly fetched master.
///
/// The master is fetched per attempt rather than carried on the queue, so the
/// queue file never holds one and a revoke that outlives its session still
/// works. See `revoke::PendingRevoke`.
#[derive(Debug)]
struct QueueRevoker {
    helpers: Arc<helper::HelperSet>,
    masters: Arc<dyn briefcred_core::MasterSource>,
}

#[async_trait::async_trait]
impl revoke::Revoker for QueueRevoker {
    async fn revoke(&self, entry: &revoke::PendingRevoke) -> briefcred_core::RevokeOutcome {
        let master = match self.masters.fetch(&entry.source_key).await {
            Ok(master) => master,
            Err(err) => return briefcred_core::RevokeOutcome::failed(err.to_string()),
        };
        crate::exec::revoke_one(&self.helpers, entry, &master).await
    }
}

/// Log a reload, and audit it when it failed.
///
/// A failed reload is the one profile event an operator has to be able to find
/// after the fact: the daemon carried on with stale profiles, and the audit
/// row is the only record that it did.
fn report_reload(state: &State, outcome: Reload) {
    match outcome {
        Reload::Loaded { count } => {
            eprintln!("briefcred-daemon: loaded {count} profile(s)");
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
