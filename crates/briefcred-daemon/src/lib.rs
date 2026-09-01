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
pub mod metrics;
pub mod profiles;
pub mod server;
pub mod session;
pub mod unlock;

use std::sync::Arc;
use std::time::Duration;

use briefcred_core::audit::AuditEntry;
use briefcred_core::paths::Paths;
use time::OffsetDateTime;

use crate::audit::AuditLog;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::metrics::Metrics;
use crate::server::State;

/// How often the retention sweep runs after the one at startup.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Run the daemon until it is asked to stop.
pub async fn run() -> Result<()> {
    let paths = Paths::discover()?;
    paths.ensure_layout()?;

    let config = Config::load(&paths.daemon_toml())?;
    let audit = AuditLog::open(&paths.audit_dir(), config.retention_days)?;
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

    let listener = server::bind(paths.sock())?;
    let (shutdown, _) = tokio::sync::watch::channel(false);
    let state = Arc::new(State::new(
        audit,
        Arc::clone(&metrics),
        metrics_addr,
        shutdown,
    ));

    // Sweep before the first row is written, so a log left behind by a much
    // older run is gone before today's file is even opened.
    state.sweep();
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

    state.audit(&AuditEntry::DaemonStop {
        ts: OffsetDateTime::now_utc(),
        pid: std::process::id(),
        uptime_secs: state.uptime_secs(),
        reason: state.shutdown_reason().to_string(),
    });
    Ok(())
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
