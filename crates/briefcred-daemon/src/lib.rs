//! The briefcred per-user daemon: IPC, lifecycle, audit, and metrics.
//!
//! Phase 1 does no credential work. The daemon exists so that later phases
//! have somewhere to put it: a process that starts with the login session,
//! owns a private socket only its own user can reach, writes an append-only
//! audit log, and is observable while it does so.

#![deny(unsafe_code)]

pub mod audit;
pub mod config;
pub mod error;
pub mod metrics;
pub mod server;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
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

/// Create `dir` if needed and make sure only its owner can enter it.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| Error::io("create", dir, e))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io("set the mode of", dir, e))
}

/// Create every directory briefcred owns, all of them private.
///
/// Idempotent, so `briefcred install` and a daemon start can both call it.
pub fn ensure_layout(paths: &Paths) -> Result<()> {
    for dir in [
        paths.root().to_path_buf(),
        paths.profiles_dir(),
        paths.audit_dir(),
        paths.ca_dir(),
        paths.log_dir(),
        paths.state_dir(),
    ] {
        ensure_private_dir(&dir)?;
    }
    Ok(())
}

/// Run the daemon until it is asked to stop.
pub async fn run() -> Result<()> {
    let paths = Paths::discover()?;
    ensure_layout(&paths)?;

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
    tokio::spawn(watch_signals(Arc::clone(&state)));

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
            _ = shutdown.changed() => return,
            _ = ticker.tick() => state.sweep(),
        }
    }
}

async fn watch_signals(state: Arc<State>) {
    use tokio::signal::unix::{signal, SignalKind};

    let (mut term, mut interrupt) = match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(term), Ok(interrupt)) => (term, interrupt),
        _ => {
            eprintln!("briefcred-daemon: cannot install signal handlers");
            return;
        }
    };

    tokio::select! {
        _ = term.recv() => state.request_shutdown("sigterm"),
        _ = interrupt.recv() => state.request_shutdown("sigint"),
    }
}
