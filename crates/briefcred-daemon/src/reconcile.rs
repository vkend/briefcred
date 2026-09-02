//! The reconciler: the net under everything else.
//!
//! The revoke queue handles a normal exit and a normal restart. It cannot
//! handle `SIGKILL` between the mint and the queue write, and it cannot handle
//! a daemon whose whole state directory was deleted. In both cases the
//! credential exists at the backend and nothing on this machine remembers it.
//!
//! The backend remembers. Every briefcred principal is named
//! `briefcred_t_<hex>` and carries the expiry its mint set, so "ours, and past
//! its expiry" identifies exactly the strays — and cannot match a principal
//! that a *live* exec is still using, because a live one has not expired yet.
//!
//! The sweep runs once at startup and then every `reconcile_interval_secs`.
//! Startup is the important one: it is the tick that immediately follows the
//! `SIGKILL` this exists for.

use std::sync::Arc;
use std::time::Duration;

use briefcred_core::audit::AuditEntry;
use briefcred_core::types::RevokeOutcome;
use briefcred_proto::helper::{HelperParams, HelperResult, ReconcileParams};
use briefcred_proto::SecretString;
use time::OffsetDateTime;

use crate::audit::AuditHandle;
use crate::helper::MinterSet;
use crate::profiles::ProfileStore;

/// How often the sweep runs when `daemon.toml` says nothing.
pub const DEFAULT_INTERVAL_SECS: u64 = 300;

/// Sweep every backend the loaded profiles name.
///
/// Runs one `reconcile` per distinct `(profile, credential)` pair, because two
/// credentials of the same kind may point at different clusters and a sweep of
/// one says nothing about the other. Failures are reported and the sweep
/// carries on: a database that is down must not stop the others being cleaned.
pub async fn sweep(
    profiles: &ProfileStore,
    helpers: &MinterSet,
    masters: &dyn briefcred_core::MasterSource,
    audit: &AuditHandle,
) {
    let registry = briefcred_core::Registry::discover();
    for profile in profiles.list().await {
        for spec in &profile.credentials {
            // The proxy's own kinds create nothing at a backend, so there is
            // nothing to strand and nothing to sweep. Skipped silently rather
            // than attempted and reported: a helper that does not exist is not
            // a reconciler failure, and logging one every interval would train
            // an operator to ignore the line.
            if registry.is_proxy(&spec.kind) {
                continue;
            }
            let master = match masters.fetch(spec.source_key()).await {
                Ok(master) => master,
                // A profile whose master has not been set up yet is a normal
                // state, not a reconciler failure: it has never minted, so it
                // has nothing to strand.
                Err(err) => {
                    eprintln!(
                        "briefcred-daemon: reconcile skipped `{}`/`{}`: {err}",
                        profile.name, spec.name
                    );
                    continue;
                }
            };
            let config = match serde_json::to_value(&spec.config) {
                Ok(config) => config,
                Err(err) => {
                    eprintln!(
                        "briefcred-daemon: reconcile skipped `{}`/`{}`: {err}",
                        profile.name, spec.name
                    );
                    continue;
                }
            };

            let helper = match helpers.get(&spec.kind, &spec.config).await {
                Ok(helper) => helper,
                Err(err) => {
                    eprintln!("briefcred-daemon: reconcile: {err}");
                    continue;
                }
            };
            let result = helper
                .call(HelperParams::Reconcile(ReconcileParams {
                    config,
                    master: SecretString::from(master),
                }))
                .await;

            let report = match result {
                Ok(HelperResult::Reconcile(report)) => report,
                Ok(_) => {
                    eprintln!(
                        "briefcred-daemon: `{}` answered a reconcile with something else",
                        spec.kind
                    );
                    continue;
                }
                Err(err) => {
                    helpers.discard(&spec.kind).await;
                    eprintln!("briefcred-daemon: reconcile: {err}");
                    continue;
                }
            };

            // One `Revoke` row per stray, so a reconciled credential is as
            // findable in the log as one the queue took care of.
            for name in &report.revoked {
                if let Ok(mint_id) = name.parse() {
                    audit.append(&AuditEntry::revoke(
                        mint_id,
                        spec.kind.clone(),
                        &RevokeOutcome::Revoked,
                    ));
                }
            }
            for failure in &report.failed {
                if let Ok(mint_id) = failure.mint_id.parse() {
                    audit.append(&AuditEntry::revoke(
                        mint_id,
                        spec.kind.clone(),
                        &RevokeOutcome::failed(failure.detail.clone()),
                    ));
                }
            }
            audit.append(&AuditEntry::Reconcile {
                ts: OffsetDateTime::now_utc(),
                kind: spec.kind.clone(),
                profile: profile.name.clone(),
                revoked: report.revoked.len(),
                failed: report.failed.len(),
            });
        }
    }
}

/// Sweep at startup, then on every tick, until shutdown.
pub async fn reconcile_loop(
    profiles: Arc<ProfileStore>,
    helpers: Arc<MinterSet>,
    masters: Arc<dyn briefcred_core::MasterSource>,
    audit: AuditHandle,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    // `interval` fires immediately, and that first tick is the startup sweep —
    // the one that cleans up after the `SIGKILL` that just happened.
    loop {
        tokio::select! {
            _ = crate::server::shutdown_requested(&mut shutdown) => return,
            _ = ticker.tick() => {
                sweep(&profiles, &helpers, masters.as_ref(), &audit).await;
                // Every sweep starts its own helpers and stops them again. A
                // sweep runs every few minutes and takes milliseconds, so a
                // helper kept between them would be a master credential
                // resident in a process that is doing nothing, for almost all
                // of the daemon's life.
                helpers.stop_all().await;
            }
        }
    }
}

/// The helpers the reconciler owns, separate from any session's.
///
/// A sweep must be able to run when no session is open — that is the normal
/// case for the startup sweep after a crash — so it cannot borrow a session's
/// helper set.
pub fn helpers_for(dirs: Vec<std::path::PathBuf>) -> Arc<MinterSet> {
    Arc::new(MinterSet::new(dirs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use briefcred_core::source::MemorySource;

    #[tokio::test]
    async fn a_profile_whose_master_is_missing_is_skipped_rather_than_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let profiles_dir = dir.path().join("profiles");
        std::fs::create_dir_all(&profiles_dir).unwrap();
        std::fs::write(
            profiles_dir.join("p.yaml"),
            "name: dev\ncredentials:\n  - name: db\n    kind: postgres-dynamic\n    config:\n      host: 127.0.0.1\n      dbname: app\n      user: m\n      sslmode: disable\n      role_template: {}\n",
        )
        .unwrap();
        let profiles = ProfileStore::new(
            profiles_dir,
            briefcred_core::Registry::discover(),
            briefcred_core::distribution::Trust::none(),
        );
        profiles.reload().await;

        let audit = crate::audit::spawn(
            crate::audit::AuditLog::open(&dir.path().join("audit"), 90).unwrap(),
        );
        // No master, and helper directories that hold no helper: the sweep must
        // return rather than panic or block.
        sweep(
            &profiles,
            &MinterSet::new(Vec::new()),
            &MemorySource::default(),
            &audit,
        )
        .await;
        audit.flush().await;

        let log: String = std::fs::read_dir(dir.path().join("audit"))
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect();
        assert!(
            log.is_empty(),
            "nothing was swept, so nothing is logged: {log}"
        );
    }

    #[tokio::test]
    async fn the_reconcile_loop_stops_when_shutdown_is_requested() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = Arc::new(ProfileStore::new(
            dir.path().join("profiles"),
            briefcred_core::Registry::discover(),
            briefcred_core::distribution::Trust::none(),
        ));
        let audit = crate::audit::spawn(
            crate::audit::AuditLog::open(&dir.path().join("audit"), 90).unwrap(),
        );
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(reconcile_loop(
            profiles,
            helpers_for(Vec::new()),
            Arc::new(MemorySource::default()),
            audit,
            Duration::from_secs(300),
            shutdown.subscribe(),
        ));

        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the reconcile loop must stop on shutdown")
            .unwrap();
    }
}
