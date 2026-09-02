//! Shared scaffolding for the daemon's unit tests.
//!
//! A `State` is the daemon: profiles, sessions, an audit log, an unlock gate, a
//! key store, a revoke queue. Several modules' tests need one, and a copy per
//! module is a copy that drifts — so it is built once, here, and the pieces a
//! test wants to steer are parameters rather than edits.
//!
//! Compiled only under `cfg(test)`, and the whole crate's unit tests link into
//! one binary, so everything here is reachable from any module's `mod tests`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use briefcred_core::profile::UnlockPolicy;
use briefcred_core::source::MemorySource;

use crate::clock::{Clock, SystemClock};
use crate::metrics::Metrics;
use crate::profiles::ProfileStore;
use crate::server::{State, StateParts};
use crate::session::SessionStore;
use crate::unlock::{UnlockError, UnlockGate};

/// A gate that records every time it is asked, so a test can assert that
/// it was *not* asked — which is the whole point of refusing a headless
/// client before the gate rather than inside it.
#[derive(Debug, Default)]
pub struct CountingGate {
    /// Incremented once per prompt a policy other than `none` would raise.
    pub prompts: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl UnlockGate for CountingGate {
    async fn unlock(&self, policy: UnlockPolicy, _reason: &str) -> Result<(), UnlockError> {
        // Honours the trait's contract that `None` succeeds without
        // prompting, so the count means "a human was actually asked".
        if policy == UnlockPolicy::None {
            return Ok(());
        }
        self.prompts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// A `State` wired to temp directories and a gate the test can inspect.
pub async fn test_state(profile_yaml: &str) -> (tempfile::TempDir, Arc<State>, Arc<AtomicUsize>) {
    test_state_with(
        profile_yaml,
        Arc::new(SystemClock::new()),
        Duration::from_secs(1800),
    )
    .await
}

/// The same, with the session clock and idle window a test chooses.
///
/// The clock is what makes an idle-eviction test exact instead of sleepy: it
/// is advanced by hand, and `evict_idle` is called directly rather than waited
/// for.
pub async fn test_state_with(
    profile_yaml: &str,
    clock: Arc<dyn Clock>,
    idle_for: Duration,
) -> (tempfile::TempDir, Arc<State>, Arc<AtomicUsize>) {
    let home = tempfile::tempdir().unwrap();
    let profiles_dir = home.path().join("profiles");
    std::fs::create_dir_all(&profiles_dir).unwrap();
    std::fs::write(profiles_dir.join("p.yaml"), profile_yaml).unwrap();

    let audit =
        crate::audit::spawn(crate::audit::AuditLog::open(&home.path().join("audit"), 90).unwrap());
    let metrics = Arc::new(Metrics::new(audit.write_errors_handle()));
    let profiles = Arc::new(ProfileStore::new(
        profiles_dir,
        briefcred_core::Registry::discover(),
        briefcred_core::distribution::Trust::none(),
    ));
    profiles.reload().await;

    let prompts = Arc::new(AtomicUsize::new(0));
    let (shutdown, _) = tokio::sync::watch::channel(false);
    let paths =
        briefcred_core::paths::Paths::resolve(briefcred_core::paths::Platform::MacOs, &|key| {
            (key == briefcred_core::paths::HOME_ENV).then(|| home.path().as_os_str().to_os_string())
        })
        .unwrap();
    let state = Arc::new(State::new(StateParts {
        audit,
        metrics,
        metrics_addr: None,
        proxy_addr: None,
        pg_proxy_addr: None,
        shutdown,
        profiles,
        sessions: Arc::new(SessionStore::new(clock.clone(), idle_for)),
        unlock: Arc::new(CountingGate {
            prompts: Arc::clone(&prompts),
        }),
        unlock_cache: crate::unlock::UnlockCache::new(clock),
        master_source: Arc::new(MemorySource::new([(
            "db".to_string(),
            "master".to_string(),
        )])),
        paths: Arc::new(paths),
        helper_dirs: Vec::new(),
        revokes: Arc::new(
            crate::revoke::RevokeQueue::open(home.path().join(crate::revoke::QUEUE_FILE)).unwrap(),
        ),
        raw_args: false,
        mcp_query_timeout: Duration::from_secs(30),
        mcp_exec_timeout: Duration::from_secs(300),
        proxy: None,
        keystore: Arc::new(briefcred_core::keystore::FileKeyStore::new(
            home.path().join("ca"),
        )),
        handing_over: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        drain: Duration::from_secs(crate::handoff::DEFAULT_DRAIN_SECS),
        listener_fds: Vec::new(),
    }));
    (home, state, prompts)
}
