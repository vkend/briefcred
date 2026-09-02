//! The loaded profile set, and the watcher that keeps it current.
//!
//! Profiles are edited with a text editor while the daemon is running, so the
//! daemon watches the directory and reloads. Two rules make that safe:
//!
//! - **A broken file never takes the daemon down with it.** A reload that
//!   fails leaves the previous set in place, logs, and writes a
//!   `ProfileLoadError` audit row. The alternative — dropping every profile
//!   because one file has a typo — turns a typo into an outage.
//! - **Reloads are debounced.** An editor's save is several filesystem events
//!   (write, rename, chmod), and a `notify` burst must produce one reload, not
//!   five, or the daemon reloads a half-written file.
//!
//! Last-good does not extend to trust. A registry profile whose signature
//! stops verifying is dropped from the set on the next reload rather than kept
//! from the previous one: continuing to run a profile precisely because its
//! signature has just gone bad is the opposite of what an operator wants. Each
//! such file produces a warning the daemon prints and audits.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use briefcred_core::distribution::{LoadedProfile, ProfileSet, Trust, TrustWarning};
use briefcred_core::{Profile, Registry};
use tokio::sync::RwLock;

/// How long the watcher waits for the filesystem to go quiet before reloading.
///
/// An editor's atomic save is a burst of events over a few milliseconds; 250 ms
/// is comfortably longer than the burst and far shorter than a human notices.
pub const DEBOUNCE: Duration = Duration::from_millis(250);

/// The profiles the daemon currently believes in.
///
/// Behind an `RwLock` because every session open reads it and only the
/// watcher writes it.
#[derive(Debug)]
pub struct ProfileStore {
    dir: PathBuf,
    registry: Registry,
    trust: Trust,
    profiles: RwLock<BTreeMap<String, LoadedProfile>>,
}

/// What one reload attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reload {
    /// The directory parsed, and the set is now what it describes.
    Loaded {
        /// How many profiles are loaded.
        count: usize,
        /// One entry per file that was dropped, distrusted, or shadowed.
        ///
        /// A reload can succeed and still have complaints: one registry file
        /// failing verification does not stop the other twenty from loading.
        warnings: Vec<TrustWarning>,
    },
    /// The directory did not parse. The previous set is still in force.
    Failed {
        /// The operator-readable complaint, naming the offending file.
        message: String,
    },
}

impl ProfileStore {
    /// An empty store that will read from `dir` and validate against `registry`.
    ///
    /// `trust` decides what happens to the `registry/` subtree: which keys
    /// count, and whether an unverified file is dropped or loaded loudly.
    pub fn new(dir: impl Into<PathBuf>, registry: Registry, trust: Trust) -> ProfileStore {
        ProfileStore {
            dir: dir.into(),
            registry,
            trust,
            profiles: RwLock::new(BTreeMap::new()),
        }
    }

    /// The directory being watched.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Re-read the directory, keeping the previous set if it does not parse.
    pub async fn reload(&self) -> Reload {
        match ProfileSet::load(&self.dir, &self.registry, &self.trust) {
            Ok(set) => {
                let count = set.profiles.len();
                let warnings = set.warnings;
                *self.profiles.write().await = set.profiles;
                Reload::Loaded { count, warnings }
            }
            Err(err) => Reload::Failed {
                message: err.to_string(),
            },
        }
    }

    /// Every loaded profile, in name order.
    pub async fn list(&self) -> Vec<Profile> {
        self.profiles
            .read()
            .await
            .values()
            .map(|loaded| loaded.profile.clone())
            .collect()
    }

    /// Every loaded profile with where it came from, in name order.
    pub async fn list_loaded(&self) -> Vec<LoadedProfile> {
        self.profiles.read().await.values().cloned().collect()
    }

    /// One profile by name.
    pub async fn get(&self, name: &str) -> Option<Profile> {
        self.profiles
            .read()
            .await
            .get(name)
            .map(|loaded| loaded.profile.clone())
    }

    /// One profile by name, with where it came from.
    pub async fn get_loaded(&self, name: &str) -> Option<LoadedProfile> {
        self.profiles.read().await.get(name).cloned()
    }

    /// Whether any loaded profile is only there because `dev_mode` is on.
    pub async fn has_dev_mode_profiles(&self) -> bool {
        self.profiles
            .read()
            .await
            .values()
            .any(|p| p.signature == briefcred_core::distribution::SignatureStatus::DevMode)
    }

    /// How many profiles are loaded.
    pub async fn len(&self) -> usize {
        self.profiles.read().await.len()
    }

    /// Whether no profile is loaded.
    pub async fn is_empty(&self) -> bool {
        self.profiles.read().await.is_empty()
    }
}

/// Watch [`ProfileStore::dir`] and reload on every debounced burst of changes.
///
/// Reloads once as soon as the watch is established, which closes the window
/// between the daemon's startup load and the watcher being ready: a profile
/// written in that gap would otherwise stay invisible until somebody touched
/// the directory again.
///
/// Returns once `shutdown` fires. `on_reload` is called with the outcome of
/// each attempt, which is how the daemon audits a load failure without this
/// module needing to know what an audit log is.
pub async fn watch<F>(
    store: Arc<ProfileStore>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    on_reload: F,
) where
    F: Fn(Reload) + Send + 'static,
{
    // `notify` calls back on its own thread, so events cross into async
    // through a channel rather than the callback touching the store directly.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(64);
    let watcher = spawn_watcher(store.dir(), tx);
    let _watcher = match watcher {
        Ok(watcher) => watcher,
        Err(err) => {
            eprintln!(
                "briefcred-daemon: cannot watch {}: {err}; profiles will not hot-reload",
                store.dir().display()
            );
            return;
        }
    };

    on_reload(store.reload().await);

    loop {
        tokio::select! {
            _ = crate::server::shutdown_requested(&mut shutdown) => return,
            event = rx.recv() => {
                if event.is_none() {
                    return;
                }
                // Drain whatever else arrived during the quiet period, so an
                // editor's save burst produces exactly one reload.
                tokio::time::sleep(DEBOUNCE).await;
                while rx.try_recv().is_ok() {}
                on_reload(store.reload().await);
            }
        }
    }
}

/// Start a recursive `notify` watcher that pings `tx` on every event.
///
/// Recursive because `profiles/registry/<name>/` holds fetched profiles, and a
/// `briefcred profile sync` that the daemon does not notice is a sync the user
/// has to restart the daemon to see.
///
/// The returned watcher must be kept alive: dropping it stops the watch.
fn spawn_watcher(
    dir: &Path,
    tx: tokio::sync::mpsc::Sender<()>,
) -> Result<notify::RecommendedWatcher, notify::Error> {
    use notify::Watcher as _;

    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        // A watch error is reported once and otherwise ignored: it must not
        // stop the daemon, and the next successful event still reloads.
        match event {
            Ok(_) => {
                // `try_send` rather than `blocking_send`: this runs on the
                // notify thread, and a full channel already means a reload is
                // pending, so dropping the ping loses nothing.
                let _ = tx.try_send(());
            }
            Err(err) => eprintln!("briefcred-daemon: profile watch error: {err}"),
        }
    })?;
    watcher.watch(dir, notify::RecursiveMode::Recursive)?;
    Ok(watcher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn store(dir: &Path) -> Arc<ProfileStore> {
        Arc::new(ProfileStore::new(dir, Registry::discover(), Trust::none()))
    }

    /// A successful reload of `count` profiles with nothing to complain about.
    fn loaded(count: usize) -> Reload {
        Reload::Loaded {
            count,
            warnings: Vec::new(),
        }
    }

    /// A store over `dir` that believes exactly one signing key.
    fn trusting_store(dir: &Path, key: &briefcred_core::minisign::SecretKey) -> Arc<ProfileStore> {
        Arc::new(ProfileStore::new(
            dir,
            Registry::discover(),
            Trust {
                roots: vec![key.public()],
                dev_mode: false,
            },
        ))
    }

    /// Write `yaml` into `dir/registry/acme/`, signed with `key` when given.
    fn publish(
        dir: &Path,
        file: &str,
        yaml: &str,
        key: Option<&briefcred_core::minisign::SecretKey>,
    ) {
        let registry_dir = dir.join("registry").join("acme");
        std::fs::create_dir_all(&registry_dir).unwrap();
        std::fs::write(registry_dir.join(file), yaml).unwrap();
        if let Some(key) = key {
            std::fs::write(
                registry_dir.join(format!("{file}.minisig")),
                key.sign(yaml.as_bytes(), file).unwrap(),
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn a_signed_registry_profile_loads_and_an_unsigned_one_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let (key, _) = briefcred_core::minisign::SecretKey::generate().unwrap();
        publish(dir.path(), "alpha.yaml", "name: alpha\n", Some(&key));
        publish(dir.path(), "beta.yaml", "name: beta\n", None);
        let store = trusting_store(dir.path(), &key);

        let Reload::Loaded { count, warnings } = store.reload().await else {
            panic!("the reload must succeed even with one bad file");
        };
        assert_eq!(count, 1);
        assert!(store.get("alpha").await.is_some());
        assert!(store.get("beta").await.is_none(), "unsigned must not load");
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            warnings[0].action,
            briefcred_core::distribution::TrustAction::Dropped
        );
        assert!(warnings[0].path.ends_with("beta.yaml"), "{warnings:?}");
        assert!(!store.has_dev_mode_profiles().await);
    }

    #[tokio::test]
    async fn a_registry_profile_whose_signature_stops_verifying_is_dropped_not_kept() {
        let dir = tempfile::tempdir().unwrap();
        let (key, _) = briefcred_core::minisign::SecretKey::generate().unwrap();
        publish(dir.path(), "alpha.yaml", "name: alpha\n", Some(&key));
        let store = trusting_store(dir.path(), &key);
        store.reload().await;
        assert_eq!(store.len().await, 1);

        // Someone edits the file under the daemon's feet. Last-good is what
        // protects a *typo*; it must not protect a tampered profile.
        std::fs::write(
            dir.path().join("registry").join("acme").join("alpha.yaml"),
            "name: alpha\ndescription: pwned\n",
        )
        .unwrap();
        let Reload::Loaded { count, warnings } = store.reload().await else {
            panic!("a trust failure is not a failed reload");
        };
        assert_eq!(count, 0, "the tampered profile must be gone, not stale");
        assert!(store.get("alpha").await.is_none());
        assert_eq!(
            warnings[0].action,
            briefcred_core::distribution::TrustAction::Dropped
        );
        assert!(warnings[0].reason.contains("invalid"), "{warnings:?}");
    }

    #[tokio::test]
    async fn dev_mode_loads_an_unverified_profile_and_marks_it() {
        let dir = tempfile::tempdir().unwrap();
        publish(dir.path(), "alpha.yaml", "name: alpha\n", None);
        let store = Arc::new(ProfileStore::new(
            dir.path(),
            Registry::discover(),
            Trust {
                roots: Vec::new(),
                dev_mode: true,
            },
        ));

        let Reload::Loaded { count, warnings } = store.reload().await else {
            panic!("dev_mode must load it");
        };
        assert_eq!(count, 1);
        assert_eq!(
            warnings[0].action,
            briefcred_core::distribution::TrustAction::LoadedDevMode
        );
        assert!(store.has_dev_mode_profiles().await);
        let loaded = store.get_loaded("alpha").await.unwrap();
        assert_eq!(
            loaded.signature,
            briefcred_core::distribution::SignatureStatus::DevMode
        );
    }

    #[tokio::test]
    async fn a_local_profile_overrides_a_registry_one_and_says_which() {
        use briefcred_core::distribution::ProfileSource;
        let dir = tempfile::tempdir().unwrap();
        let (key, _) = briefcred_core::minisign::SecretKey::generate().unwrap();
        publish(
            dir.path(),
            "alpha.yaml",
            "name: alpha\ndescription: theirs\n",
            Some(&key),
        );
        std::fs::write(
            dir.path().join("alpha.yaml"),
            "name: alpha\ndescription: mine\n",
        )
        .unwrap();
        let store = trusting_store(dir.path(), &key);
        store.reload().await;

        let loaded = store.get_loaded("alpha").await.unwrap();
        assert_eq!(loaded.source, ProfileSource::Local);
        assert_eq!(loaded.overrides.as_deref(), Some("acme"));
        assert_eq!(loaded.profile.description.as_deref(), Some("mine"));
        assert_eq!(store.len().await, 1, "an override is not a second profile");
    }

    #[tokio::test]
    async fn the_watcher_notices_a_sync_into_the_registry_subtree() {
        let dir = tempfile::tempdir().unwrap();
        let (key, _) = briefcred_core::minisign::SecretKey::generate().unwrap();
        // The subtree exists before the watch starts; what is under test is
        // that a file appearing *inside* it is noticed, which a non-recursive
        // watch on the profiles directory would miss.
        std::fs::create_dir_all(dir.path().join("registry").join("acme")).unwrap();
        let store = trusting_store(dir.path(), &key);
        store.reload().await;

        let (shutdown, _) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(watch(Arc::clone(&store), shutdown.subscribe(), |_| {}));

        publish(dir.path(), "alpha.yaml", "name: alpha\n", Some(&key));
        eventually("the synced profile to be loaded", || async {
            store.get("alpha").await.is_some()
        })
        .await;

        shutdown.send_replace(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }

    /// Wait for `check` to hold, polling rather than sleeping a fixed time so
    /// the test is neither flaky on a loaded machine nor slow on a fast one.
    ///
    /// Thirty seconds, not ten. These tests wait on a filesystem watcher, and
    /// what they assert is *that* a change is noticed and what the store does
    /// about it — never how quickly the operating system delivers the event.
    /// Ten seconds is enough on an idle machine and demonstrably not enough
    /// when the rest of the suite is running beside it, so a tighter budget
    /// buys no coverage and costs a spurious failure. A run that is genuinely
    /// broken never notices at all, and still fails here.
    async fn eventually<F, Fut>(what: &str, check: F)
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            if check().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("timed out waiting for {what}");
    }

    #[tokio::test]
    async fn a_fresh_store_is_empty_until_it_is_told_to_load() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.yaml"), "name: alpha\n").unwrap();
        let store = store(dir.path());

        assert!(store.is_empty().await);
        assert_eq!(store.reload().await, loaded(1));
        assert_eq!(store.len().await, 1);
        assert_eq!(store.get("alpha").await.unwrap().name, "alpha");
        assert!(store.get("absent").await.is_none());
    }

    #[tokio::test]
    async fn a_missing_directory_loads_as_empty_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir.path().join("profiles"));
        assert_eq!(store.reload().await, loaded(0));
    }

    #[tokio::test]
    async fn a_broken_file_leaves_the_last_good_set_in_place() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.yaml"), "name: alpha\n").unwrap();
        let store = store(dir.path());
        store.reload().await;

        std::fs::write(dir.path().join("b.yaml"), "name: beta\nbogus: 1\n").unwrap();
        let outcome = store.reload().await;

        match &outcome {
            Reload::Failed { message } => {
                assert!(message.contains("b.yaml"), "{message}");
                assert!(message.contains("bogus"), "{message}");
            }
            other => panic!("expected a failed reload, got {other:?}"),
        }
        assert_eq!(store.len().await, 1, "the good set must survive");
        assert!(store.get("alpha").await.is_some());
    }

    #[tokio::test]
    async fn a_file_naming_an_unregistered_minter_fails_the_whole_reload() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.yaml"),
            "name: alpha\ncredentials:\n  - name: db\n    kind: nope\n",
        )
        .unwrap();
        let store = store(dir.path());
        match store.reload().await {
            Reload::Failed { message } => {
                assert!(message.contains("unknown minter kind"), "{message}")
            }
            other => panic!("expected a failed reload, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_repaired_file_is_picked_up_by_the_next_reload() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.yaml"), "name: alpha\nbogus: 1\n").unwrap();
        let store = store(dir.path());
        assert!(matches!(store.reload().await, Reload::Failed { .. }));

        std::fs::write(dir.path().join("a.yaml"), "name: alpha\n").unwrap();
        assert_eq!(store.reload().await, loaded(1));
    }

    #[tokio::test]
    async fn the_watcher_reloads_a_profile_added_after_startup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.yaml"), "name: alpha\n").unwrap();
        let store = store(dir.path());
        store.reload().await;

        let (shutdown, _) = tokio::sync::watch::channel(false);
        let reloads = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reloads);
        let handle = tokio::spawn(watch(Arc::clone(&store), shutdown.subscribe(), move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        std::fs::write(dir.path().join("b.yaml"), "name: beta\n").unwrap();
        eventually("the new profile to be loaded", || async {
            store.get("beta").await.is_some()
        })
        .await;
        assert_eq!(store.len().await, 2);

        // An edit to an existing file is picked up too, not just a new file.
        std::fs::write(
            dir.path().join("b.yaml"),
            "name: beta\ndescription: edited\n",
        )
        .unwrap();
        eventually("the edit to be loaded", || async {
            store
                .get("beta")
                .await
                .and_then(|p| p.description)
                .as_deref()
                == Some("edited")
        })
        .await;

        // And so is a deletion, which is the case a naive "merge what you
        // find" loader gets wrong.
        std::fs::remove_file(dir.path().join("b.yaml")).unwrap();
        eventually("the deletion to be noticed", || async {
            store.get("beta").await.is_none()
        })
        .await;

        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the watcher must stop when shutdown is requested")
            .unwrap();
        assert!(reloads.load(Ordering::SeqCst) >= 3, "each change reloads");
    }

    #[tokio::test]
    async fn the_watcher_reports_a_broken_file_without_dropping_the_good_ones() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.yaml"), "name: alpha\n").unwrap();
        let store = store(dir.path());
        store.reload().await;

        let (shutdown, _) = tokio::sync::watch::channel(false);
        let failures = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&failures);
        let handle = tokio::spawn(watch(
            Arc::clone(&store),
            shutdown.subscribe(),
            move |outcome| {
                if matches!(outcome, Reload::Failed { .. }) {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            },
        ));

        std::fs::write(dir.path().join("b.yaml"), "name: beta\nbogus: 1\n").unwrap();
        eventually("the failure to be reported", || async {
            failures.load(Ordering::SeqCst) > 0
        })
        .await;
        assert_eq!(store.len().await, 1, "alpha must still be loaded");
        assert!(store.get("alpha").await.is_some());

        shutdown.send_replace(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }

    #[tokio::test]
    async fn an_unwatchable_directory_leaves_the_daemon_running() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir.path().join("does-not-exist"));
        let (shutdown, _) = tokio::sync::watch::channel(false);

        // Returns rather than panicking or looping: hot reload is a
        // convenience, and losing it must not cost the user their daemon.
        tokio::time::timeout(
            Duration::from_secs(5),
            watch(store, shutdown.subscribe(), |_| {}),
        )
        .await
        .expect("watch must give up rather than hang");
    }
}
