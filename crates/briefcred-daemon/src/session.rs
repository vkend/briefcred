//! Open sessions: the masters a profile needs, held for as long as it is used.
//!
//! A session is the daemon's record that a human proved presence for a profile
//! and that the master credentials for it are in memory. It is the most
//! dangerous state the daemon holds, so the whole module is built around one
//! rule: **a master exists in memory for the shortest time that still lets the
//! work happen, and is wiped the moment it does not.**
//!
//! That rule shows up three ways:
//!
//! - Masters live in [`Zeroizing<String>`], so dropping a session wipes them.
//! - [`SessionStore::close`] drops the session at once rather than marking it
//!   dead, so an explicit close is an immediate wipe.
//! - [`SessionStore::evict_idle`] runs on a timer and drops sessions nobody has
//!   touched, so a forgotten terminal does not leave a master resident for the
//!   life of the login.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use briefcred_core::types::MintId;
use briefcred_core::{MasterSource, Profile};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::clock::Clock;

/// How often the eviction task looks for idle sessions.
pub const EVICTION_INTERVAL: Duration = Duration::from_secs(30);

/// Bytes of entropy in a session identifier, before hex.
const SESSION_ID_BYTES: usize = 16;

/// One open session.
///
/// `Debug` is written by hand: `masters` must never reach a log line, and the
/// derived implementation would print every one of them.
pub struct Session {
    /// The handle the client presents on later requests.
    pub id: String,
    /// The profile this session was opened for.
    pub profile: String,
    /// Monotonic time the session was opened.
    pub opened_at: Duration,
    /// Monotonic time of the most recent request against it.
    pub last_used: Duration,
    /// The master credential for each of the profile's `source_key`s.
    pub masters: BTreeMap<String, Zeroizing<String>>,
    /// Credentials minted against this session, for revoke at close.
    ///
    /// Empty until Phase 3b, which is what does the minting.
    pub mints: Vec<MintId>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("profile", &self.profile)
            .field("opened_at", &self.opened_at)
            .field("last_used", &self.last_used)
            .field("masters", &self.masters.keys().collect::<Vec<_>>())
            .field("mints", &self.mints)
            .finish()
    }
}

impl Session {
    /// Whether nothing has touched this session for `idle_for`.
    pub fn is_idle(&self, now: Duration, idle_for: Duration) -> bool {
        now.saturating_sub(self.last_used) >= idle_for
    }

    /// When this session will be evicted if nothing touches it again.
    pub fn expires_at(&self, now: Duration, idle_for: Duration) -> time::OffsetDateTime {
        let remaining = idle_for.saturating_sub(now.saturating_sub(self.last_used));
        time::OffsetDateTime::now_utc() + remaining
    }
}

/// A fresh, unguessable session identifier.
///
/// Drawn from the OS CSPRNG rather than a counter: a session id is a bearer
/// handle, so a predictable one would let any process on the machine use a
/// session it never unlocked.
fn generate_id() -> String {
    let mut bytes = [0u8; SESSION_ID_BYTES];
    getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable");
    hex::encode(bytes)
}

/// Why a session could not be opened or found.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// No profile of that name is loaded.
    #[error("no profile `{0}`")]
    NoSuchProfile(String),

    /// The session id is unknown, or its session has already been evicted.
    #[error("no open session `{0}`; it may have been closed or evicted while idle")]
    NoSuchSession(String),

    /// A master credential could not be fetched.
    #[error("{0}")]
    Master(String),
}

/// Every open session, keyed by identifier.
#[derive(Debug)]
pub struct SessionStore {
    clock: Arc<dyn Clock>,
    idle_for: Duration,
    sessions: RwLock<BTreeMap<String, Session>>,
}

impl SessionStore {
    /// A store that evicts sessions untouched for `idle_for`.
    pub fn new(clock: Arc<dyn Clock>, idle_for: Duration) -> SessionStore {
        SessionStore {
            clock,
            idle_for,
            sessions: RwLock::new(BTreeMap::new()),
        }
    }

    /// How long a session may sit unused before eviction.
    pub fn idle_for(&self) -> Duration {
        self.idle_for
    }

    /// Open a session for `profile`, fetching every master it declares.
    ///
    /// The unlock gate is the caller's business: this runs only after presence
    /// has been proved. A single missing master fails the whole open, because
    /// a half-provisioned session would fail later at mint time with a much
    /// less obvious message.
    pub async fn open(
        &self,
        profile: &Profile,
        source: &dyn MasterSource,
    ) -> Result<(String, time::OffsetDateTime), SessionError> {
        let mut masters = BTreeMap::new();
        for spec in &profile.credentials {
            let key = spec.source_key();
            if masters.contains_key(key) {
                continue;
            }
            let master = source
                .fetch(key)
                .await
                .map_err(|e| SessionError::Master(e.to_string()))?;
            masters.insert(key.to_string(), master);
        }

        let now = self.clock.now();
        let session = Session {
            id: generate_id(),
            profile: profile.name.clone(),
            opened_at: now,
            last_used: now,
            masters,
            mints: Vec::new(),
        };
        let id = session.id.clone();
        let expires_at = session.expires_at(now, self.idle_for);
        self.sessions.write().await.insert(id.clone(), session);
        Ok((id, expires_at))
    }

    /// Mark `id` as used now, and report when it will next expire.
    ///
    /// Every request against a session goes through here, which is what makes
    /// "idle" mean idle rather than merely old.
    pub async fn touch(&self, id: &str) -> Result<time::OffsetDateTime, SessionError> {
        let now = self.clock.now();
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| SessionError::NoSuchSession(id.to_string()))?;
        session.last_used = now;
        Ok(session.expires_at(now, self.idle_for))
    }

    /// Close `id`, wiping its masters immediately.
    ///
    /// Returns the profile the session belonged to, for the audit row.
    pub async fn close(&self, id: &str) -> Result<String, SessionError> {
        // Removing drops the `Session`, and dropping it zeroises every master
        // it holds. There is deliberately no "closed" flag: a session that
        // still exists is a master that still exists.
        let session = self
            .sessions
            .write()
            .await
            .remove(id)
            .ok_or_else(|| SessionError::NoSuchSession(id.to_string()))?;
        Ok(session.profile)
    }

    /// Whether `id` is currently open.
    pub async fn contains(&self, id: &str) -> bool {
        self.sessions.read().await.contains_key(id)
    }

    /// How many sessions are open.
    pub async fn len(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Whether no session is open.
    pub async fn is_empty(&self) -> bool {
        self.sessions.read().await.is_empty()
    }

    /// The profile a session was opened for, if it is still open.
    pub async fn profile_of(&self, id: &str) -> Option<String> {
        self.sessions
            .read()
            .await
            .get(id)
            .map(|s| s.profile.clone())
    }

    /// Drop every session nobody has touched for [`SessionStore::idle_for`].
    ///
    /// Returns the `(id, profile)` of each evicted session so the caller can
    /// audit it. The masters are wiped by the time this returns.
    pub async fn evict_idle(&self) -> Vec<(String, String)> {
        let now = self.clock.now();
        let idle_for = self.idle_for;
        let mut sessions = self.sessions.write().await;

        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.is_idle(now, idle_for))
            .map(|(id, _)| id.clone())
            .collect();

        expired
            .into_iter()
            .filter_map(|id| sessions.remove(&id).map(|s| (id, s.profile)))
            .collect()
    }

    /// Close every session, wiping every master. Used at shutdown.
    pub async fn close_all(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let count = sessions.len();
        sessions.clear();
        count
    }
}

/// Evict idle sessions every [`EVICTION_INTERVAL`] until shutdown.
///
/// `on_evict` is called with each evicted `(id, profile)`, which is how the
/// daemon audits an eviction without this module knowing about audit logs.
pub async fn evict_loop<F>(
    store: Arc<SessionStore>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    on_evict: F,
) where
    F: Fn(&str, &str) + Send + 'static,
{
    let mut ticker = tokio::time::interval(EVICTION_INTERVAL);
    // `interval` fires immediately, and nothing can be idle at startup.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = crate::server::shutdown_requested(&mut shutdown) => return,
            _ = ticker.tick() => {
                for (id, profile) in store.evict_idle().await {
                    on_evict(&id, &profile);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use briefcred_core::source::MemorySource;

    fn profile(yaml: &str) -> Profile {
        Profile::from_yaml_str(yaml).unwrap()
    }

    fn one_credential() -> Profile {
        profile("name: dev\ncredentials:\n  - name: db\n    kind: postgres-dynamic\n")
    }

    fn source() -> MemorySource {
        MemorySource::new([
            ("db".to_string(), "master-secret".to_string()),
            ("shared".to_string(), "shared-secret".to_string()),
        ])
    }

    fn store(clock: Arc<TestClock>, idle_for: Duration) -> SessionStore {
        SessionStore::new(clock, idle_for)
    }

    #[tokio::test]
    async fn opening_a_session_fetches_a_master_for_every_credential() {
        let clock = TestClock::new();
        let store = store(clock, Duration::from_secs(1800));
        let profile = profile(
            "\
name: dev
credentials:
  - name: db
    kind: postgres-dynamic
  - name: warehouse
    kind: postgres-dynamic
    source_key: shared
",
        );

        let (id, _) = store.open(&profile, &source()).await.unwrap();
        assert!(store.contains(&id).await);
        assert_eq!(store.profile_of(&id).await.as_deref(), Some("dev"));
    }

    #[tokio::test]
    async fn two_credentials_sharing_a_source_key_fetch_it_once() {
        /// Counts fetches so the test proves deduplication rather than merely
        /// that the open succeeded.
        #[derive(Debug, Default)]
        struct CountingSource(std::sync::atomic::AtomicUsize);

        #[async_trait::async_trait]
        impl MasterSource for CountingSource {
            async fn fetch(&self, _key: &str) -> briefcred_core::Result<Zeroizing<String>> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(Zeroizing::new("secret".to_string()))
            }
            fn location(&self) -> String {
                "counting".to_string()
            }
        }

        let profile = profile(
            "\
name: dev
credentials:
  - name: a
    kind: postgres-dynamic
    source_key: shared
  - name: b
    kind: postgres-dynamic
    source_key: shared
",
        );
        let source = CountingSource::default();
        let store = store(TestClock::new(), Duration::from_secs(1800));
        store.open(&profile, &source).await.unwrap();
        assert_eq!(source.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_missing_master_fails_the_whole_open_rather_than_half_of_it() {
        let store = store(TestClock::new(), Duration::from_secs(1800));
        let profile = profile(
            "\
name: dev
credentials:
  - name: db
    kind: postgres-dynamic
  - name: absent
    kind: postgres-dynamic
",
        );
        let err = store.open(&profile, &source()).await.unwrap_err();
        assert!(matches!(err, SessionError::Master(_)), "{err}");
        assert!(err.to_string().contains("absent"), "{err}");
        assert!(store.is_empty().await, "no half-open session may survive");
    }

    #[tokio::test]
    async fn session_ids_are_unguessable_and_never_repeat() {
        let store = store(TestClock::new(), Duration::from_secs(1800));
        let mut ids = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let (id, _) = store.open(&one_credential(), &source()).await.unwrap();
            assert_eq!(id.len(), SESSION_ID_BYTES * 2, "{id}");
            assert!(id.bytes().all(|b| b.is_ascii_hexdigit()), "{id}");
            assert!(ids.insert(id), "session ids must not repeat");
        }
    }

    #[tokio::test]
    async fn closing_a_session_removes_it_at_once() {
        let store = store(TestClock::new(), Duration::from_secs(1800));
        let (id, _) = store.open(&one_credential(), &source()).await.unwrap();

        assert_eq!(store.close(&id).await.unwrap(), "dev");
        assert!(!store.contains(&id).await);
        assert!(store.is_empty().await);

        // Closing twice is an error rather than a silent success: a client
        // closing an id it does not own should hear about it.
        assert!(matches!(
            store.close(&id).await.unwrap_err(),
            SessionError::NoSuchSession(_)
        ));
    }

    #[tokio::test]
    async fn a_session_is_evicted_once_it_has_been_idle_for_the_configured_time() {
        let clock = TestClock::new();
        let store = store(clock.clone(), Duration::from_secs(1800));
        let (id, _) = store.open(&one_credential(), &source()).await.unwrap();

        clock.advance(Duration::from_secs(1799));
        assert!(store.evict_idle().await.is_empty(), "not idle long enough");
        assert!(store.contains(&id).await);

        clock.advance(Duration::from_secs(1));
        let evicted = store.evict_idle().await;
        assert_eq!(evicted, vec![(id.clone(), "dev".to_string())]);
        assert!(!store.contains(&id).await);
        assert!(
            store.evict_idle().await.is_empty(),
            "eviction is not repeated"
        );
    }

    #[tokio::test]
    async fn using_a_session_postpones_its_eviction() {
        let clock = TestClock::new();
        let store = store(clock.clone(), Duration::from_secs(1800));
        let (id, _) = store.open(&one_credential(), &source()).await.unwrap();

        for _ in 0..5 {
            clock.advance(Duration::from_secs(1700));
            store.touch(&id).await.unwrap();
            assert!(store.evict_idle().await.is_empty());
        }
        assert!(store.contains(&id).await, "a session in use must survive");

        clock.advance(Duration::from_secs(1800));
        assert_eq!(store.evict_idle().await.len(), 1);
    }

    #[tokio::test]
    async fn eviction_takes_only_the_idle_sessions() {
        let clock = TestClock::new();
        let store = store(clock.clone(), Duration::from_secs(1800));
        let (stale, _) = store.open(&one_credential(), &source()).await.unwrap();
        clock.advance(Duration::from_secs(1000));
        let (fresh, _) = store.open(&one_credential(), &source()).await.unwrap();
        clock.advance(Duration::from_secs(900));

        let evicted = store.evict_idle().await;
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].0, stale);
        assert!(store.contains(&fresh).await);
    }

    #[tokio::test]
    async fn touching_an_evicted_session_says_it_is_gone() {
        let clock = TestClock::new();
        let store = store(clock.clone(), Duration::from_secs(60));
        let (id, _) = store.open(&one_credential(), &source()).await.unwrap();
        clock.advance(Duration::from_secs(60));
        store.evict_idle().await;

        let err = store.touch(&id).await.unwrap_err();
        assert!(matches!(err, SessionError::NoSuchSession(_)), "{err}");
        assert!(err.to_string().contains("evicted"), "{err}");
    }

    #[tokio::test]
    async fn the_reported_expiry_moves_forward_as_the_session_is_used() {
        let clock = TestClock::new();
        let store = store(clock.clone(), Duration::from_secs(1800));
        let (id, opened_expiry) = store.open(&one_credential(), &source()).await.unwrap();

        clock.advance(Duration::from_secs(600));
        let touched_expiry = store.touch(&id).await.unwrap();
        assert!(
            touched_expiry > opened_expiry,
            "{touched_expiry} must be later than {opened_expiry}"
        );
    }

    #[tokio::test]
    async fn closing_every_session_reports_how_many_it_wiped() {
        let store = store(TestClock::new(), Duration::from_secs(1800));
        for _ in 0..3 {
            store.open(&one_credential(), &source()).await.unwrap();
        }
        assert_eq!(store.close_all().await, 3);
        assert!(store.is_empty().await);
        assert_eq!(store.close_all().await, 0);
    }

    #[tokio::test]
    async fn a_session_never_debug_prints_the_masters_it_holds() {
        let store = store(TestClock::new(), Duration::from_secs(1800));
        store.open(&one_credential(), &source()).await.unwrap();

        let rendered = format!("{:?}", store.sessions.read().await);
        assert!(!rendered.contains("master-secret"), "{rendered}");
        assert!(rendered.contains("\"db\""), "{rendered}");
    }

    #[tokio::test]
    async fn a_profile_with_no_credentials_opens_without_touching_the_source() {
        /// Fails every fetch, so an open that consults it cannot succeed.
        #[derive(Debug)]
        struct Explodes;

        #[async_trait::async_trait]
        impl MasterSource for Explodes {
            async fn fetch(&self, key: &str) -> briefcred_core::Result<Zeroizing<String>> {
                panic!("nothing should have been fetched, but `{key}` was");
            }
            fn location(&self) -> String {
                "explodes".to_string()
            }
        }

        let store = store(TestClock::new(), Duration::from_secs(1800));
        let (id, _) = store
            .open(&profile("name: dev\n"), &Explodes)
            .await
            .unwrap();
        assert!(store.contains(&id).await);
    }

    #[tokio::test]
    async fn the_eviction_loop_stops_when_shutdown_is_requested() {
        let store = Arc::new(store(TestClock::new(), Duration::from_secs(1800)));
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(evict_loop(store, shutdown.subscribe(), |_, _| {}));

        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the eviction loop must stop on shutdown")
            .unwrap();
    }
}
