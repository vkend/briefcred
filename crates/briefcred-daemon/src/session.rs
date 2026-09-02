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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use briefcred_core::types::MintId;
use briefcred_core::{MasterSource, Profile};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::helper::MinterSet;
use crate::quota::TokenBucket;
use crate::revoke::PendingRevoke;

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
    /// Credentials minted against this session and not yet handed to the
    /// revoke queue, keyed by the principal they created.
    ///
    /// A `briefcred exec` that finishes normally reports back and its entries
    /// leave here for the queue. One that does not — the wrapper was killed,
    /// the terminal was closed — leaves them behind, and closing or evicting
    /// the session is what sweeps them up. That is the second of the three
    /// nets under a minted credential, after the queue and before the
    /// reconciler.
    pub mints: BTreeMap<MintId, PendingRevoke>,
    /// The public half of the client's per-session key, when it sent one.
    ///
    /// Raw 32 Ed25519 bytes. Every synthetic token the proxy signs for this
    /// session carries a thumbprint of it, and a `DPoP` proof on a proxied
    /// request is checked against it. `None` is a client that cannot make
    /// proofs, which is most of them; the proxy then accepts the token bare.
    pub pubkey: Option<[u8; 32]>,
    /// The helper processes this session started, one per minter kind.
    ///
    /// An `Arc` so a handler can hold it across the awaits of a mint without
    /// keeping the whole session map locked for the length of a round trip to
    /// a database.
    pub helpers: Arc<MinterSet>,
    /// This session's share of the profile's `quota`, when it has one.
    ///
    /// Per session rather than per profile, so two concurrent runs of the same
    /// profile get a budget each. Dying with the session is the point: a quota
    /// bounds one run's blast radius, and one that outlived its session would
    /// refuse work on behalf of something that no longer exists.
    pub quota: Option<Arc<TokenBucket>>,
    /// What this session has done through the HTTP proxy so far.
    ///
    /// An `Arc` of atomics rather than fields on the session, because the proxy
    /// reads and increments them per request and holding the session map's lock
    /// for the length of a forwarded response would serialise the whole proxy.
    pub http: Arc<HttpCounters>,
}

/// Per-session HTTP proxy counters, for the Cedar `context`.
///
/// Counters and not a quota: these never refuse anything on their own. They are
/// what lets a policy say "this session has had enough", which is a different
/// control from a rate — a byte budget is a total, and a bucket is a speed.
#[derive(Debug, Default)]
pub struct HttpCounters {
    requests: AtomicU64,
    resp_bytes: AtomicU64,
}

impl HttpCounters {
    /// Count one request, and report how many came *before* it.
    ///
    /// Before rather than including, so the first request of a session sees
    /// zero and `context.requests_so_far < 100` permits exactly one hundred.
    pub fn begin_request(&self) -> u64 {
        self.requests.fetch_add(1, Ordering::Relaxed)
    }

    /// Add the bytes one response returned to the client.
    pub fn add_resp_bytes(&self, bytes: u64) {
        self.resp_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Bytes returned to this session so far.
    pub fn resp_bytes(&self) -> u64 {
        self.resp_bytes.load(Ordering::Relaxed)
    }

    /// Requests this session has made so far.
    pub fn requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    /// Counters resumed at what a handed-over session had already done.
    ///
    /// A policy written as `context.resp_bytes_so_far < 4096` is a budget for
    /// the session, and a session whose counters reset on upgrade would be one
    /// an agent could refill by asking for a `daemon upgrade`.
    pub fn resumed(requests: u64, resp_bytes: u64) -> HttpCounters {
        HttpCounters {
            requests: AtomicU64::new(requests),
            resp_bytes: AtomicU64::new(resp_bytes),
        }
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("profile", &self.profile)
            .field("opened_at", &self.opened_at)
            .field("last_used", &self.last_used)
            .field("masters", &self.masters.keys().collect::<Vec<_>>())
            .field("mints", &self.mints.keys().collect::<Vec<_>>())
            .field("bound_to_a_session_key", &self.pubkey.is_some())
            .field("quota", &self.quota)
            .field("http", &self.http)
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

/// How long before `now` `then` was, in milliseconds.
///
/// The handoff carries ages rather than instants: both are measured against a
/// monotonic clock that starts with the process, so an instant from the old
/// daemon means nothing in the new one.
fn millis_since(now: Duration, then: Duration) -> u64 {
    now.saturating_sub(then)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
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
        helper_dirs: Vec<std::path::PathBuf>,
        pubkey: Option<[u8; 32]>,
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
            mints: BTreeMap::new(),
            pubkey,
            helpers: Arc::new(MinterSet::new(helper_dirs)),
            // Built here, from the profile as it stood when the session was
            // opened. A profile edited mid-session does not silently hand a
            // running agent a bigger budget.
            quota: profile
                .quota
                .as_ref()
                .map(|quota| Arc::new(TokenBucket::new(quota, Arc::clone(&self.clock)))),
            http: Arc::new(HttpCounters::default()),
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
    /// Returns the whole session rather than just its name: the caller has to
    /// stop the helper processes it started and sweep any mints that no
    /// `ExecDone` ever accounted for, and both of those need the session.
    /// Dropping the returned value is what zeroises the masters, so a caller
    /// that ignores it still gets the wipe.
    pub async fn close(&self, id: &str) -> Result<Session, SessionError> {
        // Removing drops the `Session` unless the caller keeps it, and
        // dropping it zeroises every master it holds. There is deliberately no
        // "closed" flag: a session that still exists is a master that still
        // exists.
        self.sessions
            .write()
            .await
            .remove(id)
            .ok_or_else(|| SessionError::NoSuchSession(id.to_string()))
    }

    /// Record what one `Exec` minted, so a session close can still revoke it.
    pub async fn record_mints(
        &self,
        id: &str,
        mints: Vec<PendingRevoke>,
    ) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| SessionError::NoSuchSession(id.to_string()))?;
        for mint in mints {
            session.mints.insert(mint.mint_id.clone(), mint);
        }
        Ok(())
    }

    /// Take the entries for `mint_ids` off a session, for the revoke queue.
    ///
    /// Silently ignores an identifier the session does not hold: a client that
    /// reports a mint twice, or reports one from another session, must not be
    /// able to make the daemon revoke something on its say-so.
    pub async fn take_mints(
        &self,
        id: &str,
        mint_ids: &[MintId],
    ) -> Result<Vec<PendingRevoke>, SessionError> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| SessionError::NoSuchSession(id.to_string()))?;
        Ok(mint_ids
            .iter()
            .filter_map(|mint_id| session.mints.remove(mint_id))
            .collect())
    }

    /// Run `f` against an open session's masters and profile name.
    pub async fn with_session<T>(
        &self,
        id: &str,
        f: impl FnOnce(&Session) -> T,
    ) -> Result<T, SessionError> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(id)
            .ok_or_else(|| SessionError::NoSuchSession(id.to_string()))?;
        Ok(f(session))
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
    pub async fn evict_idle(&self) -> Vec<Session> {
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
            .filter_map(|id| sessions.remove(&id))
            .collect()
    }

    /// The `(id, profile)` of every open session, for shutdown auditing.
    pub async fn open_sessions(&self) -> Vec<(String, String)> {
        self.sessions
            .read()
            .await
            .iter()
            .map(|(id, s)| (id.clone(), s.profile.clone()))
            .collect()
    }

    /// Every open session, as the handoff blob carries it.
    ///
    /// `seal` encrypts one master to the daemon taking over. It is a parameter
    /// rather than something this module does, so the rule that a master leaves
    /// here only as ciphertext is visible at the one call site that matters.
    pub async fn export(
        &self,
        seal: &crate::handoff::Sealer,
    ) -> crate::error::Result<Vec<crate::handoff::SessionBlob>> {
        let now = self.clock.now();
        let sessions = self.sessions.read().await;
        let mut out = Vec::with_capacity(sessions.len());
        for session in sessions.values() {
            let mut masters_enc = BTreeMap::new();
            for (key, master) in &session.masters {
                masters_enc.insert(key.clone(), seal.seal(master.as_bytes())?);
            }
            out.push(crate::handoff::SessionBlob {
                id: session.id.clone(),
                profile: session.profile.clone(),
                opened_at: millis_since(now, session.opened_at),
                last_used: millis_since(now, session.last_used),
                mints: session.mints.values().cloned().collect(),
                quota_state: session.quota.as_ref().map(|bucket| {
                    let (tokens, spent) = bucket.snapshot();
                    crate::handoff::QuotaState { tokens, spent }
                }),
                http_counters: crate::handoff::HttpCounterState {
                    requests: session.http.requests(),
                    resp_bytes: session.http.resp_bytes(),
                },
                masters_enc,
                session_pubkey: session.pubkey.as_ref().map(|key| {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD.encode(key)
                }),
            });
        }
        Ok(out)
    }

    /// Insert sessions rebuilt from a handoff.
    ///
    /// Insert rather than replace: a daemon adopting a handoff has not served
    /// anything yet, so there is nothing to replace — and making this additive
    /// means it can never silently drop a session it has already opened.
    pub async fn adopt(&self, sessions: Vec<Session>) {
        let mut open = self.sessions.write().await;
        for session in sessions {
            open.insert(session.id.clone(), session);
        }
    }

    /// Take every session, wiping every master. Used at shutdown.
    ///
    /// Returns them so the caller can stop their helpers and queue whatever
    /// they had minted; dropping the result is still a complete wipe.
    pub async fn close_all(&self) -> Vec<Session> {
        let mut sessions = self.sessions.write().await;
        std::mem::take(&mut *sessions).into_values().collect()
    }
}

/// Evict idle sessions every [`EVICTION_INTERVAL`] until shutdown.
///
/// `on_evict` is called with each evicted `(id, profile)`, which is how the
/// daemon audits an eviction without this module knowing about audit logs.
pub async fn evict_loop<F, Fut>(
    store: Arc<SessionStore>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    on_evict: F,
) where
    F: Fn(Session) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let mut ticker = tokio::time::interval(EVICTION_INTERVAL);
    // `interval` fires immediately, and nothing can be idle at startup.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = crate::server::shutdown_requested(&mut shutdown) => return,
            _ = ticker.tick() => {
                for session in store.evict_idle().await {
                    on_evict(session).await;
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

        let (id, _) = store
            .open(&profile, &source(), Vec::new(), None)
            .await
            .unwrap();
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
        store
            .open(&profile, &source, Vec::new(), None)
            .await
            .unwrap();
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
        let err = store
            .open(&profile, &source(), Vec::new(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, SessionError::Master(_)), "{err}");
        assert!(err.to_string().contains("absent"), "{err}");
        assert!(store.is_empty().await, "no half-open session may survive");
    }

    #[tokio::test]
    async fn session_ids_are_unguessable_and_never_repeat() {
        let store = store(TestClock::new(), Duration::from_secs(1800));
        let mut ids = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let (id, _) = store
                .open(&one_credential(), &source(), Vec::new(), None)
                .await
                .unwrap();
            assert_eq!(id.len(), SESSION_ID_BYTES * 2, "{id}");
            assert!(id.bytes().all(|b| b.is_ascii_hexdigit()), "{id}");
            assert!(ids.insert(id), "session ids must not repeat");
        }
    }

    #[tokio::test]
    async fn closing_a_session_removes_it_at_once() {
        let store = store(TestClock::new(), Duration::from_secs(1800));
        let (id, _) = store
            .open(&one_credential(), &source(), Vec::new(), None)
            .await
            .unwrap();

        assert_eq!(store.close(&id).await.unwrap().profile, "dev");
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
        let (id, _) = store
            .open(&one_credential(), &source(), Vec::new(), None)
            .await
            .unwrap();

        clock.advance(Duration::from_secs(1799));
        assert!(store.evict_idle().await.is_empty(), "not idle long enough");
        assert!(store.contains(&id).await);

        clock.advance(Duration::from_secs(1));
        let evicted = store.evict_idle().await;
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].id, id);
        assert_eq!(evicted[0].profile, "dev");
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
        let (id, _) = store
            .open(&one_credential(), &source(), Vec::new(), None)
            .await
            .unwrap();

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
        let (stale, _) = store
            .open(&one_credential(), &source(), Vec::new(), None)
            .await
            .unwrap();
        clock.advance(Duration::from_secs(1000));
        let (fresh, _) = store
            .open(&one_credential(), &source(), Vec::new(), None)
            .await
            .unwrap();
        clock.advance(Duration::from_secs(900));

        let evicted = store.evict_idle().await;
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].id, stale);
        assert!(store.contains(&fresh).await);
    }

    #[tokio::test]
    async fn touching_an_evicted_session_says_it_is_gone() {
        let clock = TestClock::new();
        let store = store(clock.clone(), Duration::from_secs(60));
        let (id, _) = store
            .open(&one_credential(), &source(), Vec::new(), None)
            .await
            .unwrap();
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
        let (id, opened_expiry) = store
            .open(&one_credential(), &source(), Vec::new(), None)
            .await
            .unwrap();

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
            store
                .open(&one_credential(), &source(), Vec::new(), None)
                .await
                .unwrap();
        }
        assert_eq!(store.close_all().await.len(), 3);
        assert!(store.is_empty().await);
        assert!(store.close_all().await.is_empty());
    }

    #[tokio::test]
    async fn a_session_never_debug_prints_the_masters_it_holds() {
        let store = store(TestClock::new(), Duration::from_secs(1800));
        store
            .open(&one_credential(), &source(), Vec::new(), None)
            .await
            .unwrap();

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
            .open(&profile("name: dev\n"), &Explodes, Vec::new(), None)
            .await
            .unwrap();
        assert!(store.contains(&id).await);
    }

    #[tokio::test]
    async fn a_session_gets_its_own_bucket_from_the_profile() {
        let clock = TestClock::new();
        let store = store(clock.clone(), Duration::from_secs(1800));
        let profile = profile("name: dev\nquota:\n  rate: 10\n  burst: 2\n");

        let (first, _) = store
            .open(&profile, &source(), Vec::new(), None)
            .await
            .unwrap();
        let (second, _) = store
            .open(&profile, &source(), Vec::new(), None)
            .await
            .unwrap();

        let bucket = |id: &str| {
            let store = &store;
            let id = id.to_string();
            async move {
                store
                    .with_session(&id, |s| s.quota.clone())
                    .await
                    .unwrap()
                    .expect("the profile declares a quota")
            }
        };

        let first_bucket = bucket(&first).await;
        first_bucket.charge().outcome.unwrap();
        first_bucket.charge().outcome.unwrap();
        assert!(
            first_bucket.charge().outcome.is_err(),
            "the first session is spent"
        );

        // The second session has its own budget: one agent's burst must not be
        // another agent's refusal.
        assert!(bucket(&second).await.charge().outcome.is_ok());
    }

    #[tokio::test]
    async fn a_session_of_an_unmetered_profile_has_no_bucket() {
        let store = store(TestClock::new(), Duration::from_secs(1800));
        let (id, _) = store
            .open(&one_credential(), &source(), Vec::new(), None)
            .await
            .unwrap();
        assert!(store
            .with_session(&id, |s| s.quota.is_none())
            .await
            .unwrap());
    }

    #[test]
    fn the_http_counters_report_what_came_before_each_request() {
        let counters = HttpCounters::default();
        assert_eq!(counters.begin_request(), 0, "the first request sees none");
        assert_eq!(counters.begin_request(), 1);
        assert_eq!(counters.requests(), 2);

        assert_eq!(counters.resp_bytes(), 0);
        counters.add_resp_bytes(400);
        counters.add_resp_bytes(600);
        assert_eq!(counters.resp_bytes(), 1000);
    }

    #[tokio::test]
    async fn the_eviction_loop_stops_when_shutdown_is_requested() {
        let store = Arc::new(store(TestClock::new(), Duration::from_secs(1800)));
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(evict_loop(store, shutdown.subscribe(), |_session| async {}));

        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the eviction loop must stop on shutdown")
            .unwrap();
    }
}
