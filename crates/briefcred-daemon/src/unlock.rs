//! The presence gate: proving a human is at the machine before it mints.
//!
//! Every session goes through an [`UnlockGate`] before a single master
//! credential is fetched. On macOS that is `LAContext` — Touch ID, falling
//! back to the login password — and the whole point of briefcred's threat
//! model is that malware which has already stolen the user's shell cannot
//! satisfy it silently.
//!
//! Three properties matter more than the mechanics:
//!
//! - **A gate that cannot run must fail closed.** Over SSH there is no window
//!   server to draw the prompt on, so [`UnlockError::NoAquaSession`] is
//!   returned rather than the prompt being skipped.
//! - **The prompt never blocks the reactor.** `evaluatePolicy` is a blocking,
//!   run-loop-driven call, so it runs on a dedicated OS thread and comes back
//!   through a oneshot.
//! - **The cache is per profile.** Unlocking a low-value profile must not open
//!   a high-value one, so [`UnlockCache`] is keyed on the profile name and
//!   honours that profile's own `unlock.cache_secs`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use briefcred_core::profile::UnlockPolicy;
use tokio::sync::Mutex;

use crate::clock::Clock;

/// Set to `1` to force [`UnlockError::NoAquaSession`] from the system gate.
///
/// The tests cannot create or destroy a window server, so this is how the
/// headless path is exercised. It only ever makes the gate stricter, so a
/// hostile process gains nothing by setting it.
pub const FORCE_NO_AQUA_ENV: &str = "BRIEFCRED_FORCE_NO_AQUA";

/// Why an unlock did not succeed.
///
/// Every variant is a normal, auditable outcome rather than a daemon fault,
/// which is why the gate returns this rather than the crate error type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnlockError {
    /// The user dismissed the prompt.
    #[error("the unlock prompt was cancelled")]
    Cancelled,

    /// The user tried and did not authenticate.
    #[error("unlock failed: {0}")]
    Failed(String),

    /// There is no graphical session to draw a prompt on.
    ///
    /// The usual cause is an SSH login. briefcred refuses rather than falling
    /// back to something weaker, because a fallback anyone could reach over
    /// SSH would be the whole guarantee gone.
    #[error(
        "no graphical session to show the unlock prompt in; \
         run briefcred from a local login, or set `unlock.policy: none` on this profile \
         if it is meant to be unattended"
    )]
    NoAquaSession,

    /// This platform has no presence check briefcred knows how to run.
    #[error("this platform has no unlock mechanism; set `unlock.policy: none` on the profile")]
    Unsupported,
}

impl UnlockError {
    /// Stable machine-readable name, for audit rows and `Response::Locked`.
    pub fn reason(&self) -> &'static str {
        match self {
            UnlockError::Cancelled => "cancelled",
            UnlockError::Failed(_) => "failed",
            UnlockError::NoAquaSession => "no_aqua_session",
            UnlockError::Unsupported => "unsupported",
        }
    }
}

/// A presence check.
#[async_trait]
pub trait UnlockGate: Send + Sync + std::fmt::Debug {
    /// Ask the user to prove presence for `policy`.
    ///
    /// `reason` is shown to the user, so it names the profile rather than the
    /// mechanism. [`UnlockPolicy::None`] must succeed without prompting.
    async fn unlock(&self, policy: UnlockPolicy, reason: &str) -> Result<(), UnlockError>;
}

/// The gate this platform actually has.
///
/// macOS uses `LAContext`. Everywhere else there is nothing briefcred can rely
/// on being present, so anything stricter than [`UnlockPolicy::None`] is
/// [`UnlockError::Unsupported`] rather than a silent pass.
#[derive(Debug, Default)]
pub struct SystemUnlockGate;

impl SystemUnlockGate {
    /// The gate for the running platform.
    pub fn new() -> SystemUnlockGate {
        SystemUnlockGate
    }
}

#[async_trait]
impl UnlockGate for SystemUnlockGate {
    async fn unlock(&self, policy: UnlockPolicy, reason: &str) -> Result<(), UnlockError> {
        if policy == UnlockPolicy::None {
            return Ok(());
        }
        if no_aqua_session() {
            return Err(UnlockError::NoAquaSession);
        }
        platform_unlock(policy, reason).await
    }
}

/// Whether this process has no graphical session to draw a prompt in.
///
/// Checked before the prompt rather than after: `LAContext` over SSH reports a
/// generic failure that is indistinguishable from a wrong password, and
/// telling the user "authentication failed" when the real problem is "you are
/// on SSH" wastes an afternoon.
pub fn no_aqua_session() -> bool {
    if std::env::var(FORCE_NO_AQUA_ENV).as_deref() == Ok("1") {
        return true;
    }
    // An SSH login has no window server of its own even when the console user
    // is logged in graphically, and the prompt would be drawn on their screen
    // rather than the remote user's — which is worse than refusing.
    if std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some() {
        return true;
    }
    !has_graphic_access()
}

/// `SessionGetInfo` from `Security/AuthSession.h`: does the caller's security
/// session have a graphical subsystem to draw a prompt on?
///
/// This is the authoritative answer, and it is right in cases the environment
/// is not: a `launchd` agent in a background session has no `SSH_CONNECTION`
/// set and still cannot show a window.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn has_graphic_access() -> bool {
    /// `callerSecuritySession`: the session this process belongs to.
    const CALLER_SECURITY_SESSION: u32 = u32::MAX;
    /// `sessionHasGraphicAccess`.
    const SESSION_HAS_GRAPHIC_ACCESS: u32 = 0x0010;
    /// `errSessionSuccess`.
    const SESSION_SUCCESS: i32 = 0;

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SessionGetInfo(session: u32, session_id: *mut u32, attributes: *mut u32) -> i32;
    }

    let mut id: u32 = 0;
    let mut attributes: u32 = 0;
    // SAFETY: both out-parameters are live, correctly typed, and initialised;
    // the function writes at most one value to each and returns a status.
    let status = unsafe { SessionGetInfo(CALLER_SECURITY_SESSION, &mut id, &mut attributes) };
    // A session we cannot interrogate is one we must not assume has a screen.
    status == SESSION_SUCCESS && attributes & SESSION_HAS_GRAPHIC_ACCESS != 0
}

/// Off macOS there is no session concept to consult; the policy check in
/// [`SystemUnlockGate`] refuses anything but `none` anyway.
#[cfg(not(target_os = "macos"))]
fn has_graphic_access() -> bool {
    true
}

/// Run the platform's own prompt.
#[cfg(target_os = "macos")]
async fn platform_unlock(policy: UnlockPolicy, reason: &str) -> Result<(), UnlockError> {
    macos::evaluate(policy, reason).await
}

#[cfg(not(target_os = "macos"))]
async fn platform_unlock(_policy: UnlockPolicy, _reason: &str) -> Result<(), UnlockError> {
    Err(UnlockError::Unsupported)
}

#[cfg(target_os = "macos")]
mod macos {
    use super::UnlockError;
    use briefcred_core::profile::UnlockPolicy;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    /// `LAErrorUserCancel`, `LAErrorSystemCancel`, `LAErrorAppCancel`.
    const USER_CANCEL: isize = -2;
    const SYSTEM_CANCEL: isize = -4;
    const APP_CANCEL: isize = -9;

    /// How long the prompt may stay on screen before the daemon gives up.
    ///
    /// Bounded so a prompt nobody is in front of cannot pin an OS thread for
    /// the life of the daemon.
    const PROMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    /// Present the system prompt and wait for its answer.
    ///
    /// `evaluatePolicy` returns immediately and calls back on an internal
    /// queue, so the thread that starts it has to keep a run loop turning
    /// until the reply lands. That thread is dedicated and short-lived: doing
    /// this on a tokio worker would block the reactor for as long as the user
    /// stares at the prompt.
    pub async fn evaluate(policy: UnlockPolicy, reason: &str) -> Result<(), UnlockError> {
        let la_policy = match policy {
            // Touch ID with the login password as the fallback, which is what
            // `DeviceOwnerAuthentication` means, and what a laptop without an
            // enrolled finger still supports.
            UnlockPolicy::Biometric | UnlockPolicy::Passcode => LAPolicy::DeviceOwnerAuthentication,
            UnlockPolicy::None => return Ok(()),
        };
        let reason = reason.to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();

        std::thread::Builder::new()
            .name("briefcred-unlock".to_string())
            .spawn(move || {
                let outcome = prompt(la_policy, &reason);
                // A closed receiver means the request was abandoned; the
                // prompt has already been answered and there is nothing to do.
                let _ = tx.send(outcome);
            })
            .map_err(|e| UnlockError::Failed(format!("cannot start the unlock thread: {e}")))?;

        rx.await.map_err(|_| {
            UnlockError::Failed("the unlock thread stopped unexpectedly".to_string())
        })?
    }

    #[allow(unsafe_code)]
    fn prompt(policy: LAPolicy, reason: &str) -> Result<(), UnlockError> {
        use objc2_core_foundation::{kCFRunLoopDefaultMode, CFRunLoop};
        use std::sync::mpsc;

        // SAFETY: `LAContext::new` is the documented designated initialiser
        // and takes no arguments.
        let context = unsafe { LAContext::new() };
        let localized = NSString::from_str(reason);
        let (done_tx, done_rx) = mpsc::channel::<Result<(), UnlockError>>();

        let reply =
            block2::RcBlock::new(move |success: objc2::runtime::Bool, error: *mut NSError| {
                let outcome = if success.as_bool() {
                    Ok(())
                } else {
                    // SAFETY: the callback contract is that `error` is either null
                    // or a valid autoreleased `NSError` for the duration of the
                    // call, and it is only read here.
                    let error = unsafe { error.as_ref() };
                    Err(classify(error))
                };
                let _ = done_tx.send(outcome);
            });

        // SAFETY: the block is `Fn`, owns everything it touches, and outlives
        // the call because `reply` is held on this stack until the reply has
        // been received below.
        unsafe {
            context.evaluatePolicy_localizedReason_reply(policy, &localized, &reply);
        }

        let deadline = std::time::Instant::now() + PROMPT_TIMEOUT;
        loop {
            match done_rx.try_recv() {
                Ok(outcome) => return outcome,
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(UnlockError::Failed(
                        "the unlock prompt was dropped without an answer".to_string(),
                    ))
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err(UnlockError::Cancelled);
            }
            // Turning this thread's run loop is what lets the framework
            // deliver the reply and drive the prompt's own machinery.
            CFRunLoop::run_in_mode(unsafe { kCFRunLoopDefaultMode }, 0.1, false);
        }
    }

    /// Map an `LAError` onto the outcome the daemon reports.
    ///
    /// Cancellation is separated from failure because they mean opposite
    /// things to the user: one is "I changed my mind", the other is "the
    /// machine did not believe you".
    fn classify(error: Option<&NSError>) -> UnlockError {
        let Some(error) = error else {
            return UnlockError::Failed("the unlock prompt failed with no detail".to_string());
        };
        match error.code() {
            USER_CANCEL | SYSTEM_CANCEL | APP_CANCEL => UnlockError::Cancelled,
            _ => UnlockError::Failed(error.localizedDescription().to_string()),
        }
    }
}

/// Remembers, per profile, how long ago its unlock succeeded.
///
/// A cache hit skips the prompt entirely, so a shell running `briefcred exec`
/// in a loop asks once rather than once a second. The window is the profile's
/// own `unlock.cache_secs`, and a window of zero means every session prompts.
#[derive(Debug)]
pub struct UnlockCache {
    clock: Arc<dyn Clock>,
    unlocked_at: Mutex<HashMap<String, Duration>>,
}

impl UnlockCache {
    /// A cache reading time from `clock`.
    pub fn new(clock: Arc<dyn Clock>) -> UnlockCache {
        UnlockCache {
            clock,
            unlocked_at: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `profile` unlocked within the last `window`.
    pub async fn is_fresh(&self, profile: &str, window: Duration) -> bool {
        if window.is_zero() {
            return false;
        }
        let unlocked_at = self.unlocked_at.lock().await;
        unlocked_at
            .get(profile)
            .is_some_and(|at| self.clock.now().saturating_sub(*at) < window)
    }

    /// Record that `profile` has just unlocked.
    pub async fn record(&self, profile: &str) {
        let now = self.clock.now();
        self.unlocked_at
            .lock()
            .await
            .insert(profile.to_string(), now);
    }

    /// Forget `profile`'s unlock, so the next session prompts again.
    ///
    /// Called when a profile is reloaded from disk: the file that was unlocked
    /// for is not necessarily the file on disk now.
    pub async fn forget(&self, profile: &str) {
        self.unlocked_at.lock().await.remove(profile);
    }

    /// Forget every profile's unlock.
    pub async fn clear(&self) {
        self.unlocked_at.lock().await.clear();
    }
}

/// A gate that always succeeds. Tests only, and never constructed in `run`.
#[derive(Debug, Default)]
pub struct AlwaysUnlocked;

#[async_trait]
impl UnlockGate for AlwaysUnlocked {
    async fn unlock(&self, _policy: UnlockPolicy, _reason: &str) -> Result<(), UnlockError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A gate that counts prompts and returns a fixed answer, so a test can
    /// prove the cache actually prevented a prompt rather than merely allowed
    /// the session.
    #[derive(Debug, Default)]
    struct CountingGate {
        prompts: AtomicUsize,
        answer: Option<UnlockError>,
    }

    #[async_trait]
    impl UnlockGate for CountingGate {
        async fn unlock(&self, policy: UnlockPolicy, _reason: &str) -> Result<(), UnlockError> {
            if policy == UnlockPolicy::None {
                return Ok(());
            }
            self.prompts.fetch_add(1, Ordering::SeqCst);
            match &self.answer {
                Some(err) => Err(err.clone()),
                None => Ok(()),
            }
        }
    }

    #[tokio::test]
    async fn the_none_policy_never_reaches_the_platform_prompt() {
        // If this reached `LAContext` the test suite would hang on a Touch ID
        // sheet, which is exactly the regression being guarded against.
        assert_eq!(
            SystemUnlockGate::new()
                .unlock(UnlockPolicy::None, "test")
                .await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn the_none_policy_is_honoured_even_with_no_graphical_session() {
        let _guard = ForceNoAqua::set();
        assert!(no_aqua_session());
        assert_eq!(
            SystemUnlockGate::new()
                .unlock(UnlockPolicy::None, "test")
                .await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn a_headless_session_refuses_a_biometric_policy_rather_than_prompting() {
        let _guard = ForceNoAqua::set();
        for policy in [UnlockPolicy::Biometric, UnlockPolicy::Passcode] {
            assert_eq!(
                SystemUnlockGate::new().unlock(policy, "test").await,
                Err(UnlockError::NoAquaSession),
                "{policy:?} must fail closed without a graphical session"
            );
        }
    }

    #[test]
    fn every_unlock_failure_has_a_stable_machine_readable_reason() {
        assert_eq!(UnlockError::Cancelled.reason(), "cancelled");
        assert_eq!(UnlockError::Failed("x".into()).reason(), "failed");
        assert_eq!(UnlockError::NoAquaSession.reason(), "no_aqua_session");
        assert_eq!(UnlockError::Unsupported.reason(), "unsupported");
    }

    #[test]
    fn the_headless_message_tells_the_user_what_to_do_about_it() {
        let message = UnlockError::NoAquaSession.to_string();
        assert!(message.contains("unlock.policy: none"), "{message}");
        assert!(message.contains("graphical session"), "{message}");
    }

    #[tokio::test]
    async fn an_unlock_is_cached_for_the_configured_window_and_no_longer() {
        let clock = TestClock::new();
        let cache = UnlockCache::new(clock.clone());
        let window = Duration::from_secs(300);

        assert!(!cache.is_fresh("dev", window).await, "nothing cached yet");
        cache.record("dev").await;
        assert!(cache.is_fresh("dev", window).await);

        clock.advance(Duration::from_secs(299));
        assert!(
            cache.is_fresh("dev", window).await,
            "still inside the window"
        );
        clock.advance(Duration::from_secs(1));
        assert!(
            !cache.is_fresh("dev", window).await,
            "the window has closed"
        );
    }

    #[tokio::test]
    async fn a_zero_window_means_every_session_prompts() {
        let cache = UnlockCache::new(TestClock::new());
        cache.record("dev").await;
        assert!(!cache.is_fresh("dev", Duration::ZERO).await);
    }

    #[tokio::test]
    async fn unlocking_one_profile_does_not_unlock_another() {
        let cache = UnlockCache::new(TestClock::new());
        cache.record("low-value").await;
        assert!(!cache.is_fresh("high-value", Duration::from_secs(300)).await);
    }

    #[tokio::test]
    async fn forgetting_a_profile_makes_the_next_session_prompt_again() {
        let cache = UnlockCache::new(TestClock::new());
        let window = Duration::from_secs(300);
        cache.record("dev").await;
        cache.forget("dev").await;
        assert!(!cache.is_fresh("dev", window).await);

        cache.record("dev").await;
        cache.clear().await;
        assert!(!cache.is_fresh("dev", window).await);
    }

    #[tokio::test]
    async fn a_cache_hit_prevents_the_second_prompt_entirely() {
        let gate = CountingGate::default();
        let cache = UnlockCache::new(TestClock::new());
        let window = Duration::from_secs(300);

        for _ in 0..3 {
            if !cache.is_fresh("dev", window).await {
                gate.unlock(UnlockPolicy::Biometric, "dev").await.unwrap();
                cache.record("dev").await;
            }
        }
        assert_eq!(gate.prompts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_refused_unlock_is_not_cached() {
        let gate = CountingGate {
            prompts: AtomicUsize::new(0),
            answer: Some(UnlockError::Cancelled),
        };
        let cache = UnlockCache::new(TestClock::new());
        let window = Duration::from_secs(300);

        for _ in 0..2 {
            if !cache.is_fresh("dev", window).await
                && gate.unlock(UnlockPolicy::Biometric, "dev").await.is_ok()
            {
                cache.record("dev").await;
            }
        }
        assert_eq!(
            gate.prompts.load(Ordering::SeqCst),
            2,
            "a refusal must not cache"
        );
    }

    /// `BRIEFCRED_FORCE_NO_AQUA` is process-wide, so the tests that use it are
    /// serialised behind one mutex and always restore the previous value.
    struct ForceNoAqua {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl ForceNoAqua {
        fn set() -> ForceNoAqua {
            static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            // SAFETY: the mutex makes this the only thread in the process
            // touching the environment for the guard's lifetime.
            #[allow(unsafe_code)]
            unsafe {
                std::env::set_var(FORCE_NO_AQUA_ENV, "1")
            };
            ForceNoAqua { _lock: lock }
        }
    }

    impl Drop for ForceNoAqua {
        fn drop(&mut self) {
            #[allow(unsafe_code)]
            unsafe {
                std::env::remove_var(FORCE_NO_AQUA_ENV)
            };
        }
    }

    /// Ignored because it puts a real Touch ID sheet on the developer's
    /// screen and blocks until somebody answers it. It is the only way to
    /// check the `LAContext` path end to end, so it is kept runnable:
    /// `cargo test -p briefcred-daemon the_real_prompt -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    #[cfg(target_os = "macos")]
    async fn the_real_prompt_appears_and_reports_its_outcome() {
        let outcome = SystemUnlockGate::new()
            .unlock(UnlockPolicy::Biometric, "run the briefcred unlock test")
            .await;
        println!("unlock outcome: {outcome:?}");
        assert!(
            matches!(outcome, Ok(()) | Err(UnlockError::Cancelled)),
            "expected success or a deliberate cancel, got {outcome:?}"
        );
    }
}
