//! Whether the calling process has a screen to show a prompt on.
//!
//! This lives in `briefcred-core` because *two* processes have to answer it,
//! and they get different answers. The daemon is started by launchd and sits
//! in whatever session launchd put it in. The CLI runs in the user's shell,
//! which may be an SSH login on a machine whose console user is sitting in
//! front of a graphical session. Only the CLI can see that; the daemon cannot.
//!
//! So the CLI answers this question about itself and says so in
//! [`Request::OpenSession`], and the daemon answers it about itself and
//! refuses if *either* says headless.
//!
//! The client's half of that is a declaration, not a proof. A same-uid caller
//! can lie, and briefcred cannot stop it — it is already inside every boundary
//! briefcred has. What the flag buys is an honest client on SSH getting an
//! accurate refusal instead of a prompt drawn on somebody else's screen.
//!
//! [`Request::OpenSession`]: https://docs.rs/briefcred-proto

/// Set to `1` to force [`is_headless`] to report a headless session.
///
/// The tests cannot create or destroy a window server, so this is how the
/// headless path is exercised. It only ever makes briefcred stricter, so a
/// hostile process gains nothing by setting it.
pub const FORCE_NO_AQUA_ENV: &str = "BRIEFCRED_FORCE_NO_AQUA";

/// Whether this process has no graphical session to draw a prompt in.
///
/// Checked before the prompt rather than after: `LAContext` over SSH reports a
/// generic failure that is indistinguishable from a wrong password, and
/// telling the user "authentication failed" when the real problem is "you are
/// on SSH" wastes an afternoon.
pub fn is_headless() -> bool {
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
/// Right in cases the environment is not: a `launchd` agent in a background
/// session has no `SSH_CONNECTION` set and still cannot show a window.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub fn has_graphic_access() -> bool {
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

/// Off macOS there is no session concept to consult. The unlock gate refuses
/// anything but `none` on those platforms anyway.
#[cfg(not(target_os = "macos"))]
pub fn has_graphic_access() -> bool {
    true
}

/// Test scaffolding for forcing the headless answer.
///
/// Shared rather than duplicated per crate: it is the only place in briefcred
/// that mutates the process environment, and that wants exactly one mutex and
/// one justified `unsafe` block, not one per crate that needs the behaviour.
#[cfg(any(test, feature = "test-util"))]
pub mod testing {
    use super::FORCE_NO_AQUA_ENV;

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Forces [`super::is_headless`] to report headless until it is dropped.
    ///
    /// `FORCE_NO_AQUA_ENV` is process-wide, so holders are serialised behind
    /// one mutex and the variable is always removed again on drop.
    pub struct ForceNoAqua {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl ForceNoAqua {
        /// Set the override, blocking until any other holder has released it.
        pub fn set() -> ForceNoAqua {
            let lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            // SAFETY: the mutex makes this the only thread in the process
            // touching the environment for the guard's lifetime.
            #[allow(unsafe_code)]
            unsafe {
                std::env::set_var(FORCE_NO_AQUA_ENV, "1")
            };
            ForceNoAqua { _lock: lock }
        }

        /// Hold the lock without setting the override, so a test can observe
        /// the real answer without another test racing it.
        pub fn without_override() -> std::sync::MutexGuard<'static, ()> {
            LOCK.lock().unwrap_or_else(|e| e.into_inner())
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
}

#[cfg(test)]
mod tests {
    use super::testing::ForceNoAqua;
    use super::*;

    #[test]
    fn the_override_forces_a_headless_answer() {
        let _guard = ForceNoAqua::set();
        assert!(is_headless());
    }

    #[test]
    fn only_the_exact_value_one_forces_it() {
        let _lock = ForceNoAqua::without_override();
        // SAFETY: the lock makes this the only thread touching the
        // environment for the duration of this test.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(FORCE_NO_AQUA_ENV, "yes")
        };
        let answer = is_headless();
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var(FORCE_NO_AQUA_ENV)
        };
        // Whatever this machine's real answer is, `yes` must not have been
        // what produced it.
        assert_eq!(
            answer,
            real_answer(),
            "`yes` must not be read as the override"
        );
    }

    /// The answer `is_headless` gives with the override out of the way.
    fn real_answer() -> bool {
        std::env::var_os("SSH_CONNECTION").is_some()
            || std::env::var_os("SSH_TTY").is_some()
            || !has_graphic_access()
    }
}
