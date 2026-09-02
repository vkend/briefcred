//! The one source of "now" the daemon's time-based policies read.
//!
//! Session expiry and the unlock cache are both deadlines, and a deadline is
//! only testable if the test can move time. Everything that needs a monotonic
//! instant takes a [`Clock`] rather than calling [`std::time::Instant::now`],
//! so the idle-eviction and cache-expiry tests are exact rather than sleepy.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A monotonic clock. [`SystemClock`] in production, [`TestClock`] in tests.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Monotonic time since an arbitrary fixed origin.
    ///
    /// Monotonic rather than wall-clock: a session must not become
    /// immortal, or instantly stale, because the laptop resynchronised NTP.
    fn now(&self) -> Duration;
}

/// The real clock, anchored at the moment it was constructed.
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl Default for SystemClock {
    fn default() -> SystemClock {
        SystemClock::new()
    }
}

impl SystemClock {
    /// A clock whose zero is now.
    pub fn new() -> SystemClock {
        SystemClock {
            origin: Instant::now(),
        }
    }

    /// A clock whose zero is `backdate` in the past.
    ///
    /// For a daemon that has just adopted another one's sessions. Every age the
    /// handoff carries is measured against the old daemon's origin, and a new
    /// clock starting at zero would make the oldest session look as though it
    /// had opened at this instant — which would reset every idle timer and
    /// leave a forgotten terminal's master resident for another full window.
    /// Backdating the origin by the oldest age carries the timers across
    /// instead, so eviction picks up exactly where it left off.
    pub fn started_ago(backdate: Duration) -> SystemClock {
        SystemClock {
            // A machine whose uptime is shorter than the backdate cannot
            // represent the instant, so fall back to zero rather than panic:
            // the worst case is the one this exists to avoid, not a crash.
            origin: Instant::now()
                .checked_sub(backdate)
                .unwrap_or_else(Instant::now),
        }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// A clock that only moves when a test moves it.
#[derive(Debug, Default)]
pub struct TestClock {
    millis: AtomicU64,
}

impl TestClock {
    /// A clock stopped at zero.
    pub fn new() -> Arc<TestClock> {
        Arc::new(TestClock::default())
    }

    /// Move time forward by `delta`.
    pub fn advance(&self, delta: Duration) {
        self.millis
            .fetch_add(delta.as_millis() as u64, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.millis.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_test_clock_stands_still_until_it_is_advanced() {
        let clock = TestClock::new();
        assert_eq!(clock.now(), Duration::ZERO);
        assert_eq!(clock.now(), Duration::ZERO);
        clock.advance(Duration::from_secs(90));
        assert_eq!(clock.now(), Duration::from_secs(90));
        clock.advance(Duration::from_secs(10));
        assert_eq!(clock.now(), Duration::from_secs(100));
    }

    #[test]
    fn the_system_clock_only_moves_forward() {
        let clock = SystemClock::new();
        let first = clock.now();
        let second = clock.now();
        assert!(second >= first, "{second:?} < {first:?}");
    }
}
