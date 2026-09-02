//! The per-session rate limit, and the three surfaces that charge it.
//!
//! A policy says *what* a session may do. A quota says *how much*. They are
//! different questions and neither substitutes for the other: an agent that
//! loops on the one endpoint its Cedar policy permits is inside the policy and
//! still a runaway bill, and no allowlist of paths can express "and not four
//! thousand times a minute".
//!
//! # One bucket per session
//!
//! The bucket is created when the session is opened, from the profile's
//! `quota:` block, and dropped when the session closes. That placement is the
//! design:
//!
//! - **Per session, not per profile.** Two concurrent `briefcred exec` runs of
//!   the same profile get a budget each. A shared bucket would make one agent's
//!   burst another agent's refusal, which is a debugging experience nobody can
//!   reason about.
//! - **Not persisted.** A quota bounds one session's blast radius; carrying it
//!   across restarts would mean a daemon that came back after a crash refusing
//!   work for a session that no longer exists.
//!
//! # What one token is
//!
//! One unit of "the daemon did something with a credential on your behalf":
//!
//! | surface | one token per |
//! | --- | --- |
//! | `http` | request through the HTTP proxy |
//! | `postgres` | connection through the Postgres proxy |
//! | `exec` | `briefcred exec` or `briefcred get` that mints |
//! | `mcp` | `briefcred_db_query` or `briefcred_exec` tool call |
//!
//! A Postgres *connection* rather than a statement, because the proxy relays
//! bytes without parsing them and so has no statements to count — see
//! [`crate::pgproxy::forward::relay`].
//!
//! # Denied requests are charged
//!
//! The HTTP proxy charges before it evaluates the policy, so a request the
//! policy refuses still spends a token. That is deliberate. The expensive thing
//! to defend against is a loop, and a loop that is being denied is still a loop
//! — one that would otherwise get an unmetered retry channel precisely because
//! it is doing something the profile forbids.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use briefcred_core::profile::Quota;

use crate::clock::Clock;
use crate::metrics::Metrics;

/// The `surface` label for a request through the HTTP proxy.
pub const SURFACE_HTTP: &str = "http";

/// The `surface` label for a connection through the Postgres proxy.
pub const SURFACE_POSTGRES: &str = "postgres";

/// The `surface` label for an `exec` or `get` that mints.
pub const SURFACE_EXEC: &str = "exec";

/// The `surface` label for an MCP tool call that uses a credential.
///
/// `briefcred_db_query` and `briefcred_exec` both run *inside* the daemon
/// rather than handing a subprocess a credential, so neither passes through
/// the two proxies or the `exec` handler. Without a surface of their own they
/// would be the one way to spend a metered profile without being metered.
pub const SURFACE_MCP: &str = "mcp";

/// Why a charge was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The bucket is empty and will refill. `retry_after` is how long until it
    /// holds one token again, rounded up to a whole second.
    ///
    /// Rounded up rather than down because the value is handed to a client as
    /// `Retry-After`, and a client that came back a fraction of a second early
    /// would be refused a second time for having believed briefcred.
    Refill {
        /// Whole seconds until one token is available. At least one.
        retry_after: Duration,
    },
    /// The session's `total` cap is spent. Nothing refills it.
    ///
    /// Carries no `retry_after` because there is no time at which retrying
    /// works: the cap is per session, so the answer is a new session.
    Exhausted,
}

impl Refusal {
    /// How long until a retry could succeed, where there is such a time.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Refusal::Refill { retry_after } => Some(*retry_after),
            Refusal::Exhausted => None,
        }
    }
}

/// What one charge did, and what it left behind.
///
/// The saturation is measured under the same lock as the charge rather than
/// read back afterwards. Read back, it would include however much the bucket
/// refilled in between — which on a real clock is enough that a bucket the
/// charge emptied reports 0.998 rather than 1, and a gauge that never quite
/// reaches its own maximum is a gauge nobody can write an alert against.
#[derive(Debug)]
pub struct Charge {
    /// Whether the token was granted.
    pub outcome: Result<(), Refusal>,
    /// How full the bucket was *not* when the charge finished, 0 to 1.
    pub saturation: f64,
}

/// One session's token bucket.
///
/// `f64` tokens rather than integers so a `rate` below one per second is a
/// rate rather than a rounding error: `rate: 0.1` is six an hour, and an
/// integer bucket could only spell that as never.
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    total: Option<u64>,
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
}

/// The part of a bucket that moves.
#[derive(Debug)]
struct State {
    /// Tokens available, never above `burst`.
    tokens: f64,
    /// When `tokens` was last brought up to date.
    refilled_at: Duration,
    /// Charges granted since the session opened, for the `total` cap.
    spent: u64,
}

impl std::fmt::Debug for TokenBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBucket")
            .field("rate", &self.rate)
            .field("burst", &self.burst)
            .field("total", &self.total)
            .field("saturation", &self.saturation())
            .finish()
    }
}

impl TokenBucket {
    /// A bucket for `quota`, starting full.
    ///
    /// Full rather than empty: a session's first request should not have to
    /// wait for a bucket to fill, and `burst` is exactly the statement of how
    /// much work may happen at once.
    pub fn new(quota: &Quota, clock: Arc<dyn Clock>) -> TokenBucket {
        let burst = f64::from(quota.burst);
        let refilled_at = clock.now();
        TokenBucket {
            rate: quota.rate,
            burst,
            total: quota.total,
            clock,
            state: Mutex::new(State {
                tokens: burst,
                refilled_at,
                spent: 0,
            }),
        }
    }

    /// Take one token, or say why not, and report how full the bucket is left.
    pub fn charge(&self) -> Charge {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.refill(&mut state);

        // The hard cap first. A session that has spent its `total` is finished
        // whatever the bucket holds, and checking the other way round would
        // let it burn tokens it can never use.
        let outcome = if self.total.is_some_and(|total| state.spent >= total) {
            Err(Refusal::Exhausted)
        } else if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            state.spent += 1;
            Ok(())
        } else {
            Err(Refusal::Refill {
                retry_after: seconds_until_one(state.tokens, self.rate),
            })
        };
        Charge {
            // A refusal is a full 1, not the 0.998 the bucket literally holds.
            // On a live clock a bucket refills continuously, so an emptied one
            // is fractionally non-empty by the time it is measured — and a
            // gauge that never reaches its own maximum is a gauge nobody can
            // write `== 1` against. A bucket that could not serve a request is
            // empty in the only sense the metric is for.
            saturation: if outcome.is_err() {
                1.0
            } else {
                self.measure(&state)
            },
            outcome,
        }
    }

    /// How full the bucket is *not*, from 0 (untouched) to 1 (empty).
    ///
    /// The saturation rather than the level, because that is the direction an
    /// alert reads: a gauge climbing towards 1 is a session about to be
    /// throttled, and one that reaches it is a session being throttled now.
    pub fn saturation(&self) -> f64 {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.refill(&mut state);
        self.measure(&state)
    }

    /// The saturation of a state already brought up to date.
    fn measure(&self, state: &State) -> f64 {
        if self.total.is_some_and(|total| state.spent >= total) {
            return 1.0;
        }
        (1.0 - state.tokens / self.burst).clamp(0.0, 1.0)
    }

    /// Bring `tokens` up to date for the time that has passed.
    fn refill(&self, state: &mut State) {
        let now = self.clock.now();
        let elapsed = now.saturating_sub(state.refilled_at);
        state.refilled_at = now;
        state.tokens = (state.tokens + elapsed.as_secs_f64() * self.rate).min(self.burst);
    }
}

/// Whole seconds until `tokens` reaches one at `rate`, rounded up, at least one.
fn seconds_until_one(tokens: f64, rate: f64) -> Duration {
    let seconds = ((1.0 - tokens) / rate).ceil();
    // `max(1.0)` rather than a plain cast: a rate high enough to make the
    // shortfall a hundredth of a second still has to produce a `Retry-After`
    // a client can act on, and `Retry-After: 0` is an invitation to spin.
    Duration::from_secs(seconds.max(1.0) as u64)
}

/// Charge one token for `profile` on `surface`, recording it on `metrics`.
///
/// `bucket` is `None` for a profile with no `quota:`, which is every profile
/// that has not opted in — those are unmetered and touch neither metric, so a
/// gauge that exists is a quota somebody configured.
///
/// The one place all three surfaces go through, so the metric is updated on
/// every charge by construction rather than by three call sites remembering to.
pub fn charge(
    bucket: Option<&TokenBucket>,
    profile: &str,
    surface: &str,
    metrics: &Metrics,
) -> Result<(), Refusal> {
    let Some(bucket) = bucket else {
        return Ok(());
    };
    let charge = bucket.charge();
    metrics.record_quota_saturation(profile, charge.saturation);
    if charge.outcome.is_err() {
        metrics.record_quota_rejection(profile, surface);
    }
    charge.outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;

    /// One charge, keeping only whether it was granted.
    ///
    /// The saturation is asserted on its own where a test is about it; folding
    /// it into every call would make the rate-limiting tests read as if they
    /// were about the metric.
    fn take(bucket: &TokenBucket) -> Result<(), Refusal> {
        bucket.charge().outcome
    }

    fn quota(rate: f64, burst: u32, total: Option<u64>) -> Quota {
        Quota { rate, burst, total }
    }

    /// The brief's own example: ten a second, twenty at once.
    fn ten_per_second() -> (Arc<TestClock>, TokenBucket) {
        let clock = TestClock::new();
        let bucket = TokenBucket::new(&quota(10.0, 20, None), clock.clone());
        (clock, bucket)
    }

    #[test]
    fn the_twenty_first_request_in_one_second_is_refused() {
        let (_clock, bucket) = ten_per_second();
        for n in 0..20 {
            assert_eq!(take(&bucket), Ok(()), "request {n} must be allowed");
        }
        assert_eq!(
            take(&bucket),
            Err(Refusal::Refill {
                retry_after: Duration::from_secs(1)
            }),
            "the burst is twenty, so the twenty-first is refused"
        );
    }

    #[test]
    fn a_second_later_the_bucket_holds_another_ten() {
        let (clock, bucket) = ten_per_second();
        for _ in 0..20 {
            take(&bucket).unwrap();
        }
        assert!(take(&bucket).is_err());

        clock.advance(Duration::from_secs(1));
        for n in 0..10 {
            assert_eq!(take(&bucket), Ok(()), "refilled request {n}");
        }
        assert!(
            take(&bucket).is_err(),
            "one second buys ten tokens and not eleven"
        );
    }

    #[test]
    fn a_bucket_never_refills_past_its_burst() {
        let (clock, bucket) = ten_per_second();
        clock.advance(Duration::from_secs(3600));
        for n in 0..20 {
            assert_eq!(take(&bucket), Ok(()), "request {n}");
        }
        assert!(
            take(&bucket).is_err(),
            "an idle hour must not buy thirty-six thousand tokens"
        );
    }

    #[test]
    fn a_spent_total_is_refused_for_the_rest_of_the_session() {
        let clock = TestClock::new();
        let bucket = TokenBucket::new(&quota(10.0, 20, Some(3)), clock.clone());
        for n in 0..3 {
            assert_eq!(take(&bucket), Ok(()), "request {n}");
        }
        assert_eq!(take(&bucket), Err(Refusal::Exhausted));

        // And no amount of waiting brings it back: the cap is per session.
        clock.advance(Duration::from_secs(86_400));
        assert_eq!(take(&bucket), Err(Refusal::Exhausted));
        assert_eq!(bucket.saturation(), 1.0);
    }

    #[test]
    fn an_exhausted_total_offers_no_time_to_retry_at() {
        let bucket = TokenBucket::new(&quota(10.0, 20, Some(0)), TestClock::new());
        assert_eq!(take(&bucket).unwrap_err().retry_after(), None);
    }

    #[test]
    fn a_refill_refusal_says_how_long_to_wait() {
        let clock = TestClock::new();
        // One token every ten seconds, one at a time.
        let bucket = TokenBucket::new(&quota(0.1, 1, None), clock.clone());
        take(&bucket).unwrap();
        assert_eq!(
            take(&bucket).unwrap_err().retry_after(),
            Some(Duration::from_secs(10))
        );

        clock.advance(Duration::from_secs(6));
        assert_eq!(
            take(&bucket).unwrap_err().retry_after(),
            Some(Duration::from_secs(4)),
            "four of the ten seconds are left"
        );
        clock.advance(Duration::from_secs(4));
        assert_eq!(take(&bucket), Ok(()));
    }

    #[test]
    fn a_retry_after_is_never_zero_seconds() {
        let clock = TestClock::new();
        let bucket = TokenBucket::new(&quota(1000.0, 1, None), clock.clone());
        take(&bucket).unwrap();
        assert_eq!(
            take(&bucket).unwrap_err().retry_after(),
            Some(Duration::from_secs(1)),
            "a client told to wait zero seconds would spin"
        );
    }

    #[test]
    fn saturation_runs_from_empty_to_full_and_back() {
        let (clock, bucket) = ten_per_second();
        assert_eq!(bucket.saturation(), 0.0, "an untouched bucket is not full");

        for _ in 0..10 {
            take(&bucket).unwrap();
        }
        assert_eq!(bucket.saturation(), 0.5);

        for _ in 0..10 {
            take(&bucket).unwrap();
        }
        assert_eq!(bucket.saturation(), 1.0, "1 means the bucket is empty");

        clock.advance(Duration::from_secs(2));
        assert_eq!(bucket.saturation(), 0.0);
    }

    #[test]
    fn a_fractional_rate_is_a_rate_rather_than_a_rounding_error() {
        let clock = TestClock::new();
        // Six an hour: the shape of a quota on something expensive.
        let bucket = TokenBucket::new(&quota(0.1, 2, None), clock.clone());
        take(&bucket).unwrap();
        take(&bucket).unwrap();
        assert!(take(&bucket).is_err());

        clock.advance(Duration::from_secs(10));
        assert_eq!(take(&bucket), Ok(()));
    }

    #[test]
    fn a_bucket_never_prints_more_than_its_shape() {
        let (_clock, bucket) = ten_per_second();
        let rendered = format!("{bucket:?}");
        assert!(rendered.contains("rate"), "{rendered}");
        assert!(rendered.contains("saturation"), "{rendered}");
    }

    #[test]
    fn a_profile_with_no_quota_is_never_refused_and_never_measured() {
        let metrics = Metrics::new(Arc::new(std::sync::atomic::AtomicU64::new(0)));
        for _ in 0..1000 {
            assert_eq!(charge(None, "openai", SURFACE_HTTP, &metrics), Ok(()));
        }
        let rendered = metrics.render();
        assert!(
            !rendered.contains("briefcred_quota_saturation{"),
            "an unmetered profile must not appear on the gauge:\n{rendered}"
        );
    }

    #[test]
    fn a_refused_charge_reports_a_full_gauge_even_as_the_bucket_refills() {
        let clock = TestClock::new();
        let bucket = TokenBucket::new(&quota(0.1, 1, None), clock.clone());
        assert_eq!(bucket.charge().saturation, 1.0, "the last token was taken");

        // Nine tenths of the way to the next token: genuinely not empty, and
        // still unable to serve a request.
        clock.advance(Duration::from_secs(9));
        let charge = bucket.charge();
        assert!(charge.outcome.is_err());
        assert_eq!(
            charge.saturation, 1.0,
            "a refusal pins the gauge, so `== 1` is an alert somebody can write"
        );
        assert!(
            (bucket.saturation() - 0.1).abs() < 1e-9,
            "the bucket itself still reports what it holds: {}",
            bucket.saturation()
        );
    }

    #[test]
    fn a_charge_updates_the_gauge_and_a_refusal_updates_the_counter() {
        let metrics = Metrics::new(Arc::new(std::sync::atomic::AtomicU64::new(0)));
        let bucket = TokenBucket::new(&quota(1.0, 2, None), TestClock::new());

        assert_eq!(
            charge(Some(&bucket), "openai", SURFACE_HTTP, &metrics),
            Ok(())
        );
        assert!(metrics
            .render()
            .contains("briefcred_quota_saturation{profile=\"openai\"} 0.5"));

        charge(Some(&bucket), "openai", SURFACE_HTTP, &metrics).unwrap();
        assert!(charge(Some(&bucket), "openai", SURFACE_HTTP, &metrics).is_err());

        let rendered = metrics.render();
        assert!(
            rendered.contains("briefcred_quota_saturation{profile=\"openai\"} 1"),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "briefcred_quota_rejections_total{profile=\"openai\",surface=\"http\"} 1"
            ),
            "{rendered}"
        );
    }

    #[test]
    fn the_four_surfaces_are_the_ones_the_metric_documents() {
        assert_eq!(
            [SURFACE_HTTP, SURFACE_POSTGRES, SURFACE_EXEC, SURFACE_MCP],
            ["http", "postgres", "exec", "mcp"]
        );
    }
}
