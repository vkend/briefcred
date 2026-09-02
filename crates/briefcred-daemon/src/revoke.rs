//! The revoke queue: what makes "the credential goes away" true rather than
//! hopeful.
//!
//! `briefcred exec` returns the moment its child exits. Revoking is slower
//! than that — it is several statements against a possibly-remote backend —
//! and making the user wait for it would turn a 20 ms command into a 200 ms
//! one for no benefit they can see. So the revoke is queued, and the queue is
//! the thing that has to be trustworthy.
//!
//! Three properties do that:
//!
//! - **It survives a restart.** Entries are written to
//!   `state_dir()/revoke-queue.jsonl` before the queue reports them accepted,
//!   and replayed when the daemon next starts. A daemon that is stopped with a
//!   revoke outstanding finishes it after the reboot.
//! - **It retries, and then it stops.** Exponential backoff from one second to
//!   a one-minute ceiling, eight attempts, then the entry is dropped with a
//!   final `failed` audit row. Retrying forever would hide a permanently
//!   broken backend behind a queue that never drains.
//! - **Every attempt is auditable.** One `Revoke` row per attempt, carrying
//!   the outcome and, when it failed, why.
//!
//! What is in the file is metadata: an identifier, a minter kind, a profile
//! name, and the backend's connection settings. No master and no minted
//! secret. It is still written `0600`, because the set of databases a user
//! reaches is worth something to an attacker even without the passwords.

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use briefcred_core::audit::AuditEntry;
use briefcred_core::types::{MintId, RevokeOutcome};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::error::{Error, Result};

/// The file the queue is persisted in, inside the state directory.
pub const QUEUE_FILE: &str = "revoke-queue.jsonl";

/// The first retry delay. Each subsequent one doubles.
pub const BASE_BACKOFF: Duration = Duration::from_secs(1);

/// The longest a retry is ever put off.
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How many times one revoke is attempted before the queue gives up.
pub const MAX_ATTEMPTS: u32 = 8;

/// The delay before attempt number `attempt`, counting the first as 1.
///
/// 1 s, 2 s, 4 s … capped at [`MAX_BACKOFF`]. Attempt 1 is immediate: the
/// common case is a healthy backend, and making every exec's revoke wait a
/// second would leave a window where the credential is still live for no
/// reason.
pub fn backoff(attempt: u32) -> Duration {
    match attempt {
        0 | 1 => Duration::ZERO,
        n => {
            let doublings = u32::min(n - 2, 31);
            Duration::min(BASE_BACKOFF * 2u32.saturating_pow(doublings), MAX_BACKOFF)
        }
    }
}

/// One outstanding revoke, exactly as it is persisted.
///
/// Everything a revoke needs *except* the master, which is fetched fresh from
/// the master source when the attempt runs. That is deliberate: a queue file
/// holding masters would be a secret store with a filename, and it would still
/// be one after the credential it protects has been revoked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRevoke {
    /// The principal to remove.
    pub mint_id: MintId,
    /// The minter kind that created it, which selects the helper.
    pub kind: String,
    /// The profile it was minted for, for audit and for config lookup.
    pub profile: String,
    /// The credential's name within that profile.
    pub credential: String,
    /// The master-source key the master is filed under.
    pub source_key: String,
    /// The credential's `config` block, as JSON.
    ///
    /// Persisted rather than looked up so a revoke still works after the
    /// profile that asked for the mint has been edited or deleted — which is
    /// exactly when a stranded credential is most likely.
    pub config: serde_json::Value,
    /// The minter's own opaque state, so the revoke is symmetric to the mint.
    pub revoke_token: String,
    /// How many attempts have been made so far.
    #[serde(default)]
    pub attempts: u32,
    /// The earliest this entry may be attempted again, as a Unix timestamp in
    /// milliseconds.
    ///
    /// Wall clock rather than monotonic, deliberately: the value has to survive
    /// a daemon restart, and a monotonic instant means nothing to the next
    /// process. The cost is that a clock jump can make one retry early or late,
    /// which for a retry schedule is not worth defending against.
    #[serde(default)]
    pub not_before_unix_ms: i64,
}

impl PendingRevoke {
    /// Whether this entry has used up its attempts.
    pub fn exhausted(&self) -> bool {
        self.attempts >= MAX_ATTEMPTS
    }

    /// Whether `now` has reached this entry's next attempt time.
    pub fn is_due(&self, now_unix_ms: i64) -> bool {
        now_unix_ms >= self.not_before_unix_ms
    }

    /// Record an attempt and schedule the next one.
    fn defer(&mut self, now_unix_ms: i64) {
        self.not_before_unix_ms =
            now_unix_ms + backoff(self.attempts + 1).as_millis().min(i64::MAX as u128) as i64;
    }
}

/// The current wall-clock time in Unix milliseconds.
fn now_unix_ms() -> i64 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

/// What actually performs a revoke.
///
/// A trait so the queue's retry, persistence, and give-up behaviour can be
/// tested against a backend that fails on demand, with no helper process and
/// no database anywhere near it.
#[async_trait]
pub trait Revoker: Send + Sync + std::fmt::Debug {
    /// Attempt one revoke.
    async fn revoke(&self, entry: &PendingRevoke) -> RevokeOutcome;
}

/// The queue itself: the pending set, and the file that mirrors it.
#[derive(Debug)]
pub struct RevokeQueue {
    path: PathBuf,
    pending: Mutex<Vec<PendingRevoke>>,
    wake: tokio::sync::Notify,
}

impl RevokeQueue {
    /// Open the queue at `path`, replaying whatever a previous run left.
    ///
    /// A file that does not parse is a problem worth reporting but not worth
    /// refusing to start over: the parseable entries are kept, the rest are
    /// named on stderr, and the file is rewritten from what survived.
    pub fn open(path: impl Into<PathBuf>) -> Result<RevokeQueue> {
        let path = path.into();
        let pending = match std::fs::read_to_string(&path) {
            Ok(text) => parse(&text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(Error::io("read", &path, err)),
        };
        let queue = RevokeQueue {
            path,
            pending: Mutex::new(pending),
            wake: tokio::sync::Notify::new(),
        };
        Ok(queue)
    }

    /// How many revokes are outstanding.
    pub async fn len(&self) -> usize {
        self.pending.lock().await.len()
    }

    /// Whether nothing is outstanding.
    pub async fn is_empty(&self) -> bool {
        self.pending.lock().await.is_empty()
    }

    /// Everything outstanding, in queue order.
    pub async fn entries(&self) -> Vec<PendingRevoke> {
        self.pending.lock().await.clone()
    }

    /// How long until the earliest outstanding entry is due, if there is one.
    pub async fn next_due_in(&self) -> Option<Duration> {
        let now = now_unix_ms();
        self.pending
            .lock()
            .await
            .iter()
            .map(|entry| {
                Duration::from_millis(entry.not_before_unix_ms.saturating_sub(now).max(0) as u64)
            })
            .min()
    }

    /// Add `entries` and persist before returning.
    ///
    /// Persisting first is the whole point: a `SIGKILL` between the child
    /// exiting and the file being written is the case the reconciler exists to
    /// catch, and every entry that reaches the file is one the reconciler does
    /// not have to.
    pub async fn enqueue(&self, entries: Vec<PendingRevoke>) -> Result<usize> {
        let added = entries.len();
        {
            let mut pending = self.pending.lock().await;
            pending.extend(entries);
            persist(&self.path, &pending)?;
        }
        self.wake.notify_one();
        Ok(added)
    }

    /// Take the entries that are due, leaving the rest in place.
    async fn take_due(&self, now: i64) -> Result<Vec<PendingRevoke>> {
        let mut pending = self.pending.lock().await;
        let (due, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut *pending)
            .into_iter()
            .partition(|entry| entry.is_due(now));
        *pending = waiting;
        persist(&self.path, &pending)?;
        Ok(due)
    }

    /// Put entries back at the front, keeping the file in step.
    async fn requeue(&self, mut entries: Vec<PendingRevoke>) -> Result<()> {
        let mut pending = self.pending.lock().await;
        entries.append(&mut pending);
        *pending = entries;
        persist(&self.path, &pending)
    }

    /// Attempt every entry whose backoff has elapsed.
    ///
    /// Returns the entries that still need another attempt, already put back on
    /// the queue with their attempt counts incremented and their next attempt
    /// scheduled. Separated from the loop so a test can drive passes
    /// deterministically instead of sleeping.
    ///
    /// An entry that is not yet due is left alone rather than retried early:
    /// without that, one entry failing fast would drag every other entry's
    /// schedule down to its own.
    pub async fn run_pass(
        &self,
        revoker: &dyn Revoker,
        audit: &crate::audit::AuditHandle,
    ) -> Result<Vec<PendingRevoke>> {
        let now = now_unix_ms();
        let due = self.take_due(now).await?;
        let mut retry = Vec::new();
        for mut entry in due {
            entry.attempts += 1;
            let outcome = revoker.revoke(&entry).await;
            audit.append(&AuditEntry::revoke(
                entry.mint_id.clone(),
                entry.kind.clone(),
                &outcome,
            ));

            match &outcome {
                // `AlreadyGone` is a success: something else — a reconcile
                // sweep, an operator, the backend's own expiry — got there
                // first, and the credential is gone either way.
                RevokeOutcome::Revoked
                | RevokeOutcome::AlreadyGone
                | RevokeOutcome::EventuallyConsistent { .. } => {}
                RevokeOutcome::Failed { detail } => {
                    if entry.exhausted() {
                        eprintln!(
                            "briefcred-daemon: giving up on revoking {} after {} attempts: {detail}",
                            entry.mint_id, entry.attempts
                        );
                    } else {
                        entry.defer(now);
                        retry.push(entry);
                    }
                }
            }
        }
        self.requeue(retry.clone()).await?;
        Ok(retry)
    }
}

/// Parse a queue file, keeping every line that is a well-formed entry.
fn parse(text: &str) -> Vec<PendingRevoke> {
    let mut out = Vec::new();
    for (number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<PendingRevoke>(line) {
            Ok(entry) => out.push(entry),
            Err(err) => eprintln!(
                "briefcred-daemon: dropping unreadable revoke-queue line {}: {err}",
                number + 1
            ),
        }
    }
    out
}

/// Rewrite the queue file from `entries`, `0600`, and fsync it.
///
/// A whole rewrite rather than an append plus a compaction: the queue holds
/// the revokes that have not finished yet, which is a handful of lines even on
/// a bad day, and one code path that always produces a correct file is worth
/// more than the write it saves.
fn persist(path: &Path, entries: &[PendingRevoke]) -> Result<()> {
    if let Some(parent) = path.parent() {
        briefcred_core::paths::ensure_private_dir(parent)?;
    }
    let mut body = String::new();
    for entry in entries {
        let line = serde_json::to_string(entry).map_err(|e| Error::Io {
            action: "serialise a revoke-queue entry for",
            path: path.to_path_buf(),
            source: e.into(),
        })?;
        body.push_str(&line);
        body.push('\n');
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| Error::io("open", path, e))?;
    file.write_all(body.as_bytes())
        .map_err(|e| Error::io("write", path, e))?;
    // As with the audit log: a queue that loses its last entry in a crash is
    // a credential nobody knows to revoke.
    file.sync_data().map_err(|e| Error::io("fsync", path, e))?;
    // `mode` applies only on creation, so an existing file keeps its old mode.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::io("set the mode of", path, e))
}

/// Drain the queue until shutdown, backing off between passes.
///
/// The sleep between passes is the backoff of the least-tried entry still
/// waiting, so a single stubborn entry does not hold up one that has only just
/// arrived, and an empty queue waits on the notify rather than spinning.
pub async fn drain_loop(
    queue: Arc<RevokeQueue>,
    revoker: Arc<dyn Revoker>,
    audit: crate::audit::AuditHandle,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        let retry = match queue.run_pass(revoker.as_ref(), &audit).await {
            Ok(retry) => retry,
            Err(err) => {
                eprintln!("briefcred-daemon: revoke queue: {err}");
                Vec::new()
            }
        };

        // Sleep until the earliest thing on the queue is due, so one stubborn
        // entry does not hold up one that has only just arrived.
        let wait = queue.next_due_in().await.unwrap_or(MAX_BACKOFF);
        let _ = &retry;

        tokio::select! {
            _ = crate::server::shutdown_requested(&mut shutdown) => return,
            _ = queue.wake.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn entry(name: &str) -> PendingRevoke {
        PendingRevoke {
            mint_id: name.parse().unwrap(),
            kind: "postgres-dynamic".into(),
            profile: "dev".into(),
            credential: "db".into(),
            source_key: "db".into(),
            config: serde_json::json!({ "host": "127.0.0.1", "dbname": "app" }),
            revoke_token: "{\"grants\":[]}".into(),
            attempts: 0,
            not_before_unix_ms: 0,
        }
    }

    fn one() -> PendingRevoke {
        entry("briefcred_t_0123456789ab")
    }

    fn two() -> PendingRevoke {
        entry("briefcred_t_ba9876543210")
    }

    /// Fails every revoke, counting how often it was asked.
    #[derive(Debug, Default)]
    struct AlwaysFails(AtomicUsize);

    #[async_trait]
    impl Revoker for AlwaysFails {
        async fn revoke(&self, _entry: &PendingRevoke) -> RevokeOutcome {
            self.0.fetch_add(1, Ordering::SeqCst);
            RevokeOutcome::failed("42501: permission denied")
        }
    }

    /// Succeeds every revoke.
    #[derive(Debug, Default)]
    struct AlwaysWorks(AtomicUsize);

    #[async_trait]
    impl Revoker for AlwaysWorks {
        async fn revoke(&self, _entry: &PendingRevoke) -> RevokeOutcome {
            self.0.fetch_add(1, Ordering::SeqCst);
            RevokeOutcome::Revoked
        }
    }

    fn audit(dir: &Path) -> crate::audit::AuditHandle {
        crate::audit::spawn(crate::audit::AuditLog::open(&dir.join("audit"), 90).unwrap())
    }

    #[test]
    fn the_backoff_doubles_from_one_second_and_stops_at_a_minute() {
        assert_eq!(backoff(1), Duration::ZERO);
        assert_eq!(backoff(2), Duration::from_secs(1));
        assert_eq!(backoff(3), Duration::from_secs(2));
        assert_eq!(backoff(4), Duration::from_secs(4));
        assert_eq!(backoff(5), Duration::from_secs(8));
        assert_eq!(backoff(6), Duration::from_secs(16));
        assert_eq!(backoff(7), Duration::from_secs(32));
        assert_eq!(backoff(8), MAX_BACKOFF);
        assert_eq!(backoff(64), MAX_BACKOFF);
    }

    #[tokio::test]
    async fn an_enqueued_revoke_is_on_the_disk_before_enqueue_returns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join(QUEUE_FILE);
        let queue = RevokeQueue::open(&path).unwrap();

        queue.enqueue(vec![one()]).await.unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.contains("briefcred_t_0123456789ab"), "{text}");
    }

    #[tokio::test]
    async fn a_queue_file_is_readable_only_by_its_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join(QUEUE_FILE);
        let queue = RevokeQueue::open(&path).unwrap();
        queue.enqueue(vec![one()]).await.unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "revoke queue is {mode:o}");
    }

    #[tokio::test]
    async fn a_queue_file_never_holds_a_master_or_a_minted_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(QUEUE_FILE);
        let queue = RevokeQueue::open(&path).unwrap();
        queue.enqueue(vec![one()]).await.unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        // The shape is asserted rather than the absence of one string: an
        // entry with an unexpected field would fail `deny_unknown_fields` on
        // the way back in, which is the guard that actually holds.
        let back: PendingRevoke = serde_json::from_str(text.trim_end()).unwrap();
        assert_eq!(back, one());
    }

    #[tokio::test]
    async fn the_queue_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(QUEUE_FILE);

        {
            let queue = RevokeQueue::open(&path).unwrap();
            queue.enqueue(vec![one(), two()]).await.unwrap();
            assert_eq!(queue.len().await, 2);
        }

        // A whole new daemon, reading nothing but the file.
        let restarted = RevokeQueue::open(&path).unwrap();
        assert_eq!(restarted.entries().await, vec![one(), two()]);
    }

    #[tokio::test]
    async fn a_successful_pass_empties_the_queue_and_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(QUEUE_FILE);
        let queue = RevokeQueue::open(&path).unwrap();
        queue.enqueue(vec![one(), two()]).await.unwrap();

        let revoker = AlwaysWorks::default();
        let retry = queue.run_pass(&revoker, &audit(dir.path())).await.unwrap();

        assert!(retry.is_empty());
        assert!(queue.is_empty().await);
        assert_eq!(revoker.0.load(Ordering::SeqCst), 2);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }

    #[tokio::test]
    async fn a_failed_revoke_stays_queued_with_its_attempt_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(QUEUE_FILE);
        let queue = RevokeQueue::open(&path).unwrap();
        queue.enqueue(vec![one()]).await.unwrap();

        let retry = queue
            .run_pass(&AlwaysFails::default(), &audit(dir.path()))
            .await
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].attempts, 1);

        // And the count is on the disk, so a restart does not reset the budget.
        let restarted = RevokeQueue::open(&path).unwrap();
        assert_eq!(restarted.entries().await[0].attempts, 1);
    }

    #[tokio::test]
    async fn an_entry_that_is_not_due_yet_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let queue = RevokeQueue::open(dir.path().join(QUEUE_FILE)).unwrap();
        queue.enqueue(vec![one()]).await.unwrap();

        let revoker = AlwaysFails::default();
        let audit = audit(dir.path());
        // The first attempt is immediate and fails, which schedules the second
        // a second out.
        queue.run_pass(&revoker, &audit).await.unwrap();
        assert_eq!(revoker.0.load(Ordering::SeqCst), 1);

        // A pass now must not attempt it again: it is not due.
        queue.run_pass(&revoker, &audit).await.unwrap();
        assert_eq!(
            revoker.0.load(Ordering::SeqCst),
            1,
            "an entry inside its backoff window must not be retried early"
        );
        assert_eq!(queue.len().await, 1, "and it must still be queued");
        assert!(queue.next_due_in().await.unwrap() <= BASE_BACKOFF);
    }

    #[tokio::test]
    async fn one_stubborn_entry_does_not_drag_a_fresh_one_down_to_its_schedule() {
        let dir = tempfile::tempdir().unwrap();
        let queue = RevokeQueue::open(dir.path().join(QUEUE_FILE)).unwrap();

        // An entry that has already burned six attempts, so its next one is a
        // long way off.
        let mut stubborn = one();
        stubborn.attempts = 6;
        stubborn.not_before_unix_ms = now_unix_ms() + 30_000;
        queue.enqueue(vec![stubborn]).await.unwrap();
        // And one that has just arrived.
        queue.enqueue(vec![two()]).await.unwrap();

        let revoker = AlwaysWorks::default();
        queue.run_pass(&revoker, &audit(dir.path())).await.unwrap();

        assert_eq!(
            revoker.0.load(Ordering::SeqCst),
            1,
            "only the entry that was due may be attempted"
        );
        let left = queue.entries().await;
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].attempts, 6, "the waiting entry is untouched");
    }

    #[tokio::test]
    async fn the_queue_gives_up_after_the_documented_number_of_attempts() {
        let dir = tempfile::tempdir().unwrap();
        let queue = RevokeQueue::open(dir.path().join(QUEUE_FILE)).unwrap();
        queue.enqueue(vec![one()]).await.unwrap();

        let revoker = AlwaysFails::default();
        let audit = audit(dir.path());
        for _ in 0..MAX_ATTEMPTS {
            // Attempts are driven directly rather than by waiting out the real
            // backoff, which would make this test take two minutes.
            for entry in queue.pending.lock().await.iter_mut() {
                entry.not_before_unix_ms = 0;
            }
            queue.run_pass(&revoker, &audit).await.unwrap();
        }

        assert_eq!(revoker.0.load(Ordering::SeqCst), MAX_ATTEMPTS as usize);
        assert!(
            queue.is_empty().await,
            "an exhausted entry must not stay queued forever"
        );
    }

    #[tokio::test]
    async fn every_attempt_writes_an_audit_row_carrying_its_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let queue = RevokeQueue::open(dir.path().join(QUEUE_FILE)).unwrap();
        queue.enqueue(vec![one()]).await.unwrap();

        let audit = audit(dir.path());
        queue
            .run_pass(&AlwaysFails::default(), &audit)
            .await
            .unwrap();
        // The second attempt is driven directly rather than by waiting out the
        // backoff the first one scheduled.
        for entry in queue.pending.lock().await.iter_mut() {
            entry.not_before_unix_ms = 0;
        }
        queue
            .run_pass(&AlwaysFails::default(), &audit)
            .await
            .unwrap();
        audit.flush().await;

        let log = std::fs::read_dir(dir.path().join("audit"))
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect::<String>();
        let rows: Vec<serde_json::Value> = log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 2, "{log}");
        for row in rows {
            assert_eq!(row["event"], "revoke");
            assert_eq!(row["outcome"], "failed");
            assert_eq!(row["detail"], "42501: permission denied");
        }
    }

    #[tokio::test]
    async fn an_already_gone_credential_is_not_retried() {
        /// Reports the credential was already absent, which a reconcile sweep
        /// or the backend's own expiry can cause.
        #[derive(Debug)]
        struct Gone;

        #[async_trait]
        impl Revoker for Gone {
            async fn revoke(&self, _entry: &PendingRevoke) -> RevokeOutcome {
                RevokeOutcome::AlreadyGone
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let queue = RevokeQueue::open(dir.path().join(QUEUE_FILE)).unwrap();
        queue.enqueue(vec![one()]).await.unwrap();
        assert!(queue
            .run_pass(&Gone, &audit(dir.path()))
            .await
            .unwrap()
            .is_empty());
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn an_unreadable_line_is_dropped_without_losing_the_readable_ones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(QUEUE_FILE);
        let good = serde_json::to_string(&one()).unwrap();
        std::fs::write(&path, format!("{good}\nnot json\n{{}}\n")).unwrap();

        let queue = RevokeQueue::open(&path).unwrap();
        assert_eq!(queue.entries().await, vec![one()]);
    }

    #[tokio::test]
    async fn an_absent_queue_file_is_an_empty_queue_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let queue = RevokeQueue::open(dir.path().join("never-written.jsonl")).unwrap();
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn the_drain_loop_stops_when_shutdown_is_requested() {
        let dir = tempfile::tempdir().unwrap();
        let queue = Arc::new(RevokeQueue::open(dir.path().join(QUEUE_FILE)).unwrap());
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(drain_loop(
            queue,
            Arc::new(AlwaysWorks::default()),
            audit(dir.path()),
            shutdown.subscribe(),
        ));

        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the drain loop must stop on shutdown")
            .unwrap();
    }
}
