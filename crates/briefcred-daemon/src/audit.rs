//! The append-only JSONL audit log.
//!
//! One [`AuditEntry`] per line, in a file named for the UTC date it covers, so
//! rotation is a filename change rather than a rename dance and retention is a
//! date comparison rather than a stat. Every write is followed by an `fsync`:
//! an audit log that loses its last rows in a crash is not an audit log.
//!
//! # Why there is a writer task
//!
//! `fsync` blocks, and it blocks for as long as the disk wants. Holding a
//! `std::sync::Mutex` across it — which is what this module used to do —
//! parks an async worker thread inside a lock that every other request handler
//! is queueing on, so one slow disk stalls the whole daemon.
//!
//! So the log lives in one owner: a [`writer`] loop on a dedicated blocking
//! thread, fed by an unbounded channel. Handlers hold an [`AuditHandle`] and
//! hand rows over without waiting. Ordering is preserved because a channel is
//! a queue, the fsync-per-row guarantee is unchanged because the writer still
//! syncs every row before taking the next, and a caller that genuinely needs
//! the row to be on disk — a test, or the last row before the process exits —
//! calls [`AuditHandle::flush`].

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use briefcred_core::audit::AuditEntry;
use time::macros::format_description;
use time::{Date, OffsetDateTime};

use crate::error::{Error, Result};

const FILE_PREFIX: &str = "audit-";
const FILE_SUFFIX: &str = ".jsonl";

/// An open audit log, rotated daily and swept by retention.
#[derive(Debug)]
pub struct AuditLog {
    dir: PathBuf,
    retention_days: u32,
    open: Option<OpenFile>,
    write_errors: Arc<AtomicU64>,
}

#[derive(Debug)]
struct OpenFile {
    date: Date,
    path: PathBuf,
    file: File,
}

impl AuditLog {
    /// Prepare `dir` as a private audit directory. No file is opened until the
    /// first row is appended.
    pub fn open(dir: &Path, retention_days: u32) -> Result<AuditLog> {
        std::fs::create_dir_all(dir).map_err(|e| Error::io("create", dir, e))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::io("set the mode of", dir, e))?;
        Ok(AuditLog {
            dir: dir.to_path_buf(),
            retention_days,
            open: None,
            write_errors: Arc::new(AtomicU64::new(0)),
        })
    }

    /// The file rows are currently going to, or today's file if none is open.
    pub fn current_path(&self) -> PathBuf {
        match &self.open {
            Some(open) => open.path.clone(),
            None => self.path_for(OffsetDateTime::now_utc().date()),
        }
    }

    /// How many appends have failed over this log's lifetime.
    ///
    /// Surfaced as `briefcred_audit_write_errors_total`.
    pub fn write_errors(&self) -> u64 {
        self.write_errors.load(Ordering::Relaxed)
    }

    /// A handle to the same counter, for the metrics endpoint to read.
    pub fn write_errors_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.write_errors)
    }

    /// Append one row, rotating first if the UTC date has moved on.
    pub fn append(&mut self, entry: &AuditEntry) -> Result<()> {
        self.append_at(entry, OffsetDateTime::now_utc())
    }

    /// Append one row as if the clock read `now`.
    ///
    /// Taking the instant as an argument is what makes rotation testable
    /// without waiting for midnight.
    pub fn append_at(&mut self, entry: &AuditEntry, now: OffsetDateTime) -> Result<()> {
        self.append_inner(entry, now).inspect_err(|_| {
            self.write_errors.fetch_add(1, Ordering::Relaxed);
        })
    }

    fn append_inner(&mut self, entry: &AuditEntry, now: OffsetDateTime) -> Result<()> {
        let date = now.date();
        if self.open.as_ref().is_none_or(|open| open.date != date) {
            self.open = Some(self.open_for(date)?);
        }
        // Set above, so the expect cannot fire.
        let open = self.open.as_mut().expect("audit file was just opened");

        let mut line = serde_json::to_vec(entry).map_err(|e| Error::Io {
            action: "serialise an audit row for",
            path: open.path.clone(),
            source: e.into(),
        })?;
        line.push(b'\n');

        open.file
            .write_all(&line)
            .map_err(|e| Error::io("append to", &open.path, e))?;
        open.file
            .sync_data()
            .map_err(|e| Error::io("fsync", &open.path, e))?;
        Ok(())
    }

    fn open_for(&self, date: Date) -> Result<OpenFile> {
        let path = self.path_for(date);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| Error::io("open", &path, e))?;
        // The mode above applies only when the file is created, and a
        // permissive umask can only narrow it. Set it again so a log left
        // behind with a wider mode is corrected rather than inherited.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::io("set the mode of", &path, e))?;
        Ok(OpenFile { date, path, file })
    }

    fn path_for(&self, date: Date) -> PathBuf {
        self.dir.join(format!("{FILE_PREFIX}{date}{FILE_SUFFIX}"))
    }

    /// Delete audit files older than the retention window.
    pub fn sweep(&self) -> Result<usize> {
        self.sweep_at(OffsetDateTime::now_utc())
    }

    /// Delete audit files older than the retention window as of `now`.
    ///
    /// Returns how many were removed. The file currently being appended to is
    /// never a candidate, and a filename this log did not write is ignored
    /// rather than guessed at.
    pub fn sweep_at(&self, now: OffsetDateTime) -> Result<usize> {
        let cutoff = now.date() - time::Duration::days(i64::from(self.retention_days));
        let current = self.open.as_ref().map(|open| open.path.as_path());

        let entries = std::fs::read_dir(&self.dir).map_err(|e| Error::io("list", &self.dir, e))?;
        let mut removed = 0;
        for entry in entries {
            let entry = entry.map_err(|e| Error::io("list", &self.dir, e))?;
            let path = entry.path();
            if Some(path.as_path()) == current {
                continue;
            }
            let Some(date) = date_of(&entry.file_name().to_string_lossy()) else {
                continue;
            };
            if date < cutoff {
                std::fs::remove_file(&path).map_err(|e| Error::io("delete", &path, e))?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// One instruction to the [`writer`] loop.
enum Command {
    /// Append this row, then fsync it.
    Append(Box<AuditEntry>),
    /// Run the retention sweep.
    Sweep,
    /// Answer with the file rows are currently going to.
    Path(tokio::sync::oneshot::Sender<PathBuf>),
    /// Answer once every command queued before this one has been carried out.
    Barrier(tokio::sync::oneshot::Sender<()>),
}

/// A handle to the audit log's writer task.
///
/// Cloneable and cheap: every handler holds one. Appending never blocks and
/// never fails, which is deliberate — a daemon that stops serving because it
/// could not write a log line is worse than one that keeps serving with
/// `briefcred_audit_write_errors_total` climbing.
#[derive(Debug, Clone)]
pub struct AuditHandle {
    tx: tokio::sync::mpsc::UnboundedSender<Command>,
    write_errors: Arc<AtomicU64>,
}

impl AuditHandle {
    /// Queue one row. Returns immediately, before the row reaches the disk.
    pub fn append(&self, entry: &AuditEntry) {
        // A closed channel means the writer thread is gone, which only happens
        // as the process exits. Counting it keeps the metric honest.
        if self
            .tx
            .send(Command::Append(Box::new(entry.clone())))
            .is_err()
        {
            self.write_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Queue a retention sweep.
    pub fn sweep(&self) {
        let _ = self.tx.send(Command::Sweep);
    }

    /// The file rows are currently going to.
    pub async fn path(&self) -> PathBuf {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.tx.send(Command::Path(tx)).is_err() {
            return PathBuf::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Wait until everything queued so far has been written and synced.
    pub async fn flush(&self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.tx.send(Command::Barrier(tx)).is_ok() {
            let _ = rx.await;
        }
    }

    /// How many appends have failed over this log's lifetime.
    pub fn write_errors(&self) -> u64 {
        self.write_errors.load(Ordering::Relaxed)
    }

    /// A handle to the same counter, for the metrics endpoint to read.
    pub fn write_errors_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.write_errors)
    }
}

/// Start the writer thread for `log` and return the handle to it.
///
/// The loop runs on [`tokio::task::spawn_blocking`] rather than as an ordinary
/// task: it calls `fsync`, and an async worker thread is exactly the wrong
/// place to do that.
pub fn spawn(log: AuditLog) -> AuditHandle {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let handle = AuditHandle {
        tx,
        write_errors: log.write_errors_handle(),
    };
    tokio::task::spawn_blocking(move || writer(log, rx));
    handle
}

/// Own the log and carry out one command at a time until the last handle drops.
fn writer(mut log: AuditLog, mut rx: tokio::sync::mpsc::UnboundedReceiver<Command>) {
    while let Some(command) = rx.blocking_recv() {
        match command {
            Command::Append(entry) => {
                if let Err(err) = log.append(&entry) {
                    eprintln!("briefcred-daemon: audit write failed: {err}");
                }
            }
            Command::Sweep => {
                if let Err(err) = log.sweep() {
                    eprintln!("briefcred-daemon: audit retention sweep failed: {err}");
                }
            }
            Command::Path(reply) => {
                let _ = reply.send(log.current_path());
            }
            // Nothing to do: reaching this command at all means every command
            // queued before it has already been carried out.
            Command::Barrier(reply) => {
                let _ = reply.send(());
            }
        }
    }
}

/// The date an audit filename covers, or `None` if it is not one of ours.
fn date_of(name: &str) -> Option<Date> {
    let stem = name.strip_prefix(FILE_PREFIX)?.strip_suffix(FILE_SUFFIX)?;
    Date::parse(stem, format_description!("[year]-[month]-[day]")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::date;

    #[test]
    fn only_our_own_filenames_parse_as_dates() {
        assert_eq!(
            date_of("audit-2026-09-01.jsonl"),
            Some(date!(2026 - 09 - 01))
        );
        assert_eq!(date_of("audit-2026-13-99.jsonl"), None);
        assert_eq!(date_of("audit-.jsonl"), None);
        assert_eq!(date_of("audit.jsonl"), None);
        assert_eq!(date_of("audit-2026-09-01.jsonl.gz"), None);
        assert_eq!(date_of("notes.txt"), None);
    }
}
