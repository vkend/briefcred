//! The JSONL audit log: one row per line, daily rotation by filename, and a
//! retention sweep that deletes by the date in that filename.

use std::os::unix::fs::PermissionsExt;

use briefcred_core::audit::AuditEntry;
use briefcred_daemon::audit::AuditLog;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

fn start(pid: u32) -> AuditEntry {
    AuditEntry::DaemonStart {
        ts: OffsetDateTime::UNIX_EPOCH,
        pid,
        version: "0.1.0".into(),
    }
}

fn lines(path: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn rows_are_appended_one_json_object_per_line() {
    let dir = tempfile::tempdir().unwrap();
    let day = datetime!(2026-09-01 10:00 UTC);
    let mut log = AuditLog::open(dir.path(), 90).unwrap();

    log.append_at(&start(1), day).unwrap();
    log.append_at(&start(2), day).unwrap();

    let path = dir.path().join("audit-2026-09-01.jsonl");
    assert_eq!(log.current_path(), path);
    let lines = lines(&path);
    assert_eq!(lines.len(), 2);
    for line in &lines {
        let back: AuditEntry = serde_json::from_str(line).unwrap();
        assert!(matches!(back, AuditEntry::DaemonStart { .. }));
    }
    assert!(lines[0].contains("\"pid\":1"));
    assert!(lines[1].contains("\"pid\":2"));
}

#[test]
fn crossing_midnight_opens_tomorrows_file_and_leaves_todays_alone() {
    let dir = tempfile::tempdir().unwrap();
    let mut log = AuditLog::open(dir.path(), 90).unwrap();

    log.append_at(&start(1), datetime!(2026-09-01 23:59:59 UTC))
        .unwrap();
    log.append_at(&start(2), datetime!(2026-09-02 00:00:01 UTC))
        .unwrap();

    let first = dir.path().join("audit-2026-09-01.jsonl");
    let second = dir.path().join("audit-2026-09-02.jsonl");
    assert_eq!(lines(&first).len(), 1);
    assert_eq!(lines(&second).len(), 1);
    assert_eq!(log.current_path(), second);
}

#[test]
fn reopening_appends_rather_than_truncating() {
    let dir = tempfile::tempdir().unwrap();
    let day = datetime!(2026-09-01 10:00 UTC);

    let mut log = AuditLog::open(dir.path(), 90).unwrap();
    log.append_at(&start(1), day).unwrap();
    drop(log);

    let mut log = AuditLog::open(dir.path(), 90).unwrap();
    log.append_at(&start(2), day).unwrap();

    assert_eq!(lines(&dir.path().join("audit-2026-09-01.jsonl")).len(), 2);
}

#[test]
fn the_directory_is_private_and_so_is_every_log_file() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    let mut log = AuditLog::open(&audit, 90).unwrap();
    log.append_at(&start(1), datetime!(2026-09-01 10:00 UTC))
        .unwrap();

    let dir_mode = std::fs::metadata(&audit).unwrap().permissions().mode() & 0o777;
    let file_mode = std::fs::metadata(log.current_path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "audit dir mode {dir_mode:o}");
    assert_eq!(file_mode, 0o600, "audit file mode {file_mode:o}");
}

#[test]
fn the_sweep_deletes_logs_older_than_retention_and_keeps_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let now = datetime!(2026-09-01 10:00 UTC);
    for back in [0i64, 1, 6, 7, 8, 400] {
        let day = (now - Duration::days(back)).date();
        let name = format!("audit-{day}.jsonl");
        std::fs::write(dir.path().join(name), "{}\n").unwrap();
    }

    let log = AuditLog::open(dir.path(), 7).unwrap();
    let removed = log.sweep_at(now).unwrap();
    assert_eq!(removed, 2, "the 8-day-old and 400-day-old files");

    let mut kept: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    kept.sort();
    assert_eq!(
        kept,
        vec![
            "audit-2026-08-25.jsonl".to_string(),
            "audit-2026-08-26.jsonl".to_string(),
            "audit-2026-08-31.jsonl".to_string(),
            "audit-2026-09-01.jsonl".to_string(),
        ]
    );
}

#[test]
fn the_sweep_never_deletes_the_file_it_is_currently_appending_to() {
    let dir = tempfile::tempdir().unwrap();
    let now = datetime!(2026-09-01 10:00 UTC);
    let mut log = AuditLog::open(dir.path(), 1).unwrap();
    log.append_at(&start(1), now).unwrap();

    assert_eq!(log.sweep_at(now).unwrap(), 0);
    assert!(log.current_path().exists());
}

#[test]
fn the_sweep_ignores_files_it_did_not_write() {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "notes.txt",
        "audit.jsonl",
        "audit-2026-13-99.jsonl",
        "audit-",
    ] {
        std::fs::write(dir.path().join(name), "x").unwrap();
    }
    std::fs::write(dir.path().join("audit-2000-01-01.jsonl"), "x").unwrap();

    let log = AuditLog::open(dir.path(), 30).unwrap();
    assert_eq!(log.sweep_at(datetime!(2026-09-01 10:00 UTC)).unwrap(), 1);
    assert!(dir.path().join("audit-2026-13-99.jsonl").exists());
    assert!(dir.path().join("notes.txt").exists());
}

#[test]
fn write_errors_are_counted_rather_than_swallowed() {
    let dir = tempfile::tempdir().unwrap();
    let mut log = AuditLog::open(dir.path(), 90).unwrap();
    assert_eq!(log.write_errors(), 0);

    // Make the directory unwritable so tomorrow's rotation cannot create a file.
    log.append_at(&start(1), datetime!(2026-09-01 10:00 UTC))
        .unwrap();
    let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
    perms.set_mode(0o500);
    std::fs::set_permissions(dir.path(), perms).unwrap();

    let result = log.append_at(&start(2), datetime!(2026-09-02 10:00 UTC));

    let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(dir.path(), perms).unwrap();

    assert!(result.is_err(), "rotation into an unwritable directory");
    assert_eq!(log.write_errors(), 1);
}
