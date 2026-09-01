//! `briefcred daemon status` against a real daemon, and against none.
//!
//! The daemon is spawned directly rather than through `launchctl`, and both
//! processes are pinned to a temporary `BRIEFCRED_HOME`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The `briefcred-daemon` built alongside the `briefcred` under test.
fn daemon_binary() -> PathBuf {
    let path = Path::new(env!("CARGO_BIN_EXE_briefcred"))
        .parent()
        .expect("the test binary has a directory")
        .join("briefcred-daemon");
    assert!(
        path.is_file(),
        "{} is missing; run `cargo test --workspace` so the daemon is built too",
        path.display()
    );
    path
}

fn briefcred(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_briefcred"))
        .env("BRIEFCRED_HOME", home)
        .args(args)
        .output()
        .expect("run briefcred")
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_daemon(home: &Path) -> Daemon {
    // Wrapped before the wait loop so the child is reaped on the panic path too.
    let daemon = Daemon(
        Command::new(daemon_binary())
            .env("BRIEFCRED_HOME", home)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn briefcred-daemon"),
    );
    for _ in 0..300 {
        if std::os::unix::net::UnixStream::connect(home.join("sock")).is_ok() {
            return daemon;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("the daemon never came up under {}", home.display());
}

#[test]
fn status_without_a_daemon_says_how_to_start_one_and_exits_three() {
    let temp = tempfile::tempdir().unwrap();
    let output = briefcred(temp.path(), &["daemon", "status"]);

    assert_eq!(output.status.code(), Some(3), "exit code");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("daemon is not running; run 'briefcred daemon start'"),
        "{stderr}"
    );
}

#[test]
fn status_against_a_running_daemon_reports_its_health() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("daemon.toml"), "metrics_port = 0\n").unwrap();
    let _daemon = start_daemon(temp.path());

    let output = briefcred(temp.path(), &["daemon", "status"]);
    assert!(output.status.success(), "{output:?}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("briefcred daemon is running"), "{stdout}");
    assert!(stdout.contains("version    0.1.0"), "{stdout}");
    assert!(stdout.contains("metrics    http://127.0.0.1:"), "{stdout}");
    assert!(
        stdout.contains(&temp.path().join("audit").display().to_string()),
        "the audit path must stay inside BRIEFCRED_HOME:\n{stdout}"
    );
    assert!(
        !stdout.contains("password") && !stdout.contains("secret"),
        "status is metadata only:\n{stdout}"
    );
}

#[test]
fn install_dry_run_touches_nothing_and_names_the_launch_agent() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let output = Command::new(env!("CARGO_BIN_EXE_briefcred"))
        .env("BRIEFCRED_HOME", &home)
        .args(["install", "--dry-run"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("dry run: briefcred install"), "{stdout}");
    assert!(stdout.contains("dev.briefcred.daemon.plist"), "{stdout}");
    assert!(stdout.contains("launchctl bootstrap"), "{stdout}");
    assert!(
        !home.exists(),
        "a dry run must not create {}",
        home.display()
    );
}
