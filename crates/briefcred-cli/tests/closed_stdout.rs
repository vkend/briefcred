//! A reader that stops early, `briefcred audit | head` style, must not make
//! the CLI panic.

use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};

#[test]
fn audit_into_a_pipe_closed_after_one_line_exits_quietly() {
    let home = tempfile::tempdir().unwrap();
    let audit = home.path().join("audit");
    std::fs::create_dir_all(&audit).unwrap();
    // Far more than a pipe buffers, so the CLI is still writing when the
    // reader goes away.
    let row = r#"{"event":"revoke","ts":"2026-01-01T00:00:00.000001Z","mint_id":"briefcred_t_1","kind":"http-bearer","outcome":"revoked"}"#;
    let rows = vec![row; 20_000].join("\n") + "\n";
    std::fs::write(audit.join("audit-2026-01-01.jsonl"), rows).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_briefcred"))
        .env("BRIEFCRED_HOME", home.path())
        .args(["audit", "--since", "3650d"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap();
    assert!(first.contains("revoke"), "{first}");
    // The reader is dropped here, closing the pipe.

    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "a closed stdout must not be a crash:\n{stderr}"
    );
    assert!(output.status.success(), "{:?}\n{stderr}", output.status);
}
