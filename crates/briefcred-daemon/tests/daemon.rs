//! End-to-end exercise of the real `briefcred-daemon` binary.
//!
//! The daemon is spawned directly, never through `launchctl`, and every run is
//! confined to a temporary `BRIEFCRED_HOME`, so this test never touches the
//! developer's own socket, audit log, or LaunchAgents.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use briefcred_core::audit::AuditEntry;
use briefcred_proto::{read_frame, write_frame, Request, Response};
use tokio::net::UnixStream;

/// A spawned daemon, killed if a test fails before shutting it down.
struct Daemon {
    child: Option<Child>,
    home: tempfile::TempDir,
}

impl Daemon {
    fn start(config: &str) -> Daemon {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("daemon.toml"), config).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_briefcred-daemon"))
            .env("BRIEFCRED_HOME", home.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn briefcred-daemon");
        Daemon {
            child: Some(child),
            home,
        }
    }

    fn sock(&self) -> PathBuf {
        self.home.path().join("sock")
    }

    fn audit_dir(&self) -> PathBuf {
        self.home.path().join("audit")
    }

    async fn connect(&self) -> UnixStream {
        for _ in 0..300 {
            if let Ok(stream) = UnixStream::connect(self.sock()).await {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("daemon never accepted a connection on {:?}", self.sock());
    }

    /// Wait for the process to exit, returning whether it exited successfully.
    fn wait(&mut self) -> bool {
        let mut child = self.child.take().expect("daemon already reaped");
        for _ in 0..300 {
            match child.try_wait().unwrap() {
                Some(status) => return status.success(),
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        let _ = child.kill();
        panic!("daemon did not exit within six seconds");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

async fn call(stream: &mut UnixStream, request: Request) -> Response {
    write_frame(stream, &request).await.unwrap();
    read_frame(stream).await.unwrap().unwrap()
}

/// One blocking HTTP/1.1 GET, so the test needs no HTTP client dependency.
fn http_get(addr: &str, path: &str) -> String {
    let mut socket = std::net::TcpStream::connect(addr).unwrap();
    socket
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
    let mut body = String::new();
    socket.read_to_string(&mut body).unwrap();
    body
}

fn audit_rows(dir: &Path) -> Vec<AuditEntry> {
    let mut rows = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        for line in std::fs::read_to_string(&path).unwrap().lines() {
            rows.push(serde_json::from_str(line).expect("every audit line is one entry"));
        }
    }
    rows
}

#[tokio::test]
async fn the_daemon_pings_reports_status_serves_metrics_and_shuts_down() {
    let mut daemon = Daemon::start("retention_days = 90\nmetrics_port = 0\n");
    let mut stream = daemon.connect().await;

    assert_eq!(call(&mut stream, Request::Ping).await, Response::Pong);

    let Response::Status {
        version,
        pid,
        uptime_secs,
        audit_path,
        metrics_addr,
        ..
    } = call(&mut stream, Request::Status).await
    else {
        panic!("Status did not answer with a Status");
    };
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        pid,
        daemon.child.as_ref().unwrap().id(),
        "the daemon reports its own pid"
    );
    assert!(uptime_secs < 60);
    assert!(
        audit_path.starts_with(daemon.home.path()),
        "audit path {audit_path:?} escaped BRIEFCRED_HOME"
    );
    let metrics_addr = metrics_addr.expect("metrics are enabled by default");
    assert!(metrics_addr.starts_with("127.0.0.1:"), "{metrics_addr}");

    let scrape = http_get(&metrics_addr, "/metrics");
    assert!(scrape.starts_with("HTTP/1.1 200 OK"), "{scrape}");
    assert!(scrape.contains("text/plain; version=0.0.4"), "{scrape}");
    assert!(
        scrape.contains("# TYPE briefcred_uptime_seconds gauge"),
        "{scrape}"
    );
    assert!(
        scrape.contains("briefcred_audit_write_errors_total 0"),
        "{scrape}"
    );
    assert!(
        scrape.contains("briefcred_ipc_requests_total{request=\"ping\"} 1"),
        "the ping above should have been counted:\n{scrape}"
    );

    let missing = http_get(&metrics_addr, "/");
    assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");

    assert_eq!(
        call(&mut stream, Request::Shutdown).await,
        Response::ShuttingDown
    );
    assert!(daemon.wait(), "the daemon exited cleanly");

    assert!(
        !daemon.sock().exists(),
        "the socket file must not outlive the daemon"
    );

    let rows = audit_rows(&daemon.audit_dir());
    assert!(
        rows.iter()
            .any(|row| matches!(row, AuditEntry::DaemonStart { .. })),
        "{rows:?}"
    );
    let stop = rows
        .iter()
        .find_map(|row| match row {
            AuditEntry::DaemonStop { reason, .. } => Some(reason.clone()),
            _ => None,
        })
        .expect("a DaemonStop row");
    assert_eq!(stop, "request");
}

#[tokio::test]
async fn the_socket_and_its_directory_are_private_to_the_owner() {
    let daemon = Daemon::start("metrics_enabled = false\n");
    let _stream = daemon.connect().await;

    let sock_mode = std::fs::metadata(daemon.sock())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let dir_mode = std::fs::metadata(daemon.home.path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(sock_mode, 0o600, "socket mode {sock_mode:o}");
    assert_eq!(dir_mode, 0o700, "home mode {dir_mode:o}");
}

#[tokio::test]
async fn metrics_can_be_switched_off_entirely() {
    let daemon = Daemon::start("metrics_enabled = false\n");
    let mut stream = daemon.connect().await;

    let Response::Status { metrics_addr, .. } = call(&mut stream, Request::Status).await else {
        panic!("Status did not answer with a Status");
    };
    assert_eq!(metrics_addr, None);
}

#[tokio::test]
async fn a_socket_left_behind_by_a_dead_daemon_is_cleared_on_start() {
    let home = tempfile::tempdir().unwrap();
    // A plain file where the socket belongs: what a SIGKILLed daemon leaves.
    std::fs::write(home.path().join("sock"), b"stale").unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_briefcred-daemon"))
        .env("BRIEFCRED_HOME", home.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut connected = false;
    for _ in 0..300 {
        if UnixStream::connect(home.path().join("sock")).await.is_ok() {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(connected, "the daemon did not replace the stale socket");
}

#[tokio::test]
async fn a_second_daemon_refuses_to_take_over_a_live_socket() {
    let daemon = Daemon::start("metrics_enabled = false\n");
    let _stream = daemon.connect().await;

    let second = Command::new(env!("CARGO_BIN_EXE_briefcred-daemon"))
        .env("BRIEFCRED_HOME", daemon.home.path())
        .output()
        .unwrap();
    assert!(!second.status.success(), "the second daemon should refuse");
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(stderr.contains("already listening"), "{stderr}");
}
