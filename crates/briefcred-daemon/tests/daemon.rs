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

/// Add the port overrides every test needs, unless the test set them itself.
///
/// A daemon started by a test must not bind either of the real ports: two test
/// binaries run concurrently, and one of them would lose the race to whichever
/// daemon the developer actually has installed.
fn with_ephemeral_ports(config: &str) -> String {
    let mut config = config.to_string();
    for line in ["metrics_port = 0", "proxy_port = 0"] {
        let key = line.split_whitespace().next().expect("a key");
        if !config
            .lines()
            .any(|existing| existing.trim_start().starts_with(key))
        {
            config.push('\n');
            config.push_str(line);
        }
    }
    config.push('\n');
    config
}

impl Daemon {
    fn start(config: &str) -> Daemon {
        Daemon::start_with(config, |_| {})
    }

    /// Start a daemon whose home has been populated first.
    ///
    /// Profiles and master secrets have to exist before the process starts, or
    /// the test is racing the daemon's own startup load.
    fn start_with(config: &str, populate: impl FnOnce(&Path)) -> Daemon {
        Daemon::start_with_env(config, &[], populate)
    }

    /// Start a daemon with extra environment, for a test that has to control
    /// something the daemon reads from it — `TMPDIR`, in the SSH case, so a
    /// minted private key lands somewhere the test can watch and clean up.
    fn start_with_env(config: &str, env: &[(&str, &Path)], populate: impl FnOnce(&Path)) -> Daemon {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join("daemon.toml"),
            with_ephemeral_ports(config),
        )
        .unwrap();
        populate(home.path());
        let mut command = Command::new(env!("CARGO_BIN_EXE_briefcred-daemon"));
        command.env("BRIEFCRED_HOME", home.path());
        for (key, value) in env {
            command.env(key, value);
        }
        let child = command
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
    ///
    /// The budget is generous on purpose. How *fast* shutdown is belongs to
    /// `shutdown_does_not_wait_out_the_drain_timeout_on_idle_connections`;
    /// a tight budget here would only turn a loaded machine into a flake.
    fn wait(&mut self) -> bool {
        let mut child = self.child.take().expect("daemon already reaped");
        for _ in 0..750 {
            match child.try_wait().unwrap() {
                Some(status) => return status.success(),
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        let _ = child.kill();
        panic!("daemon did not exit within fifteen seconds");
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

struct Timer(&'static str, std::time::Instant);
impl Drop for Timer {
    fn drop(&mut self) {
        eprintln!("TIME {} {:?}", self.0, self.1.elapsed());
    }
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
    let __t = std::time::Instant::now();
    let __g = Timer(
        "the_daemon_pings_reports_status_serves_metrics_and_shuts_down",
        __t,
    );
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
    let __t = std::time::Instant::now();
    let __g = Timer("the_socket_and_its_directory_are_private_to_the_owner", __t);
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
    let __t = std::time::Instant::now();
    let __g = Timer("metrics_can_be_switched_off_entirely", __t);
    let daemon = Daemon::start("metrics_enabled = false\n");
    let mut stream = daemon.connect().await;

    let Response::Status { metrics_addr, .. } = call(&mut stream, Request::Status).await else {
        panic!("Status did not answer with a Status");
    };
    assert_eq!(metrics_addr, None);
}

#[tokio::test]
async fn a_socket_left_behind_by_a_dead_daemon_is_cleared_on_start() {
    let __t = std::time::Instant::now();
    let __g = Timer(
        "a_socket_left_behind_by_a_dead_daemon_is_cleared_on_start",
        __t,
    );
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
    let __t = std::time::Instant::now();
    let __g = Timer("a_second_daemon_refuses_to_take_over_a_live_socket", __t);
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

#[tokio::test]
async fn shutdown_does_not_wait_out_the_drain_timeout_on_idle_connections() {
    let __t = std::time::Instant::now();
    let __g = Timer(
        "shutdown_does_not_wait_out_the_drain_timeout_on_idle_connections",
        __t,
    );
    let mut daemon = Daemon::start("metrics_enabled = false\n");
    let mut control = daemon.connect().await;
    // A second connection that is open, authenticated, and silent. Before the
    // connection loop learned to watch for shutdown, this held the drain open
    // for its full five seconds on every single stop.
    let _idle = daemon.connect().await;

    let started = std::time::Instant::now();
    assert_eq!(
        call(&mut control, Request::Shutdown).await,
        Response::ShuttingDown
    );
    assert!(daemon.wait());
    let elapsed = started.elapsed();

    assert!(
        elapsed < briefcred_daemon::server::DRAIN_TIMEOUT,
        "shutdown took {elapsed:?}, which is the whole drain timeout"
    );
}

#[tokio::test]
async fn sigterm_stops_the_daemon_and_says_so_in_the_audit_log() {
    let __t = std::time::Instant::now();
    let __g = Timer("sigterm_stops_the_daemon_and_says_so_in_the_audit_log", __t);
    let mut daemon = Daemon::start("metrics_enabled = false\n");
    let _stream = daemon.connect().await;

    let pid = daemon.child.as_ref().unwrap().id();
    let killed = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    assert!(daemon.wait(), "SIGTERM is a clean exit, not a crash");

    assert!(!daemon.sock().exists(), "the socket must be cleaned up");
    let reason = audit_rows(&daemon.audit_dir())
        .into_iter()
        .find_map(|row| match row {
            AuditEntry::DaemonStop { reason, .. } => Some(reason),
            _ => None,
        })
        .expect("a DaemonStop row");
    assert_eq!(reason, "sigterm");
}

#[tokio::test]
async fn a_connection_racing_the_signal_does_not_hold_the_drain_open() {
    // Connect and signal with no pause in between, so the connection is
    // sometimes still in the accept backlog and sometimes accepted in the same
    // breath as the shutdown request. The second case used to leave the
    // connection task waiting on a change that had already happened, and the
    // daemon then sat out its whole drain timeout on every such stop.
    for attempt in 0..6 {
        let mut daemon = Daemon::start("metrics_enabled = false\n");
        let _stream = daemon.connect().await;
        let pid = daemon.child.as_ref().unwrap().id();

        let started = std::time::Instant::now();
        assert!(Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .unwrap()
            .success());
        assert!(daemon.wait(), "attempt {attempt} did not exit cleanly");

        let elapsed = started.elapsed();
        assert!(
            elapsed < briefcred_daemon::server::DRAIN_TIMEOUT,
            "attempt {attempt} took {elapsed:?}, the whole drain timeout"
        );
    }
}

/// A profile that needs no prompt and one master the file source can serve.
const UNATTENDED_PROFILE: &str = "\
name: dev
description: unattended development profile
unlock:
  policy: none
credentials:
  - name: db
    kind: postgres-dynamic
    ttl_secs: 300
    source_key: app-db
    config:
      host: 127.0.0.1
      dbname: app
      user: master
      sslmode: disable
      role_template: {}
";

/// Write a `0600` master file the way `briefcred master set` will.
fn write_master(home: &Path, key: &str, value: &str) {
    let dir = home.join("secrets");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(key);
    std::fs::write(&path, value).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn write_profile(home: &Path, file: &str, yaml: &str) {
    let dir = home.join("profiles");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(file), yaml).unwrap();
}

#[tokio::test]
async fn the_daemon_lists_a_profile_opens_a_session_and_closes_it() {
    let mut daemon = Daemon::start_with(
        "metrics_enabled = false\nmaster_source = \"file\"\n",
        |home| {
            write_profile(home, "dev.yaml", UNATTENDED_PROFILE);
            write_master(home, "app-db", "the-master-password\n");
        },
    );
    let mut stream = daemon.connect().await;

    let Response::Profiles { profiles } = call(&mut stream, Request::ListProfiles).await else {
        panic!("expected a profile list");
    };
    assert_eq!(profiles.len(), 1, "{profiles:?}");
    assert_eq!(profiles[0].name, "dev");
    assert_eq!(profiles[0].unlock_policy, "none");
    assert_eq!(profiles[0].credentials[0].source_key, "app-db");

    let Response::Profile { profile } =
        call(&mut stream, Request::ShowProfile { name: "dev".into() }).await
    else {
        panic!("expected one profile");
    };
    assert_eq!(profile.credentials[0].ttl_secs, 300);

    let Response::SessionOpened { session_id, .. } = call(
        &mut stream,
        Request::OpenSession {
            profile: "dev".into(),
            client_headless: false,
            session_pubkey: None,
        },
    )
    .await
    else {
        panic!("expected a session");
    };

    assert_eq!(
        call(
            &mut stream,
            Request::CloseSession {
                session_id: session_id.clone(),
            },
        )
        .await,
        Response::SessionClosed {
            session_id: session_id.clone()
        }
    );

    // Closing twice must say so rather than silently succeed.
    let Response::Error { message } = call(
        &mut stream,
        Request::CloseSession {
            session_id: session_id.clone(),
        },
    )
    .await
    else {
        panic!("expected an error for an already-closed session");
    };
    assert!(message.contains("no open session"), "{message}");

    assert_eq!(
        call(&mut stream, Request::Shutdown).await,
        Response::ShuttingDown
    );
    assert!(daemon.wait());

    let rows = audit_rows(&daemon.audit_dir());
    let opened = rows.iter().any(|r| {
        matches!(r, AuditEntry::SessionOpen { session_id: id, profile, credentials, .. }
            if *id == session_id && profile == "dev" && *credentials == 1)
    });
    let closed = rows.iter().any(|r| {
        matches!(r, AuditEntry::SessionClose { session_id: id, reason, .. }
            if *id == session_id && reason == "request")
    });
    assert!(opened, "no SessionOpen row in {rows:#?}");
    assert!(closed, "no SessionClose row in {rows:#?}");

    // The master must never appear in the audit log, in any row.
    let raw = std::fs::read_dir(daemon.audit_dir())
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect::<String>();
    assert!(!raw.contains("the-master-password"), "{raw}");
}

#[tokio::test]
async fn opening_a_session_for_an_unknown_profile_says_which_one() {
    let mut daemon = Daemon::start("metrics_enabled = false\nmaster_source = \"file\"\n");
    let mut stream = daemon.connect().await;

    let Response::Error { message } = call(
        &mut stream,
        Request::OpenSession {
            profile: "absent".into(),
            client_headless: false,
            session_pubkey: None,
        },
    )
    .await
    else {
        panic!("expected an error");
    };
    assert!(message.contains("absent"), "{message}");

    call(&mut stream, Request::Shutdown).await;
    assert!(daemon.wait());
}

#[tokio::test]
async fn a_missing_master_fails_the_open_and_names_where_it_looked() {
    let mut daemon = Daemon::start_with(
        "metrics_enabled = false\nmaster_source = \"file\"\n",
        |home| write_profile(home, "dev.yaml", UNATTENDED_PROFILE),
    );
    let mut stream = daemon.connect().await;

    let Response::Error { message } = call(
        &mut stream,
        Request::OpenSession {
            profile: "dev".into(),
            client_headless: false,
            session_pubkey: None,
        },
    )
    .await
    else {
        panic!("expected an error");
    };
    assert!(message.contains("app-db"), "{message}");
    assert!(message.contains("secrets"), "{message}");

    call(&mut stream, Request::Shutdown).await;
    assert!(daemon.wait());
}

#[tokio::test]
async fn a_profile_written_while_the_daemon_runs_is_picked_up() {
    let mut daemon = Daemon::start("metrics_enabled = false\nmaster_source = \"file\"\n");
    let mut stream = daemon.connect().await;

    let Response::Profiles { profiles } = call(&mut stream, Request::ListProfiles).await else {
        panic!("expected a profile list");
    };
    assert!(profiles.is_empty(), "{profiles:?}");

    write_profile(daemon.home.path(), "late.yaml", "name: late\n");

    let mut seen = false;
    for _ in 0..200 {
        if let Response::Profiles { profiles } = call(&mut stream, Request::ListProfiles).await {
            if profiles.iter().any(|p| p.name == "late") {
                seen = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(seen, "the watcher never picked up the new profile");

    call(&mut stream, Request::Shutdown).await;
    assert!(daemon.wait());
}

#[tokio::test]
async fn a_broken_profile_is_audited_and_the_good_ones_survive() {
    let mut daemon = Daemon::start_with(
        "metrics_enabled = false\nmaster_source = \"file\"\n",
        |home| write_profile(home, "dev.yaml", UNATTENDED_PROFILE),
    );
    let mut stream = daemon.connect().await;

    write_profile(
        daemon.home.path(),
        "broken.yaml",
        "name: broken\nbogus: 1\n",
    );

    // A minute, not ten seconds. What is under test is *that* the broken file
    // is audited and that service is undisturbed meanwhile, not how quickly the
    // filesystem watcher notices — and on a machine running the rest of the
    // suite in parallel, several ephemeral PostgreSQL clusters and the proxy's
    // end-to-end tests among it, the notification and the reload behind it are
    // not prompt. A budget tight enough to catch a regression in watcher
    // *latency* would be a budget that fails under load, which is a worse test
    // than a slow one.
    let mut audited = false;
    for _ in 0..1_200 {
        // Keep the connection working while the reload happens: a broken file
        // must not disturb service at all.
        assert_eq!(call(&mut stream, Request::Ping).await, Response::Pong);
        if daemon.audit_dir().exists()
            && audit_rows(&daemon.audit_dir())
                .iter()
                .any(|r| matches!(r, AuditEntry::ProfileLoadError { .. }))
        {
            audited = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(audited, "the broken file was never audited");

    let Response::Profiles { profiles } = call(&mut stream, Request::ListProfiles).await else {
        panic!("expected a profile list");
    };
    assert_eq!(profiles.len(), 1, "the good profile must survive");
    assert_eq!(profiles[0].name, "dev");

    call(&mut stream, Request::Shutdown).await;
    assert!(daemon.wait());
}

#[tokio::test]
async fn a_session_still_open_at_shutdown_is_closed_and_audited() {
    let mut daemon = Daemon::start_with(
        "metrics_enabled = false\nmaster_source = \"file\"\n",
        |home| {
            write_profile(home, "dev.yaml", UNATTENDED_PROFILE);
            write_master(home, "app-db", "the-master-password");
        },
    );
    let mut stream = daemon.connect().await;

    let Response::SessionOpened { session_id, .. } = call(
        &mut stream,
        Request::OpenSession {
            profile: "dev".into(),
            client_headless: false,
            session_pubkey: None,
        },
    )
    .await
    else {
        panic!("expected a session");
    };

    call(&mut stream, Request::Shutdown).await;
    assert!(daemon.wait());

    let rows = audit_rows(&daemon.audit_dir());
    assert!(
        rows.iter().any(|r| matches!(
            r,
            AuditEntry::SessionClose { session_id: id, reason, .. }
                if *id == session_id && reason == "shutdown"
        )),
        "no shutdown SessionClose row in {rows:#?}"
    );
}

#[tokio::test]
async fn an_idle_session_is_evicted_and_audited() {
    // One second idle plus the 30-second sweep is the shortest this can be
    // driven through the real binary; the exact boundary is unit-tested with
    // a stopped clock in `session::tests`.
    let mut daemon = Daemon::start_with(
        "metrics_enabled = false\nmaster_source = \"file\"\nsession_idle_secs = 1\n",
        |home| {
            write_profile(home, "dev.yaml", UNATTENDED_PROFILE);
            write_master(home, "app-db", "the-master-password");
        },
    );
    let mut stream = daemon.connect().await;

    let Response::SessionOpened { session_id, .. } = call(
        &mut stream,
        Request::OpenSession {
            profile: "dev".into(),
            client_headless: false,
            session_pubkey: None,
        },
    )
    .await
    else {
        panic!("expected a session");
    };

    let mut evicted = false;
    for _ in 0..900 {
        if audit_rows(&daemon.audit_dir()).iter().any(|r| {
            matches!(r, AuditEntry::SessionClose { session_id: id, reason, .. }
                if *id == session_id && reason == "idle")
        }) {
            evicted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(evicted, "the idle session was never evicted");

    // And the handle is genuinely gone, not merely audited as gone.
    let Response::Error { message } = call(
        &mut stream,
        Request::CloseSession {
            session_id: session_id.clone(),
        },
    )
    .await
    else {
        panic!("expected the evicted session to be unknown");
    };
    assert!(message.contains("no open session"), "{message}");

    call(&mut stream, Request::Shutdown).await;
    assert!(daemon.wait());
}

/// The same profile, but with the default biometric policy left in place.
const GUARDED_PROFILE: &str = "\
name: guarded
credentials:
  - name: db
    kind: postgres-dynamic
    source_key: app-db
    config:
      host: 127.0.0.1
      dbname: app
      user: master
      sslmode: disable
      role_template: {}
";

#[tokio::test]
async fn a_headless_daemon_refuses_a_guarded_profile_and_reads_no_master() {
    // `BRIEFCRED_FORCE_NO_AQUA` stands in for an SSH login, which is the case
    // that must never fall back to something weaker.
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join("daemon.toml"),
        with_ephemeral_ports("metrics_enabled = false\nmaster_source = \"file\"\n"),
    )
    .unwrap();
    write_profile(home.path(), "guarded.yaml", GUARDED_PROFILE);
    write_master(home.path(), "app-db", "the-master-password");

    let child = Command::new(env!("CARGO_BIN_EXE_briefcred-daemon"))
        .env("BRIEFCRED_HOME", home.path())
        .env("BRIEFCRED_FORCE_NO_AQUA", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn briefcred-daemon");
    let mut daemon = Daemon {
        child: Some(child),
        home,
    };
    let mut stream = daemon.connect().await;

    let Response::Locked { reason, message } = call(
        &mut stream,
        Request::OpenSession {
            profile: "guarded".into(),
            client_headless: false,
            session_pubkey: None,
        },
    )
    .await
    else {
        panic!("a headless daemon must refuse a biometric profile");
    };
    assert_eq!(reason, "no_aqua_session");
    assert!(message.contains("unlock.policy: none"), "{message}");

    call(&mut stream, Request::Shutdown).await;
    assert!(daemon.wait());

    let rows = audit_rows(&daemon.audit_dir());
    assert!(
        rows.iter().any(|r| matches!(
            r,
            AuditEntry::UnlockDenied { profile, policy, reason, .. }
                if profile == "guarded" && policy == "biometric" && reason == "no_aqua_session"
        )),
        "no UnlockDenied row in {rows:#?}"
    );
    assert!(
        !rows
            .iter()
            .any(|r| matches!(r, AuditEntry::SessionOpen { .. })),
        "a refused unlock must open no session"
    );
}

#[tokio::test]
async fn a_client_that_declares_itself_headless_is_refused_by_a_daemon_that_is_not() {
    // The daemon here has a graphical session; the client says it does not.
    // That is the SSH case the daemon cannot see for itself, and it is the
    // whole reason `client_headless` crosses the wire.
    let mut daemon = Daemon::start_with(
        "metrics_enabled = false\nmaster_source = \"file\"\n",
        |home| {
            write_profile(home, "guarded.yaml", GUARDED_PROFILE);
            write_master(home, "app-db", "the-master-password");
        },
    );
    let mut stream = daemon.connect().await;

    let Response::Locked { reason, message } = call(
        &mut stream,
        Request::OpenSession {
            profile: "guarded".into(),
            client_headless: true,
            session_pubkey: None,
        },
    )
    .await
    else {
        panic!("a client with no screen must be refused");
    };
    assert_eq!(reason, "no_aqua_session");
    assert!(message.contains("unlock.policy: none"), "{message}");

    call(&mut stream, Request::Shutdown).await;
    assert!(daemon.wait());

    let rows = audit_rows(&daemon.audit_dir());
    assert!(
        rows.iter().any(|r| matches!(
            r,
            AuditEntry::UnlockDenied { profile, reason, .. }
                if profile == "guarded" && reason == "no_aqua_session"
        )),
        "no UnlockDenied row in {rows:#?}"
    );
    assert!(
        !rows
            .iter()
            .any(|r| matches!(r, AuditEntry::SessionOpen { .. })),
        "a refused client must open no session"
    );
}

#[tokio::test]
async fn an_unattended_profile_still_opens_for_a_headless_client() {
    // The documented escape hatch has to keep working, or every unattended
    // profile breaks the moment it is run from cron or over SSH.
    let mut daemon = Daemon::start_with(
        "metrics_enabled = false\nmaster_source = \"file\"\n",
        |home| {
            write_profile(home, "dev.yaml", UNATTENDED_PROFILE);
            write_master(home, "app-db", "the-master-password");
        },
    );
    let mut stream = daemon.connect().await;

    let Response::SessionOpened { .. } = call(
        &mut stream,
        Request::OpenSession {
            profile: "dev".into(),
            client_headless: true,
            session_pubkey: None,
        },
    )
    .await
    else {
        panic!("`unlock.policy: none` must open regardless of the client's session");
    };

    call(&mut stream, Request::Shutdown).await;
    assert!(daemon.wait());
}

/// A profile that mints an SSH certificate, which is the one minter kind the
/// daemon runs in its own process rather than in a helper.
const SSH_PROFILE: &str = "\
name: bastion
unlock:
  policy: none
credentials:
  - name: host
    kind: ssh-cert
    ttl_secs: 300
    source_key: ssh-ca
    config:
      principals: [ubuntu]
env:
  GIT_SSH_COMMAND: \"${minted.host.GIT_SSH_COMMAND}\"
exec:
  allow_argv0: [\"/usr/bin/true\"]
";

fn ssh_keygen() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join("ssh-keygen"))
        .find(|candidate| candidate.is_file())
}

/// The whole in-daemon minting path, through the real binary: no helper
/// process exists for `ssh-cert`, so this fails outright if the daemon has not
/// routed the kind to itself.
#[tokio::test]
async fn the_daemon_mints_an_ssh_certificate_itself_and_revokes_it_into_the_krl() {
    let Some(ssh_keygen) = ssh_keygen() else {
        eprintln!("skipping: no `ssh-keygen` on PATH to make a CA key with");
        return;
    };
    let keys = tempfile::tempdir().unwrap();
    let ca_path = keys.path().join("ca");
    assert!(Command::new(&ssh_keygen)
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "briefcred-ca", "-f"])
        .arg(&ca_path)
        .status()
        .unwrap()
        .success());
    let ca = std::fs::read_to_string(&ca_path).unwrap();

    // The daemon writes minted keys under `TMPDIR`, so it is pointed at a
    // directory this test owns and can prove is empty at the end.
    let tmp = tempfile::tempdir().unwrap();
    let mut daemon = Daemon::start_with_env(
        "metrics_enabled = false\nmaster_source = \"file\"\n",
        &[("TMPDIR", tmp.path())],
        |home| {
            write_profile(home, "bastion.yaml", SSH_PROFILE);
            write_master(home, "ssh-ca", &ca);
        },
    );
    let mut stream = daemon.connect().await;

    let Response::SessionOpened { session_id, .. } = call(
        &mut stream,
        Request::OpenSession {
            profile: "bastion".into(),
            client_headless: false,
            session_pubkey: None,
        },
    )
    .await
    else {
        panic!("expected a session");
    };

    let Response::Minted { mints, env, .. } = call(
        &mut stream,
        Request::Exec {
            session_id: session_id.clone(),
            credentials: None,
            argv0: "/usr/bin/true".into(),
            args: Vec::new(),
            pid: std::process::id(),
        },
    )
    .await
    else {
        panic!("expected a mint");
    };
    assert_eq!(mints.len(), 1, "{mints:?}");
    let mint_id = mints[0].mint_id.clone();
    let key_path = PathBuf::from(mints[0].fields["SSH_IDENTITY_FILE"].expose());
    assert!(key_path.starts_with(tmp.path()), "{key_path:?}");
    assert!(key_path.exists(), "the private key must be on disk");
    assert!(
        env["GIT_SSH_COMMAND"].expose().starts_with("ssh -i "),
        "the profile's template must have been filled from the mint"
    );

    // The certificate next to the key is a real one the CA signed, which
    // `ssh-keygen -L` will only print if it parses.
    let listed = Command::new(&ssh_keygen)
        .arg("-L")
        .arg("-f")
        .arg(key_path.with_file_name("id_ed25519-cert.pub"))
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&listed.stdout).to_string();
    assert!(
        listed.contains(&mint_id),
        "the key id is the mint id:\n{listed}"
    );
    assert!(listed.contains("ubuntu"), "{listed}");

    call(
        &mut stream,
        Request::ExecDone {
            session_id: session_id.clone(),
            mint_ids: vec![mint_id],
            exit_code: Some(0),
            duration_ms: 1,
            hold_until_expiry: false,
        },
    )
    .await;

    // The revoke queue runs in the background, so this waits for it.
    let krl = daemon.home.path().join("state").join("ssh-krl");
    let mut revoked = false;
    for _ in 0..200 {
        if krl.exists() && !key_path.exists() {
            revoked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        revoked,
        "the key was never deleted or the KRL never written"
    );
    assert!(
        std::fs::read(&krl).unwrap().starts_with(b"SSHKRL\n\0"),
        "the revocation list must be an OpenSSH KRL"
    );
    assert_eq!(
        std::fs::read_dir(tmp.path()).unwrap().count(),
        0,
        "the mint directory must be gone"
    );

    call(&mut stream, Request::Shutdown).await;
    assert!(daemon.wait());
}
