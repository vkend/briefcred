//! A real `briefcred-daemon` process, under a temporary `BRIEFCRED_HOME`.
//!
//! The reconciler and the memory-hygiene checks are both about what happens to
//! a *process* — one that is killed, one whose address space is inspected — so
//! neither can be tested against an in-process `State`. This starts the actual
//! binary the way launchd would, points it at a temporary home, and gives the
//! test a socket to talk to.
//!
//! Nothing here touches the developer's real directories: `BRIEFCRED_HOME`
//! relocates the whole layout including the socket, and the master source is
//! set to `file` so no keychain item is created either.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use briefcred_proto::{read_frame, write_frame, Request, Response};
use tempfile::TempDir;
use tokio::net::UnixStream;

/// How long the daemon gets to bind its socket before the test gives up.
const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// The directory holding the workspace's compiled binaries.
///
/// Derived from the test binary's own path — `target/<profile>/deps/<test>` —
/// rather than from `CARGO_MANIFEST_DIR`, so it is right for a debug build, a
/// release build, and a custom `CARGO_TARGET_DIR` alike.
pub fn binary_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary knows where it is");
    exe.parent()
        .and_then(Path::parent)
        .expect("target/<profile>/deps/<test>")
        .to_path_buf()
}

/// A running daemon and the temporary home it owns.
///
/// Dropping it kills the daemon and removes the home, so a failing test leaves
/// nothing behind.
pub struct Daemon {
    home: TempDir,
    child: Option<Child>,
    binaries: PathBuf,
}

impl Daemon {
    /// Lay out a home directory without starting anything.
    ///
    /// Split from [`Daemon::start`] so a test can write profiles and secrets
    /// into the home, and so the same home can be handed to a second daemon
    /// after the first has been killed.
    pub fn prepare(daemon_toml: &str) -> Daemon {
        let home = TempDir::new().expect("temp home");
        for dir in ["profiles", "secrets", "audit", "state", "ca", "logs"] {
            std::fs::create_dir_all(home.path().join(dir)).expect("home layout");
        }
        std::fs::write(home.path().join("daemon.toml"), daemon_toml).expect("daemon.toml");
        Daemon {
            home,
            child: None,
            binaries: binary_dir(),
        }
    }

    /// The temporary `BRIEFCRED_HOME`.
    pub fn home(&self) -> &Path {
        self.home.path()
    }

    /// The daemon's socket inside that home.
    pub fn sock(&self) -> PathBuf {
        self.home.path().join("sock")
    }

    /// Write a profile document into the home.
    pub fn write_profile(&self, name: &str, yaml: &str) {
        std::fs::write(
            self.home
                .path()
                .join("profiles")
                .join(format!("{name}.yaml")),
            yaml,
        )
        .expect("write profile");
    }

    /// Write a master credential into the file-backed master source.
    pub fn write_master(&self, key: &str, value: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        let path = self.home.path().join("secrets").join(key);
        std::fs::write(&path, value).expect("write master");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("master mode");
    }

    /// The daemon's process id, while it is running.
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Start the daemon and wait until it is answering.
    ///
    /// The binary is whatever `cargo` last built into the target directory,
    /// which is how the memory-hygiene test gets a daemon with its extra
    /// feature: `just mem-hygiene` builds one first. A missing binary is
    /// reported rather than panicked on, so that test can skip.
    pub async fn start(&mut self) -> Result<(), String> {
        let binary = self.binaries.join("briefcred-daemon");
        if !binary.is_file() {
            return Err(format!("no daemon binary at {}", binary.display()));
        }

        let log = std::fs::File::create(self.home.path().join("logs").join("daemon.log"))
            .map_err(|e| e.to_string())?;
        let child = Command::new(&binary)
            .env("BRIEFCRED_HOME", self.home.path())
            // The daemon looks next to its own executable first, so this is
            // redundant for a cargo build and is set anyway: it is the variable
            // a packaged install would use, and exercising it here is free.
            .env("BRIEFCRED_HELPER_DIR", &self.binaries)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
            .stderr(Stdio::from(log))
            .spawn()
            .map_err(|e| format!("cannot start {}: {e}", binary.display()))?;
        self.child = Some(child);

        let deadline = Instant::now() + READY_TIMEOUT;
        while Instant::now() < deadline {
            if matches!(self.request(Request::Ping).await, Ok(Response::Pong)) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(format!(
            "the daemon did not answer within {}s\n{}",
            READY_TIMEOUT.as_secs(),
            self.log()
        ))
    }

    /// Send one request on a connection of its own.
    pub async fn request(&self, request: Request) -> Result<Response, String> {
        let mut connection = self.connect().await?;
        connection.send(request).await
    }

    /// Open a connection that several requests can share.
    pub async fn connect(&self) -> Result<Client, String> {
        let stream = UnixStream::connect(self.sock())
            .await
            .map_err(|e| e.to_string())?;
        Ok(Client { stream })
    }

    /// Kill the daemon outright, the way a crash or an `Activity Monitor`
    /// force-quit would: no signal handler runs, no revoke queue drains.
    pub fn sigkill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // The socket outlives the process it belonged to. Removing it is what a
        // graceful shutdown would have done, and leaving it would make the next
        // daemon's own stale-socket check the thing under test.
        let _ = std::fs::remove_file(self.sock());
    }

    /// Ask the daemon to shut down, and wait for it.
    pub async fn shutdown(&mut self) {
        let _ = self.request(Request::Shutdown).await;
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
    }

    /// The daemon's own stdout and stderr, for a failure message.
    pub fn log(&self) -> String {
        std::fs::read_to_string(self.home.path().join("logs").join("daemon.log"))
            .unwrap_or_default()
    }

    /// Every audit row written so far, oldest first.
    pub fn audit_rows(&self) -> Vec<serde_json::Value> {
        let dir = self.home.path().join("audit");
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect();
        files.sort();
        files
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .flat_map(|text| {
                text.lines()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect::<Vec<serde_json::Value>>()
            })
            .collect()
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

/// One open connection to a test daemon.
pub struct Client {
    stream: UnixStream,
}

impl Client {
    /// Send one request and read its answer.
    pub async fn send(&mut self, request: Request) -> Result<Response, String> {
        write_frame(&mut self.stream, &request)
            .await
            .map_err(|e| e.to_string())?;
        read_frame(&mut self.stream)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "the daemon closed the connection".to_string())
    }
}

/// Poll `check` until it is true or the deadline passes.
pub async fn wait_until<F, Fut>(within: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}
