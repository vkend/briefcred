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

/// Every `briefcred-helper-*` binary the daemon shells out to.
///
/// Spelled out rather than globbed for a directory whose contents are the
/// thing in doubt: a glob over a target directory with no helpers in it finds
/// nothing and reports nothing missing, which is exactly the case this list
/// exists to catch. A helper added to the workspace and not added here is
/// caught by [`every_helper_binary_in_the_workspace_is_listed`].
const HELPERS: [&str; 2] = [
    "briefcred-helper-postgres-dynamic",
    "briefcred-helper-aws-sts",
];

/// Which of [`HELPERS`] are absent from `binaries`.
pub fn missing_helpers(binaries: &Path) -> Vec<&'static str> {
    HELPERS
        .into_iter()
        .filter(|name| !binaries.join(name).is_file())
        .collect()
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

/// Add the port overrides every test needs, unless the test set them itself.
///
/// A daemon started by a test must not bind any of the real ports: two test
/// binaries run concurrently, and one of them would lose the race to whichever
/// daemon the developer actually has installed.
fn with_ephemeral_ports(config: &str) -> String {
    let missing: Vec<&str> = ["metrics_port = 0", "proxy_port = 0", "pg_proxy_port = 0"]
        .into_iter()
        .filter(|line| {
            let key = line.split_whitespace().next().expect("a key");
            !config
                .lines()
                .any(|existing| existing.trim_start().starts_with(key))
        })
        .collect();

    // Inserted before the first table header, not appended. These are
    // top-level keys, and in TOML a key written after `[profiles]` belongs to
    // `[profiles]` — so appending would silently move the daemon's ports into
    // whichever table a test happened to write last, and the daemon would
    // refuse to start with a message about the wrong key entirely.
    let mut out = String::new();
    let mut inserted = false;
    for line in config.lines() {
        if !inserted && line.trim_start().starts_with('[') {
            for extra in &missing {
                out.push_str(extra);
                out.push('\n');
            }
            inserted = true;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !inserted {
        for extra in &missing {
            out.push_str(extra);
            out.push('\n');
        }
    }
    out
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
        std::fs::write(
            home.path().join("daemon.toml"),
            with_ephemeral_ports(daemon_toml),
        )
        .expect("daemon.toml");
        Daemon {
            home,
            child: None,
            binaries: binary_dir(),
        }
    }

    /// The temporary home this daemon owns, for a test that has to write into
    /// it directly — a CA, say, which no request can install.
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
        self.check_helpers()?;

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

    /// Refuse to start when a helper the daemon will need is not built.
    ///
    /// `cargo test` does not build a package's binaries unless a test target
    /// asks for them, so `cargo test -p briefcred-e2e` on a clean checkout
    /// leaves the helpers absent. The daemon then starts perfectly well and
    /// every mint fails, which surfaces as "the credential did not mint" — a
    /// message about the wrong thing entirely. Saying so here costs one
    /// `is_file` and turns half an hour into a sentence. `just test` builds the
    /// workspace first and never reaches this.
    fn check_helpers(&self) -> Result<(), String> {
        let missing = missing_helpers(&self.binaries);
        if missing.is_empty() {
            return Ok(());
        }
        Err(format!(
            "{} is not built in {}; run `cargo build --workspace` (or `just test`, \
             which does it for you) before running the end-to-end tests",
            missing.join(", "),
            self.binaries.display()
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

    /// Wait for the daemon to exit on its own, reaping it when it does.
    ///
    /// `try_wait` and not a signal probe: this process is the daemon's parent,
    /// so an exited daemon it has not reaped is a zombie — and a zombie still
    /// answers `kill -0`. A test asking "has the daemon that handed over
    /// finished draining" would be told "no" forever.
    pub async fn wait_for_exit(&mut self, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        loop {
            match self.child.as_mut() {
                None => return true,
                Some(child) => match child.try_wait() {
                    Ok(Some(_)) => {
                        self.child = None;
                        return true;
                    }
                    Ok(None) => {}
                    Err(_) => return false,
                },
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Every daemon log under this home, for a failure message.
    ///
    /// Both files, because an upgrade produces two daemons: this harness's own
    /// child writes `daemon.log`, and the successor `briefcred daemon upgrade`
    /// starts writes `daemon.err.log`. A handoff that failed inside the
    /// successor would otherwise leave the test reporting the log of the
    /// process that was working fine.
    pub fn log(&self) -> String {
        let logs = self.home.path().join("logs");
        ["daemon.log", "daemon.err.log", "daemon.out.log"]
            .into_iter()
            .filter_map(|name| {
                let text = std::fs::read_to_string(logs.join(name)).ok()?;
                (!text.trim().is_empty()).then(|| format!("--- {name}\n{text}"))
            })
            .collect::<Vec<String>>()
            .join("\n")
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
    /// The underlying stream, for a request that upgrades the connection.
    ///
    /// `Request::Mcp` hands the socket to the daemon's MCP server, so a test
    /// that sends one has to keep speaking on the same stream rather than
    /// framing another request onto it.
    pub fn into_stream(self) -> UnixStream {
        self.stream
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The workspace root, two levels above this crate's manifest.
    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crates/<crate>")
            .to_path_buf()
    }

    #[test]
    fn a_directory_with_no_helpers_in_it_is_reported_as_missing_all_of_them() {
        let empty = TempDir::new().expect("temp dir");
        assert_eq!(missing_helpers(empty.path()), HELPERS.to_vec());
    }

    #[test]
    fn a_helper_that_is_present_is_not_reported() {
        let dir = TempDir::new().expect("temp dir");
        std::fs::write(dir.path().join(HELPERS[0]), b"").expect("write");
        assert_eq!(missing_helpers(dir.path()), vec![HELPERS[1]]);
    }

    /// The check is only worth having if it covers every helper.
    ///
    /// A new `briefcred-helper-*` crate that nobody adds to [`HELPERS`] would
    /// reintroduce exactly the failure the check exists to prevent, silently,
    /// for the one helper that is newest and least understood. Reading the
    /// binary names out of the manifests is what makes forgetting impossible.
    #[test]
    fn every_helper_binary_in_the_workspace_is_listed() {
        let mut found: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(workspace_root().join("crates")).expect("crates dir") {
            let manifest = entry.expect("dir entry").path().join("Cargo.toml");
            let Ok(text) = std::fs::read_to_string(&manifest) else {
                continue;
            };
            let parsed: toml::Value =
                toml::from_str(&text).expect("a crate manifest is valid TOML");
            let Some(bins) = parsed.get("bin").and_then(|b| b.as_array()) else {
                continue;
            };
            for bin in bins {
                let name = bin
                    .get("name")
                    .and_then(|n| n.as_str())
                    .expect("a bin name");
                if name.starts_with("briefcred-helper-") {
                    found.push(name.to_string());
                }
            }
        }
        found.sort();
        let mut listed: Vec<String> = HELPERS.iter().map(|h| h.to_string()).collect();
        listed.sort();
        assert_eq!(
            found, listed,
            "the workspace's helper binaries and daemon_harness::HELPERS disagree"
        );
    }
}
