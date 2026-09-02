//! Helper processes: one per `(profile, minter kind)`, alive for the session.
//!
//! The daemon does not mint. It spawns `briefcred-helper-<kind>` and talks to
//! it over stdio, so the code that opens a database connection, parses a
//! backend's replies, and holds a master password runs somewhere the daemon's
//! own memory is not. A helper that panics costs one backend; a helper with a
//! memory-disclosure bug exposes one master.
//!
//! # Where a helper comes from
//!
//! Next to the daemon's own executable first, then `BRIEFCRED_HELPER_DIR`. The
//! executable's own directory is checked first on purpose: an installed
//! briefcred has its binaries side by side, and preferring an environment
//! variable would let anything that can set the daemon's environment choose
//! what code the daemon runs. The variable exists for `cargo test` and
//! `cargo run`, where the binaries are in `target/debug` and the daemon is not
//! installed anywhere.
//!
//! # Lifetime
//!
//! A helper is started on first use and kept until the session that needed it
//! closes, so a burst of `briefcred exec` calls against one profile pays one
//! process start and one backend handshake. Closing sends `shutdown` and then
//! waits briefly; a helper that ignores it is killed, because a stuck helper
//! holding a master is precisely what must not outlive its session.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use briefcred_proto::helper::{
    encode_line, HelperError, HelperParams, HelperRequest, HelperResponse, HelperResult,
    ShutdownParams, CODE_BACKEND,
};
use briefcred_proto::MAX_FRAME_BYTES;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::Mutex;

/// Environment variable naming a second place to look for helper binaries.
pub const HELPER_DIR_ENV: &str = "BRIEFCRED_HELPER_DIR";

/// The prefix every helper binary's name starts with.
pub const HELPER_PREFIX: &str = "briefcred-helper-";

/// How long a helper gets to exit after being asked to.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// How long one helper call may take before the daemon gives up on it.
///
/// A helper that has stopped answering is holding a master and blocking the
/// mint that is waiting on it, so the daemon would rather kill it and report a
/// failure than wait forever. Thirty seconds is comfortably longer than a TLS
/// handshake to a remote database and far shorter than a user's patience.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a helper could not be started or could not be spoken to.
#[derive(Debug, thiserror::Error)]
pub enum HelperFailure {
    /// No binary of that name was found anywhere it was looked for.
    #[error("no `{HELPER_PREFIX}{kind}` binary; looked in {looked_in}")]
    NotFound {
        /// The minter kind whose helper is missing.
        kind: String,
        /// The directories that were searched, comma separated.
        looked_in: String,
    },

    /// The process could not be started.
    #[error("cannot start {path}: {source}")]
    Spawn {
        /// The binary that would not start.
        path: PathBuf,
        /// The operating system's complaint.
        #[source]
        source: std::io::Error,
    },

    /// The pipe to or from the helper broke.
    #[error("`{HELPER_PREFIX}{kind}` stopped answering: {detail}")]
    Pipe {
        /// The minter kind whose helper went away.
        kind: String,
        /// What went wrong.
        detail: String,
    },

    /// The helper answered, but with a failure.
    #[error("`{HELPER_PREFIX}{kind}` refused: {source}")]
    Refused {
        /// The minter kind that refused.
        kind: String,
        /// The helper's own error object.
        #[source]
        source: HelperError,
    },
}

/// The directories a helper binary is looked for, in order.
///
/// `exe_dir` is the directory holding the running daemon; passing it in rather
/// than reading `current_exe` here is what makes the search testable.
pub fn search_path(exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(dir) = exe_dir {
        dirs.push(dir.to_path_buf());
    }
    if let Some(dir) = std::env::var_os(HELPER_DIR_ENV) {
        let dir = PathBuf::from(dir);
        // Deduplicated so a development setup that points the variable at the
        // directory the daemon is already in does not report every "not found"
        // twice.
        if !dir.as_os_str().is_empty() && !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs
}

/// Find the helper binary for `kind`.
pub fn locate(kind: &str, dirs: &[PathBuf]) -> Result<PathBuf, HelperFailure> {
    let name = format!("{HELPER_PREFIX}{kind}");
    for dir in dirs {
        let candidate = dir.join(&name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(HelperFailure::NotFound {
        kind: kind.to_string(),
        looked_in: dirs
            .iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
    })
}

/// The directory the running executable is in.
pub fn own_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
}

/// One running helper process and its pipes.
///
/// Behind a `Mutex` because a call is a write followed by the matching read,
/// and two concurrent calls interleaving on one pipe would each read the
/// other's answer.
#[derive(Debug)]
pub struct Helper {
    kind: String,
    io: Mutex<HelperIo>,
}

#[derive(Debug)]
struct HelperIo {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Helper {
    /// Start the helper for `kind`, searching `dirs` for its binary.
    pub fn start(kind: &str, dirs: &[PathBuf]) -> Result<Helper, HelperFailure> {
        let path = locate(kind, dirs)?;
        // The child inherits stderr so a helper's diagnostics land in the
        // daemon's log, and inherits nothing else: stdin and stdout are the
        // protocol and belong to the daemon alone.
        let mut child = tokio::process::Command::new(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|source| HelperFailure::Spawn { path, source })?;

        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        Ok(Helper {
            kind: kind.to_string(),
            io: Mutex::new(HelperIo {
                child,
                stdin,
                stdout: BufReader::new(stdout),
                next_id: 1,
            }),
        })
    }

    /// Send one call and read its answer.
    pub async fn call(&self, params: HelperParams) -> Result<HelperResult, HelperFailure> {
        let method = params.method().to_string();
        let mut io = self.io.lock().await;
        let id = io.next_id;
        io.next_id += 1;

        let line =
            encode_line(&HelperRequest::new(id, params)).map_err(|e| HelperFailure::Pipe {
                kind: self.kind.clone(),
                detail: format!("cannot encode a `{method}` call: {e}"),
            })?;

        let exchange = async {
            io.stdin.write_all(line.as_bytes()).await?;
            io.stdin.flush().await?;
            read_reply(&mut io.stdout).await
        };

        let reply = match tokio::time::timeout(CALL_TIMEOUT, exchange).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(err)) => {
                return Err(HelperFailure::Pipe {
                    kind: self.kind.clone(),
                    detail: err.to_string(),
                })
            }
            Err(_) => {
                // A helper that has stopped answering is holding a master. Kill
                // it rather than leave it, and let the caller retry against a
                // fresh one.
                let _ = io.child.start_kill();
                return Err(HelperFailure::Pipe {
                    kind: self.kind.clone(),
                    detail: format!("no answer to `{method}` within {}s", CALL_TIMEOUT.as_secs()),
                });
            }
        };

        let response: HelperResponse =
            serde_json::from_str(reply.trim_end()).map_err(|e| HelperFailure::Pipe {
                kind: self.kind.clone(),
                detail: format!("unparsable answer to `{method}`: {e}"),
            })?;
        if response.id != id {
            return Err(HelperFailure::Pipe {
                kind: self.kind.clone(),
                detail: format!("answered call {} with call {}", id, response.id),
            });
        }
        match (response.result, response.error) {
            (Some(result), _) => Ok(result),
            (None, Some(source)) => Err(HelperFailure::Refused {
                kind: self.kind.clone(),
                source,
            }),
            (None, None) => Err(HelperFailure::Refused {
                kind: self.kind.clone(),
                source: HelperError {
                    code: CODE_BACKEND,
                    message: format!("empty answer to `{method}`"),
                },
            }),
        }
    }

    /// Ask the helper to stop, then make sure it has.
    pub async fn stop(&self) {
        let _ = tokio::time::timeout(
            SHUTDOWN_GRACE,
            self.call(HelperParams::Shutdown(ShutdownParams {})),
        )
        .await;
        let mut io = self.io.lock().await;
        match tokio::time::timeout(SHUTDOWN_GRACE, io.child.wait()).await {
            Ok(_) => {}
            // A helper that will not leave is holding a master. Nothing it
            // could still be doing is worth that.
            Err(_) => {
                let _ = io.child.kill().await;
            }
        }
    }
}

/// Read one reply line, refusing one that is too long to be a real answer.
///
/// `read_line` on its own is unbounded: a helper that writes without ever
/// emitting a newline — a runaway loop, a corrupted stream, a compromised
/// binary — would have the daemon grow a `String` until it was killed for it.
/// The ceiling is [`MAX_FRAME_BYTES`], the same 16 MiB the client socket
/// enforces, so both of the daemon's inputs are bounded by the same number.
///
/// Reading through a `take` means the cap is applied while the bytes arrive
/// rather than after, so an oversize line cannot be allocated even once. Being
/// over the ceiling is unrecoverable for this connection — the rest of the line
/// is still in the pipe and would be read as the next reply — so the caller
/// discards the helper, which is what the `Pipe` failure already causes.
async fn read_reply(stdout: &mut BufReader<ChildStdout>) -> std::io::Result<String> {
    let mut reply = String::new();
    // One byte over the ceiling, so a line that is exactly at it still reads.
    let read = (&mut *stdout)
        .take(MAX_FRAME_BYTES as u64 + 1)
        .read_line(&mut reply)
        .await?;
    if read == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the helper closed its stdout",
        ));
    }
    if read > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("reply of over {MAX_FRAME_BYTES} bytes; refusing to read it"),
        ));
    }
    Ok(reply)
}

/// Every helper a session has started, keyed by minter kind.
///
/// Owned by the session, so closing the session closes the helpers, and the
/// masters they hold go away with them.
#[derive(Debug, Default)]
pub struct HelperSet {
    dirs: Vec<PathBuf>,
    helpers: Mutex<BTreeMap<String, Arc<Helper>>>,
}

impl HelperSet {
    /// A set that looks for binaries in `dirs`.
    pub fn new(dirs: Vec<PathBuf>) -> HelperSet {
        HelperSet {
            dirs,
            helpers: Mutex::new(BTreeMap::new()),
        }
    }

    /// The helper for `kind`, starting it if this is the first call.
    pub async fn get(&self, kind: &str) -> Result<Arc<Helper>, HelperFailure> {
        let mut helpers = self.helpers.lock().await;
        if let Some(helper) = helpers.get(kind) {
            return Ok(Arc::clone(helper));
        }
        let helper = Arc::new(Helper::start(kind, &self.dirs)?);
        helpers.insert(kind.to_string(), Arc::clone(&helper));
        Ok(helper)
    }

    /// Forget the helper for `kind` without stopping it.
    ///
    /// Used after a pipe failure: the process has already been killed, and the
    /// next call must build a fresh one rather than reuse a dead handle.
    pub async fn discard(&self, kind: &str) {
        self.helpers.lock().await.remove(kind);
    }

    /// The kinds currently running.
    pub async fn kinds(&self) -> Vec<String> {
        self.helpers.lock().await.keys().cloned().collect()
    }

    /// Stop and forget every helper.
    ///
    /// The take and the clear are one locked step. Taking the map out and then
    /// locking again to clear it leaves a window in which another task can
    /// `get` a kind, find the entry still present, and hand back a helper this
    /// call is about to stop — so the caller would be talking to a dead process
    /// and, worse, a `get` racing the clear could insert a fresh helper that
    /// the clear then dropped on the floor, orphaning it with a master in it.
    pub async fn stop_all(&self) {
        let taken = std::mem::take(&mut *self.helpers.lock().await);
        for (_, helper) in taken {
            helper.stop().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_executables_own_directory_is_searched_before_the_override() {
        let dirs = search_path(Some(Path::new("/opt/briefcred/bin")));
        assert_eq!(dirs.first().unwrap(), Path::new("/opt/briefcred/bin"));
    }

    #[test]
    fn a_helper_is_named_for_the_minter_kind_it_serves() {
        // `kind: postgres-dynamic` in a profile means
        // `briefcred-helper-postgres-dynamic` on disk. The daemon holds only
        // the kind string, so the mapping has to be the name itself.
        let err = locate("postgres-dynamic", &[PathBuf::from("/nowhere")]).unwrap_err();
        assert!(
            err.to_string()
                .contains("briefcred-helper-postgres-dynamic"),
            "{err}"
        );
    }

    #[test]
    fn a_missing_helper_names_the_binary_and_everywhere_it_looked() {
        let dirs = vec![PathBuf::from("/nowhere/a"), PathBuf::from("/nowhere/b")];
        let err = locate("postgres", &dirs).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("briefcred-helper-postgres"), "{text}");
        assert!(text.contains("/nowhere/a"), "{text}");
        assert!(text.contains("/nowhere/b"), "{text}");
    }

    #[test]
    fn the_first_directory_holding_the_binary_wins() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for dir in [&first, &second] {
            std::fs::write(dir.path().join("briefcred-helper-postgres"), "#!/bin/sh\n").unwrap();
        }
        let dirs = vec![first.path().to_path_buf(), second.path().to_path_buf()];
        assert_eq!(
            locate("postgres", &dirs).unwrap(),
            first.path().join("briefcred-helper-postgres")
        );
    }

    #[test]
    fn a_directory_of_that_name_is_not_a_helper() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("briefcred-helper-postgres")).unwrap();
        assert!(locate("postgres", &[dir.path().to_path_buf()]).is_err());
    }

    /// A stand-in helper written in `sh`, so the pipe protocol can be tested
    /// without a database anywhere near it.
    fn script_helper(dir: &Path, kind: &str, body: &str) -> Vec<PathBuf> {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join(format!("{HELPER_PREFIX}{kind}"));
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        vec![dir.to_path_buf()]
    }

    #[tokio::test]
    async fn a_helper_that_answers_is_read_back_on_the_matching_id() {
        let dir = tempfile::tempdir().unwrap();
        let dirs = script_helper(
            dir.path(),
            "echo",
            r#"while read -r line; do
  printf '{"jsonrpc":"2.0","id":1,"result":{"stopping":true}}\n'
done"#,
        );

        let helper = Helper::start("echo", &dirs).unwrap();
        let result = helper
            .call(HelperParams::Shutdown(ShutdownParams {}))
            .await
            .unwrap();
        assert!(matches!(result, HelperResult::Shutdown(_)), "{result:?}");
        helper.stop().await;
    }

    #[tokio::test]
    async fn a_helper_that_answers_the_wrong_id_is_a_pipe_failure() {
        let dir = tempfile::tempdir().unwrap();
        let dirs = script_helper(
            dir.path(),
            "confused",
            r#"while read -r line; do
  printf '{"jsonrpc":"2.0","id":99,"result":{"stopping":true}}\n'
done"#,
        );

        let helper = Helper::start("confused", &dirs).unwrap();
        let err = helper
            .call(HelperParams::Shutdown(ShutdownParams {}))
            .await
            .unwrap_err();
        assert!(matches!(err, HelperFailure::Pipe { .. }), "{err}");
        assert!(err.to_string().contains("call 99"), "{err}");
    }

    #[tokio::test]
    async fn a_helper_that_refuses_reports_its_own_error() {
        let dir = tempfile::tempdir().unwrap();
        let dirs = script_helper(
            dir.path(),
            "grumpy",
            r#"while read -r line; do
  printf '{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"28P01: password authentication failed"}}\n'
done"#,
        );

        let helper = Helper::start("grumpy", &dirs).unwrap();
        let err = helper
            .call(HelperParams::Shutdown(ShutdownParams {}))
            .await
            .unwrap_err();
        assert!(matches!(err, HelperFailure::Refused { .. }), "{err}");
        assert!(err.to_string().contains("28P01"), "{err}");
    }

    #[tokio::test]
    async fn a_reply_over_the_frame_ceiling_is_refused_rather_than_allocated() {
        let dir = tempfile::tempdir().unwrap();
        // 17 MiB of `x` on one line, with no newline in sight until the end:
        // exactly what a runaway helper looks like from the daemon's side.
        let dirs = script_helper(
            dir.path(),
            "flood",
            r#"while read -r line; do
  awk 'BEGIN { while (i++ < 17408) printf "%1024s", "" }' | tr ' ' 'x'
  printf '
'
done"#,
        );

        let helper = Helper::start("flood", &dirs).unwrap();
        let err = helper
            .call(HelperParams::Shutdown(ShutdownParams {}))
            .await
            .unwrap_err();
        assert!(matches!(err, HelperFailure::Pipe { .. }), "{err}");
        assert!(
            err.to_string().contains("refusing to read it"),
            "the failure must say why: {err}"
        );
        helper.stop().await;
    }

    #[tokio::test]
    async fn a_reply_just_under_the_ceiling_is_still_read() {
        let dir = tempfile::tempdir().unwrap();
        // A valid response padded with a long — but legal — message field.
        let dirs = script_helper(
            dir.path(),
            "chatty",
            r#"while read -r line; do
  pad=$(awk 'BEGIN { while (i++ < 64) printf "%1024s", "" }' | tr ' ' 'y')
  printf '{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"%s"}}
' "$pad"
done"#,
        );

        let helper = Helper::start("chatty", &dirs).unwrap();
        let err = helper
            .call(HelperParams::Shutdown(ShutdownParams {}))
            .await
            .unwrap_err();
        // Refused, not a pipe failure: the line was read and parsed fine.
        assert!(matches!(err, HelperFailure::Refused { .. }), "{err}");
        helper.stop().await;
    }

    #[tokio::test]
    async fn a_helper_that_dies_is_a_pipe_failure_rather_than_a_hang() {
        let dir = tempfile::tempdir().unwrap();
        let dirs = script_helper(dir.path(), "quitter", "exit 0");

        let helper = Helper::start("quitter", &dirs).unwrap();
        let err = helper
            .call(HelperParams::Shutdown(ShutdownParams {}))
            .await
            .unwrap_err();
        assert!(matches!(err, HelperFailure::Pipe { .. }), "{err}");
    }

    #[tokio::test]
    async fn a_set_starts_one_process_per_kind_and_stops_them_all() {
        let dir = tempfile::tempdir().unwrap();
        script_helper(
            dir.path(),
            "one",
            r#"while read -r line; do printf '{"jsonrpc":"2.0","id":1,"result":{"stopping":true}}\n'; done"#,
        );
        let dirs = script_helper(
            dir.path(),
            "two",
            r#"while read -r line; do printf '{"jsonrpc":"2.0","id":1,"result":{"stopping":true}}\n'; done"#,
        );

        let set = HelperSet::new(dirs);
        let first = set.get("one").await.unwrap();
        let again = set.get("one").await.unwrap();
        assert!(
            Arc::ptr_eq(&first, &again),
            "a second call must reuse the running process"
        );
        set.get("two").await.unwrap();
        assert_eq!(set.kinds().await, vec!["one", "two"]);

        set.stop_all().await;
        assert!(set.kinds().await.is_empty());
    }

    #[tokio::test]
    async fn a_discarded_helper_is_replaced_rather_than_reused() {
        let dir = tempfile::tempdir().unwrap();
        let dirs = script_helper(
            dir.path(),
            "one",
            r#"while read -r line; do printf '{"jsonrpc":"2.0","id":1,"result":{"stopping":true}}\n'; done"#,
        );
        let set = HelperSet::new(dirs);
        let first = set.get("one").await.unwrap();
        set.discard("one").await;
        let second = set.get("one").await.unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        set.stop_all().await;
        first.stop().await;
    }
}
