//! The CLI's error type and the exit codes it maps to.

use std::path::PathBuf;

/// Result alias used throughout the CLI.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The exit code for "the daemon is not running".
///
/// Distinct from the generic failure code so a script can tell "start it" from
/// "something is wrong".
pub const EXIT_NOT_RUNNING: u8 = 3;

/// Everything the CLI can fail with.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// There is no daemon listening on the socket.
    #[error("daemon is not running; run 'briefcred daemon start'")]
    NotRunning,

    /// A file or directory operation failed.
    #[error("cannot {action} {path}: {source}")]
    Io {
        /// What was being attempted.
        action: &'static str,
        /// The path it was attempted on.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The daemon replied, but not with something this command can use.
    #[error("the daemon replied with {0}")]
    Unexpected(String),

    /// The IPC connection failed.
    #[error("ipc: {0}")]
    Ipc(#[from] briefcred_proto::FrameError),

    /// The platform's service manager refused a command.
    #[error("{command} failed: {detail}")]
    ServiceManager {
        /// The command line that was run.
        command: String,
        /// Its stderr, or a description of why it could not run.
        detail: String,
    },

    /// The `briefcred-daemon` binary could not be found next to this one.
    #[error("cannot find the briefcred-daemon binary at {0}")]
    DaemonBinaryMissing(PathBuf),

    /// The on-disk layout could not be resolved.
    #[error(transparent)]
    Layout(#[from] briefcred_core::Error),
}

impl Error {
    /// Attach an action and a path to an [`std::io::Error`].
    pub fn io(action: &'static str, path: impl Into<PathBuf>, source: std::io::Error) -> Error {
        Error::Io {
            action,
            path: path.into(),
            source,
        }
    }

    /// The process exit code this error should produce.
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::NotRunning => EXIT_NOT_RUNNING,
            _ => 1,
        }
    }
}
