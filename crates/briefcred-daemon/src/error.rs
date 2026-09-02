//! The daemon's error type.

use std::path::PathBuf;

/// Result alias used throughout the daemon.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Every failure mode the daemon surfaces to its caller or its exit code.
///
/// As with `briefcred-core`, variants carry metadata only. No credential
/// material ever reaches an error message, because errors are logged.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file or directory operation failed.
    #[error("cannot {action} {path}: {source}")]
    Io {
        /// What was being attempted, as a verb phrase.
        action: &'static str,
        /// The path it was attempted on.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// `daemon.toml` is malformed, has an unknown key, or fails validation.
    #[error("invalid {path}: {message}")]
    Config {
        /// The configuration file that was read.
        path: PathBuf,
        /// What is wrong with it.
        message: String,
    },

    /// Another daemon already owns the socket.
    #[error("a briefcred daemon is already listening on {0}")]
    AlreadyRunning(PathBuf),

    /// The HTTP proxy could not be set up or could not serve a connection.
    ///
    /// Carries what went wrong with a certificate, a listener, or an upstream
    /// — never a header, a body, or a credential.
    #[error("proxy: {0}")]
    Proxy(String),

    /// A daemon-to-daemon handoff could not be completed.
    ///
    /// Carries what went wrong with the socket, the signature, or the
    /// descriptors — never a master, a token, or a signing key.
    #[error("handoff: {0}")]
    Handoff(String),

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
}
