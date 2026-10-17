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

    /// A loopback listener could not be bound.
    ///
    /// Names the address, not the briefcred home: the home is not what was
    /// being bound, and a message pointing at a directory sends whoever reads
    /// it looking for a file problem. When the port is taken it also names the
    /// `daemon.toml` key that moves it, because loopback ports are shared by
    /// every account on the machine and the usual holder is another account's
    /// briefcred daemon.
    #[error("cannot bind the {listener} on 127.0.0.1:{port}: {source}{}", in_use_hint(.source, .key))]
    Bind {
        /// Which listener, for the message.
        listener: &'static str,
        /// The port that was asked for.
        port: u16,
        /// The `daemon.toml` key that sets it.
        key: &'static str,
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

/// What to do about a port somebody else holds, or nothing for any other error.
fn in_use_hint(source: &std::io::Error, key: &str) -> String {
    if source.kind() == std::io::ErrorKind::AddrInUse {
        format!(
            "; another process holds it, possibly another account's briefcred daemon. \
             Set `{key}` in daemon.toml to a free port, or to 0 for any free port"
        )
    } else {
        String::new()
    }
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

    /// Attach a listener, its port and its `daemon.toml` key to a bind error.
    pub fn bind(
        listener: &'static str,
        port: u16,
        key: &'static str,
        source: std::io::Error,
    ) -> Error {
        Error::Bind {
            listener,
            port,
            key,
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_taken_port_names_the_address_and_the_key_that_moves_it() {
        let source = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        let message = Error::bind("metrics listener", 9317, "metrics_port", source).to_string();
        assert!(message.contains("127.0.0.1:9317"), "{message}");
        assert!(message.contains("`metrics_port`"), "{message}");
        assert!(!message.contains("Application Support"), "{message}");
    }

    #[test]
    fn any_other_bind_failure_carries_no_hint() {
        let source = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let message = Error::bind("proxy listener", 80, "proxy_port", source).to_string();
        assert!(message.starts_with("cannot bind the proxy listener on 127.0.0.1:80: "));
        assert!(!message.contains("daemon.toml"), "{message}");
    }
}
