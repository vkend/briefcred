//! The crate-wide error type.

use std::path::PathBuf;

/// Result alias used throughout briefcred.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Every failure mode `briefcred-core` can surface.
///
/// Variants deliberately carry only metadata. A secret must never reach an
/// error message, because errors are logged and audited.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The filesystem layout could not be resolved.
    #[error("cannot resolve the briefcred home directory: {0}")]
    Layout(String),

    /// A profile file or directory could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A profile document is malformed or violates the schema.
    #[error("invalid profile{}: {message}", .path.as_ref().map(|p| format!(" {}", p.display())).unwrap_or_default())]
    Profile {
        /// The file the profile was read from, when it came from disk.
        path: Option<PathBuf>,
        /// What is wrong with it.
        message: String,
    },

    /// A string was not a well-formed [`crate::MintId`].
    #[error("invalid mint id: {0}")]
    MintId(String),

    /// A minter's `config` block does not match the schema that minter expects.
    #[error("invalid config for minter kind `{kind}`: {message}")]
    MinterConfig {
        /// The minter kind the config was addressed to.
        kind: &'static str,
        /// What is wrong with it.
        message: String,
    },

    /// A database operation failed while minting.
    #[error("postgres: {0}")]
    Postgres(String),

    /// An SSH key, certificate, or revocation list could not be handled.
    ///
    /// Carries what went wrong with the material, never the material itself.
    #[error("ssh: {0}")]
    Ssh(String),

    /// TLS could not be configured for an outbound database connection.
    #[error("tls: {0}")]
    Tls(String),

    /// The private-key store could not be read, written, or opened.
    ///
    /// Carries the backend's complaint, never the key it was protecting.
    #[error("keystore: {0}")]
    Keystore(String),

    /// The root CA could not be generated, loaded, or used to issue a leaf.
    #[error("ca: {0}")]
    Ca(String),

    /// A master credential source could not be read, written, or opened.
    ///
    /// Carries the backend's complaint, never the master it was protecting.
    #[error("master source: {0}")]
    Master(String),

    /// The master source has nothing filed under this key.
    ///
    /// Separate from [`Error::Master`] because it is the one failure the user
    /// fixes themselves, and the message has to say where to put the secret.
    #[error("no master credential `{key}` in {location}")]
    MasterNotFound {
        /// The key that was looked up.
        key: String,
        /// Where the source looked, from [`crate::MasterSource::location`].
        location: String,
    },
}

impl Error {
    /// Build a [`Error::Profile`] for a document that did not come from disk.
    pub fn profile(message: impl Into<String>) -> Self {
        Error::Profile {
            path: None,
            message: message.into(),
        }
    }

    /// Attach a file path to a [`Error::Profile`], leaving other variants alone.
    pub(crate) fn at_path(self, at: impl Into<PathBuf>) -> Self {
        match self {
            Error::Profile { message, .. } => Error::Profile {
                path: Some(at.into()),
                message,
            },
            other => other,
        }
    }
}
