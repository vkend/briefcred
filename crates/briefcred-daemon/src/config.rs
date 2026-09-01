//! `daemon.toml`: the daemon's few tunables, with defaults that work.
//!
//! Every key is optional, so an absent or empty file is a valid configuration.
//! Unknown keys are errors, for the same reason they are in the profile
//! schema: a typo must not silently switch a control off.

use std::path::Path;

use serde::Deserialize;

use crate::error::{Error, Result};

/// How many days of audit logs are kept when the file says nothing.
pub const DEFAULT_RETENTION_DAYS: u32 = 90;

/// The Prometheus port used when the file says nothing.
pub const DEFAULT_METRICS_PORT: u16 = 9317;

/// The daemon's resolved configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Audit logs older than this many days are deleted by the retention sweep.
    pub retention_days: u32,
    /// The loopback port the Prometheus endpoint listens on.
    ///
    /// Zero asks the operating system for a free port, which is how the
    /// integration tests avoid colliding with a real daemon.
    pub metrics_port: u16,
    /// Whether to serve the Prometheus endpoint at all.
    pub metrics_enabled: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            retention_days: DEFAULT_RETENTION_DAYS,
            metrics_port: DEFAULT_METRICS_PORT,
            metrics_enabled: true,
        }
    }
}

impl Config {
    /// Read `path`, falling back to [`Config::default`] when it does not exist.
    pub fn load(path: &Path) -> Result<Config> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(err) => return Err(Error::io("read", path, err)),
        };
        Config::from_toml_str(&text).map_err(|message| Error::Config {
            path: path.to_path_buf(),
            message,
        })
    }

    /// Parse and validate a `daemon.toml` document.
    ///
    /// Split out from [`Config::load`] so the parsing rules are testable
    /// without a file on disk.
    pub fn from_toml_str(text: &str) -> std::result::Result<Config, String> {
        let config: Config = toml::from_str(text).map_err(|err| err.message().to_string())?;
        if config.retention_days == 0 {
            return Err(
                "retention_days must be at least 1; 0 would delete today's own audit log"
                    .to_string(),
            );
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_documented_ones() {
        let config = Config::from_toml_str("").unwrap();
        assert_eq!(config.retention_days, 90);
        assert_eq!(config.metrics_port, 9317);
        assert!(config.metrics_enabled);
    }

    #[test]
    fn an_unknown_key_names_itself() {
        let err = Config::from_toml_str("retention_dayz = 1").unwrap_err();
        assert!(err.contains("retention_dayz"), "{err}");
    }

    #[test]
    fn a_wrongly_typed_value_is_rejected() {
        assert!(Config::from_toml_str("metrics_port = \"9317\"").is_err());
        assert!(Config::from_toml_str("metrics_enabled = 1").is_err());
    }
}
