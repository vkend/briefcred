//! `daemon.toml`: the daemon's few tunables, with defaults that work.
//!
//! Every key is optional, so an absent or empty file is a valid configuration.
//! Unknown keys are errors, for the same reason they are in the profile
//! schema: a typo must not silently switch a control off.

use std::path::Path;

use std::time::Duration;

use briefcred_core::ca::CaConfig;
use briefcred_core::SourceKind;
use serde::Deserialize;

use crate::error::{Error, Result};

/// How many days of audit logs are kept when the file says nothing.
pub const DEFAULT_RETENTION_DAYS: u32 = 90;

/// The Prometheus port used when the file says nothing.
pub const DEFAULT_METRICS_PORT: u16 = 9317;

/// How often the reconciler sweeps when the file says nothing.
pub const DEFAULT_RECONCILE_INTERVAL_SECS: u64 = crate::reconcile::DEFAULT_INTERVAL_SECS;

/// How long a session may sit unused before the daemon wipes it.
///
/// Thirty minutes: long enough to survive a lunch break mid-task, short enough
/// that a laptop left open overnight is not still holding a database
/// superuser password in the morning.
pub const DEFAULT_SESSION_IDLE_SECS: u64 = 1800;

/// The `[audit]` table of `daemon.toml`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditConfig {
    /// Record command arguments verbatim alongside their digests.
    ///
    /// Off by default, and the one setting that puts text a user typed into
    /// the audit log. An operator who needs to see the actual SQL an agent ran
    /// turns it on knowingly and accepts that the log is now sensitive.
    pub raw_args: bool,
}

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
    /// Seconds a session may go untouched before it is evicted and wiped.
    pub session_idle_secs: u64,
    /// Seconds between reconciliation sweeps.
    ///
    /// The sweep also runs once at startup, which is the tick that matters:
    /// it is what cleans up after a `SIGKILL`.
    pub reconcile_interval_secs: u64,
    /// What the audit log records beyond the defaults.
    pub audit: AuditConfig,
    /// Where master credentials are read from.
    ///
    /// Absent means the platform default: the login keychain on macOS, files
    /// under the secrets directory elsewhere. Never the environment, which has
    /// to be asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_source: Option<SourceKind>,
    /// Where the root CA's private key is kept.
    ///
    /// Owned by `briefcred_core::ca` rather than parsed twice: the CLI reads
    /// the same table out of this file without needing the rest of the schema.
    pub ca: CaConfig,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            retention_days: DEFAULT_RETENTION_DAYS,
            metrics_port: DEFAULT_METRICS_PORT,
            metrics_enabled: true,
            session_idle_secs: DEFAULT_SESSION_IDLE_SECS,
            reconcile_interval_secs: DEFAULT_RECONCILE_INTERVAL_SECS,
            audit: AuditConfig::default(),
            master_source: None,
            ca: CaConfig::default(),
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
        // Zero would evict a session in the same breath as opening it, which
        // reads as "sessions are broken" rather than as a policy choice.
        if config.session_idle_secs == 0 {
            return Err(
                "session_idle_secs must be at least 1; 0 would evict every session immediately"
                    .to_string(),
            );
        }
        // Zero would make the reconciler a busy loop against every backend a
        // profile names, which is a denial of service on the user's own
        // databases rather than a policy choice.
        if config.reconcile_interval_secs == 0 {
            return Err(
                "reconcile_interval_secs must be at least 1; 0 would sweep continuously"
                    .to_string(),
            );
        }
        Ok(config)
    }

    /// The reconcile interval as a [`Duration`].
    pub fn reconcile_interval(&self) -> Duration {
        Duration::from_secs(self.reconcile_interval_secs)
    }

    /// The idle window as a [`Duration`].
    pub fn session_idle(&self) -> Duration {
        Duration::from_secs(self.session_idle_secs)
    }

    /// The master source to open, resolving the platform default.
    pub fn master_source(&self, platform: briefcred_core::paths::Platform) -> SourceKind {
        self.master_source
            .unwrap_or_else(|| SourceKind::platform_default(platform))
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
        assert_eq!(config.session_idle_secs, 1800);
        assert_eq!(config.session_idle(), Duration::from_secs(1800));
        assert_eq!(config.master_source, None);
        assert_eq!(config.reconcile_interval_secs, 300);
        assert_eq!(config.reconcile_interval(), Duration::from_secs(300));
        assert!(!config.audit.raw_args, "raw args must be opted into");
    }

    #[test]
    fn raw_args_are_opt_in_through_their_own_table() {
        let config = Config::from_toml_str("[audit]\nraw_args = true\n").unwrap();
        assert!(config.audit.raw_args);
        assert!(Config::from_toml_str("[audit]\nraw_argz = true\n").is_err());
    }

    #[test]
    fn a_zero_reconcile_interval_is_rejected_rather_than_becoming_a_busy_loop() {
        let err = Config::from_toml_str("reconcile_interval_secs = 0").unwrap_err();
        assert!(err.contains("reconcile_interval_secs"), "{err}");
        assert_eq!(
            Config::from_toml_str("reconcile_interval_secs = 30")
                .unwrap()
                .reconcile_interval(),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn the_master_source_defaults_to_the_platform_and_can_be_overridden() {
        use briefcred_core::paths::Platform;
        let config = Config::from_toml_str("").unwrap();
        assert_eq!(config.master_source(Platform::MacOs), SourceKind::Keychain);
        assert_eq!(config.master_source(Platform::Linux), SourceKind::File);

        let config = Config::from_toml_str("master_source = \"env\"").unwrap();
        assert_eq!(config.master_source(Platform::MacOs), SourceKind::Env);
    }

    #[test]
    fn a_zero_idle_window_is_rejected_rather_than_making_sessions_useless() {
        let err = Config::from_toml_str("session_idle_secs = 0").unwrap_err();
        assert!(err.contains("session_idle_secs"), "{err}");
    }

    #[test]
    fn the_idle_window_is_configurable() {
        let config = Config::from_toml_str("session_idle_secs = 60").unwrap();
        assert_eq!(config.session_idle(), Duration::from_secs(60));
    }

    #[test]
    fn the_ca_table_is_part_of_the_schema_rather_than_an_unknown_key() {
        let config = Config::from_toml_str("[ca]\nkeystore = \"file\"\n").unwrap();
        assert_eq!(config.ca.keystore, Some(briefcred_core::KeystoreKind::File));
        assert_eq!(Config::from_toml_str("").unwrap().ca.keystore, None);
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
