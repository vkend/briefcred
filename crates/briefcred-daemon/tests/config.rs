//! `daemon.toml` loading: defaults, overrides, and refusal to guess.

use briefcred_daemon::config::{Config, DEFAULT_METRICS_PORT, DEFAULT_RETENTION_DAYS};

fn write(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
    let path = dir.path().join("daemon.toml");
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn an_absent_file_yields_the_documented_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::load(&dir.path().join("daemon.toml")).unwrap();
    assert_eq!(config, Config::default());
    assert_eq!(config.retention_days, DEFAULT_RETENTION_DAYS);
    assert_eq!(config.retention_days, 90);
    assert_eq!(config.metrics_port, DEFAULT_METRICS_PORT);
    assert_eq!(config.metrics_port, 9317);
    assert!(config.metrics_enabled);
}

#[test]
fn an_empty_file_is_the_same_as_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::load(&write(&dir, "")).unwrap();
    assert_eq!(config, Config::default());
}

#[test]
fn each_key_can_be_set_independently() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::load(&write(&dir, "retention_days = 7\n")).unwrap();
    assert_eq!(config.retention_days, 7);
    assert_eq!(config.metrics_port, DEFAULT_METRICS_PORT);

    let config = Config::load(&write(&dir, "metrics_port = 19317\n")).unwrap();
    assert_eq!(config.metrics_port, 19317);
    assert_eq!(config.retention_days, DEFAULT_RETENTION_DAYS);

    let config = Config::load(&write(&dir, "metrics_enabled = false\n")).unwrap();
    assert!(!config.metrics_enabled);
}

#[test]
fn an_unknown_key_is_an_error_rather_than_a_silent_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let err = Config::load(&write(&dir, "retention_dayz = 7\n")).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("retention_dayz"), "{text}");
    assert!(text.contains("daemon.toml"), "{text}");
}

#[test]
fn malformed_toml_names_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let err = Config::load(&write(&dir, "retention_days = \n")).unwrap_err();
    assert!(err.to_string().contains("daemon.toml"), "{err}");
}

#[test]
fn a_zero_retention_is_refused_because_it_would_delete_todays_log() {
    let dir = tempfile::tempdir().unwrap();
    let err = Config::load(&write(&dir, "retention_days = 0\n")).unwrap_err();
    assert!(err.to_string().contains("retention_days"), "{err}");
}

#[test]
fn port_zero_is_allowed_so_tests_can_ask_the_os_for_a_free_port() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::load(&write(&dir, "metrics_port = 0\n")).unwrap();
    assert_eq!(config.metrics_port, 0);
}
