//! What `briefcred install` and `briefcred uninstall` do to the filesystem.
//!
//! These tests exercise the provisioning half only. The service-manager half
//! is deliberately not called: `launchctl bootstrap` would load a real agent
//! into the session of whoever is running the tests, and `launchctl bootout`
//! would unload theirs.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use briefcred_cli::install::{provision, remove_files, STARTER_CONFIG};
use briefcred_core::paths::{Paths, Platform};

fn paths_at(root: &Path) -> Paths {
    let root = root.to_path_buf();
    Paths::resolve(Platform::MacOs, &move |key| {
        (key == "BRIEFCRED_HOME").then(|| OsString::from(root.as_os_str()))
    })
    .unwrap()
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_dry_run_writes_nothing_but_reports_everything() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let paths = paths_at(&root);

    let report = provision(&paths, Path::new("/opt/bin/briefcred-daemon"), true).unwrap();

    assert!(!root.exists(), "a dry run must not create the home");
    assert!(report.directories.contains(&paths.audit_dir()));
    assert!(report.files.iter().any(|(p, _)| *p == paths.daemon_toml()));
    assert!(report.files.iter().any(|(p, _)| *p == paths.service_file()));
    assert!(
        report.commands.iter().any(|c| c.contains("launchctl")),
        "{:?}",
        report.commands
    );
}

#[test]
fn provisioning_creates_a_private_layout_and_a_readable_unit() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let paths = paths_at(&root);

    provision(&paths, Path::new("/opt/bin/briefcred-daemon"), false).unwrap();

    for dir in [
        paths.root().to_path_buf(),
        paths.profiles_dir(),
        paths.audit_dir(),
        paths.ca_dir(),
        paths.log_dir(),
        paths.state_dir(),
    ] {
        assert_eq!(mode(&dir), 0o700, "{} is {:o}", dir.display(), mode(&dir));
    }
    assert_eq!(mode(&paths.daemon_toml()), 0o600);
    // launchd has to read the plist, so it is not part of the 0700 layout.
    assert_eq!(mode(&paths.service_file()), 0o644);

    let plist = std::fs::read_to_string(paths.service_file()).unwrap();
    assert!(
        plist.contains("<string>/opt/bin/briefcred-daemon</string>"),
        "{plist}"
    );
    assert!(
        plist.contains(&format!("<string>{}</string>", root.display())),
        "the plist must pin BRIEFCRED_HOME:\n{plist}"
    );
}

#[test]
fn the_starter_config_is_all_comments_so_it_changes_no_behaviour() {
    for line in STARTER_CONFIG.lines() {
        assert!(
            line.is_empty() || line.starts_with('#'),
            "uncommented starter config line: {line}"
        );
    }
    // It must still parse as the defaults once written.
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));
    provision(&paths, Path::new("/opt/bin/briefcred-daemon"), false).unwrap();
    let written = std::fs::read_to_string(paths.daemon_toml()).unwrap();
    assert_eq!(written, STARTER_CONFIG);
}

#[test]
fn provisioning_twice_is_a_no_op_that_keeps_an_edited_config() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));
    let binary = Path::new("/opt/bin/briefcred-daemon");

    provision(&paths, binary, false).unwrap();
    std::fs::write(paths.daemon_toml(), "retention_days = 7\n").unwrap();

    let second = provision(&paths, binary, false).unwrap();

    assert_eq!(
        std::fs::read_to_string(paths.daemon_toml()).unwrap(),
        "retention_days = 7\n",
        "an install must never overwrite an edited config"
    );
    assert!(second.kept.contains(&paths.daemon_toml()));
    assert!(second.files.iter().any(|(p, _)| *p == paths.service_file()));
}

#[test]
fn a_reinstall_rewrites_the_unit_so_a_moved_binary_is_picked_up() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));

    provision(&paths, Path::new("/old/briefcred-daemon"), false).unwrap();
    provision(&paths, Path::new("/new/briefcred-daemon"), false).unwrap();

    let plist = std::fs::read_to_string(paths.service_file()).unwrap();
    assert!(plist.contains("/new/briefcred-daemon"), "{plist}");
    assert!(!plist.contains("/old/briefcred-daemon"), "{plist}");
}

#[test]
fn uninstalling_removes_the_unit_and_keeps_the_audit_trail() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));
    provision(&paths, Path::new("/opt/bin/briefcred-daemon"), false).unwrap();
    std::fs::write(paths.audit_dir().join("audit-2026-09-01.jsonl"), "{}\n").unwrap();

    let removal = remove_files(&paths).unwrap();

    assert!(!paths.service_file().exists(), "the plist must be gone");
    assert!(removal.removed.contains(&paths.service_file()));
    assert!(
        paths.audit_dir().join("audit-2026-09-01.jsonl").exists(),
        "uninstall must never delete the audit trail"
    );
    assert!(
        removal
            .retained
            .iter()
            .any(|(p, _)| *p == paths.audit_dir()),
        "and must say so: {:?}",
        removal.retained
    );
}

#[test]
fn uninstalling_twice_is_not_an_error() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));
    provision(&paths, Path::new("/opt/bin/briefcred-daemon"), false).unwrap();

    assert_eq!(remove_files(&paths).unwrap().removed.len(), 1);
    assert!(remove_files(&paths).unwrap().removed.is_empty());
}

#[test]
fn uninstalling_clears_a_socket_the_daemon_left_behind() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));
    provision(&paths, Path::new("/opt/bin/briefcred-daemon"), false).unwrap();
    std::fs::write(paths.sock(), b"stale").unwrap();

    let removal = remove_files(&paths).unwrap();
    assert!(removal.removed.contains(&paths.sock().to_path_buf()));
    assert!(!paths.sock().exists());
}
