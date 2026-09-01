//! What `briefcred install` and `briefcred uninstall` do to the filesystem.
//!
//! These tests exercise the provisioning half only. The service-manager half
//! is deliberately not called: `launchctl bootstrap` would load a real agent
//! into the session of whoever is running the tests, and `launchctl bootout`
//! would unload theirs.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use std::time::Duration;

use briefcred_cli::install::{
    provision, remove_files, wait_until_gone, wait_until_listening, InstallOptions, Report,
    STARTER_CONFIG,
};
use briefcred_core::ca::CertificateAuthority;
use briefcred_core::keystore::{FileKeyStore, KeyStore, CA_KEY_ITEM};
use briefcred_core::paths::{Paths, Platform};

/// A key store under the test's own temporary directory.
///
/// Never the platform default: on macOS that is the developer's real login
/// keychain, and a test suite has no business writing into it.
fn store_for(paths: &Paths) -> FileKeyStore {
    FileKeyStore::new(paths.ca_dir())
}

fn run_provision(paths: &Paths, binary: &str, dry_run: bool) -> Report {
    provision(
        paths,
        Path::new(binary),
        InstallOptions {
            dry_run,
            trust_ca: false,
        },
        &store_for(paths),
    )
    .unwrap()
}

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

    let report = run_provision(&paths, "/opt/bin/briefcred-daemon", true);

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

    run_provision(&paths, "/opt/bin/briefcred-daemon", false);

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
    run_provision(&paths, "/opt/bin/briefcred-daemon", false);
    let written = std::fs::read_to_string(paths.daemon_toml()).unwrap();
    assert_eq!(written, STARTER_CONFIG);
}

#[test]
fn provisioning_twice_is_a_no_op_that_keeps_an_edited_config() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));
    let binary = "/opt/bin/briefcred-daemon";

    run_provision(&paths, binary, false);
    std::fs::write(paths.daemon_toml(), "retention_days = 7\n").unwrap();

    let second = run_provision(&paths, binary, false);

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

    run_provision(&paths, "/old/briefcred-daemon", false);
    run_provision(&paths, "/new/briefcred-daemon", false);

    let plist = std::fs::read_to_string(paths.service_file()).unwrap();
    assert!(plist.contains("/new/briefcred-daemon"), "{plist}");
    assert!(!plist.contains("/old/briefcred-daemon"), "{plist}");
}

#[test]
fn uninstalling_removes_the_unit_and_keeps_the_audit_trail() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));
    run_provision(&paths, "/opt/bin/briefcred-daemon", false);
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
    run_provision(&paths, "/opt/bin/briefcred-daemon", false);

    assert_eq!(remove_files(&paths).unwrap().removed.len(), 1);
    assert!(remove_files(&paths).unwrap().removed.is_empty());
}

#[test]
fn uninstalling_clears_a_socket_the_daemon_left_behind() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));
    run_provision(&paths, "/opt/bin/briefcred-daemon", false);
    std::fs::write(paths.sock(), b"stale").unwrap();

    let removal = remove_files(&paths).unwrap();
    assert!(removal.removed.contains(&paths.sock().to_path_buf()));
    assert!(!paths.sock().exists());
}

#[test]
fn waiting_for_a_socket_nothing_is_listening_on_gives_up() {
    let temp = tempfile::tempdir().unwrap();
    let sock = temp.path().join("sock");

    let started = std::time::Instant::now();
    assert!(!wait_until_listening(&sock, Duration::from_millis(200)));
    let elapsed = started.elapsed();

    assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(3),
        "it must not overshoot: {elapsed:?}"
    );
}

#[test]
fn waiting_for_a_socket_that_is_listening_returns_at_once() {
    let temp = tempfile::tempdir().unwrap();
    let sock = temp.path().join("sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

    let started = std::time::Instant::now();
    assert!(wait_until_listening(&sock, Duration::from_secs(10)));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn a_socket_file_with_no_listener_is_not_mistaken_for_a_daemon() {
    let temp = tempfile::tempdir().unwrap();
    let sock = temp.path().join("sock");
    // A plain file at the socket path, which is what a SIGKILLed daemon leaves.
    std::fs::write(&sock, b"stale").unwrap();

    assert!(!wait_until_listening(&sock, Duration::from_millis(150)));
}

#[test]
fn a_dry_run_never_claims_the_daemon_is_ready() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));
    let report = run_provision(&paths, "/opt/bin/briefcred-daemon", true);
    assert!(!report.ready);
}

#[test]
fn waiting_for_a_socket_to_go_quiet_returns_once_the_listener_is_gone() {
    let temp = tempfile::tempdir().unwrap();
    let sock = temp.path().join("sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

    assert!(
        !wait_until_gone(&sock, Duration::from_millis(150)),
        "a live listener is not gone"
    );

    drop(listener);
    std::fs::remove_file(&sock).unwrap();
    let started = std::time::Instant::now();
    assert!(wait_until_gone(&sock, Duration::from_secs(10)));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn provisioning_creates_the_root_ca_and_reports_it() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));

    let report = run_provision(&paths, "/opt/bin/briefcred-daemon", false);

    let ca = report.ca.expect("provisioning must create a CA");
    assert!(ca.generated, "the first install generates one");
    assert_eq!(ca.cert, paths.ca_cert());
    assert_eq!(ca.keystore, "file");
    assert_eq!(ca.fingerprint.len(), 64);

    // Present, usable, and with its private key kept out of the public half.
    let loaded = CertificateAuthority::load(&paths, &store_for(&paths))
        .unwrap()
        .unwrap();
    assert_eq!(loaded.info().unwrap().fingerprint_sha256, ca.fingerprint);
    loaded.issue_leaf(&["localhost".to_string()]).unwrap();
    let on_disk = std::fs::read_to_string(paths.ca_cert()).unwrap();
    assert!(!on_disk.contains("PRIVATE KEY"), "{on_disk}");
}

#[test]
fn the_ca_certificate_is_readable_by_the_runtimes_that_need_it() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));
    run_provision(&paths, "/opt/bin/briefcred-daemon", false);

    assert_eq!(mode(&paths.ca_cert()), 0o644);
    assert_eq!(mode(&store_for(&paths).path(CA_KEY_ITEM)), 0o600);
}

#[test]
fn reinstalling_keeps_the_ca_that_the_machine_already_trusts() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));
    let first = run_provision(&paths, "/opt/bin/briefcred-daemon", false)
        .ca
        .unwrap();

    let second = run_provision(&paths, "/opt/bin/briefcred-daemon", false)
        .ca
        .unwrap();

    assert!(!second.generated, "a reinstall must not replace the CA");
    assert_eq!(second.fingerprint, first.fingerprint);
}

#[test]
fn a_dry_run_creates_no_ca_and_touches_no_key_store() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));

    let report = run_provision(&paths, "/opt/bin/briefcred-daemon", true);

    assert!(report.ca.is_none(), "{:?}", report.ca);
    assert!(!paths.ca_cert().exists());
    assert!(!temp.path().join("home").exists());
}

#[test]
fn trust_ca_reports_the_command_it_would_run_without_running_it() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));

    let report = provision(
        &paths,
        Path::new("/opt/bin/briefcred-daemon"),
        InstallOptions {
            dry_run: false,
            trust_ca: true,
        },
        &store_for(&paths),
    )
    .unwrap();

    assert_eq!(report.trust.len(), 1, "{:?}", report.trust);
    assert!(report.trust[0].starts_with("sudo security add-trusted-cert"));
    assert!(
        report.trust[0].ends_with(&paths.ca_cert().display().to_string()),
        "{:?}",
        report.trust
    );
    // Provisioning plans the trust step; only `install` may execute it.
    assert_eq!(report.trusted, None);
}

#[test]
fn an_install_without_trust_ca_plans_no_privileged_command() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));
    let report = run_provision(&paths, "/opt/bin/briefcred-daemon", false);
    assert!(report.trust.is_empty(), "{:?}", report.trust);
}

#[test]
fn uninstalling_keeps_the_ca_so_a_reinstall_stays_trusted() {
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(&temp.path().join("home"));
    run_provision(&paths, "/opt/bin/briefcred-daemon", false);

    let removal = remove_files(&paths).unwrap();

    assert!(paths.ca_cert().exists(), "uninstall must not delete the CA");
    assert!(store_for(&paths).get(CA_KEY_ITEM).unwrap().is_some());
    assert!(
        removal.retained.iter().any(|(p, _)| *p == paths.ca_dir()),
        "and must say so: {:?}",
        removal.retained
    );
}
