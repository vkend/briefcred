//! A signed profile registry, synced by the real CLI and loaded by the real daemon.
//!
//! Everything below the surface is unit-tested elsewhere. What this test is
//! for is the seam: `briefcred profile sync` writes files, the daemon's
//! watcher notices them, and the daemon's own verification — a separate check
//! from the CLI's, deliberately — decides whether they load. A profile that
//! verifies in one process and not the other is precisely the bug this catches.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use briefcred_core::minisign::{PublicKey, SecretKey};
use briefcred_e2e::daemon_harness::{binary_dir, wait_until, Daemon};
use briefcred_proto::{Request, Response};

/// A profile the daemon will accept but that mints nothing, so the test needs
/// no database and no master credential.
const PROFILE: &str = "name: published\nunlock:\n  policy: none\n";

/// Lay out a directory of signed profiles, and return the signing key pair.
fn publish(dir: &Path) -> (SecretKey, PublicKey) {
    let (secret, public) = SecretKey::generate().unwrap();
    std::fs::write(dir.join("published.yaml"), PROFILE).unwrap();
    std::fs::write(
        dir.join("published.yaml.minisig"),
        secret
            .sign(PROFILE.as_bytes(), "file:published.yaml")
            .unwrap(),
    )
    .unwrap();
    // A second profile with no signature at all, which must not survive the
    // trip in either process.
    std::fs::write(dir.join("unsigned.yaml"), "name: unsigned\n").unwrap();
    (secret, public)
}

/// Run `briefcred <args>` against `home`, returning its stdout.
fn briefcred(home: &Path, args: &[&str]) -> (bool, String) {
    let binary = binary_dir().join("briefcred");
    assert!(
        binary.is_file(),
        "no briefcred binary at {}; run `cargo build --workspace`",
        binary.display()
    );
    let output = Command::new(binary)
        .env("BRIEFCRED_HOME", home)
        .args(args)
        .output()
        .expect("run briefcred");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text)
}

#[tokio::test]
async fn a_synced_registry_profile_loads_and_an_unsigned_one_never_arrives() {
    let source = tempfile::tempdir().unwrap();
    let (_secret, public) = publish(source.path());

    let mut daemon = Daemon::prepare(&format!(
        "master_source = \"file\"\n\
         metrics_enabled = false\n\
         [profiles]\n\
         trust_roots = [\"{}\"]\n\
         registries = [{{ name = \"acme\", url = \"file://{}\" }}]\n",
        public.to_line(),
        source.path().display()
    ));

    // The sync runs before the daemon starts, which is the ordinary case: a
    // machine is provisioned and then the daemon comes up.
    let (ok, output) = briefcred(daemon.home(), &["profile", "sync"]);
    assert!(!ok, "a skipped file must be a non-zero exit: {output}");
    assert!(output.contains("acme"), "{output}");
    assert!(output.contains("unsigned.yaml"), "{output}");

    let fetched = daemon.home().join("profiles").join("registry").join("acme");
    assert!(fetched.join("published.yaml").is_file(), "{output}");
    assert!(
        !fetched.join("unsigned.yaml").exists(),
        "an unsigned profile must not be written: {output}"
    );

    daemon.start().await.expect("the daemon must start");

    let Ok(Response::Profiles { profiles }) = daemon.request(Request::ListProfiles).await else {
        panic!("the daemon must list its profiles");
    };
    assert_eq!(profiles.len(), 1, "{profiles:?}");
    assert_eq!(profiles[0].name, "published");
    assert_eq!(profiles[0].source, "registry(acme)");
    assert_eq!(profiles[0].signature, "verified");
    assert_eq!(
        profiles[0].signer_key_id.as_deref(),
        Some(public.key_id().to_string().as_str())
    );

    // `profile show` prints the provenance the daemon reported.
    let (ok, output) = briefcred(daemon.home(), &["profile", "show", "published"]);
    assert!(ok, "{output}");
    assert!(output.contains("registry(acme)"), "{output}");
    assert!(output.contains("verified"), "{output}");

    daemon.shutdown().await;
}

#[tokio::test]
async fn tampering_with_a_synced_profile_removes_it_and_leaves_an_audit_row() {
    let source = tempfile::tempdir().unwrap();
    let (_secret, public) = publish(source.path());
    std::fs::remove_file(source.path().join("unsigned.yaml")).unwrap();

    let mut daemon = Daemon::prepare(&format!(
        "master_source = \"file\"\n\
         metrics_enabled = false\n\
         [profiles]\n\
         trust_roots = [\"{}\"]\n\
         registries = [{{ name = \"acme\", url = \"file://{}\" }}]\n",
        public.to_line(),
        source.path().display()
    ));
    let (ok, output) = briefcred(daemon.home(), &["profile", "sync"]);
    assert!(ok, "{output}");
    daemon.start().await.expect("the daemon must start");
    assert!(
        wait_until(Duration::from_secs(20), || async {
            matches!(
                daemon.request(Request::ListProfiles).await,
                Ok(Response::Profiles { ref profiles }) if profiles.len() == 1
            )
        })
        .await,
        "the synced profile must load first\n{}",
        daemon.log()
    );

    // Edit the file under the running daemon, the way a compromised sync or a
    // local attacker with write access to the registry directory would.
    std::fs::write(
        daemon
            .home()
            .join("profiles")
            .join("registry")
            .join("acme")
            .join("published.yaml"),
        "name: published\ndescription: pwned\n",
    )
    .unwrap();

    assert!(
        wait_until(Duration::from_secs(20), || async {
            matches!(
                daemon.request(Request::ListProfiles).await,
                Ok(Response::Profiles { ref profiles }) if profiles.is_empty()
            )
        })
        .await,
        "a profile whose signature stopped verifying must be dropped, not kept\n{}",
        daemon.log()
    );

    let rows = daemon.audit_rows();
    let warning = rows
        .iter()
        .find(|row| row["event"] == "profile_trust_warning")
        .unwrap_or_else(|| panic!("no profile_trust_warning row in {rows:#?}"));
    assert_eq!(warning["action"], "dropped");
    assert!(
        warning["path"].as_str().unwrap().contains("published.yaml"),
        "{warning}"
    );

    daemon.shutdown().await;
}

#[tokio::test]
async fn dev_mode_loads_an_unsigned_profile_and_says_so_everywhere() {
    let source = tempfile::tempdir().unwrap();
    let (_secret, _public) = publish(source.path());

    let mut daemon = Daemon::prepare(&format!(
        "master_source = \"file\"\n\
         metrics_enabled = false\n\
         [profiles]\n\
         dev_mode = true\n\
         registries = [{{ name = \"acme\", url = \"file://{}\" }}]\n",
        source.path().display()
    ));
    let (_ok, output) = briefcred(daemon.home(), &["profile", "sync"]);
    assert!(output.contains("dev_mode"), "{output}");

    daemon.start().await.expect("the daemon must start");
    let Ok(Response::Profiles { profiles }) = daemon.request(Request::ListProfiles).await else {
        panic!("the daemon must list its profiles");
    };
    assert_eq!(profiles.len(), 2, "dev_mode loads both: {profiles:?}");
    let unsigned = profiles.iter().find(|p| p.name == "unsigned").unwrap();
    assert_eq!(unsigned.signature, "dev_mode");

    // The daemon says so on startup, `briefcred profiles` says so in its
    // output, and the audit log has a row per file.
    assert!(
        daemon.log().contains("PROFILE NOT VERIFIED"),
        "the daemon must warn on start:\n{}",
        daemon.log()
    );
    let (ok, output) = briefcred(daemon.home(), &["profiles"]);
    assert!(ok, "{output}");
    assert!(output.contains("NOT verified"), "{output}");

    let dev_rows: Vec<_> = daemon
        .audit_rows()
        .into_iter()
        .filter(|row| row["event"] == "profile_trust_warning")
        .collect();
    assert!(!dev_rows.is_empty(), "no trust warning rows");
    assert!(
        dev_rows
            .iter()
            .all(|row| row["action"] == "loaded_dev_mode"),
        "{dev_rows:#?}"
    );

    daemon.shutdown().await;
}
