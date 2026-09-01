//! Adding briefcred's root CA to, and removing it from, the system trust
//! store.
//!
//! This is the only part of briefcred that needs administrator rights, so it
//! follows the same shape as [`crate::lifecycle`]: the commands are built as
//! a [`Plan`] and returned, and running them is a separate step. `--dry-run`
//! prints the plan, the tests assert on it, and nothing in the test suite
//! ever invokes `sudo`.

use std::path::Path;
use std::process::Command;

use briefcred_core::paths::{Paths, Platform};

use crate::error::{Error, Result};

/// The system keychain macOS keeps machine-wide trust settings in.
pub const MACOS_SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

/// Where `update-ca-certificates` reads locally added certificates from.
pub const LINUX_TRUST_PATH: &str = "/usr/local/share/ca-certificates/briefcred.crt";

/// The commands that make up one trust action, in the order they must run.
///
/// Unlike a [`crate::lifecycle::Plan`], where the first success ends the
/// plan, every step here has to succeed: copying the certificate without
/// refreshing the bundle would leave the machine untrusting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The commands, in order.
    pub steps: Vec<Vec<String>>,
}

impl Plan {
    fn of(steps: Vec<Vec<&str>>) -> Plan {
        Plan {
            steps: steps
                .into_iter()
                .map(|argv| argv.into_iter().map(String::from).collect())
                .collect(),
        }
    }

    /// The plan rendered as shell lines, for `--dry-run` and for telling a
    /// user what to run themselves.
    pub fn lines(&self) -> Vec<String> {
        self.steps.iter().map(|argv| argv.join(" ")).collect()
    }

    /// Whether running this plan will ask for an administrator password.
    pub fn needs_sudo(&self) -> bool {
        self.steps
            .iter()
            .any(|argv| argv.first().is_some_and(|program| program == "sudo"))
    }
}

/// The commands that add `ca.pem` to the system trust store.
pub fn trust_plan(paths: &Paths) -> Plan {
    let cert = cert_arg(paths);
    match paths.platform() {
        // `-d` puts the setting in the admin domain rather than the user's,
        // and `-r trustRoot` says this certificate is trusted as a root, not
        // merely as a link in someone else's chain.
        Platform::MacOs => Plan::of(vec![vec![
            "sudo",
            "security",
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            MACOS_SYSTEM_KEYCHAIN,
            &cert,
        ]]),
        // `install` rather than `cp` so the mode is set in the same step:
        // `update-ca-certificates` skips a file it cannot read.
        Platform::Linux => Plan::of(vec![
            vec!["sudo", "install", "-m", "0644", &cert, LINUX_TRUST_PATH],
            vec!["sudo", "update-ca-certificates"],
        ]),
    }
}

/// The commands that remove `ca.pem` from the system trust store.
///
/// On macOS this matches on the certificate's content, so it has to run
/// while the file still holds the certificate being untrusted. Regenerating
/// first would leave the old trust setting behind with nothing to remove it.
pub fn untrust_plan(paths: &Paths) -> Plan {
    let cert = cert_arg(paths);
    match paths.platform() {
        Platform::MacOs => Plan::of(vec![vec![
            "sudo",
            "security",
            "remove-trusted-cert",
            "-d",
            &cert,
        ]]),
        // `--fresh` rebuilds the bundle from what is left rather than
        // appending, which is the only way a removal actually takes effect.
        Platform::Linux => Plan::of(vec![
            vec!["sudo", "rm", "-f", LINUX_TRUST_PATH],
            vec!["sudo", "update-ca-certificates", "--fresh"],
        ]),
    }
}

/// The read-only command that answers "does this machine trust `ca.pem`?".
///
/// Needs no administrator rights, so `briefcred ca show` can run it.
pub fn verify_plan(paths: &Paths) -> Plan {
    match paths.platform() {
        // Succeeds only if the certificate chains to something this machine
        // already trusts, which for a self-signed root means itself.
        Platform::MacOs => Plan::of(vec![vec![
            "security",
            "verify-cert",
            "-c",
            &cert_arg(paths),
            "-p",
            "basic",
        ]]),
        Platform::Linux => Plan::of(vec![vec!["test", "-f", LINUX_TRUST_PATH]]),
    }
}

/// Run every step of `plan`, stopping at the first that fails.
pub fn run(plan: &Plan) -> Result<()> {
    for argv in &plan.steps {
        let (program, args) = argv.split_first().expect("a plan step is never empty");
        let output =
            Command::new(program)
                .args(args)
                .output()
                .map_err(|err| Error::ServiceManager {
                    command: argv.join(" "),
                    detail: err.to_string(),
                })?;
        if !output.status.success() {
            let mut detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if detail.is_empty() {
                detail = format!("exited with {}", output.status);
            }
            return Err(Error::ServiceManager {
                command: argv.join(" "),
                detail,
            });
        }
    }
    Ok(())
}

/// Whether the machine currently trusts `ca.pem`.
///
/// `None` when the question cannot be answered, which is not the same as a
/// "no": `briefcred ca show` says "unknown" rather than claiming it is
/// untrusted and sending the user to fix something that is not broken.
pub fn is_trusted(paths: &Paths) -> Option<bool> {
    if !paths.ca_cert().exists() {
        return Some(false);
    }
    let plan = verify_plan(paths);
    let argv = plan.steps.first()?;
    let (program, args) = argv.split_first()?;
    let output = Command::new(program).args(args).output().ok()?;
    Some(output.status.success())
}

fn cert_arg(paths: &Paths) -> String {
    path_arg(&paths.ca_cert())
}

fn path_arg(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn paths(platform: Platform) -> Paths {
        Paths::resolve(platform, &|key| {
            (key == briefcred_core::paths::HOME_ENV).then(|| OsString::from("/tmp/bc"))
        })
        .unwrap()
    }

    #[test]
    fn macos_trusts_the_root_in_the_system_keychain() {
        assert_eq!(
            trust_plan(&paths(Platform::MacOs)).lines(),
            vec![concat!(
                "sudo security add-trusted-cert -d -r trustRoot ",
                "-k /Library/Keychains/System.keychain /tmp/bc/ca/ca.pem"
            )]
        );
    }

    #[test]
    fn macos_untrusts_the_certificate_the_file_still_holds() {
        assert_eq!(
            untrust_plan(&paths(Platform::MacOs)).lines(),
            vec!["sudo security remove-trusted-cert -d /tmp/bc/ca/ca.pem"]
        );
    }

    #[test]
    fn linux_installs_the_certificate_and_then_refreshes_the_bundle() {
        assert_eq!(
            trust_plan(&paths(Platform::Linux)).lines(),
            vec![
                format!("sudo install -m 0644 /tmp/bc/ca/ca.pem {LINUX_TRUST_PATH}"),
                "sudo update-ca-certificates".to_string(),
            ]
        );
    }

    #[test]
    fn linux_untrust_removes_the_certificate_and_rebuilds_from_scratch() {
        assert_eq!(
            untrust_plan(&paths(Platform::Linux)).lines(),
            vec![
                format!("sudo rm -f {LINUX_TRUST_PATH}"),
                "sudo update-ca-certificates --fresh".to_string(),
            ]
        );
    }

    #[test]
    fn every_trust_change_announces_that_it_needs_a_password() {
        for platform in [Platform::MacOs, Platform::Linux] {
            let paths = paths(platform);
            assert!(trust_plan(&paths).needs_sudo(), "{platform:?}");
            assert!(untrust_plan(&paths).needs_sudo(), "{platform:?}");
        }
    }

    #[test]
    fn asking_whether_the_ca_is_trusted_never_needs_a_password() {
        for platform in [Platform::MacOs, Platform::Linux] {
            let plan = verify_plan(&paths(platform));
            assert!(!plan.needs_sudo(), "{platform:?}: {:?}", plan.lines());
            assert_eq!(plan.steps.len(), 1, "{platform:?}");
        }
    }

    #[test]
    fn a_ca_that_does_not_exist_is_reported_as_untrusted() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_str().unwrap().to_string();
        let paths = Paths::resolve(Platform::MacOs, &|key| {
            (key == briefcred_core::paths::HOME_ENV).then(|| OsString::from(root.clone()))
        })
        .unwrap();
        assert_eq!(is_trusted(&paths), Some(false));
    }

    #[test]
    fn a_failing_step_names_the_command_and_what_it_said() {
        let plan = Plan::of(vec![vec!["false"]]);
        let err = run(&plan).unwrap_err();
        assert!(err.to_string().contains("false"), "{err}");
    }

    #[test]
    fn a_missing_program_is_an_error_rather_than_a_silent_success() {
        let plan = Plan::of(vec![vec!["briefcred-no-such-program"]]);
        assert!(run(&plan).is_err());
    }
}
