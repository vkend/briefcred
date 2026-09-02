//! Starting and stopping the daemon through the platform's service manager.
//!
//! `launchctl` on macOS, `systemctl --user` on Linux. The CLI never spawns
//! `briefcred-daemon` itself: the service manager owns the process, restarts
//! it, and starts it again at login, and a hand-spawned copy would fight it
//! for the socket.

use std::path::Path;
use std::process::Command;

use briefcred_core::paths::{Paths, Platform};

use crate::error::{Error, Result};

/// The commands that make up one lifecycle action, as they will be run.
///
/// Returned rather than executed so `--dry-run` can print them and the tests
/// can assert on them without touching a real service manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The commands, in order. The first that succeeds ends the plan.
    pub attempts: Vec<Vec<String>>,
}

impl Plan {
    fn of(attempts: &[&[&str]]) -> Plan {
        Plan {
            attempts: attempts
                .iter()
                .map(|argv| argv.iter().map(|s| (*s).to_string()).collect())
                .collect(),
        }
    }

    /// The plan rendered as shell-ish lines, for `--dry-run` output.
    pub fn lines(&self) -> Vec<String> {
        self.attempts.iter().map(|argv| argv.join(" ")).collect()
    }
}

/// The uid the service manager scopes this user's agents to.
#[allow(unsafe_code)]
pub fn uid() -> u32 {
    // SAFETY: `getuid` takes no arguments, reads no memory, and cannot fail.
    unsafe { libc::getuid() }
}

/// The commands that load the agent and start the daemon.
pub fn start_plan(paths: &Paths) -> Plan {
    let service = paths.service_file().to_string_lossy().into_owned();
    let domain = format!("gui/{}", uid());
    let target = format!("{domain}/{}", paths.service_label());
    match paths.platform() {
        // `bootstrap` fails if the agent is already loaded, in which case
        // `kickstart` is the idempotent way to make sure it is running.
        Platform::MacOs => Plan {
            attempts: vec![
                vec!["launchctl".into(), "bootstrap".into(), domain, service],
                vec!["launchctl".into(), "kickstart".into(), target],
            ],
        },
        Platform::Linux => Plan::of(&[
            &[
                "systemctl",
                "--user",
                "enable",
                "--now",
                "briefcred.service",
            ],
            &["systemctl", "--user", "start", "briefcred.service"],
        ]),
    }
}

/// The commands that stop the daemon and unload the agent.
pub fn stop_plan(paths: &Paths) -> Plan {
    let target = format!("gui/{}/{}", uid(), paths.service_label());
    match paths.platform() {
        Platform::MacOs => Plan {
            attempts: vec![vec!["launchctl".into(), "bootout".into(), target]],
        },
        Platform::Linux => Plan::of(&[&["systemctl", "--user", "stop", "briefcred.service"]]),
    }
}

/// The commands that restart the daemon in place.
pub fn restart_plan(paths: &Paths) -> Plan {
    let target = format!("gui/{}/{}", uid(), paths.service_label());
    match paths.platform() {
        Platform::MacOs => Plan {
            attempts: vec![vec![
                "launchctl".into(),
                "kickstart".into(),
                "-k".into(),
                target,
            ]],
        },
        Platform::Linux => Plan::of(&[&["systemctl", "--user", "restart", "briefcred.service"]]),
    }
}

/// Run a plan, stopping at the first attempt that succeeds.
///
/// Reports the last failure if none of them do.
pub fn run(plan: &Plan) -> Result<()> {
    let mut last: Option<(String, String)> = None;
    for argv in &plan.attempts {
        let (program, args) = argv.split_first().expect("a plan command is never empty");
        let output = Command::new(program).args(args).output();
        match output {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                let mut detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if detail.is_empty() {
                    detail = format!("exited with {}", output.status);
                }
                last = Some((argv.join(" "), detail));
            }
            Err(err) => last = Some((argv.join(" "), err.to_string())),
        }
    }

    let (command, detail) = last.expect("a plan always has at least one attempt");
    Err(Error::ServiceManager { command, detail })
}

/// Run a plan, treating "it was not loaded anyway" as success.
///
/// Used by `uninstall`, which must be safe to run twice.
pub fn run_tolerantly(plan: &Plan) -> Option<String> {
    match run(plan) {
        Ok(()) => None,
        Err(Error::ServiceManager { detail, .. }) => Some(detail),
        Err(err) => Some(err.to_string()),
    }
}

/// Whether the `briefcred-daemon` binary sits next to this executable.
pub fn daemon_binary(next_to: &Path) -> Result<std::path::PathBuf> {
    let candidate = next_to
        .parent()
        .unwrap_or(Path::new("."))
        .join("briefcred-daemon");
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(Error::DaemonBinaryMissing(candidate))
    }
}

/// The flag the daemon takes to wait for a handoff.
pub const TAKEOVER_FLAG: &str = "--takeover";

/// Start `binary` in takeover mode, waiting on `socket`.
///
/// The one place the CLI runs `briefcred-daemon` itself, and the exception
/// proves the rule the rest of this module is built on: the service manager
/// owns the *installed* daemon, and this is a second process that exists only
/// long enough to be handed the first one's sockets. It is not `wait`ed on —
/// it outlives this command, which is the whole point.
///
/// `BRIEFCRED_HOME` is passed explicitly for the same reason the unit files
/// carry it: the new daemon has to resolve the identical layout, and a daemon
/// that guessed a different home would take over nothing and bind a second
/// socket somewhere else.
pub fn spawn_takeover(paths: &Paths, binary: &Path, socket: &Path) -> Result<std::process::Child> {
    let log = paths.log_dir().join("daemon.err.log");
    let stderr = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .map_err(|e| Error::io("open", &log, e))?;
    let stdout = stderr.try_clone().map_err(|e| Error::io("open", &log, e))?;
    Command::new(binary)
        .arg(TAKEOVER_FLAG)
        .arg(socket)
        .env("BRIEFCRED_HOME", paths.root())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr))
        .spawn()
        .map_err(|e| Error::io("start", binary, e))
}

/// Whether the takeover socket has appeared, polled until `timeout`.
///
/// The new daemon binds it before it will accept anything, so this is the
/// signal that it has started far enough to be handed the sockets. Sending the
/// handoff request any earlier would have the old daemon fail to connect and
/// report an upgrade that never happened.
///
/// Existence, deliberately, and never a connection. The takeover socket accepts
/// exactly once, and a probe that connected would *be* that one connection: the
/// new daemon would greet the CLI, wait for a state blob the CLI has no way to
/// send, and time out with the old daemon still holding everything.
pub fn wait_until_bound(socket: &Path, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::fs::symlink_metadata(socket).is_ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn paths(platform: Platform) -> Paths {
        Paths::resolve(platform, &|key| {
            (key == "BRIEFCRED_HOME").then(|| OsString::from("/tmp/bc"))
        })
        .unwrap()
    }

    #[test]
    fn macos_bootstraps_into_the_gui_domain_of_this_uid() {
        let lines = start_plan(&paths(Platform::MacOs)).lines();
        assert_eq!(
            lines[0],
            format!(
                "launchctl bootstrap gui/{} /tmp/bc/Library/LaunchAgents/dev.briefcred.daemon.plist",
                uid()
            )
        );
        assert_eq!(
            lines[1],
            format!("launchctl kickstart gui/{}/dev.briefcred.daemon", uid())
        );
    }

    #[test]
    fn macos_stop_and_restart_address_the_loaded_agent() {
        let paths = paths(Platform::MacOs);
        assert_eq!(
            stop_plan(&paths).lines(),
            vec![format!(
                "launchctl bootout gui/{}/dev.briefcred.daemon",
                uid()
            )]
        );
        assert_eq!(
            restart_plan(&paths).lines(),
            vec![format!(
                "launchctl kickstart -k gui/{}/dev.briefcred.daemon",
                uid()
            )]
        );
    }

    #[test]
    fn linux_uses_the_user_scoped_systemctl() {
        let paths = paths(Platform::Linux);
        assert_eq!(
            start_plan(&paths).lines()[0],
            "systemctl --user enable --now briefcred.service"
        );
        assert_eq!(
            stop_plan(&paths).lines(),
            vec!["systemctl --user stop briefcred.service"]
        );
        assert_eq!(
            restart_plan(&paths).lines(),
            vec!["systemctl --user restart briefcred.service"]
        );
    }

    #[test]
    fn no_plan_ever_spawns_the_daemon_directly() {
        for platform in [Platform::MacOs, Platform::Linux] {
            let paths = paths(platform);
            for plan in [start_plan(&paths), stop_plan(&paths), restart_plan(&paths)] {
                for line in plan.lines() {
                    assert!(
                        !line.contains("briefcred-daemon"),
                        "the CLI must go through the service manager: {line}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_missing_daemon_binary_names_where_it_looked() {
        let temp = tempfile::tempdir().unwrap();
        let cli = temp.path().join("briefcred");
        let err = daemon_binary(&cli).unwrap_err();
        assert!(err.to_string().contains("briefcred-daemon"), "{err}");
    }

    #[test]
    fn a_sibling_daemon_binary_is_found() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("briefcred-daemon"), b"#!/bin/sh\n").unwrap();
        let found = daemon_binary(&temp.path().join("briefcred")).unwrap();
        assert_eq!(found, temp.path().join("briefcred-daemon"));
    }
}
