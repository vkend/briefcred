//! Generating the launchd LaunchAgent and the systemd user unit.
//!
//! Both are pure functions of a [`ServiceSpec`], with no I/O and no
//! environment lookups, so the exact bytes that will land in
//! `~/Library/LaunchAgents` are snapshot-tested rather than inspected by hand
//! after an install.
//!
//! briefcred is a per-user agent, never a system daemon. On macOS a
//! LaunchDaemon has no Aqua session, so a biometric prompt from one would hang
//! forever; that is why this file writes a LaunchAgent and `install` bootstraps
//! it into `gui/<uid>`.

use std::path::{Path, PathBuf};

use briefcred_core::paths::Paths;

/// Everything both unit formats need, resolved once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    label: String,
    program: PathBuf,
    home: PathBuf,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
}

impl ServiceSpec {
    /// Describe the service for a resolved layout and a daemon binary.
    ///
    /// `BRIEFCRED_HOME` is written into the unit explicitly rather than left
    /// to be re-derived: launchd starts the daemon with a sparse environment,
    /// and an agent that guessed a different home than the CLI would be a
    /// silent split-brain.
    pub fn new(paths: &Paths, program: &Path) -> ServiceSpec {
        ServiceSpec {
            label: paths.service_label().to_string(),
            program: program.to_path_buf(),
            home: paths.root().to_path_buf(),
            stdout_log: paths.log_dir().join("daemon.out.log"),
            stderr_log: paths.log_dir().join("daemon.err.log"),
        }
    }

    /// The label the service manager knows the daemon by.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The daemon binary the unit will execute.
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The `BRIEFCRED_HOME` the daemon will be started with.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Where the daemon's stdout is redirected.
    pub fn stdout_log(&self) -> &Path {
        &self.stdout_log
    }

    /// Where the daemon's stderr is redirected.
    pub fn stderr_log(&self) -> &Path {
        &self.stderr_log
    }
}

/// The macOS LaunchAgent property list.
pub fn launch_agent_plist(spec: &ServiceSpec) -> String {
    let label = xml(&spec.label);
    let program = xml(&spec.program.to_string_lossy());
    let home = xml(&spec.home.to_string_lossy());
    let stdout = xml(&spec.stdout_log.to_string_lossy());
    let stderr = xml(&spec.stderr_log.to_string_lossy());

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{program}</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>BRIEFCRED_HOME</key>
		<string>{home}</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>StandardOutPath</key>
	<string>{stdout}</string>
	<key>StandardErrorPath</key>
	<string>{stderr}</string>
</dict>
</plist>
"#
    )
}

/// The Linux systemd user unit.
pub fn systemd_unit(spec: &ServiceSpec) -> String {
    format!(
        "\
[Unit]
Description=briefcred credential broker
Documentation=https://github.com/briefcred/briefcred
After=default.target

[Service]
Type=simple
ExecStart={program}
Environment=BRIEFCRED_HOME={home}
Restart=always
RestartSec=1
StandardOutput=append:{stdout}
StandardError=append:{stderr}

[Install]
WantedBy=default.target
",
        program = spec.program.display(),
        home = spec.home.display(),
        stdout = spec.stdout_log.display(),
        stderr = spec.stderr_log.display(),
    )
}

/// The unit text for the platform this layout was resolved for.
pub fn unit_text(paths: &Paths, spec: &ServiceSpec) -> String {
    match paths.platform() {
        briefcred_core::paths::Platform::MacOs => launch_agent_plist(spec),
        briefcred_core::paths::Platform::Linux => systemd_unit(spec),
    }
}

/// Escape the five XML metacharacters so a path cannot break the plist.
fn xml(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_covers_every_metacharacter() {
        assert_eq!(xml("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
        assert_eq!(xml("/plain/path"), "/plain/path");
    }
}
