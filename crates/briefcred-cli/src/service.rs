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
    sock: PathBuf,
    ports: Ports,
}

/// The three loopback ports the socket unit binds on the daemon's behalf.
///
/// Read from `daemon.toml` where it names them, and the built-in defaults
/// otherwise — the same resolution the daemon does, because the unit and the
/// daemon have to agree about which socket is which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    /// The Prometheus endpoint.
    pub metrics: u16,
    /// The HTTP proxy.
    pub proxy: u16,
    /// The Postgres proxy.
    pub pg_proxy: u16,
}

impl Default for Ports {
    fn default() -> Ports {
        Ports {
            metrics: briefcred_core::ports::DEFAULT_METRICS_PORT,
            proxy: briefcred_core::ports::DEFAULT_PROXY_PORT,
            pg_proxy: briefcred_core::ports::DEFAULT_PG_PROXY_PORT,
        }
    }
}

impl Ports {
    /// The three ports as `daemon.toml` leaves them.
    ///
    /// Only the three keys are read, on the same terms as the `master_source`
    /// lookup in `cli`: a `daemon.toml` carrying a key this binary is too old
    /// to know about must still install cleanly, so this parses what it needs
    /// rather than the daemon's whole schema.
    pub fn from_daemon_toml(text: &str) -> Ports {
        let parsed: toml::Value = match toml::from_str(text) {
            Ok(value) => value,
            Err(_) => return Ports::default(),
        };
        let mut ports = Ports::default();
        let read = |key: &str, into: &mut u16| {
            if let Some(port) = parsed.get(key).and_then(toml::Value::as_integer) {
                if let Ok(port) = u16::try_from(port) {
                    *into = port;
                }
            }
        };
        read("metrics_port", &mut ports.metrics);
        read("proxy_port", &mut ports.proxy);
        read("pg_proxy_port", &mut ports.pg_proxy);
        ports
    }
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
            sock: paths.sock().to_path_buf(),
            ports: Ports::default(),
        }
    }

    /// The same spec with the ports `daemon.toml` actually names.
    ///
    /// A builder rather than a lookup inside [`ServiceSpec::new`], so this
    /// module stays a pure function of its input: the exact bytes that land in
    /// `~/.config/systemd/user` are snapshot-tested, and a constructor that
    /// read a file would make those snapshots depend on the developer's disk.
    pub fn with_ports(mut self, ports: Ports) -> ServiceSpec {
        self.ports = ports;
        self
    }

    /// The ports the socket unit will bind.
    pub fn ports(&self) -> Ports {
        self.ports
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
Documentation=https://github.com/vkend/briefcred
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

/// The Linux systemd socket unit.
///
/// systemd binds these four and passes them to the daemon as `LISTEN_FDS`, in
/// the order they are listed here. The order is not cosmetic: systemd says only
/// how many descriptors there are, so this list and the daemon's
/// `handoff::ACTIVATION_ORDER` are one fact written in two places, and swapping
/// two lines here would have the daemon publish its HTTP proxy on `/metrics`.
///
/// Socket activation is what makes an unattended restart seamless on Linux:
/// systemd holds the listeners, so a client connecting while the daemon is
/// being replaced is queued rather than refused. `briefcred daemon upgrade`
/// covers the same ground on both platforms and does not need this.
pub fn systemd_socket_unit(spec: &ServiceSpec) -> String {
    format!(
        "\
[Unit]
Description=briefcred credential broker sockets
Documentation=https://github.com/vkend/briefcred

[Socket]
ListenStream={sock}
ListenStream=127.0.0.1:{metrics}
ListenStream=127.0.0.1:{proxy}
ListenStream=127.0.0.1:{pg_proxy}
SocketMode=0600
Service=briefcred.service

[Install]
WantedBy=sockets.target
",
        sock = spec.sock.display(),
        metrics = spec.ports.metrics,
        proxy = spec.ports.proxy,
        pg_proxy = spec.ports.pg_proxy,
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
