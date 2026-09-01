//! Exactly what `briefcred install` writes into `~/Library/LaunchAgents` and
//! `~/.config/systemd/user`. These are snapshots on purpose: a silent change
//! to `RunAtLoad` or `KeepAlive` is a change to whether the daemon survives a
//! reboot, and that should never slip through unreviewed.

use std::path::Path;

use briefcred_cli::service::{launch_agent_plist, systemd_unit, ServiceSpec};
use briefcred_core::paths::{Paths, Platform};

fn spec(platform: Platform) -> ServiceSpec {
    let paths = Paths::resolve(platform, &|key| match key {
        "BRIEFCRED_HOME" => Some("/tmp/bc".into()),
        _ => None,
    })
    .unwrap();
    ServiceSpec::new(&paths, Path::new("/opt/briefcred/bin/briefcred-daemon"))
}

#[test]
fn the_launch_agent_plist_is_exactly_this() {
    let expected = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>dev.briefcred.daemon</string>
	<key>ProgramArguments</key>
	<array>
		<string>/opt/briefcred/bin/briefcred-daemon</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>BRIEFCRED_HOME</key>
		<string>/tmp/bc</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>StandardOutPath</key>
	<string>/tmp/bc/logs/daemon.out.log</string>
	<key>StandardErrorPath</key>
	<string>/tmp/bc/logs/daemon.err.log</string>
</dict>
</plist>
"#;
    assert_eq!(launch_agent_plist(&spec(Platform::MacOs)), expected);
}

#[test]
fn the_systemd_unit_is_exactly_this() {
    let expected = "\
[Unit]
Description=briefcred credential broker
Documentation=https://github.com/briefcred/briefcred
After=default.target

[Service]
Type=simple
ExecStart=/opt/briefcred/bin/briefcred-daemon
Environment=BRIEFCRED_HOME=/tmp/bc
Restart=always
RestartSec=1
StandardOutput=append:/tmp/bc/logs/daemon.out.log
StandardError=append:/tmp/bc/logs/daemon.err.log

[Install]
WantedBy=default.target
";
    assert_eq!(systemd_unit(&spec(Platform::Linux)), expected);
}

#[test]
fn the_plist_survives_a_reboot_and_reaches_the_aqua_session() {
    // The three keys Phase 1's "done when" depends on, asserted by name so a
    // reformat of the snapshot above cannot quietly drop one.
    let plist = launch_agent_plist(&spec(Platform::MacOs));
    assert!(plist.contains("<key>RunAtLoad</key>\n\t<true/>"), "{plist}");
    assert!(plist.contains("<key>KeepAlive</key>\n\t<true/>"), "{plist}");
    assert!(
        plist.contains("<key>ProcessType</key>\n\t<string>Interactive</string>"),
        "{plist}"
    );
}

#[test]
fn xml_special_characters_in_a_path_are_escaped() {
    let paths = Paths::resolve(Platform::MacOs, &|key| match key {
        "BRIEFCRED_HOME" => Some("/tmp/a&b<c>".into()),
        _ => None,
    })
    .unwrap();
    let spec = ServiceSpec::new(&paths, Path::new("/opt/x&y/briefcred-daemon"));
    let plist = launch_agent_plist(&spec);
    assert!(
        plist.contains("<string>/opt/x&amp;y/briefcred-daemon</string>"),
        "{plist}"
    );
    assert!(
        plist.contains("<string>/tmp/a&amp;b&lt;c&gt;</string>"),
        "{plist}"
    );
    assert!(!plist.contains("a&b"), "{plist}");
}

#[test]
fn both_files_point_at_the_same_home_the_paths_resolved() {
    let spec = spec(Platform::MacOs);
    assert_eq!(spec.home(), Path::new("/tmp/bc"));
    assert_eq!(spec.label(), "dev.briefcred.daemon");
    assert!(spec.stdout_log().ends_with("logs/daemon.out.log"));
    assert!(spec.stderr_log().ends_with("logs/daemon.err.log"));
}
