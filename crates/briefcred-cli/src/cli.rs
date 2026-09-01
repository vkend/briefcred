//! The command surface and its output.

use std::path::Path;

use briefcred_core::ca::machine_hostname;
use briefcred_core::paths::Paths;
use briefcred_proto::Response;
use clap::{Parser, Subcommand};

use crate::error::{Error, Result};
use crate::{ca, client, install, lifecycle, trust};

/// A local, biometric-gated credential broker for AI agents and tooling.
#[derive(Debug, Parser)]
#[command(name = "briefcred", version, about, long_about = None)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Provision the layout, install the service unit, and start the daemon.
    Install {
        /// Print what would be written and run, and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Also add the root CA to the system trust store. Needs sudo.
        #[arg(long)]
        trust_ca: bool,
    },
    /// Stop the daemon and remove the service unit. Leaves the audit log.
    Uninstall,
    /// Inspect and manage the per-machine root certificate authority.
    Ca {
        /// What to do with the CA.
        #[command(subcommand)]
        action: CaAction,
    },
    /// Inspect and control the running daemon.
    Daemon {
        /// The lifecycle action.
        #[command(subcommand)]
        action: DaemonAction,
    },
}

/// The `briefcred ca` subcommands.
#[derive(Debug, Subcommand)]
pub enum CaAction {
    /// Print the CA's subject, fingerprint, validity, and trust state.
    Show,
    /// Replace the CA with a new one. Every issued leaf stops being trusted.
    Regenerate {
        /// Add the new CA to the system trust store. Needs sudo.
        #[arg(long)]
        trust_ca: bool,
    },
    /// Remove the CA from the system trust store, keeping the files. Needs sudo.
    Untrust,
}

/// The `briefcred daemon` subcommands.
#[derive(Debug, Subcommand)]
pub enum DaemonAction {
    /// Report the daemon's version, uptime, audit log, and metrics endpoint.
    Status,
    /// Ask the service manager to start the daemon.
    Start,
    /// Ask the service manager to stop the daemon.
    Stop,
    /// Ask the service manager to restart the daemon.
    Restart,
}

/// Execute one parsed command.
pub async fn run(cli: Cli) -> Result<()> {
    let paths = Paths::discover()?;
    match cli.command {
        Command::Install { dry_run, trust_ca } => {
            let binary = lifecycle::daemon_binary(&current_exe()?)?;
            let options = install::InstallOptions { dry_run, trust_ca };
            let report = install::install(&paths, &binary, options, keystore(&paths)?.as_ref())?;
            print_install(&report, dry_run);
            Ok(())
        }
        Command::Uninstall => {
            let removal = install::uninstall(&paths)?;
            print_uninstall(&removal);
            Ok(())
        }
        Command::Ca { action } => run_ca(&paths, action),
        Command::Daemon { action } => run_daemon(&paths, action).await,
    }
}

/// The key store the CA's private key lives in, as configured.
fn keystore(paths: &Paths) -> Result<Box<dyn briefcred_core::KeyStore>> {
    Ok(briefcred_core::ca::CaConfig::load(paths)?.open_keystore(paths)?)
}

fn run_ca(paths: &Paths, action: CaAction) -> Result<()> {
    let store = keystore(paths)?;
    match action {
        CaAction::Show => {
            let status = ca::describe(paths, store.as_ref(), trust::is_trusted(paths))?;
            print_ca(&status);
            Ok(())
        }
        CaAction::Regenerate { trust_ca } => {
            // The old certificate has to be untrusted while the file still
            // holds it: `security remove-trusted-cert` matches on content,
            // and after the replacement there is nothing left to match.
            let untrusted = if paths.ca_cert().exists() {
                trust::run(&trust::untrust_plan(paths)).err()
            } else {
                None
            };

            let result = ca::regenerate(paths, store.as_ref(), &machine_hostname())?;
            print_regenerated(&result, untrusted.as_ref());

            if trust_ca {
                trust::run(&trust::trust_plan(paths))?;
                println!("  trusted    the new CA is in the system trust store");
            } else {
                println!("\nthe new CA is not trusted yet; run:");
                for line in trust::trust_plan(paths).lines() {
                    println!("  {line}");
                }
            }
            Ok(())
        }
        CaAction::Untrust => {
            trust::run(&trust::untrust_plan(paths))?;
            println!("the CA is no longer in the system trust store");
            println!(
                "  kept       {} (run 'briefcred install --trust-ca' to trust it again)",
                paths.ca_cert().display()
            );
            Ok(())
        }
    }
}

async fn run_daemon(paths: &Paths, action: DaemonAction) -> Result<()> {
    match action {
        DaemonAction::Status => {
            let status = client::status(paths.sock()).await?;
            print_status(&status, paths.sock());
            Ok(())
        }
        // Each of these waits for the daemon to actually reach the requested
        // state. The service manager returns as soon as it has accepted the
        // job, so without the wait a `status` typed straight afterwards races
        // the daemon and reports it down.
        DaemonAction::Start => {
            lifecycle::run(&lifecycle::start_plan(paths))?;
            report_settled(
                install::wait_until_listening(paths.sock(), install::READY_TIMEOUT),
                "started",
                "listening",
            );
            Ok(())
        }
        DaemonAction::Stop => {
            lifecycle::run(&lifecycle::stop_plan(paths))?;
            report_settled(
                install::wait_until_gone(paths.sock(), install::READY_TIMEOUT),
                "stopped",
                "gone",
            );
            Ok(())
        }
        DaemonAction::Restart => {
            lifecycle::run(&lifecycle::restart_plan(paths))?;
            report_settled(
                install::wait_until_listening(paths.sock(), install::READY_TIMEOUT),
                "restarted",
                "listening",
            );
            Ok(())
        }
    }
}

fn report_settled(settled: bool, done: &str, expected: &str) {
    if settled {
        println!("daemon {done}");
    } else {
        println!(
            "the service manager accepted the job, but the daemon was not {expected} after {} s",
            install::READY_TIMEOUT.as_secs()
        );
    }
}

fn current_exe() -> Result<std::path::PathBuf> {
    std::env::current_exe().map_err(|e| Error::io("locate", "the briefcred binary", e))
}

fn print_install(report: &install::Report, dry_run: bool) {
    let verb = if dry_run { "would " } else { "" };
    println!(
        "{}briefcred install",
        if dry_run { "dry run: " } else { "" }
    );
    for dir in &report.directories {
        println!("  {verb}provision  {} (0700)", dir.display());
    }
    for (path, why) in &report.files {
        println!("  {verb}write      {} ({why})", path.display());
    }
    for path in &report.kept {
        println!("  keep       {} (already present)", path.display());
    }
    for command in &report.commands {
        println!("  {verb}run        {command}");
    }
    for command in &report.trust {
        println!("  {verb}run        {command}");
    }
    if let Some(ca) = &report.ca {
        println!(
            "  ca         {} ({}, key in the {} store)",
            ca.fingerprint,
            if ca.generated {
                "generated"
            } else {
                "existing"
            },
            ca.keystore
        );
    }
    if dry_run {
        return;
    }
    if let Some(detail) = &report.trust_error {
        println!("\nthe CA could not be trusted: {detail}");
        println!("run this yourself, then 'briefcred ca show' to confirm:");
        for line in &report.trust {
            println!("  {line}");
        }
    }
    if report.ready {
        println!("\nthe daemon is listening; 'briefcred daemon status' has the details");
    } else {
        println!(
            "\nthe service manager accepted the job, but the daemon was not listening after {} s.",
            install::READY_TIMEOUT.as_secs()
        );
        println!("check the daemon logs, then run 'briefcred daemon status'");
    }
}

fn print_uninstall(removal: &install::Removal) {
    println!("briefcred uninstall");
    for path in &removal.removed {
        println!("  removed    {}", path.display());
    }
    for (path, why) in &removal.retained {
        println!("  retained   {} ({why})", path.display());
    }
    if let Some(note) = &removal.note {
        println!("  note       the service manager said: {note}");
    }
}

fn print_ca(status: &ca::Status) {
    let rfc3339 = &time::format_description::well_known::Rfc3339;
    println!("briefcred root CA");
    println!("  subject      {}", status.info.common_name);
    println!("  fingerprint  sha256:{}", status.info.fingerprint_sha256);
    println!(
        "  valid        {} to {}",
        status
            .info
            .not_before
            .format(rfc3339)
            .unwrap_or_else(|_| status.info.not_before.to_string()),
        status
            .info
            .not_after
            .format(rfc3339)
            .unwrap_or_else(|_| status.info.not_after.to_string())
    );
    println!("  certificate  {}", status.cert.display());
    println!(
        "  private key  {} ({} store)",
        status.key_location, status.keystore
    );
    match status.trusted {
        Some(true) => println!("  trusted      yes"),
        Some(false) => println!("  trusted      no; run 'briefcred install --trust-ca' to add it"),
        None => println!("  trusted      unknown"),
    }
}

fn print_regenerated(result: &ca::Regenerated, untrust_error: Option<&crate::Error>) {
    println!("briefcred ca regenerate");
    match &result.previous_fingerprint {
        Some(old) => println!("  replaced     sha256:{old}"),
        None => println!("  replaced     nothing; there was no CA"),
    }
    println!("  fingerprint  sha256:{}", result.info.fingerprint_sha256);
    println!("  certificate  {}", result.cert.display());
    if let Some(err) = untrust_error {
        println!("  note         the old CA could not be untrusted: {err}");
    }
    println!("\nevery certificate the old CA issued is now untrusted.");
}

fn print_status(status: &Response, sock: &Path) {
    let Response::Status {
        version,
        pid,
        uptime_secs,
        started_at,
        audit_path,
        metrics_addr,
    } = status
    else {
        return;
    };

    println!("briefcred daemon is running");
    println!("  version    {version}");
    println!("  pid        {pid}");
    println!("  uptime     {}", human_uptime(*uptime_secs));
    println!(
        "  started    {}",
        started_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| started_at.to_string())
    );
    println!("  socket     {}", sock.display());
    println!("  audit      {}", audit_path.display());
    match metrics_addr {
        Some(addr) => println!("  metrics    http://{addr}/metrics"),
        None => println!("  metrics    disabled"),
    }
}

/// Render a duration in seconds as the largest two useful units.
pub fn human_uptime(secs: u64) -> String {
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let (hours, rest) = (rest / 3_600, rest % 3_600);
    let (minutes, seconds) = (rest / 60, rest % 60);
    match (days, hours, minutes) {
        (0, 0, 0) => format!("{seconds}s"),
        (0, 0, _) => format!("{minutes}m {seconds}s"),
        (0, _, _) => format!("{hours}h {minutes}m"),
        _ => format!("{days}d {hours}h"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_documented_invocation_parses() {
        for argv in [
            vec!["briefcred", "install"],
            vec!["briefcred", "install", "--dry-run"],
            vec!["briefcred", "install", "--trust-ca"],
            vec!["briefcred", "install", "--dry-run", "--trust-ca"],
            vec!["briefcred", "ca", "show"],
            vec!["briefcred", "ca", "regenerate"],
            vec!["briefcred", "ca", "regenerate", "--trust-ca"],
            vec!["briefcred", "ca", "untrust"],
            vec!["briefcred", "uninstall"],
            vec!["briefcred", "daemon", "status"],
            vec!["briefcred", "daemon", "start"],
            vec!["briefcred", "daemon", "stop"],
            vec!["briefcred", "daemon", "restart"],
        ] {
            Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        }
    }

    #[test]
    fn an_unknown_daemon_action_is_rejected_rather_than_guessed() {
        assert!(Cli::try_parse_from(["briefcred", "daemon", "reboot"]).is_err());
        assert!(Cli::try_parse_from(["briefcred", "instal"]).is_err());
        assert!(Cli::try_parse_from(["briefcred", "ca", "trust"]).is_err());
        assert!(Cli::try_parse_from(["briefcred", "ca"]).is_err());
    }

    #[test]
    fn uptime_reads_as_a_duration_not_a_number() {
        assert_eq!(human_uptime(0), "0s");
        assert_eq!(human_uptime(42), "42s");
        assert_eq!(human_uptime(90), "1m 30s");
        assert_eq!(human_uptime(3_661), "1h 1m");
        assert_eq!(human_uptime(90_061), "1d 1h");
    }
}
