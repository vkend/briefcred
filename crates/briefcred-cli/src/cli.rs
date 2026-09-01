//! The command surface and its output.

use std::path::Path;

use briefcred_core::paths::Paths;
use briefcred_proto::Response;
use clap::{Parser, Subcommand};

use crate::error::{Error, Result};
use crate::{client, install, lifecycle};

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
    },
    /// Stop the daemon and remove the service unit. Leaves the audit log.
    Uninstall,
    /// Inspect and control the running daemon.
    Daemon {
        /// The lifecycle action.
        #[command(subcommand)]
        action: DaemonAction,
    },
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
        Command::Install { dry_run } => {
            let binary = lifecycle::daemon_binary(&current_exe()?)?;
            let report = install::install(&paths, &binary, dry_run)?;
            print_install(&report, dry_run);
            Ok(())
        }
        Command::Uninstall => {
            let removal = install::uninstall(&paths)?;
            print_uninstall(&removal);
            Ok(())
        }
        Command::Daemon { action } => run_daemon(&paths, action).await,
    }
}

async fn run_daemon(paths: &Paths, action: DaemonAction) -> Result<()> {
    match action {
        DaemonAction::Status => {
            let status = client::status(paths.sock()).await?;
            print_status(&status, paths.sock());
            Ok(())
        }
        DaemonAction::Start => {
            lifecycle::run(&lifecycle::start_plan(paths))?;
            println!("daemon started");
            Ok(())
        }
        DaemonAction::Stop => {
            lifecycle::run(&lifecycle::stop_plan(paths))?;
            println!("daemon stopped");
            Ok(())
        }
        DaemonAction::Restart => {
            lifecycle::run(&lifecycle::restart_plan(paths))?;
            println!("daemon restarted");
            Ok(())
        }
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
    if !dry_run {
        println!("\nrun 'briefcred daemon status' to confirm it came up");
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
