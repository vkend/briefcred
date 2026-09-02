//! The command surface and its output.

use std::path::Path;

use briefcred_core::ca::machine_hostname;
use briefcred_core::paths::Paths;
use briefcred_proto::Response;
use clap::{Parser, Subcommand};

use crate::error::{Error, Result};
use crate::{audit, bootstrap, ca, client, exec, install, lifecycle, trust};

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
    /// Run a command with freshly minted, short-lived credentials.
    ///
    /// The command runs with a cleared environment: it gets what the profile
    /// grants it, plus `PATH`, `HOME`, `TERM`, `LANG`, `TMPDIR`, and whatever
    /// the profile's `env_passthrough` names. Its exit code becomes this
    /// command's.
    Exec {
        /// The profile to run under.
        #[arg(long)]
        profile: String,
        /// Comma-separated credential names. Defaults to all of them.
        #[arg(long = "cred")]
        credentials: Option<String>,
        /// The program and its arguments.
        #[arg(last = true, required = true, num_args = 1..)]
        command: Vec<String>,
    },
    /// Print one field of one minted credential.
    ///
    /// Refuses to write to a terminal unless `--force`: a short-lived
    /// credential in a scrollback buffer is a long-lived one.
    Get {
        /// The profile to mint under.
        #[arg(long)]
        profile: String,
        /// The credential to mint.
        #[arg(long = "cred")]
        credential: String,
        /// The field to print, for example `PGPASSWORD`.
        #[arg(long)]
        field: String,
        /// Print to a terminal anyway.
        #[arg(long)]
        force: bool,
    },
    /// List the profiles the daemon has loaded.
    Profiles,
    /// Report whether briefcred is working, and what is missing if not.
    Health,
    /// Print audit rows.
    Audit {
        /// Only rows from the last `30m`, `24h`, `7d`, and so on.
        #[arg(long)]
        since: Option<String>,
        /// Print the rows as they are stored, one JSON object per line.
        #[arg(long)]
        json: bool,
    },
    /// Create and inspect profiles.
    Profile {
        /// What to do with profiles.
        #[command(subcommand)]
        action: ProfileAction,
    },
}

/// The `briefcred profile` subcommands.
#[derive(Debug, Subcommand)]
pub enum ProfileAction {
    /// Interactively write a profile and store its master credential.
    Bootstrap,
    /// Print one profile as the daemon parsed it.
    Show {
        /// The profile's name.
        name: String,
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

/// Execute one parsed command, returning the process exit code.
///
/// A code rather than `()` because `briefcred exec` exits with its child's
/// status: a wrapper that swallowed a non-zero exit would break every script
/// that used it.
pub async fn run(cli: Cli) -> Result<u8> {
    let paths = Paths::discover()?;
    match cli.command {
        Command::Install { dry_run, trust_ca } => {
            let binary = lifecycle::daemon_binary(&current_exe()?)?;
            let options = install::InstallOptions { dry_run, trust_ca };
            let report = install::install(&paths, &binary, options, keystore(&paths)?.as_ref())?;
            print_install(&report, dry_run);
            Ok(0)
        }
        Command::Uninstall => {
            let removal = install::uninstall(&paths)?;
            print_uninstall(&removal);
            Ok(0)
        }
        Command::Ca { action } => run_ca(&paths, action).map(|()| 0),
        Command::Daemon { action } => run_daemon(&paths, action).await.map(|()| 0),
        Command::Exec {
            profile,
            credentials,
            command,
        } => {
            let credentials = credentials
                .as_deref()
                .map(exec::parse_credentials)
                .transpose()?;
            let (argv0, args) = command.split_first().expect("clap requires at least one");
            let code = exec::run(
                paths.sock(),
                exec::ExecRequest {
                    profile: &profile,
                    credentials,
                    argv0,
                    args,
                },
            )
            .await?;
            // The child's exit code is this command's, so a script wrapping
            // `briefcred exec` behaves as if briefcred were not there.
            Ok(code)
        }
        Command::Get {
            profile,
            credential,
            field,
            force,
        } => {
            let value = exec::get(
                paths.sock(),
                &profile,
                &credential,
                &field,
                force,
                stdout_is_tty(),
            )
            .await?;
            // No trailing newline: the value is meant to be captured, and
            // `$(briefcred get ...)` strips one but a file redirect does not.
            print!("{value}");
            Ok(0)
        }
        Command::Profiles => {
            print_profiles(
                &client::request(paths.sock(), briefcred_proto::Request::ListProfiles).await?,
            );
            Ok(0)
        }
        Command::Health => {
            print_health(&paths).await;
            Ok(0)
        }
        Command::Audit { since, json } => {
            let window = since.as_deref().map(audit::parse_since).transpose()?;
            for row in audit::read_since(&paths.audit_dir(), window)? {
                if json {
                    println!("{row}");
                } else {
                    println!("{}", audit::render(&row));
                }
            }
            Ok(0)
        }
        Command::Profile { action } => run_profile(&paths, action).await.map(|()| 0),
    }
}

/// Whether stdout is a terminal.
///
/// The one place the CLI asks: `briefcred get` refuses one, and nothing else
/// changes its behaviour based on it.
fn stdout_is_tty() -> bool {
    // SAFETY-free: `isatty` takes an integer, touches no memory, and cannot
    // fail in a way that matters here.
    #[allow(unsafe_code)]
    unsafe {
        libc::isatty(libc::STDOUT_FILENO) == 1
    }
}

async fn run_profile(paths: &Paths, action: ProfileAction) -> Result<()> {
    match action {
        ProfileAction::Bootstrap => {
            let source_kind = master_source_kind(paths)?;
            let done = bootstrap::run(paths, paths.sock(), source_kind).await?;
            println!("briefcred profile bootstrap");
            println!("  wrote      {}", done.path.display());
            println!("  master     `{}` in {}", done.source_key, done.location);
            println!(
                "
the daemon reloads profiles by itself; 'briefcred profiles' will show it"
            );
            Ok(())
        }
        ProfileAction::Show { name } => {
            let reply =
                client::request(paths.sock(), briefcred_proto::Request::ShowProfile { name })
                    .await?;
            match reply {
                Response::Profile { profile } => {
                    print_profiles(&Response::Profiles {
                        profiles: vec![profile],
                    });
                    Ok(())
                }
                Response::Error { message } => Err(Error::Refused(message)),
                other => Err(Error::Unexpected(format!("{other:?}"))),
            }
        }
    }
}

/// Which master source the daemon is configured to use.
fn master_source_kind(paths: &Paths) -> Result<briefcred_core::SourceKind> {
    #[derive(serde::Deserialize)]
    struct JustTheSource {
        master_source: Option<briefcred_core::SourceKind>,
    }
    let text = std::fs::read_to_string(paths.daemon_toml()).unwrap_or_default();
    // The CLI reads only the one key it needs rather than the daemon's whole
    // schema: a `daemon.toml` with a key this binary is too old to know about
    // must not stop somebody bootstrapping a profile.
    let parsed: JustTheSource = toml::from_str(&text).unwrap_or(JustTheSource {
        master_source: None,
    });
    Ok(parsed
        .master_source
        .unwrap_or_else(|| briefcred_core::SourceKind::platform_default(paths.platform())))
}

fn print_profiles(reply: &Response) {
    let Response::Profiles { profiles } = reply else {
        return;
    };
    if profiles.is_empty() {
        println!("no profiles; run 'briefcred profile bootstrap' to write one");
        return;
    }
    println!(
        "{:<20}{:<12}{:<8}{}",
        "PROFILE", "UNLOCK", "CACHE", "CREDENTIALS"
    );
    for profile in profiles {
        let credentials = if profile.credentials.is_empty() {
            "-".to_string()
        } else {
            profile
                .credentials
                .iter()
                .map(|c| format!("{} ({}, {}s)", c.name, c.kind, c.ttl_secs))
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "{:<20}{:<12}{:<8}{credentials}",
            profile.name,
            profile.unlock_policy,
            format!("{}s", profile.unlock_cache_secs)
        );
    }
}

/// Report what is working and, for anything that is not, what to run.
///
/// Every line is a check somebody has actually been stuck on: the daemon not
/// running, the CA not trusted, no profiles yet.
async fn print_health(paths: &Paths) {
    println!("briefcred health");
    match client::status(paths.sock()).await {
        Ok(Response::Status {
            version,
            uptime_secs,
            audit_path,
            ..
        }) => {
            println!(
                "  daemon     running, {version}, up {}",
                human_uptime(uptime_secs)
            );
            println!("  audit      {}", audit_path.display());
        }
        Ok(other) => println!("  daemon     answered unexpectedly: {other:?}"),
        Err(err) => println!("  daemon     {err}"),
    }

    match client::request(paths.sock(), briefcred_proto::Request::ListProfiles).await {
        Ok(Response::Profiles { profiles }) if profiles.is_empty() => {
            println!("  profiles   none; run 'briefcred profile bootstrap'");
        }
        Ok(Response::Profiles { profiles }) => {
            println!("  profiles   {} loaded", profiles.len());
        }
        _ => println!("  profiles   unknown; the daemon is not answering"),
    }

    if paths.ca_cert().exists() {
        match trust::is_trusted(paths) {
            Some(true) => println!("  ca         present and trusted"),
            Some(false) => {
                println!("  ca         present, not trusted; run 'briefcred install --trust-ca'")
            }
            None => println!("  ca         present, trust state unknown"),
        }
    } else {
        println!("  ca         missing; run 'briefcred install --trust-ca'");
    }

    let queue = paths.state_dir().join("revoke-queue.jsonl");
    let outstanding = std::fs::read_to_string(&queue)
        .map(|text| text.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or_default();
    match outstanding {
        0 => println!("  revokes    none outstanding"),
        n => println!("  revokes    {n} outstanding in {}", queue.display()),
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
            //
            // Only when it is actually trusted, though. Untrusting regardless
            // would ask for an administrator password to remove something
            // that was never added.
            let untrusted = if trust::is_trusted(paths) == Some(true) {
                trust::run_announced(&trust::untrust_plan(paths)).err()
            } else {
                None
            };

            let result = ca::regenerate(paths, store.as_ref(), &machine_hostname())?;
            print_regenerated(&result, untrusted.as_ref());

            if trust_ca {
                trust::run_announced(&trust::trust_plan(paths))?;
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
            trust::run_announced(&trust::untrust_plan(paths))?;
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
            vec!["briefcred", "exec", "--profile=db-ro", "--", "psql"],
            vec![
                "briefcred",
                "exec",
                "--profile",
                "db-ro",
                "--cred",
                "db,warehouse",
                "--",
                "psql",
                "-c",
                "SELECT 1",
            ],
            vec![
                "briefcred",
                "get",
                "--profile",
                "db-ro",
                "--cred",
                "db",
                "--field",
                "PGPASSWORD",
            ],
            vec![
                "briefcred",
                "get",
                "--profile",
                "db-ro",
                "--cred",
                "db",
                "--field",
                "PGPASSWORD",
                "--force",
            ],
            vec!["briefcred", "profiles"],
            vec!["briefcred", "health"],
            vec!["briefcred", "audit"],
            vec!["briefcred", "audit", "--since", "24h", "--json"],
            vec!["briefcred", "profile", "bootstrap"],
            vec!["briefcred", "profile", "show", "db-ro"],
        ] {
            Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        }
    }

    /// Everything after `--` belongs to the child, including things that look
    /// like briefcred's own flags. Without this an agent's `psql --profile x`
    /// would be silently reinterpreted.
    #[test]
    fn the_child_command_swallows_flags_that_look_like_briefcreds_own() {
        let cli = Cli::try_parse_from([
            "briefcred",
            "exec",
            "--profile",
            "db-ro",
            "--",
            "psql",
            "--profile",
            "--force",
            "--json",
        ])
        .unwrap();
        let Command::Exec {
            profile, command, ..
        } = cli.command
        else {
            panic!("expected an exec");
        };
        assert_eq!(profile, "db-ro");
        assert_eq!(command, vec!["psql", "--profile", "--force", "--json"]);
    }

    #[test]
    fn an_exec_with_no_command_is_rejected() {
        assert!(Cli::try_parse_from(["briefcred", "exec", "--profile", "db-ro"]).is_err());
        assert!(Cli::try_parse_from(["briefcred", "exec", "--profile", "db-ro", "--"]).is_err());
    }

    #[test]
    fn get_requires_every_part_of_the_address_it_is_given() {
        assert!(Cli::try_parse_from(["briefcred", "get", "--profile", "p"]).is_err());
        assert!(Cli::try_parse_from(["briefcred", "get", "--cred", "c", "--field", "f"]).is_err());
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
