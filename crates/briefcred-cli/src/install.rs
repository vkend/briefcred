//! `briefcred install` and `briefcred uninstall`.
//!
//! Both are idempotent. `install` provisions the directory layout, writes a
//! starter `daemon.toml` if there is none, writes the service unit, and asks
//! the service manager to start the daemon. `uninstall` reverses exactly the
//! parts `install` created that belong to the system: the unit file and the
//! loaded agent. It never deletes the audit log, because deleting the audit
//! trail on the way out is the one thing an audit trail must not do.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use briefcred_core::ca::{machine_hostname, CertificateAuthority};
use briefcred_core::keystore::KeyStore;
use briefcred_core::paths::Paths;

use crate::error::{Error, Result};
use crate::lifecycle;
use crate::service::{unit_text, ServiceSpec};
use crate::trust;

/// The `daemon.toml` written on a first install.
///
/// Every value is the built-in default, commented out, so the file documents
/// what can be tuned without changing any behaviour by existing.
pub const STARTER_CONFIG: &str = "\
# briefcred daemon configuration. Every key is optional; the values shown are
# the built-in defaults.

# How many days of audit logs to keep.
# retention_days = 90

# The loopback port for the Prometheus endpoint. 0 asks for a free port.
# metrics_port = 9317

# Whether to serve the Prometheus endpoint at all.
# metrics_enabled = true
";

/// How long `install` waits for the started daemon to start listening.
pub const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether a daemon is listening on `sock` yet, polled until `timeout`.
///
/// `launchctl bootstrap` and `systemctl --user start` both return as soon as
/// the service manager has accepted the job, not when the daemon has bound its
/// socket. Without this wait, `install` would tell the user to run
/// `briefcred daemon status` and that command would fail if they were quick.
pub fn wait_until_listening(sock: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if std::os::unix::net::UnixStream::connect(sock).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Whether the socket has stopped answering, polled until `timeout`.
///
/// The mirror of [`wait_until_listening`], for `stop`: the service manager
/// returns once it has signalled the daemon, not once the daemon has finished
/// draining and removed its socket.
pub fn wait_until_gone(sock: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if std::os::unix::net::UnixStream::connect(sock).is_err() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The switches `briefcred install` accepts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InstallOptions {
    /// Print what would be written and run, and change nothing.
    pub dry_run: bool,
    /// Also add the root CA to the system trust store, which needs `sudo`.
    pub trust_ca: bool,
}

/// The root CA an install found or created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaSummary {
    /// Where the certificate is.
    pub cert: PathBuf,
    /// Whether this install generated it, as opposed to finding it.
    pub generated: bool,
    /// Its SHA-256 fingerprint, so the user can check what they are trusting.
    pub fingerprint: String,
    /// Which key store holds the private key.
    pub keystore: String,
}

/// What an install did, or would do under `--dry-run`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Directories created or confirmed.
    pub directories: Vec<PathBuf>,
    /// Files written, with the reason.
    pub files: Vec<(PathBuf, &'static str)>,
    /// Files left alone because they already exist.
    pub kept: Vec<PathBuf>,
    /// The service-manager commands that were, or would be, run.
    pub commands: Vec<String>,
    /// Whether the daemon was listening before `install` returned.
    ///
    /// Always false for a dry run, which starts nothing.
    pub ready: bool,
    /// The root CA. `None` for a dry run, which generates nothing.
    pub ca: Option<CaSummary>,
    /// The trust-store commands. Empty unless `--trust-ca` was given.
    pub trust: Vec<String>,
    /// Whether the trust step succeeded. `None` when it was not run.
    pub trusted: Option<bool>,
    /// What the trust step complained about, if it failed.
    ///
    /// A failure here does not fail the install: the daemon is provisioned
    /// and running either way, and the user can retry the one command.
    pub trust_error: Option<String>,
}

/// Provision the layout, write the unit, and start the daemon.
///
/// With `dry_run` the report is filled in exactly as it would be, and nothing
/// is written or executed.
pub fn install(
    paths: &Paths,
    daemon_binary: &Path,
    options: InstallOptions,
    store: &dyn KeyStore,
) -> Result<Report> {
    let mut report = provision(paths, daemon_binary, options, store)?;
    if options.dry_run {
        return Ok(report);
    }

    // Trusting comes before starting: it is the step that can fail on a
    // mistyped password, and failing it after the daemon is up would leave
    // the user unsure which half of the install took.
    if options.trust_ca {
        match trust::run(&trust::trust_plan(paths)) {
            Ok(()) => report.trusted = Some(true),
            Err(err) => {
                report.trusted = Some(false);
                report.trust_error = Some(err.to_string());
            }
        }
    }

    lifecycle::run(&lifecycle::start_plan(paths))?;
    report.ready = wait_until_listening(paths.sock(), READY_TIMEOUT);
    Ok(report)
}

/// The filesystem half of an install: directories, config, and the unit file.
///
/// Separate from [`install`] so it can be tested without a service manager;
/// a test that ran `launchctl bootstrap` would load a real agent for the
/// developer running it.
pub fn provision(
    paths: &Paths,
    daemon_binary: &Path,
    options: InstallOptions,
    store: &dyn KeyStore,
) -> Result<Report> {
    let dry_run = options.dry_run;
    let mut report = Report::default();

    let dirs = [
        paths.root().to_path_buf(),
        paths.profiles_dir(),
        paths.audit_dir(),
        paths.ca_dir(),
        paths.log_dir(),
        paths.state_dir(),
    ];
    if !dry_run {
        paths.ensure_layout()?;
    }
    report.directories.extend(dirs);

    let config = paths.daemon_toml();
    if config.exists() {
        report.kept.push(config);
    } else {
        if !dry_run {
            std::fs::write(&config, STARTER_CONFIG).map_err(|e| Error::io("write", &config, e))?;
            set_mode(&config, 0o600)?;
        }
        report.files.push((config, "starter configuration"));
    }

    let spec = ServiceSpec::new(paths, daemon_binary);
    let unit = paths.service_file();
    if !dry_run {
        // The service directory belongs to launchd or systemd and is expected
        // to be world-readable, so it is not part of the 0700 layout.
        std::fs::create_dir_all(paths.service_dir())
            .map_err(|e| Error::io("create", paths.service_dir(), e))?;
        std::fs::write(&unit, unit_text(paths, &spec)).map_err(|e| Error::io("write", &unit, e))?;
        set_mode(&unit, 0o644)?;
    }
    report.files.push((unit, "service unit"));

    if !dry_run {
        // Idempotent: a reinstall keeps the CA the machine already trusts,
        // because replacing it would silently break every trusted copy.
        let (ca, generated) = CertificateAuthority::ensure(paths, store, &machine_hostname())?;
        report.ca = Some(CaSummary {
            cert: paths.ca_cert(),
            generated,
            fingerprint: ca.info()?.fingerprint_sha256,
            keystore: store.kind().to_string(),
        });
        if generated {
            report.files.push((paths.ca_cert(), "root CA certificate"));
        } else {
            report.kept.push(paths.ca_cert());
        }
    } else {
        report.files.push((paths.ca_cert(), "root CA certificate"));
    }

    if options.trust_ca {
        report.trust = trust::trust_plan(paths).lines();
    }

    report.commands = lifecycle::start_plan(paths).lines();
    Ok(report)
}

/// What an uninstall removed and what it deliberately left behind.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Removal {
    /// Files that were deleted.
    pub removed: Vec<PathBuf>,
    /// Paths left in place, with the reason.
    pub retained: Vec<(PathBuf, &'static str)>,
    /// A service-manager complaint that was tolerated, if there was one.
    pub note: Option<String>,
}

/// Stop the daemon, unload the agent, and delete the unit file.
pub fn uninstall(paths: &Paths) -> Result<Removal> {
    let note = lifecycle::run_tolerantly(&lifecycle::stop_plan(paths));
    let mut removal = remove_files(paths)?;
    removal.note = note;
    Ok(removal)
}

/// The filesystem half of an uninstall: the unit file and a stale socket.
///
/// Separate from [`uninstall`] for the same reason [`provision`] is separate
/// from [`install`]: the service-manager call is not safe to run in a test.
pub fn remove_files(paths: &Paths) -> Result<Removal> {
    let mut removal = Removal::default();

    let unit = paths.service_file();
    match std::fs::remove_file(&unit) {
        Ok(()) => removal.removed.push(unit),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(Error::io("remove", &unit, err)),
    }

    match std::fs::remove_file(paths.sock()) {
        Ok(()) => removal.removed.push(paths.sock().to_path_buf()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(Error::io("remove", paths.sock(), err)),
    }

    removal
        .retained
        .push((paths.audit_dir(), "the audit trail is never deleted"));
    removal
        .retained
        .push((paths.ca_dir(), "the CA this machine already trusts"));
    removal
        .retained
        .push((paths.root().to_path_buf(), "profiles and configuration"));
    Ok(removal)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| Error::io("set the mode of", path, e))
}
