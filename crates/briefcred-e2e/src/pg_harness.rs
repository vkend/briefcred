//! An ephemeral PostgreSQL cluster, started per test and thrown away after.
//!
//! There is no Docker on the development machine, so the harness drives
//! `initdb` and `pg_ctl` directly. Everything — data directory, log, and Unix
//! socket — lives under one temporary directory, and the server listens on a
//! free loopback port, so a running system cluster is never touched.
//!
//! Two roles exist in every cluster:
//!
//! * `master` — the bootstrap superuser.
//! * `master_limited` — a `CREATEROLE` role that does **not** own schema
//!   `public` but holds the grant options it needs to pass privileges on.
//!   This mirrors the managed-PostgreSQL default, where relying on
//!   `DROP OWNED BY` alone leaves privileges behind.
//!
//! Host authentication is `scram-sha-256`, so a test that connects as a minted
//! role really does have to present the minted password.

use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;
use tokio_postgres::{Client, NoTls};
use zeroize::Zeroizing;

/// The bootstrap superuser created by `initdb`.
pub const MASTER_USER: &str = "master";

/// A `CREATEROLE` role that does not own schema `public`.
pub const LIMITED_USER: &str = "master_limited";

/// The database every test connects to.
pub const DBNAME: &str = "postgres";

/// Fallback location for PostgreSQL server binaries on this machine.
const HOMEBREW_PG14_BIN: &str = "/opt/homebrew/opt/postgresql@14/bin";

/// Environment variable that overrides binary discovery.
pub const PG_BIN_ENV: &str = "BRIEFCRED_PG_BIN";

/// Why the harness could not produce a cluster.
#[derive(Debug)]
pub enum HarnessError {
    /// No usable PostgreSQL server installation was found. Tests print this
    /// and skip rather than fail.
    NoServerBinary(String),
    /// A cluster was found but could not be started or initialised.
    Failed(String),
}

impl std::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HarnessError::NoServerBinary(m) => write!(f, "{m}"),
            HarnessError::Failed(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for HarnessError {}

/// Locate a directory holding `initdb`, `pg_ctl`, and the `postgres` server.
///
/// Requiring the server binary is what rejects client-only installations such
/// as `libpq`, which ship `initdb` and `pg_ctl` but cannot run a cluster.
pub fn find_pg_bin() -> Result<PathBuf, HarnessError> {
    let mut tried: Vec<String> = Vec::new();

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = std::env::var_os(PG_BIN_ENV) {
        candidates.push(PathBuf::from(dir));
    }
    candidates.push(PathBuf::from(HOMEBREW_PG14_BIN));
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path));
    }

    for dir in candidates {
        if ["initdb", "pg_ctl", "postgres"]
            .iter()
            .all(|bin| dir.join(bin).is_file())
        {
            return Ok(dir);
        }
        tried.push(dir.display().to_string());
    }

    Err(HarnessError::NoServerBinary(format!(
        "no PostgreSQL server binaries (initdb, pg_ctl, postgres) found; set {PG_BIN_ENV}. Looked in: {}",
        tried.join(", ")
    )))
}

/// A running, throwaway PostgreSQL cluster.
///
/// Dropping the value stops the server and removes its data directory.
pub struct PgCluster {
    bin: PathBuf,
    dir: TempDir,
    port: u16,
    master_password: Zeroizing<String>,
    limited_password: Zeroizing<String>,
    running: bool,
}

impl PgCluster {
    /// Initialise and start a cluster, then create the `master_limited` role.
    pub async fn start() -> Result<PgCluster, HarnessError> {
        PgCluster::start_with_tls(false).await
    }

    /// The same, with `ssl = on` and a freshly generated self-signed
    /// certificate for `localhost` and `127.0.0.1`.
    ///
    /// Self-signed on purpose: it is what makes the difference between
    /// `sslmode: require` and `sslmode: verify-full` observable, since the
    /// first must connect and the second must refuse. `pg_hba.conf` is left as
    /// `initdb` wrote it — `host`, not `hostssl` — so an unencrypted
    /// connection is still accepted and `sslmode: disable` remains testable
    /// against the very same cluster.
    pub async fn start_with_tls(tls: bool) -> Result<PgCluster, HarnessError> {
        let bin = find_pg_bin()?;
        let dir = TempDir::new().map_err(|e| HarnessError::Failed(e.to_string()))?;
        let port = free_port()?;
        let master_password = Zeroizing::new(random_token());
        let limited_password = Zeroizing::new(random_token());

        let data = dir.path().join("data");
        let pwfile = dir.path().join("pw");
        std::fs::write(&pwfile, master_password.as_str())
            .map_err(|e| HarnessError::Failed(e.to_string()))?;

        run(
            &bin.join("initdb"),
            &[
                "-D".as_ref(),
                data.as_os_str(),
                "-U".as_ref(),
                MASTER_USER.as_ref(),
                "--auth-local=trust".as_ref(),
                "--auth-host=scram-sha-256".as_ref(),
                "--pwfile".as_ref(),
                pwfile.as_os_str(),
                "--no-sync".as_ref(),
                "-E".as_ref(),
                "UTF8".as_ref(),
                "--locale=C".as_ref(),
            ],
        )?;
        std::fs::remove_file(&pwfile).ok();

        let log = dir.path().join("server.log");
        let mut options = format!(
            "-p {port} -h 127.0.0.1 -k {} -c fsync=off -c synchronous_commit=off",
            dir.path().display()
        );
        if tls {
            let (cert, key) = write_self_signed(&data)?;
            options.push_str(&format!(
                " -c ssl=on -c ssl_cert_file={} -c ssl_key_file={}",
                cert.display(),
                key.display()
            ));
        }
        let mut cluster = PgCluster {
            bin,
            dir,
            port,
            master_password,
            limited_password,
            running: false,
        };
        run(
            &cluster.bin.join("pg_ctl"),
            &[
                "-D".as_ref(),
                data.as_os_str(),
                "-l".as_ref(),
                log.as_os_str(),
                "-o".as_ref(),
                options.as_ref(),
                "-w".as_ref(),
                "-t".as_ref(),
                "30".as_ref(),
                "start".as_ref(),
            ],
        )
        .map_err(|e| HarnessError::Failed(format!("{e}\n{}", tail_of(&log))))?;
        cluster.running = true;

        cluster.provision().await?;
        Ok(cluster)
    }

    /// Create `master_limited` and give it grant options without ownership.
    async fn provision(&self) -> Result<(), HarnessError> {
        let client = self
            .connect_as(MASTER_USER, &self.master_password)
            .await
            .map_err(|e| HarnessError::Failed(format!("cannot connect as master: {e}")))?;
        let statements = [
            format!(
                "CREATE ROLE {LIMITED_USER} LOGIN PASSWORD '{}' CREATEROLE",
                self.limited_password.as_str()
            ),
            // Grant options, but never ownership of schema public.
            format!("GRANT USAGE, CREATE ON SCHEMA public TO {LIMITED_USER} WITH GRANT OPTION"),
            format!(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public \
                 TO {LIMITED_USER} WITH GRANT OPTION"
            ),
        ];
        for statement in statements {
            client
                .batch_execute(&statement)
                .await
                .map_err(|e| HarnessError::Failed(format!("{statement}: {e}")))?;
        }
        Ok(())
    }

    /// The loopback port the server listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The password of the bootstrap superuser.
    pub fn master_password(&self) -> Zeroizing<String> {
        self.master_password.clone()
    }

    /// The password of the `CREATEROLE`, non-owning role.
    pub fn limited_password(&self) -> Zeroizing<String> {
        self.limited_password.clone()
    }

    /// Open a connection as an arbitrary role.
    pub async fn connect_as(
        &self,
        user: &str,
        password: &str,
    ) -> Result<Client, tokio_postgres::Error> {
        let mut config = tokio_postgres::Config::new();
        config
            .host("127.0.0.1")
            .port(self.port)
            .dbname(DBNAME)
            .user(user)
            .password(password)
            .ssl_mode(tokio_postgres::config::SslMode::Disable);
        let (client, connection) = config.connect(NoTls).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    }

    /// Open a connection as the bootstrap superuser.
    pub async fn connect_master(&self) -> Client {
        self.connect_as(MASTER_USER, &self.master_password)
            .await
            .expect("connect as master")
    }

    /// A `postgres-dynamic` credential config pointing at this cluster.
    ///
    /// `user` selects which master role the minter authenticates as; `grants`
    /// is the YAML body of `role_template.grants`.
    pub fn minter_config(&self, user: &str, grants: &str) -> serde_yaml_ng::Value {
        let yaml = format!(
            "host: 127.0.0.1\nport: {}\ndbname: {DBNAME}\nuser: {user}\nsslmode: disable\nrole_template:\n  grants:\n{grants}",
            self.port
        );
        serde_yaml_ng::from_str(&yaml).expect("harness minter config is valid YAML")
    }

    /// How many `briefcred_t_%` roles the cluster still has.
    pub async fn leaked_role_count(&self) -> i64 {
        let client = self.connect_master().await;
        client
            .query_one(
                "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'briefcred\\_t\\_%'",
                &[],
            )
            .await
            .expect("count briefcred roles")
            .get(0)
    }

    fn stop(&mut self) {
        if !self.running {
            return;
        }
        let data = self.dir.path().join("data");
        let _ = Command::new(self.bin.join("pg_ctl"))
            .args(["-D".as_ref(), data.as_os_str()])
            .args(["-m", "immediate", "-w", "-t", "20", "stop"])
            .output();
        self.running = false;
    }
}

impl Drop for PgCluster {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start a cluster, or print why the test is being skipped and return `None`.
///
/// A missing PostgreSQL installation is a skip; anything else is a failure,
/// because a half-working cluster silently passing would defeat the point.
pub async fn cluster_or_skip(test: &str) -> Option<PgCluster> {
    cluster_or_skip_with_tls(test, false).await
}

/// The same, for a cluster that speaks TLS.
pub async fn cluster_or_skip_with_tls(test: &str, tls: bool) -> Option<PgCluster> {
    match PgCluster::start_with_tls(tls).await {
        Ok(cluster) => Some(cluster),
        Err(HarnessError::NoServerBinary(reason)) => {
            println!("skipping {test}: {reason}");
            None
        }
        Err(HarnessError::Failed(reason)) => panic!("{test}: harness failed: {reason}"),
    }
}

/// Generate a self-signed server certificate into `data`, returning its paths.
///
/// The key is written `0600`: PostgreSQL refuses to start with a key any group
/// or other can read, and does so with a message that is easy to misread as a
/// TLS misconfiguration.
fn write_self_signed(data: &Path) -> Result<(PathBuf, PathBuf), HarnessError> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

    let failed = |what: &str, e: String| HarnessError::Failed(format!("{what}: {e}"));

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| failed("cannot generate a server key", e.to_string()))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    let mut params = CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
        .map_err(|e| failed("cannot build certificate parameters", e.to_string()))?;
    params.distinguished_name = dn;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(1);
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| failed("cannot sign the server certificate", e.to_string()))?;

    let cert_path = data.join("briefcred-server.crt");
    let key_path = data.join("briefcred-server.key");
    std::fs::write(&cert_path, cert.pem()).map_err(|e| failed("write cert", e.to_string()))?;
    std::fs::write(&key_path, key_pair.serialize_pem())
        .map_err(|e| failed("write key", e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| failed("chmod key", e.to_string()))?;
    }
    Ok((cert_path, key_path))
}

fn run(program: &Path, args: &[&std::ffi::OsStr]) -> Result<(), HarnessError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| HarnessError::Failed(format!("cannot run {}: {e}", program.display())))?;
    if output.status.success() {
        return Ok(());
    }
    Err(HarnessError::Failed(format!(
        "{} exited with {}\nstdout: {}\nstderr: {}",
        program.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim(),
    )))
}

fn free_port() -> Result<u16, HarnessError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| HarnessError::Failed(format!("cannot find a free port: {e}")))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| HarnessError::Failed(e.to_string()))
}

fn random_token() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn tail_of(log: &Path) -> String {
    let mut text = String::new();
    if let Ok(mut file) = std::fs::File::open(log) {
        let _ = file.read_to_string(&mut text);
    }
    text.lines()
        .rev()
        .take(20)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_finds_a_server_installation_or_says_where_it_looked() {
        match find_pg_bin() {
            Ok(dir) => {
                for bin in ["initdb", "pg_ctl", "postgres"] {
                    assert!(
                        dir.join(bin).is_file(),
                        "{} missing from {}",
                        bin,
                        dir.display()
                    );
                }
            }
            Err(err) => {
                assert!(err.to_string().contains(PG_BIN_ENV), "{err}");
                assert!(err.to_string().contains("Looked in"), "{err}");
            }
        }
    }

    #[test]
    fn free_port_returns_a_usable_loopback_port() {
        let port = free_port().unwrap();
        assert!(port >= 1024, "{port}");
        assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());
    }
}
