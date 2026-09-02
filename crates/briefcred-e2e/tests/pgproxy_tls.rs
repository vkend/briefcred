//! The Postgres proxy's **upstream** TLS, against a real cluster with `ssl = on`.
//!
//! The master password is the one secret the `postgres-proxy` kind exists to
//! withhold from the subprocess, and it is the one secret the daemon has to
//! present to the real server. SCRAM keeps it off the wire as a plaintext
//! string, but SCRAM alone leaves the whole session — every statement, every
//! row, and the channel-binding material — readable by anything on the path.
//! So the daemon negotiates TLS before it writes the startup packet.
//!
//! The cluster here is started with a **self-signed** certificate, which is
//! what makes the three modes distinguishable in one fixture:
//!
//! | `sslmode` | expected |
//! | --- | --- |
//! | `require` (the default) | connects, encrypted, certificate unchecked |
//! | `verify-full` | refused: the certificate chains to nothing trusted |
//! | `disable` | connects, unencrypted |
//!
//! Its `pg_hba.conf` is `initdb`'s own — `host`, not `hostssl` — so the same
//! cluster serves all three rows.

use briefcred_e2e::daemon_harness::Daemon;
use briefcred_e2e::pg_harness::{cluster_or_skip_with_tls, PgCluster, MASTER_USER};
use briefcred_proto::{Request, Response};

/// The database the profile authorises. `postgres` is what `initdb` makes.
const DBNAME: &str = "postgres";

/// The credential's name inside the profile.
const CREDENTIAL: &str = "warehouse";

fn profile(port: u16, sslmode: &str) -> String {
    format!(
        "\
name: warehouse
unlock:
  policy: none
credentials:
  - name: {CREDENTIAL}
    kind: postgres-proxy
    ttl_secs: 300
    config:
      host: 127.0.0.1
      port: {port}
      dbname: {DBNAME}
      user: {MASTER_USER}
      sslmode: {sslmode}
env:
  DATABASE_URL: ${{minted.{CREDENTIAL}.DATABASE_URL}}
"
    )
}

/// A TLS cluster, a daemon pointed straight at it, and a minted DSN.
struct Fixture {
    daemon: Daemon,
    database_url: String,
    _cluster: PgCluster,
}

async fn start(test: &str, sslmode: &str) -> Option<Fixture> {
    let cluster = cluster_or_skip_with_tls(test, true).await?;

    let daemon = Daemon::prepare(
        "metrics_enabled = false\nmetrics_port = 0\nproxy_port = 0\npg_proxy_port = 0\n\
         master_source = \"file\"\n[ca]\nkeystore = \"file\"\n",
    );
    daemon.write_profile("warehouse", &profile(cluster.port(), sslmode));
    daemon.write_master(CREDENTIAL, &cluster.master_password());

    let mut daemon = daemon;
    daemon.start().await.unwrap_or_else(|e| panic!("{e}"));

    let Response::SessionOpened { session_id, .. } = daemon
        .request(Request::OpenSession {
            profile: "warehouse".to_string(),
            client_headless: true,
            session_pubkey: None,
        })
        .await
        .unwrap()
    else {
        panic!("the session did not open:\n{}", daemon.log());
    };

    let Response::Minted { env, .. } = daemon
        .request(Request::Exec {
            session_id,
            credentials: None,
            argv0: "psql".to_string(),
            args: Vec::new(),
            pid: std::process::id(),
        })
        .await
        .unwrap()
    else {
        panic!("nothing was minted:\n{}", daemon.log());
    };

    Some(Fixture {
        daemon,
        database_url: env["DATABASE_URL"].expose().to_string(),
        _cluster: cluster,
    })
}

/// Ask the server, through the proxy, whether *its own* view of the connection
/// briefcred opened is encrypted.
///
/// `pg_stat_ssl` reports the backend's connection, which is the upstream one —
/// the client's hop to the proxy is a separate socket the server never sees.
/// That makes this the only assertion that distinguishes "briefcred negotiated
/// TLS" from "briefcred said it did".
async fn upstream_is_encrypted(database_url: &str) -> std::process::Output {
    let psql = briefcred_e2e::pg_harness::find_pg_bin()
        .expect("a PostgreSQL installation, since the cluster started")
        .join("psql");
    tokio::process::Command::new(psql)
        .args([
            "-tAc",
            "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
            database_url,
        ])
        .env("PGCONNECT_TIMEOUT", "10")
        .output()
        .await
        .expect("psql runs")
}

#[tokio::test]
async fn require_encrypts_the_upstream_connection_without_trusting_the_certificate() {
    let Some(fixture) = start(
        "require_encrypts_the_upstream_connection_without_trusting_the_certificate",
        "require",
    )
    .await
    else {
        return;
    };

    let output = upstream_is_encrypted(&fixture.database_url).await;
    assert!(
        output.status.success(),
        "psql failed: {}\n{}",
        String::from_utf8_lossy(&output.stderr),
        fixture.daemon.log()
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "t",
        "the server's own view of briefcred's connection must be an encrypted one"
    );
}

#[tokio::test]
async fn verify_full_refuses_a_self_signed_certificate_and_says_why() {
    let Some(fixture) = start(
        "verify_full_refuses_a_self_signed_certificate_and_says_why",
        "verify-full",
    )
    .await
    else {
        return;
    };

    let output = upstream_is_encrypted(&fixture.database_url).await;
    assert!(
        !output.status.success(),
        "verify-full must not connect to a self-signed server: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    // The client is told only that the database could not be reached; the
    // reason is the daemon's, because it is about a master this client has
    // never held.
    let log = fixture.daemon.log();
    assert!(
        log.contains("TLS handshake"),
        "the daemon's log must name the handshake failure:\n{log}"
    );
}

#[tokio::test]
async fn disable_still_connects_over_plaintext_to_a_tls_capable_server() {
    let Some(fixture) = start(
        "disable_still_connects_over_plaintext_to_a_tls_capable_server",
        "disable",
    )
    .await
    else {
        return;
    };

    let output = upstream_is_encrypted(&fixture.database_url).await;
    assert!(
        output.status.success(),
        "psql failed: {}\n{}",
        String::from_utf8_lossy(&output.stderr),
        fixture.daemon.log()
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "f",
        "`disable` must mean no TLS, even against a server offering it"
    );
}

#[tokio::test]
async fn require_refuses_a_server_that_will_not_speak_tls() {
    // The same profile, against a cluster with `ssl = off`: the server answers
    // the `SSLRequest` with `N`, and briefcred does not fall back.
    let test = "require_refuses_a_server_that_will_not_speak_tls";
    let Some(cluster) = cluster_or_skip_with_tls(test, false).await else {
        return;
    };

    let daemon = Daemon::prepare(
        "metrics_enabled = false\nmetrics_port = 0\nproxy_port = 0\npg_proxy_port = 0\n\
         master_source = \"file\"\n[ca]\nkeystore = \"file\"\n",
    );
    daemon.write_profile("warehouse", &profile(cluster.port(), "require"));
    daemon.write_master(CREDENTIAL, &cluster.master_password());
    let mut daemon = daemon;
    daemon.start().await.unwrap_or_else(|e| panic!("{e}"));

    let Response::SessionOpened { session_id, .. } = daemon
        .request(Request::OpenSession {
            profile: "warehouse".to_string(),
            client_headless: true,
            session_pubkey: None,
        })
        .await
        .unwrap()
    else {
        panic!("the session did not open:\n{}", daemon.log());
    };
    let Response::Minted { env, .. } = daemon
        .request(Request::Exec {
            session_id,
            credentials: None,
            argv0: "psql".to_string(),
            args: Vec::new(),
            pid: std::process::id(),
        })
        .await
        .unwrap()
    else {
        panic!("nothing was minted:\n{}", daemon.log());
    };

    let output = upstream_is_encrypted(env["DATABASE_URL"].expose()).await;
    assert!(
        !output.status.success(),
        "a server that refuses TLS must not be fallen back to in plaintext"
    );
    let log = daemon.log();
    assert!(
        log.contains("refused TLS"),
        "the daemon's log must say the server refused TLS:\n{log}"
    );
}
