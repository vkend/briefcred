//! The Postgres proxy, end to end, against a real daemon and a real PostgreSQL.
//!
//! Everything here runs against the actual `briefcred-daemon` binary and an
//! ephemeral PostgreSQL 14 cluster configured for `scram-sha-256`, so the
//! daemon really does have to perform a SCRAM exchange with the master password
//! before anything is relayed.
//!
//! What is being proved is the thing that cannot be proved anywhere else: that
//! a subprocess holding only a synthetic token reaches the database as the
//! **real** master role, that the master password never crosses the wire, and
//! that a token which does not authorise the connection is refused before a
//! single byte reaches the server.
//!
//! Every upstream connection goes through a **tap** — a counting splice in this
//! test process, sitting between the daemon and the cluster. It is what turns
//! "the request was refused" into "the request was refused *and nothing reached
//! the database*", which is the claim that actually matters.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use briefcred_e2e::daemon_harness::{wait_until, Daemon};
use briefcred_e2e::pg_harness::{cluster_or_skip, PgCluster, MASTER_USER};
use briefcred_proto::{Request, Response};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The database the profile authorises. `postgres` is what `initdb` makes.
const DBNAME: &str = "postgres";

/// The credential's name inside the profile.
const CREDENTIAL: &str = "warehouse";

// ------------------------------------------------------------------- the tap

/// A counting splice between the daemon and the real cluster.
///
/// Two jobs. It counts connections, so a test can assert that a refused client
/// caused none; and it keeps the first few kibibytes the daemon sent upstream,
/// so a test can assert the master password was never among them.
struct Tap {
    port: u16,
    connections: Arc<AtomicUsize>,
    sent_upstream: Arc<Mutex<Vec<u8>>>,
    accepting: tokio::task::JoinHandle<()>,
}

/// How much of each connection's client-to-server traffic the tap keeps.
///
/// Enough to cover the startup packet and the whole authentication exchange,
/// which is where a password would be if one were ever sent in the clear.
const TAP_CAPTURE: usize = 8 * 1024;

async fn start_tap(upstream_port: u16) -> Tap {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let sent_upstream = Arc::new(Mutex::new(Vec::new()));

    let counted = Arc::clone(&connections);
    let captured = Arc::clone(&sent_upstream);
    let accepting = tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            counted.fetch_add(1, Ordering::SeqCst);
            let captured = Arc::clone(&captured);
            tokio::spawn(async move {
                let Ok(server) = tokio::net::TcpStream::connect(("127.0.0.1", upstream_port)).await
                else {
                    return;
                };
                let (mut client_read, mut client_write) = client.into_split();
                let (mut server_read, mut server_write) = server.into_split();
                let upward = async move {
                    let mut buffer = vec![0u8; 8192];
                    while let Ok(read) = client_read.read(&mut buffer).await {
                        if read == 0 || server_write.write_all(&buffer[..read]).await.is_err() {
                            break;
                        }
                        let mut seen = captured.lock().unwrap();
                        let room = TAP_CAPTURE.saturating_sub(seen.len());
                        seen.extend_from_slice(&buffer[..read.min(room)]);
                    }
                    let _ = server_write.shutdown().await;
                };
                let downward = async move {
                    let _ = tokio::io::copy(&mut server_read, &mut client_write).await;
                    let _ = client_write.shutdown().await;
                };
                tokio::join!(upward, downward);
            });
        }
    });

    Tap {
        port,
        connections,
        sent_upstream,
        accepting,
    }
}

impl Tap {
    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

// --------------------------------------------------------------- the fixture

/// A cluster, a tap, a daemon, an open session, and a minted connection string.
struct Fixture {
    daemon: Daemon,
    tap: Tap,
    session_id: String,
    database_url: String,
    token: String,
    /// Kept alive for the length of the test; dropping it stops the cluster.
    _cluster: PgCluster,
}

fn profile(tap_port: u16) -> String {
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
      port: {tap_port}
      dbname: {DBNAME}
      user: {MASTER_USER}
env:
  DATABASE_URL: ${{minted.{CREDENTIAL}.DATABASE_URL}}
  PGPASSWORD: ${{minted.{CREDENTIAL}.PGPASSWORD}}
"
    )
}

/// Start everything, or return `None` when there is no PostgreSQL to test with.
async fn start(test: &str) -> Option<Fixture> {
    let cluster = cluster_or_skip(test).await?;
    let tap = start_tap(cluster.port()).await;

    // The port overrides are spelled out rather than left to the harness,
    // which appends them — and would append them into the `[ca]` table.
    let daemon = Daemon::prepare(
        "metrics_enabled = false\nmetrics_port = 0\nproxy_port = 0\npg_proxy_port = 0\n\
         master_source = \"file\"\n[ca]\nkeystore = \"file\"\n",
    );
    daemon.write_profile("warehouse", &profile(tap.port));
    // The master is the cluster's superuser password, and nothing else: the
    // role is named in the credential's `config`, so having it here too would
    // be a way for the two to disagree.
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

    let Response::Minted { mints, env, .. } = daemon
        .request(Request::Exec {
            session_id: session_id.clone(),
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

    let database_url = env["DATABASE_URL"].expose().to_string();
    let token = mints[0].fields["PGPASSWORD"].expose().to_string();
    assert!(
        token.starts_with("bc."),
        "the password handed to the subprocess must be a synthetic token"
    );
    assert!(
        !database_url.contains(&*cluster.master_password()),
        "the connection string must not carry the master password"
    );

    Some(Fixture {
        daemon,
        tap,
        session_id,
        database_url,
        token,
        _cluster: cluster,
    })
}

impl Fixture {
    /// Where the daemon's Postgres proxy is listening.
    async fn proxy_addr(&self) -> String {
        let Response::Status { pg_proxy_addr, .. } =
            self.daemon.request(Request::Status).await.unwrap()
        else {
            panic!("expected a status");
        };
        pg_proxy_addr.expect("the postgres proxy is enabled")
    }

    /// Connect through the proxy as a driver would, with an explicit password.
    ///
    /// `tokio-postgres` rather than `psql` for the refusal tests, because it
    /// surfaces the server's SQLSTATE and `psql` prints only the message.
    async fn connect(&self, user: &str, password: &str, dbname: &str) -> tokio_postgres::Error {
        let address = self.proxy_addr().await;
        let (host, port) = address.rsplit_once(':').expect("host:port");
        let mut config = tokio_postgres::Config::new();
        config
            .host(host)
            .port(port.parse().unwrap())
            .dbname(dbname)
            .user(user)
            .password(password)
            .ssl_mode(tokio_postgres::config::SslMode::Disable);
        config
            .connect(tokio_postgres::NoTls)
            .await
            .err()
            .expect("this connection was supposed to be refused")
    }
}

/// Run `psql` with a connection string and collect its output.
///
/// Spawned through `tokio::process` rather than `std::process`, and that is not
/// a stylistic choice: the tap is a task on this test's own runtime, so a
/// blocking `Command::output` would stop it being polled and the daemon's
/// connection to it would hang until `psql` gave up.
async fn psql(database_url: &str, sql: &str) -> std::process::Output {
    let psql = briefcred_e2e::pg_harness::find_pg_bin()
        .expect("a PostgreSQL installation, since the cluster started")
        .join("psql");
    tokio::process::Command::new(psql)
        // `-t` drops the header, `-A` drops the column alignment: what comes
        // back is the value and a newline, which is what a test can assert on.
        .args(["-tAc", sql, database_url])
        .env("PGCONNECT_TIMEOUT", "10")
        .output()
        .await
        .expect("psql runs")
}

// -------------------------------------------------------------------- the tests

#[tokio::test]
async fn psql_with_the_synthetic_dsn_connects_as_the_real_master_role() {
    let Some(fixture) = start("psql_with_the_synthetic_dsn_connects_as_the_real_master_role").await
    else {
        return;
    };

    let output = psql(&fixture.database_url, "SELECT current_user").await;
    assert!(
        output.status.success(),
        "psql failed: {}\n{}",
        String::from_utf8_lossy(&output.stderr),
        fixture.daemon.log()
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        MASTER_USER,
        "the subprocess held only a token and still arrived as the master role"
    );
    assert_eq!(
        fixture.tap.connections(),
        1,
        "exactly one upstream connection was opened"
    );
}

#[tokio::test]
async fn the_master_password_never_crosses_the_wire() {
    let Some(fixture) = start("the_master_password_never_crosses_the_wire").await else {
        return;
    };
    let output = psql(&fixture.database_url, "SELECT 1").await;
    assert!(output.status.success(), "{}", fixture.daemon.log());

    // Everything the daemon sent upstream during the startup and SCRAM
    // exchange. A password in the clear would be in here.
    let sent = fixture.tap.sent_upstream.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&sent).to_string();
    assert!(
        !text.contains(&*fixture._cluster.master_password()),
        "the master password went upstream in the clear"
    );
    assert!(
        text.contains("SCRAM-SHA-256"),
        "the upstream exchange was not SCRAM: {text:?}"
    );
    assert!(
        !text.contains(&fixture.token),
        "the synthetic token has no business reaching the database"
    );
}

#[tokio::test]
async fn a_wrong_token_is_refused_and_never_reaches_the_database() {
    let Some(fixture) = start("a_wrong_token_is_refused_and_never_reaches_the_database").await
    else {
        return;
    };

    // Well formed enough to be a token, signed by nobody.
    let forged = format!("{}X", fixture.token);
    let err = fixture.connect(&fixture.session_id, &forged, DBNAME).await;

    assert_eq!(
        err.code(),
        Some(&tokio_postgres::error::SqlState::INVALID_AUTHORIZATION_SPECIFICATION),
        "a refusal must be a proper 28000 ErrorResponse, not a dropped socket: {err}"
    );
    assert_eq!(
        fixture.tap.connections(),
        0,
        "a token that does not authorise must not open an upstream connection"
    );
}

#[tokio::test]
async fn a_token_presented_as_another_user_is_refused() {
    let Some(fixture) = start("a_token_presented_as_another_user_is_refused").await else {
        return;
    };
    // The right token, but the startup packet claims a different session.
    let err = fixture
        .connect("0000000000000000", &fixture.token, DBNAME)
        .await;
    assert_eq!(
        err.code(),
        Some(&tokio_postgres::error::SqlState::INVALID_AUTHORIZATION_SPECIFICATION),
        "{err}"
    );
    assert_eq!(fixture.tap.connections(), 0);
}

#[tokio::test]
async fn a_token_for_one_database_cannot_open_another() {
    let Some(fixture) = start("a_token_for_one_database_cannot_open_another").await else {
        return;
    };
    // The right token and the right session, for a database the credential
    // does not name. `template1` exists in every cluster, so the refusal is
    // briefcred's rather than the server's.
    let err = fixture
        .connect(&fixture.session_id, &fixture.token, "template1")
        .await;
    assert_eq!(
        err.code(),
        Some(&tokio_postgres::error::SqlState::INVALID_AUTHORIZATION_SPECIFICATION),
        "{err}"
    );
    assert_eq!(fixture.tap.connections(), 0);
}

#[tokio::test]
async fn the_audit_row_records_the_connection_and_never_a_credential() {
    let Some(fixture) = start("the_audit_row_records_the_connection_and_never_a_credential").await
    else {
        return;
    };
    let output = psql(&fixture.database_url, "SELECT repeat('x', 4096)").await;
    assert!(output.status.success(), "{}", fixture.daemon.log());

    // The audit writer is a task of its own, and the row is written when the
    // connection closes, which is after `psql` has already exited.
    let written = wait_until(Duration::from_secs(10), || async {
        fixture
            .daemon
            .audit_rows()
            .iter()
            .any(|row| row["event"] == "pg_connection")
    })
    .await;
    assert!(written, "no pg_connection row:\n{}", fixture.daemon.log());

    let rows = fixture.daemon.audit_rows();
    let row = rows.iter().find(|r| r["event"] == "pg_connection").unwrap();
    assert_eq!(row["master_user"], MASTER_USER);
    assert!(row["mint_id"].as_str().unwrap().starts_with("briefcred_t_"));
    assert!(
        row["client_bytes"].as_u64().unwrap() > 0,
        "the client sent a query: {row}"
    );
    assert!(
        row["server_bytes"].as_u64().unwrap() > 4096,
        "the server sent four kibibytes back: {row}"
    );
    assert!(
        row["started"].is_string() && row["ended"].is_string(),
        "{row}"
    );

    let whole = serde_json::to_string(&rows).unwrap();
    assert!(
        !whole.contains(&*fixture._cluster.master_password()),
        "the audit log holds the master password"
    );
    assert!(
        !whole.contains("bc."),
        "the audit log holds a synthetic token"
    );
    assert!(
        !whole.contains("repeat("),
        "the audit log holds a statement the proxy never parsed"
    );
}

#[tokio::test]
async fn a_revoked_grant_stops_opening_connections() {
    let Some(fixture) = start("a_revoked_grant_stops_opening_connections").await else {
        return;
    };
    assert!(psql(&fixture.database_url, "SELECT 1")
        .await
        .status
        .success());

    // What `briefcred exec` sends when the child exits.
    let mint_ids: Vec<String> = fixture
        .daemon
        .audit_rows()
        .iter()
        .filter(|row| row["event"] == "mint")
        .filter_map(|row| row["mint_id"].as_str().map(str::to_string))
        .collect();
    fixture
        .daemon
        .request(Request::ExecDone {
            session_id: fixture.session_id.clone(),
            mint_ids,
            exit_code: Some(0),
            duration_ms: 1,
            hold_until_expiry: false,
        })
        .await
        .unwrap();

    let refused = wait_until(Duration::from_secs(10), || async {
        !psql(&fixture.database_url, "SELECT 1")
            .await
            .status
            .success()
    })
    .await;
    assert!(
        refused,
        "a revoked grant must stop opening connections:\n{}",
        fixture.daemon.log()
    );
}
