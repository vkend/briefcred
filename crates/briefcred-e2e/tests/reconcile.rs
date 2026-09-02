//! The reconciler, against a real cluster and a real daemon that gets killed.
//!
//! This is the test the whole reconciliation design exists for. Every other
//! path to revoking a credential — the queue, the session close, the shutdown
//! sweep — needs the daemon to still be alive. `SIGKILL` is the case where none
//! of them run, and the only thing left that knows the credential exists is the
//! database.
//!
//! So: mint a role, kill the daemon mid-run, prove the role survived, start a
//! new daemon, and prove the startup sweep removed it.

use std::time::Duration;

use briefcred_e2e::daemon_harness::{wait_until, Daemon};
use briefcred_e2e::pg_harness::{cluster_or_skip, PgCluster, DBNAME, LIMITED_USER};
use briefcred_proto::{Request, Response};

/// A short reconcile interval so a test does not wait five minutes, and a
/// one-second TTL so a minted role is stale almost immediately.
fn daemon_toml() -> String {
    "master_source = \"file\"\n\
     metrics_enabled = false\n\
     reconcile_interval_secs = 2\n"
        .to_string()
}

fn profile_yaml(cluster: &PgCluster) -> String {
    format!(
        "\
name: db-ro
unlock:
  policy: none
credentials:
  - name: db
    kind: postgres-dynamic
    ttl_secs: 1
    config:
      host: 127.0.0.1
      port: {port}
      dbname: {DBNAME}
      user: {LIMITED_USER}
      sslmode: disable
      role_template:
        grants:
          - privileges: [SELECT]
            on: ALL TABLES IN SCHEMA public
exec:
  allow_argv0: [true]
env:
  PGUSER: ${{minted.db.PGUSER}}
  PGPASSWORD: ${{minted.db.PGPASSWORD}}
",
        port = cluster.port()
    )
}

/// Lay out a home pointed at `cluster`, with the master already in place.
fn home_for(cluster: &PgCluster) -> Daemon {
    let daemon = Daemon::prepare(&daemon_toml());
    daemon.write_profile("db-ro", &profile_yaml(cluster));
    daemon.write_master("db", &cluster.limited_password());
    daemon
}

/// Mint one credential and return the role it created, leaving it un-revoked.
async fn mint_and_abandon(daemon: &Daemon) -> String {
    let mut client = daemon.connect().await.expect("connect");
    let session_id = match client
        .send(Request::OpenSession {
            profile: "db-ro".into(),
            client_headless: true,
        })
        .await
        .expect("open session")
    {
        Response::SessionOpened { session_id, .. } => session_id,
        other => panic!("expected a session, got {other:?}\n{}", daemon.log()),
    };

    let minted = client
        .send(Request::Exec {
            session_id,
            credentials: None,
            argv0: "true".into(),
            args: Vec::new(),
            pid: std::process::id(),
        })
        .await
        .expect("exec");

    match minted {
        Response::Minted { mints, .. } => {
            assert_eq!(mints.len(), 1, "{mints:?}");
            mints[0].mint_id.clone()
        }
        other => panic!("expected a mint, got {other:?}\n{}", daemon.log()),
    }
    // Deliberately no `ExecDone` and no `CloseSession`: this is the wrapper
    // that never got to report back.
}

async fn role_exists(cluster: &PgCluster, role: &str) -> bool {
    cluster
        .connect_master()
        .await
        .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&role])
        .await
        .expect("query pg_roles")
        .is_some()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_role_stranded_by_a_sigkill_is_cleaned_up_by_the_next_reconcile() {
    let Some(cluster) = cluster_or_skip("reconcile after SIGKILL").await else {
        return;
    };

    let mut daemon = home_for(&cluster);
    if let Err(why) = daemon.start().await {
        panic!("{why}");
    }

    let role = mint_and_abandon(&daemon).await;
    assert!(
        role_exists(&cluster, &role).await,
        "the mint must have created a real role"
    );

    // The kill that makes this test worth having: no signal handler runs, the
    // revoke queue is never drained, and the session is never closed.
    daemon.sigkill();
    assert!(
        role_exists(&cluster, &role).await,
        "a killed daemon revokes nothing; that is the premise"
    );

    // The role's `VALID UNTIL` is one second out, and the sweep only takes
    // roles that have passed it — otherwise it would be racing live execs.
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    let mut restarted = daemon;
    if let Err(why) = restarted.start().await {
        panic!("{why}");
    }
    let cleaned = wait_until(Duration::from_secs(20), || async {
        !role_exists(&cluster, &role).await
    })
    .await;
    assert!(
        cleaned,
        "the startup sweep must remove the stranded role\n{}",
        restarted.log()
    );

    // And it is on the record: an operator has to be able to see that a
    // credential was cleaned up by reconciliation rather than by its owner.
    let rows = restarted.audit_rows();
    assert!(
        rows.iter().any(|row| row["event"] == "revoke"
            && row["mint_id"] == role.as_str()
            && row["outcome"] == "revoked"),
        "no revoke row for {role} in {rows:#?}"
    );
    assert!(
        rows.iter().any(|row| row["event"] == "reconcile"
            && row["profile"] == "db-ro"
            && row["revoked"].as_u64().unwrap_or_default() >= 1),
        "no reconcile row in {rows:#?}"
    );

    restarted.shutdown().await;
    assert_eq!(
        cluster.leaked_role_count().await,
        0,
        "the cluster must be left exactly as it was found"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_normal_exec_revokes_through_the_queue_without_the_reconciler() {
    let Some(cluster) = cluster_or_skip("exec revokes through the queue").await else {
        return;
    };

    // A reconcile interval far longer than the test, so anything cleaned up
    // here was cleaned up by the queue.
    let mut daemon = Daemon::prepare(
        "master_source = \"file\"\nmetrics_enabled = false\nreconcile_interval_secs = 3600\n",
    );
    daemon.write_profile("db-ro", &profile_yaml(&cluster));
    daemon.write_master("db", &cluster.limited_password());
    if let Err(why) = daemon.start().await {
        panic!("{why}");
    }

    let mut client = daemon.connect().await.expect("connect");
    let Response::SessionOpened { session_id, .. } = client
        .send(Request::OpenSession {
            profile: "db-ro".into(),
            client_headless: true,
        })
        .await
        .expect("open session")
    else {
        panic!("expected a session\n{}", daemon.log());
    };

    let Response::Minted { mints, env, .. } = client
        .send(Request::Exec {
            session_id: session_id.clone(),
            credentials: None,
            argv0: "true".into(),
            args: Vec::new(),
            pid: std::process::id(),
        })
        .await
        .expect("exec")
    else {
        panic!("expected a mint\n{}", daemon.log());
    };
    let role = mints[0].mint_id.clone();

    // The minted credential really works: without this the test would pass
    // just as well if the daemon had returned a made-up role name.
    let password = env
        .get("PGPASSWORD")
        .expect("the profile's env sets PGPASSWORD")
        .expose()
        .to_string();
    cluster
        .connect_as(&role, &password)
        .await
        .expect("the minted role must be able to log in");

    client
        .send(Request::ExecDone {
            session_id: session_id.clone(),
            mint_ids: vec![role.clone()],
            exit_code: Some(0),
            duration_ms: 5,
        })
        .await
        .expect("exec done");

    let revoked = wait_until(Duration::from_secs(20), || async {
        !role_exists(&cluster, &role).await
    })
    .await;
    assert!(
        revoked,
        "the queue must revoke the role without the reconciler\n{}",
        daemon.log()
    );

    daemon.shutdown().await;
    assert_eq!(cluster.leaked_role_count().await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_closed_without_an_exec_done_still_revokes_what_it_minted() {
    let Some(cluster) = cluster_or_skip("session close revokes orphans").await else {
        return;
    };

    let mut daemon = Daemon::prepare(
        "master_source = \"file\"\nmetrics_enabled = false\nreconcile_interval_secs = 3600\n",
    );
    daemon.write_profile("db-ro", &profile_yaml(&cluster));
    daemon.write_master("db", &cluster.limited_password());
    if let Err(why) = daemon.start().await {
        panic!("{why}");
    }

    let mut client = daemon.connect().await.expect("connect");
    let Response::SessionOpened { session_id, .. } = client
        .send(Request::OpenSession {
            profile: "db-ro".into(),
            client_headless: true,
        })
        .await
        .expect("open session")
    else {
        panic!("expected a session\n{}", daemon.log());
    };
    let Response::Minted { mints, .. } = client
        .send(Request::Exec {
            session_id: session_id.clone(),
            credentials: None,
            argv0: "true".into(),
            args: Vec::new(),
            pid: std::process::id(),
        })
        .await
        .expect("exec")
    else {
        panic!("expected a mint\n{}", daemon.log());
    };
    let role = mints[0].mint_id.clone();

    // Closing without reporting: the wrapper died, or the user hit ctrl-C
    // between the mint and the child exiting.
    client
        .send(Request::CloseSession { session_id })
        .await
        .expect("close");

    let revoked = wait_until(Duration::from_secs(20), || async {
        !role_exists(&cluster, &role).await
    })
    .await;
    assert!(
        revoked,
        "closing a session must sweep up what it minted\n{}",
        daemon.log()
    );

    daemon.shutdown().await;
    assert_eq!(cluster.leaked_role_count().await, 0);
}
