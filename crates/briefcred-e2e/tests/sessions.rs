//! Many sessions of one profile at once, against a real daemon.
//!
//! The claim under test is isolation. A profile is a shared document and the
//! daemon is a shared process, but a *session* is not shared: it owns its own
//! masters, its own mints, its own quota bucket and its own counters, and two
//! agents running the same profile at the same time must not be able to see or
//! spend each other's. Everything below is a way of asking "did any of the
//! twenty get another one's credential".
//!
//! Twenty is chosen to be more than the number of runtime worker threads on a
//! developer's machine, so the requests genuinely interleave rather than being
//! serialised by the executor.

use std::collections::BTreeSet;
use std::time::Duration;

use briefcred_e2e::daemon_harness::{wait_until, Daemon};
use briefcred_proto::{Request, Response};

/// How many sessions run at once.
const CONCURRENCY: usize = 20;

/// A profile whose credential is minted by the daemon itself.
///
/// `http-bearer`, deliberately: it needs no database, no helper subprocess and
/// no network, so what the test measures is the daemon's own session
/// bookkeeping rather than twenty round trips to PostgreSQL.
const PROFILE: &str = "\
name: agents
unlock:
  policy: none
credentials:
  - name: openai
    kind: http-bearer
    ttl_secs: 300
env:
  OPENAI_API_KEY: ${minted.openai.TOKEN}
";

/// The real credential every session's token stands in for.
const REAL_KEY: &str = "sk-the-one-shared-master";

async fn start() -> Daemon {
    let mut daemon = Daemon::prepare(
        "master_source = \"file\"\nproxy_enabled = true\n[ca]\nkeystore = \"file\"\n",
    );
    daemon.write_profile("agents", PROFILE);
    daemon.write_master("openai", REAL_KEY);
    daemon.start().await.unwrap_or_else(|e| panic!("{e}"));
    daemon
}

/// One session's whole life: open, mint, report, close.
struct Run {
    session_id: String,
    mint_id: String,
    token: String,
}

async fn run_one(daemon: &Daemon) -> Run {
    // One connection for the whole run, exactly as `briefcred exec` does: the
    // daemon notices a dead wrapper by the socket closing, so a connection per
    // request would be a different thing under test.
    let mut client = daemon.connect().await.expect("connect");

    let Response::SessionOpened { session_id, .. } = client
        .send(Request::OpenSession {
            profile: "agents".to_string(),
            client_headless: true,
            session_pubkey: None,
        })
        .await
        .expect("open")
    else {
        panic!("the session did not open");
    };

    let Response::Minted { mints, env, .. } = client
        .send(Request::Exec {
            session_id: session_id.clone(),
            credentials: None,
            argv0: "curl".to_string(),
            args: Vec::new(),
            pid: std::process::id(),
        })
        .await
        .expect("exec")
    else {
        panic!("nothing was minted for session {session_id}");
    };

    let mint_id = mints[0].mint_id.clone();
    let token = mints[0].fields["TOKEN"].expose().to_string();
    assert_eq!(
        env["OPENAI_API_KEY"].expose(),
        token,
        "every session's environment must carry its own token"
    );

    let Response::ExecRecorded { queued } = client
        .send(Request::ExecDone {
            session_id: session_id.clone(),
            mint_ids: vec![mint_id.clone()],
            exit_code: Some(0),
            duration_ms: 1,
            hold_until_expiry: false,
        })
        .await
        .expect("exec_done")
    else {
        panic!("the run was not recorded");
    };
    assert_eq!(queued, 1, "each session queues exactly its own revoke");

    client
        .send(Request::CloseSession {
            session_id: session_id.clone(),
        })
        .await
        .expect("close");

    Run {
        session_id,
        mint_id,
        token,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn twenty_concurrent_sessions_of_one_profile_each_get_their_own_credential() {
    let daemon = start().await;

    let runs: Vec<Run> =
        futures_util::future::join_all((0..CONCURRENCY).map(|_| run_one(&daemon))).await;

    let sessions: BTreeSet<&str> = runs.iter().map(|run| run.session_id.as_str()).collect();
    let mints: BTreeSet<&str> = runs.iter().map(|run| run.mint_id.as_str()).collect();
    let tokens: BTreeSet<&str> = runs.iter().map(|run| run.token.as_str()).collect();

    assert_eq!(
        sessions.len(),
        CONCURRENCY,
        "two sessions were handed the same identifier"
    );
    assert_eq!(
        mints.len(),
        CONCURRENCY,
        "two sessions were handed the same principal:\n{}",
        daemon.log()
    );
    assert_eq!(
        tokens.len(),
        CONCURRENCY,
        "two sessions were handed the same token, so one could use the other's grant"
    );

    // Nothing is left holding a master once the twenty have finished.
    assert!(
        matches!(
            daemon.request(Request::Status).await,
            Ok(Response::Status { .. })
        ),
        "the daemon must still be serving after twenty concurrent sessions"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_one_of_the_twenty_is_revoked_and_none_of_them_twice() {
    let daemon = start().await;

    let runs: Vec<Run> =
        futures_util::future::join_all((0..CONCURRENCY).map(|_| run_one(&daemon))).await;
    let minted: BTreeSet<String> = runs.iter().map(|run| run.mint_id.clone()).collect();

    let revoked = |daemon: &Daemon| {
        daemon
            .audit_rows()
            .into_iter()
            .filter(|row| row["event"] == "revoke")
            .filter_map(|row| row["mint_id"].as_str().map(str::to_string))
            .collect::<Vec<String>>()
    };

    assert!(
        wait_until(Duration::from_secs(30), || async {
            revoked(&daemon).len() >= CONCURRENCY
        })
        .await,
        "only {} of {CONCURRENCY} revokes were written:\n{}",
        revoked(&daemon).len(),
        daemon.log()
    );

    let rows = revoked(&daemon);
    assert_eq!(
        rows.len(),
        CONCURRENCY,
        "a mint was revoked more than once: {rows:?}"
    );
    assert_eq!(
        rows.iter().cloned().collect::<BTreeSet<String>>(),
        minted,
        "the revoked principals are not the ones that were minted"
    );

    // The row every session wrote, exactly once each. A session that had
    // silently reused another's would be missing from here.
    let opened = daemon
        .audit_rows()
        .into_iter()
        .filter(|row| row["event"] == "session_open")
        .count();
    assert_eq!(opened, CONCURRENCY);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_session_closing_leaves_the_other_nineteen_working() {
    // Isolation the other way round: the shared thing is the profile and the
    // master behind it, so closing one session must not wipe a master another
    // session is still using.
    let daemon = start().await;

    let mut sessions = Vec::new();
    for _ in 0..CONCURRENCY {
        let Response::SessionOpened { session_id, .. } = daemon
            .request(Request::OpenSession {
                profile: "agents".to_string(),
                client_headless: true,
                session_pubkey: None,
            })
            .await
            .expect("open")
        else {
            panic!("the session did not open");
        };
        sessions.push(session_id);
    }

    let closed = sessions.remove(0);
    daemon
        .request(Request::CloseSession {
            session_id: closed.clone(),
        })
        .await
        .expect("close");

    for session_id in &sessions {
        let response = daemon
            .request(Request::Exec {
                session_id: session_id.clone(),
                credentials: None,
                argv0: "curl".to_string(),
                args: Vec::new(),
                pid: std::process::id(),
            })
            .await
            .expect("exec");
        assert!(
            matches!(response, Response::Minted { .. }),
            "session {session_id} broke when another session closed: {response:?}"
        );
    }

    let response = daemon
        .request(Request::Exec {
            session_id: closed,
            credentials: None,
            argv0: "curl".to_string(),
            args: Vec::new(),
            pid: std::process::id(),
        })
        .await
        .expect("exec");
    assert!(
        matches!(&response, Response::Error { message } if message.contains("no open session")),
        "a closed session must stay closed: {response:?}"
    );
}
