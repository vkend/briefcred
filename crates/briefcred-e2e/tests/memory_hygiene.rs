//! Is the master credential really gone from the daemon after a session ends?
//!
//! briefcred's central claim about the daemon is that a master lives for the
//! length of the session that needed it and no longer. Everything else — the
//! `Zeroizing` wrappers, the hand-written `Debug` impls, dropping the session
//! rather than flagging it closed — is machinery in service of that claim.
//! This test checks the claim itself.
//!
//! # How it works, and what it cannot prove
//!
//! The daemon is built with `debug-heapscan`, which adds a request that makes
//! it scan its own address space for a 32-byte marker. The test uses that
//! marker as the master credential, so:
//!
//! - after opening a session, the daemon **must** hold it — if it does not,
//!   the scan is not working and a later "absent" answer means nothing;
//! - after closing the session, it must not.
//!
//! What this cannot prove is that no copy escaped to swap, to a core file, or
//! to a page the allocator has since handed to something else and not yet
//! overwritten. It proves the much narrower thing that is still worth proving:
//! the daemon does not keep a live copy after the session is closed.
//!
//! Ignored by default and run by `just mem-hygiene`, because it needs a daemon
//! built with a feature no shipping daemon has, and because the scan takes
//! seconds.

#![cfg(all(target_os = "macos", feature = "debug-heapscan"))]

use std::time::Duration;

use briefcred_e2e::daemon_harness::Daemon;
use briefcred_proto::{Request, Response};

/// The environment variable that opts a run into this test.
const OPT_IN: &str = "BRIEFCRED_MEM_HYGIENE";

/// A 32-byte marker, drawn fresh so no earlier run's value is resident.
fn marker() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable");
    // Hex, so it is a valid UTF-8 master credential, and exactly 32 bytes.
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest(value: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(value.as_bytes()))
}

async fn heap_scan(daemon: &Daemon, needle_sha256: &str) -> (bool, usize) {
    match daemon
        .request(Request::HeapScan {
            needle_sha256: needle_sha256.to_string(),
        })
        .await
        .expect("heap scan")
    {
        Response::HeapScanned {
            present,
            regions_scanned,
            ..
        } => (present, regions_scanned),
        other => panic!("expected a scan result, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a daemon built with --features debug-heapscan; run `just mem-hygiene`"]
async fn a_master_is_gone_from_the_daemon_once_its_session_is_closed() {
    if std::env::var(OPT_IN).as_deref() != Ok("1") {
        println!("skipping: set {OPT_IN}=1 to run the memory-hygiene check");
        return;
    }

    let master = marker();
    assert_eq!(master.len(), 32, "the scan looks for exactly 32 bytes");
    let needle = digest(&master);

    // No credentials: this test is about the *master*, and minting one would
    // need a database. The session still fetches the master, which is the
    // whole path under test.
    let mut daemon = Daemon::prepare("master_source = \"file\"\nmetrics_enabled = false\n");
    daemon.write_profile(
        "marked",
        "name: marked\nunlock:\n  policy: none\ncredentials:\n  - name: db\n    kind: postgres-dynamic\n    config:\n      host: 127.0.0.1\n      dbname: app\n      user: m\n      sslmode: disable\n      role_template: {}\n",
    );
    daemon.write_master("db", &master);

    if let Err(why) = daemon.start().await {
        println!("skipping: {why}");
        return;
    }

    // The control. A scan that cannot find a master the daemon is definitely
    // holding would report "absent" for every reason except the right one, and
    // the assertion below would be worthless.
    let session_id = match daemon
        .request(Request::OpenSession {
            profile: "marked".into(),
            client_headless: true,
        })
        .await
        .expect("open session")
    {
        Response::SessionOpened { session_id, .. } => session_id,
        other => panic!("expected a session, got {other:?}\n{}", daemon.log()),
    };

    let (present, regions) = heap_scan(&daemon, &needle).await;
    assert!(regions > 0, "the scan examined nothing");
    assert!(
        present,
        "the daemon must hold the master while the session is open, or this test proves nothing"
    );

    daemon
        .request(Request::CloseSession { session_id })
        .await
        .expect("close session");
    // The close drops the session synchronously, but the allocator may not have
    // returned the page yet. A short wait costs nothing and removes a source of
    // flake that has nothing to do with the property under test.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (still_present, _) = heap_scan(&daemon, &needle).await;
    assert!(
        !still_present,
        "the master is still in the daemon's memory after its session was closed\n{}",
        daemon.log()
    );

    daemon.shutdown().await;
}
