//! The Model Context Protocol server, through the real daemon binary.
//!
//! Everything here goes over the actual Unix socket: the test performs the
//! same `Request::Mcp` upgrade `briefcred mcp` performs, then drives the
//! connection with a real `rmcp` client. So a broken upgrade, a wrong tool
//! schema, or a tool that fails to mint all show up here, and none of them
//! could show up in a test that called the handler directly.

use std::time::Duration;

use briefcred_e2e::daemon_harness::{wait_until, Daemon};
use briefcred_e2e::pg_harness::{self, cluster_or_skip, PgCluster};
use briefcred_proto::{read_frame, write_frame, Request, Response};
use rmcp::model::CallToolRequestParams;
use rmcp::service::{RoleClient, RunningService};
use rmcp::ServiceExt;

/// A profile with no credentials, for the tools that mint nothing.
const LISTING_ONLY: &str = "\
name: listing
description: nothing to mint
unlock:
  policy: none
exec:
  allow_argv0: [\"/bin/echo\"]
";

/// Open an MCP connection to a running daemon, upgrade included.
async fn mcp_client(daemon: &Daemon) -> RunningService<RoleClient, ()> {
    let mut stream = daemon.connect().await.expect("connect").into_stream();
    write_frame(&mut stream, &Request::Mcp).await.expect("send");
    let ready = read_frame(&mut stream)
        .await
        .expect("read")
        .expect("a reply");
    assert!(
        matches!(ready, Response::McpReady { .. }),
        "the daemon must accept the upgrade: {ready:?}"
    );
    ().serve(stream).await.expect("MCP handshake")
}

/// The text of a tool result's first content block.
fn text_of(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|block| block.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("")
}

fn json_of(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    serde_json::from_str(&text_of(result)).expect("a tool result is JSON")
}

#[tokio::test]
async fn the_daemon_upgrades_a_connection_and_lists_its_tools() {
    let mut daemon = Daemon::prepare("metrics_enabled = false\nmaster_source = \"file\"\n");
    daemon.write_profile("listing", LISTING_ONLY);
    if let Err(reason) = daemon.start().await {
        panic!("{reason}");
    }

    let client = mcp_client(&daemon).await;

    let tools = client.list_all_tools().await.expect("list tools");
    let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            "briefcred_db_query",
            "briefcred_exec",
            "briefcred_list_profiles"
        ]
    );

    let listed = client
        .call_tool(CallToolRequestParams::new("briefcred_list_profiles"))
        .await
        .expect("list profiles");
    let listed = json_of(&listed);
    assert_eq!(listed["profiles"][0]["name"], "listing");
    assert_eq!(listed["profiles"][0]["unlock_policy"], "none");
    assert!(
        !text_of(
            &client
                .call_tool(CallToolRequestParams::new("briefcred_list_profiles"))
                .await
                .unwrap()
        )
        .contains("config"),
        "a profile's config block must not reach an agent"
    );

    client.cancel().await.ok();
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_command_the_profile_forbids_is_refused_without_minting() {
    let mut daemon = Daemon::prepare("metrics_enabled = false\nmaster_source = \"file\"\n");
    daemon.write_profile("listing", LISTING_ONLY);
    daemon.start().await.expect("start");
    let client = mcp_client(&daemon).await;

    let refused = client
        .call_tool(
            CallToolRequestParams::new("briefcred_exec").with_arguments(
                serde_json::json!({ "profile": "listing", "argv": ["/bin/rm", "-rf", "/"] })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await;
    let err = refused.expect_err("a forbidden command must be refused");
    assert!(err.to_string().contains("/bin/rm"), "{err}");

    // And one it does permit runs, with the profile's environment.
    let allowed = client
        .call_tool(
            CallToolRequestParams::new("briefcred_exec").with_arguments(
                serde_json::json!({ "profile": "listing", "argv": ["/bin/echo", "hello"] })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("an allowed command runs");
    let allowed = json_of(&allowed);
    assert_eq!(allowed["stdout"], "hello\n");
    assert_eq!(allowed["exit_code"], 0);
    assert_eq!(allowed["truncated"], false);

    client.cancel().await.ok();
    daemon.shutdown().await;

    // The audit log ties the call to its tool and says how it went.
    let rows = daemon.audit_rows();
    let calls: Vec<&serde_json::Value> = rows.iter().filter(|r| r["event"] == "mcp_call").collect();
    assert!(calls.len() >= 2, "{rows:#?}");
    assert!(calls.iter().all(|c| c["mcp_call_id"]
        .as_str()
        .is_some_and(|id| id.starts_with("mcp-"))));
    assert!(calls.iter().any(|c| c["outcome"] == "error"));
    assert!(calls.iter().any(|c| c["outcome"] == "ok"));
    assert!(
        !serde_json::to_string(&rows).unwrap().contains("-rf"),
        "an audit row must not carry the arguments a caller typed"
    );
    let refused = calls
        .iter()
        .find(|c| c["outcome"] == "error")
        .expect("the refusal is audited");
    assert!(
        refused["detail"]
            .as_str()
            .is_some_and(|d| d.contains("/bin/rm") && d.contains("exec policy")),
        "{refused:#?}"
    );
}

/// A profile whose `postgres-dynamic` credential points at `cluster`.
fn db_profile(cluster: &PgCluster) -> String {
    format!(
        "\
name: analytics
unlock:
  policy: none
credentials:
  - name: db
    kind: postgres-dynamic
    ttl_secs: 300
    source_key: pg-master
    config:
      host: 127.0.0.1
      port: {}
      dbname: {}
      user: {}
      sslmode: disable
      role_template:
        grants:
          - privileges: [SELECT]
            on: ALL TABLES IN SCHEMA public
exec:
  allow_argv0: [\"/bin/echo\"]
",
        cluster.port(),
        pg_harness::DBNAME,
        pg_harness::MASTER_USER,
    )
}

#[tokio::test]
async fn db_query_runs_as_a_minted_role_and_revokes_it_when_the_client_leaves() {
    let Some(cluster) = cluster_or_skip("db_query_runs_as_a_minted_role").await else {
        return;
    };
    let setup = cluster.connect_master().await;
    setup
        .batch_execute(
            "CREATE TABLE reports (id int primary key, title text, ok boolean, seen timestamptz);\
             INSERT INTO reports VALUES (1, 'first', true, '2026-01-01T00:00:00Z'), (2, NULL, false, NULL);",
        )
        .await
        .expect("fixture table");

    let mut daemon = Daemon::prepare("metrics_enabled = false\nmaster_source = \"file\"\n");
    daemon.write_profile("analytics", &db_profile(&cluster));
    daemon.write_master("pg-master", &cluster.master_password());
    daemon.start().await.expect("start");
    let client = mcp_client(&daemon).await;

    let result = client
        .call_tool(
            CallToolRequestParams::new("briefcred_db_query").with_arguments(
                serde_json::json!({
                    "profile": "analytics",
                    "sql": "SELECT id, title, ok, seen FROM reports ORDER BY id",
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await
        .expect("the query runs");
    let result = json_of(&result);

    assert_eq!(result["row_count"], 2);
    assert_eq!(result["truncated"], false);
    assert_eq!(result["rows"][0]["id"], 1);
    assert_eq!(result["rows"][0]["title"], "first");
    assert_eq!(result["rows"][0]["ok"], true);
    assert!(result["rows"][0]["seen"]
        .as_str()
        .unwrap()
        .contains("2026-01-01"));
    assert_eq!(result["rows"][1]["title"], serde_json::Value::Null);
    let columns: Vec<&str> = result["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(columns, vec!["id", "title", "ok", "seen"]);

    // No credential came back, only rows.
    let text = text_of(
        &client
            .call_tool(
                CallToolRequestParams::new("briefcred_db_query").with_arguments(
                    serde_json::json!({ "profile": "analytics", "sql": "SELECT 1 AS one" })
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .unwrap(),
    );
    assert!(!text.contains("PGPASSWORD"), "{text}");
    assert!(
        !text.contains(cluster.master_password().as_str()),
        "the master must never reach an agent"
    );

    // `max_rows` bounds what comes back, and says that it did.
    let capped = json_of(
        &client
            .call_tool(
                CallToolRequestParams::new("briefcred_db_query").with_arguments(
                    serde_json::json!({
                        "profile": "analytics",
                        "sql": "SELECT id FROM reports ORDER BY id",
                        "max_rows": 1,
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                ),
            )
            .await
            .unwrap(),
    );
    assert_eq!(capped["row_count"], 1);
    assert_eq!(capped["truncated"], true);

    // One mint for the whole connection, however many calls it made.
    assert_eq!(
        cluster.leaked_role_count().await,
        1,
        "one MCP connection mints once"
    );

    // A profile the connection is not bound to is refused rather than opening
    // a second session.
    daemon.write_profile("listing", LISTING_ONLY);
    let bound = wait_until(Duration::from_secs(5), || async {
        client
            .call_tool(
                CallToolRequestParams::new("briefcred_exec").with_arguments(
                    serde_json::json!({ "profile": "listing", "argv": ["/bin/echo", "hi"] })
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .is_err()
    })
    .await;
    assert!(
        bound,
        "a second profile must be refused on the same connection"
    );

    // Closing the connection revokes what it minted.
    client.cancel().await.ok();
    let cleaned = wait_until(Duration::from_secs(20), || async {
        cluster.leaked_role_count().await == 0
    })
    .await;
    assert!(
        cleaned,
        "the minted role outlived the MCP connection\n{}",
        daemon.log()
    );

    daemon.shutdown().await;
}

#[tokio::test]
async fn a_bad_statement_reports_the_databases_own_complaint() {
    let Some(cluster) = cluster_or_skip("a_bad_statement_reports").await else {
        return;
    };
    let mut daemon = Daemon::prepare("metrics_enabled = false\nmaster_source = \"file\"\n");
    daemon.write_profile("analytics", &db_profile(&cluster));
    daemon.write_master("pg-master", &cluster.master_password());
    daemon.start().await.expect("start");
    let client = mcp_client(&daemon).await;

    let err = client
        .call_tool(
            CallToolRequestParams::new("briefcred_db_query").with_arguments(
                serde_json::json!({ "profile": "analytics", "sql": "SELECT * FROM no_such_table" })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect_err("a bad statement must fail");
    let text = err.to_string();
    assert!(
        text.contains("42P01"),
        "the SQLSTATE belongs in the message: {text}"
    );
    assert!(text.contains("no_such_table"), "{text}");

    client.cancel().await.ok();
    daemon.shutdown().await;

    // ...and the audit log records the SQLSTATE without the statement. A
    // database's complaint quotes the SQL back, which is caller text an audit
    // row may not hold.
    let log = serde_json::to_string(&daemon.audit_rows()).unwrap();
    assert!(
        log.contains("42P01"),
        "the SQLSTATE is what an operator acts on"
    );
    assert!(
        !log.contains("no_such_table"),
        "the caller's SQL reached the audit log:\n{log}"
    );
}

/// Two tool calls arriving together on a fresh connection must mint once.
///
/// `rmcp` runs each request as its own task, so a check-then-act
/// `ensure_minted` has both find the slot empty, both mint, and the second
/// overwrite the first — leaving a role that nothing revokes, because the
/// disconnect can only close the session it can still see.
#[tokio::test]
async fn two_concurrent_tool_calls_on_a_fresh_connection_mint_once() {
    let Some(cluster) = cluster_or_skip("two_concurrent_tool_calls").await else {
        return;
    };
    let mut daemon = Daemon::prepare("metrics_enabled = false\nmaster_source = \"file\"\n");
    daemon.write_profile("analytics", &db_profile(&cluster));
    daemon.write_master("pg-master", &cluster.master_password());
    daemon.start().await.expect("start");
    let client = mcp_client(&daemon).await;

    let query = |sql: &'static str| {
        client.call_tool(
            CallToolRequestParams::new("briefcred_db_query").with_arguments(
                serde_json::json!({ "profile": "analytics", "sql": sql })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
    };
    let (first, second) = tokio::join!(query("SELECT 1 AS a"), query("SELECT 2 AS b"));
    first.expect("the first call succeeds");
    second.expect("the second call succeeds");

    assert_eq!(
        cluster.leaked_role_count().await,
        1,
        "two concurrent calls must share one mint, not race to two"
    );

    client.cancel().await.ok();
    let cleaned = wait_until(Duration::from_secs(20), || async {
        cluster.leaked_role_count().await == 0
    })
    .await;
    assert!(
        cleaned,
        "a role survived the disconnect, so a session was stranded\n{}",
        daemon.log()
    );
    daemon.shutdown().await;

    let rows = daemon.audit_rows();
    let mints = rows.iter().filter(|r| r["event"] == "mint").count();
    assert_eq!(mints, 1, "{rows:#?}");
    let opened = rows.iter().filter(|r| r["event"] == "session_open").count();
    let closed = rows
        .iter()
        .filter(|r| r["event"] == "session_close")
        .count();
    assert_eq!(opened, 1, "one session for one connection");
    assert_eq!(closed, opened, "every session opened must be closed");
}

/// `max_rows` must bound what the daemon *fetches*, not only what it returns.
#[tokio::test]
async fn max_rows_stops_the_fetch_rather_than_trimming_the_answer() {
    let Some(cluster) = cluster_or_skip("max_rows_stops_the_fetch").await else {
        return;
    };
    let mut daemon = Daemon::prepare("metrics_enabled = false\nmaster_source = \"file\"\n");
    daemon.write_profile("analytics", &db_profile(&cluster));
    daemon.write_master("pg-master", &cluster.master_password());
    daemon.start().await.expect("start");
    let client = mcp_client(&daemon).await;

    // A generator of a hundred million rows. Streaming and stopping at five
    // returns in milliseconds; collecting the result set first takes minutes
    // and gigabytes, so the timeout *is* the assertion — this test passed in
    // under ten seconds only because the fetch stopped.
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        client.call_tool(
            CallToolRequestParams::new("briefcred_db_query").with_arguments(
                serde_json::json!({
                    "profile": "analytics",
                    "sql": "SELECT i FROM generate_series(1, 100000000) AS i",
                    "max_rows": 5,
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        ),
    )
    .await
    .expect("the fetch must stop at max_rows rather than collecting the result set")
    .expect("the query runs");

    let result = json_of(&result);
    assert_eq!(result["row_count"], 5);
    assert_eq!(result["truncated"], true);
    assert_eq!(result["rows"][0]["i"], 1);

    client.cancel().await.ok();
    daemon.shutdown().await;
}

/// A statement with no end is ended by the server, not waited out here.
#[tokio::test]
async fn a_runaway_statement_is_cancelled_by_the_configured_timeout() {
    let Some(cluster) = cluster_or_skip("a_runaway_statement").await else {
        return;
    };
    let mut daemon = Daemon::prepare(
        "metrics_enabled = false\nmaster_source = \"file\"\nmcp_query_timeout_secs = 1\n",
    );
    daemon.write_profile("analytics", &db_profile(&cluster));
    daemon.write_master("pg-master", &cluster.master_password());
    daemon.start().await.expect("start");
    let client = mcp_client(&daemon).await;

    let err = tokio::time::timeout(
        Duration::from_secs(30),
        client.call_tool(
            CallToolRequestParams::new("briefcred_db_query").with_arguments(
                serde_json::json!({ "profile": "analytics", "sql": "SELECT pg_sleep(60)" })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        ),
    )
    .await
    .expect("the server must cancel it long before this timeout")
    .expect_err("a cancelled statement is a failure");
    // 57014: query_canceled.
    assert!(err.to_string().contains("57014"), "{err}");

    client.cancel().await.ok();
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_profile_with_no_database_says_so_rather_than_minting() {
    let mut daemon = Daemon::prepare("metrics_enabled = false\nmaster_source = \"file\"\n");
    daemon.write_profile("listing", LISTING_ONLY);
    daemon.start().await.expect("start");
    let client = mcp_client(&daemon).await;

    let err = client
        .call_tool(
            CallToolRequestParams::new("briefcred_db_query").with_arguments(
                serde_json::json!({ "profile": "listing", "sql": "SELECT 1" })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect_err("there is no database to query");
    assert!(err.to_string().contains("postgres-dynamic"), "{err}");

    client.cancel().await.ok();
    daemon.shutdown().await;
}
