//! The two binaries an operator actually runs, against a real daemon.
//!
//! Everything else in this suite drives the daemon through `briefcred_proto`
//! directly, which is the right level for the daemon's own behaviour and the
//! wrong level for two things that are not the daemon: the `briefcred` CLI
//! composing and applying a child's environment, and the `briefcred-hook`
//! filter turning a `PreToolUse` payload into the exact JSON an agent parses.
//!
//! Both of those are contracts with somebody else's software — a shell, and an
//! agent — so both are exercised here as processes with real stdin and stdout.

use std::process::Stdio;

use briefcred_e2e::daemon_harness::{binary_dir, Daemon};

/// A profile with one HTTP credential and a permissive `exec` allowlist.
///
/// `http-bearer` because it mints without a helper or a backend: the subject
/// here is the environment the child ends up with, not what produced it.
fn profile() -> String {
    "\
name: dev
unlock:
  policy: none
credentials:
  - name: openai
    kind: http-bearer
    ttl_secs: 300
exec:
  allow_argv0:
    - /usr/bin/env
    - env
    - psql
env:
  OPENAI_API_KEY: ${minted.openai.TOKEN}
"
    .to_string()
}

async fn daemon_with_profile() -> Daemon {
    let daemon = Daemon::prepare(
        "metrics_enabled = false\nmetrics_port = 0\nproxy_port = 0\npg_proxy_port = 0\n\
         master_source = \"file\"\n[ca]\nkeystore = \"file\"\n",
    );
    daemon.write_profile("dev", &profile());
    daemon.write_master("openai", "sk-the-real-openai-key");
    let mut daemon = daemon;
    daemon.start().await.unwrap_or_else(|e| panic!("{e}"));
    daemon
}

/// Run one of the workspace's binaries with the daemon's home.
fn command(name: &str, home: &std::path::Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(binary_dir().join(name));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("BRIEFCRED_HOME", home);
    command
}

#[tokio::test]
async fn the_cli_runs_a_child_with_the_composed_environment_and_audits_it() {
    let daemon = daemon_with_profile().await;

    let output = command("briefcred", daemon.home())
        .args(["exec", "--profile=dev", "--", "/usr/bin/env"])
        .output()
        .await
        .expect("the briefcred binary runs");

    assert!(
        output.status.success(),
        "exec failed: {}\n{}",
        String::from_utf8_lossy(&output.stderr),
        daemon.log()
    );
    let printed = String::from_utf8_lossy(&output.stdout).to_string();
    let env: std::collections::BTreeMap<&str, &str> = printed
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();

    // The token, not the key. This is the whole claim of a Model A credential
    // and it is asserted here against the environment a real child really got,
    // rather than against the reply the daemon sent the wrapper.
    let key = env
        .get("OPENAI_API_KEY")
        .expect("the profile's env reaches the child");
    assert!(
        key.starts_with("bc."),
        "the child must hold a synthetic token: {key}"
    );
    assert!(
        !printed.contains("sk-the-real-openai-key"),
        "the real key must not be anywhere in the child's environment"
    );

    // The proxy and trust variables ride along, because a profile with an HTTP
    // credential is one whose traffic has to go through briefcred.
    for name in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"] {
        assert!(env.contains_key(name), "{name} is missing from {env:#?}");
    }
    assert!(
        env.keys().any(|name| name.contains("CA")),
        "a CA trust variable must be set: {env:#?}"
    );

    // And the environment is composed rather than inherited: nothing of this
    // test process's own environment is in it.
    assert!(
        !env.contains_key("CARGO_MANIFEST_DIR"),
        "the child's environment is built, not inherited: {env:#?}"
    );

    let mut daemon = daemon;
    daemon.shutdown().await;

    let rows = daemon.audit_rows();
    let mint = rows
        .iter()
        .find(|row| row["event"] == "mint")
        .unwrap_or_else(|| panic!("no mint row in {rows:#?}"));
    assert_eq!(mint["credential"], "openai");
    assert_eq!(mint["kind"], "http-bearer");

    let start = rows
        .iter()
        .find(|row| row["event"] == "exec_start")
        .unwrap_or_else(|| panic!("no exec_start row in {rows:#?}"));
    assert_eq!(start["argv0"], "/usr/bin/env");
    let end = rows
        .iter()
        .find(|row| row["event"] == "exec_end")
        .unwrap_or_else(|| panic!("no exec_end row in {rows:#?}"));
    assert_eq!(end["exit_code"], 0);
    assert_eq!(
        start["session_id"], end["session_id"],
        "one session, opened and accounted for"
    );

    // Metadata only: not one row may carry the real key or the token.
    let whole = serde_json::to_string(&rows).unwrap();
    assert!(
        !whole.contains("sk-the-real-openai-key"),
        "an audit row carried the master"
    );
    assert!(!whole.contains("bc."), "an audit row carried a token");
}

/// The rule file the hook tests decide against.
///
/// First match wins, so the `ask` rule for `env ASK` sits above the `allow`
/// rule for every other `env`.
const RULES: &str = "\
rules:
  - match: '^env ASK'
    profile: dev
    decision: ask
  - match: '^env '
    profile: dev
    decision: allow
  - match: '^psql '
    profile: dev
    decision: allow
    rewrite: true
  - match: '^rm '
    profile: dev
    decision: allow
";

/// Feed one `PreToolUse` payload to the hook binary and read its answer.
async fn hook(daemon: &Daemon, command_line: &str) -> (String, Option<serde_json::Value>) {
    use tokio::io::AsyncWriteExt as _;

    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command_line },
    })
    .to_string();

    let mut child = command("briefcred-hook", daemon.home())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the briefcred-hook binary runs");
    child
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(payload.as_bytes())
        .await
        .unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().await.expect("the hook exits");

    // Always zero. A non-zero exit from a hook is a hook failure, and briefcred
    // expresses a denial in the payload rather than in the exit code.
    assert!(
        output.status.success(),
        "the hook must exit 0 whatever it decides: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let parsed = (!stdout.is_empty()).then(|| {
        serde_json::from_str::<serde_json::Value>(&stdout)
            .unwrap_or_else(|e| panic!("the hook printed {stdout:?}: {e}"))
    });
    (stdout, parsed)
}

/// The decision in one answer, or a panic naming what was printed instead.
fn decision(answer: &Option<serde_json::Value>) -> String {
    let answer = answer.as_ref().expect("a matching rule produces output");
    answer["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or_else(|| panic!("no permissionDecision in {answer}"))
        .to_string()
}

#[tokio::test]
async fn the_hook_binary_answers_allow_deny_and_ask_in_the_agents_own_shape() {
    let daemon = daemon_with_profile().await;
    std::fs::write(daemon.home().join(briefcred_hook::rules::RULES_FILE), RULES).unwrap();

    // Allow: the rule permits it, and so does the profile's `exec.allow_argv0`.
    let (_, allowed) = hook(&daemon, "env FOO=1").await;
    assert_eq!(decision(&allowed), "allow");
    let allowed = allowed.unwrap();
    assert_eq!(
        allowed["hookSpecificOutput"]["hookEventName"], "PreToolUse",
        "{allowed}"
    );
    assert!(
        allowed["hookSpecificOutput"]["updatedInput"].is_null(),
        "a rule without `rewrite` rewrites nothing: {allowed}"
    );

    // Ask: the rule says so, and the daemon's yes does not upgrade it.
    let (_, asked) = hook(&daemon, "env ASK=1").await;
    assert_eq!(decision(&asked), "ask");

    // Deny: the rule says allow and the daemon refuses, because `rm` is not in
    // this profile's `allow_argv0`. That direction is the one that matters —
    // the hook can only ever be more restrictive than its rule file.
    let (_, denied) = hook(&daemon, "rm -rf /").await;
    assert_eq!(decision(&denied), "deny");
    let denied = denied.unwrap();
    assert!(
        denied["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("briefcred"),
        "the reason is shown to a person and must say who refused: {denied}"
    );

    // Allow and rewrite, which is the only answer that changes what runs.
    let (_, rewritten) = hook(&daemon, "psql -c 'SELECT 1'").await;
    assert_eq!(decision(&rewritten), "allow");
    let rewritten = rewritten.unwrap();
    assert_eq!(
        rewritten["hookSpecificOutput"]["updatedInput"]["command"],
        "briefcred exec --profile=dev -- psql -c 'SELECT 1'",
        "{rewritten}"
    );

    // The same rule, on a line with a second program on it: `ask`, and nothing
    // is rewritten. Wrapping it would put briefcred's name on a `tee` the
    // daemon never judged.
    let (_, compound) = hook(&daemon, "psql -c 'SELECT 1' | tee /tmp/out").await;
    assert_eq!(decision(&compound), "ask");
    assert!(
        compound.unwrap()["hookSpecificOutput"]["updatedInput"].is_null(),
        "a compound line is never rewritten"
    );

    // And a command no rule matches produces nothing at all, so briefcred has
    // no opinion about the agent's `ls`.
    let (empty, _) = hook(&daemon, "ls -la").await;
    assert!(empty.is_empty(), "expected no output, got {empty:?}");

    let mut daemon = daemon;
    daemon.shutdown().await;
}
