use super::*;

/// The tool surface is a public contract: a renamed tool silently breaks every
/// agent configuration that named it, and a new one is a new capability an
/// operator has not agreed to. Both should be a failing test, not a surprise.
#[test]
fn the_server_offers_exactly_the_three_documented_tools() {
    let names: Vec<String> = McpServer::tool_router()
        .list_all()
        .iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert_eq!(
        names,
        vec![
            "briefcred_db_query",
            "briefcred_exec",
            "briefcred_list_profiles",
        ]
    );
}

#[test]
fn every_tool_describes_itself_and_its_arguments() {
    for tool in McpServer::tool_router().list_all() {
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(
            description.len() > 40,
            "`{}` needs a description a model can choose it from: {description:?}",
            tool.name
        );
        assert!(
            tool.input_schema.contains_key("type"),
            "`{}` must publish an input schema",
            tool.name
        );
    }
}

/// The two tools that mint say so, because "this returns no credential" is the
/// claim the whole design rests on and it belongs where a model reads it.
#[test]
fn the_minting_tools_say_that_no_credential_comes_back() {
    for tool in McpServer::tool_router().list_all() {
        if tool.name == "briefcred_list_profiles" {
            continue;
        }
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(
            description.contains("never returned"),
            "`{}` must say the credential does not come back: {description}",
            tool.name
        );
    }
}

#[test]
fn output_under_the_cap_is_returned_whole_and_unmarked() {
    let (text, truncated) = capped(b"hello");
    assert_eq!(text, "hello");
    assert!(!truncated);

    let exact = vec![b'x'; MAX_OUTPUT_BYTES];
    let (text, truncated) = capped(&exact);
    assert_eq!(text.len(), MAX_OUTPUT_BYTES);
    assert!(!truncated, "exactly at the cap is not over it");
}

#[test]
fn output_over_the_cap_is_cut_and_says_so() {
    let flood = vec![b'x'; MAX_OUTPUT_BYTES * 2];
    let (text, truncated) = capped(&flood);
    assert!(truncated);
    assert!(text.len() <= MAX_OUTPUT_BYTES, "{}", text.len());
}

#[test]
fn a_cut_never_lands_inside_a_character() {
    // Three-byte characters, so the cap falls in the middle of one.
    let mut bytes = "€".repeat(MAX_OUTPUT_BYTES).into_bytes();
    bytes.truncate(MAX_OUTPUT_BYTES + 2);
    let (text, truncated) = capped(&bytes);
    assert!(truncated);
    assert!(
        !text.contains('\u{FFFD}'),
        "a cut inside a character would leave a replacement character"
    );
    assert!(text.chars().all(|c| c == '€'), "{}", &text[..12]);
}

#[test]
fn an_empty_output_is_an_empty_string_rather_than_a_truncation() {
    assert_eq!(capped(b""), (String::new(), false));
}

/// `run_capped` is the thing standing between the daemon's memory and a
/// command a model asked for, so it is tested against a command that really
/// does write without stopping.
#[tokio::test]
async fn a_command_that_never_stops_writing_is_cut_and_killed() {
    // `cat /dev/zero` rather than a shell loop. Both are unbounded writers and
    // both exercise the same path, but a `while :; do printf ...; done` needs
    // tens of thousands of shell-builtin iterations to reach a megabyte, and it
    // burns a core doing it — inside the same test binary as the filesystem
    // watcher tests, which then time out waiting for an event. One `cat` reaches
    // the cap at pipe speed and costs almost nothing.
    let mut command = tokio::process::Command::new("/bin/cat");
    command
        .arg("/dev/zero")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = tokio::time::timeout(std::time::Duration::from_secs(30), run_capped(command))
        .await
        .expect("an unbounded writer must not hang the daemon")
        .expect("the command runs");

    assert!(output.truncated, "the cap must be reported");
    assert!(
        output.stdout.len() <= MAX_OUTPUT_BYTES,
        "{} bytes came back",
        output.stdout.len()
    );
    assert!(
        !output.stdout.is_empty(),
        "the cap must not be reached by reading nothing"
    );
    // Killed rather than exited: `start_kill` sends SIGKILL, which has no exit
    // code. A `Some(_)` here would mean the child was allowed to finish, which
    // for this command means it never was.
    assert_eq!(output.exit_code, None, "the child must have been killed");
}

#[tokio::test]
async fn a_command_that_stops_on_its_own_keeps_its_exit_code_and_both_streams() {
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .args(["-c", "printf out; printf err >&2; exit 3"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = run_capped(command).await.unwrap();
    assert_eq!(output.stdout, "out");
    assert_eq!(output.stderr, "err");
    assert_eq!(output.exit_code, Some(3));
    assert!(!output.truncated);
}

/// A child that fills one pipe while the other is being drained deadlocks if
/// the two are read in sequence, so both are read at once. This is the shape
/// that catches it: far more on stderr than a pipe buffer holds.
#[tokio::test]
async fn a_child_writing_heavily_to_both_streams_does_not_deadlock() {
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .args([
            "-c",
            "i=0; while [ $i -lt 400 ]; do printf '%1024s' '' >&2; printf '%1024s' ''; \
             i=$((i+1)); done",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = tokio::time::timeout(std::time::Duration::from_secs(30), run_capped(command))
        .await
        .expect("reading one stream at a time would hang here")
        .unwrap();
    assert_eq!(output.stdout.len(), 400 * 1024);
    assert_eq!(output.stderr.len(), 400 * 1024);
    assert_eq!(output.exit_code, Some(0));
}

/// The audit detail and the caller's message are deliberately different
/// strings, and the difference is the whole point of `ToolFailure`.
#[test]
fn a_redacted_failure_tells_the_caller_more_than_the_audit_log() {
    let failure = ToolFailure::redacted(
        invalid("42P01: relation \"salaries\" does not exist"),
        "the database refused the statement: 42P01",
    );
    assert!(failure.reported.message.contains("salaries"));
    assert!(!failure.audited.contains("salaries"), "{}", failure.audited);
    assert!(failure.audited.contains("42P01"), "{}", failure.audited);
}

#[test]
fn a_failure_briefcred_wrote_itself_is_audited_as_written() {
    let failure: ToolFailure = invalid("no profile `analytics`").into();
    assert_eq!(failure.audited, "no profile `analytics`");
}

#[test]
fn an_unexpected_unlock_answer_is_named_rather_than_debug_printed() {
    // `Minted` carries credential material. If the unlock gate ever answered
    // one, a `{:?}` fallback would put it in a tool result.
    let message = locked_or_internal(briefcred_proto::Response::Minted {
        mints: Vec::new(),
        env: std::collections::BTreeMap::from([(
            "PGPASSWORD".to_string(),
            briefcred_proto::SecretString::new("hunter2"),
        )]),
        passthrough: Vec::new(),
    })
    .message
    .to_string();
    assert!(!message.contains("hunter2"), "{message}");
    assert!(message.contains("minted"), "{message}");

    let locked = locked_or_internal(briefcred_proto::Response::Locked {
        reason: "cancelled".into(),
        message: "the prompt was cancelled".into(),
    });
    assert!(locked.message.contains("cancelled"));
}
