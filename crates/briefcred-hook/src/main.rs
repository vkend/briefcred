//! The `briefcred-hook` binary.
//!
//! Reads a `PreToolUse` payload on stdin, writes a decision on stdout, and
//! exits 0 whatever it decides: a non-zero exit from a hook is a hook failure,
//! not a denial, and briefcred expresses denial in the payload.

use std::io::Read as _;

use briefcred_hook::rules::Rules;
use briefcred_hook::{decide, split_command, HookInput, PolicyAnswer};
use briefcred_proto::{read_frame, write_frame, Request, Response};

fn main() -> std::process::ExitCode {
    let mut stdin = String::new();
    if let Err(err) = std::io::stdin().read_to_string(&mut stdin) {
        eprintln!("briefcred-hook: cannot read stdin: {err}");
        return std::process::ExitCode::SUCCESS;
    }
    let input: HookInput = match serde_json::from_str(&stdin) {
        Ok(input) => input,
        Err(err) => {
            eprintln!("briefcred-hook: unreadable PreToolUse payload: {err}");
            return std::process::ExitCode::SUCCESS;
        }
    };
    // Only shell tools carry a command line worth matching. Anything else is
    // not briefcred's business and gets no output at all.
    if input.tool_input.command.trim().is_empty() {
        return std::process::ExitCode::SUCCESS;
    }

    let paths = match briefcred_core::paths::Paths::discover() {
        Ok(paths) => paths,
        Err(err) => {
            eprintln!("briefcred-hook: {err}");
            return std::process::ExitCode::SUCCESS;
        }
    };
    let rules = match Rules::load(paths.config_dir()) {
        Ok(rules) => rules,
        Err(err) => {
            eprintln!("briefcred-hook: {err}");
            return std::process::ExitCode::SUCCESS;
        }
    };

    let words = split_command(&input.tool_input.command);
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("briefcred-hook: cannot start the async runtime: {err}");
            return std::process::ExitCode::SUCCESS;
        }
    };

    let decision = decide(&rules, &input.tool_input.command, |profile| {
        runtime.block_on(ask(paths.sock(), profile, &words))
    });

    if let Some(output) = decision {
        match serde_json::to_string(&output) {
            Ok(json) => println!("{json}"),
            Err(err) => eprintln!("briefcred-hook: cannot render the decision: {err}"),
        }
    }
    std::process::ExitCode::SUCCESS
}

/// Ask the daemon whether the profile's `exec` policy permits this command.
///
/// Nothing is minted: `HookCheck` is the policy question on its own, because
/// the tool call the agent is asking about may never happen.
async fn ask(sock: &std::path::Path, profile: &str, words: &[String]) -> PolicyAnswer {
    let Some((argv0, args)) = words.split_first() else {
        return PolicyAnswer::Unknown("the command is empty".to_string());
    };

    let mut stream = match tokio::net::UnixStream::connect(sock).await {
        Ok(stream) => stream,
        Err(err) => return PolicyAnswer::Unknown(format!("the daemon is not running ({err})")),
    };
    let request = Request::HookCheck {
        profile: profile.to_string(),
        argv0: argv0.clone(),
        args: args.to_vec(),
    };
    if let Err(err) = write_frame(&mut stream, &request).await {
        return PolicyAnswer::Unknown(err.to_string());
    }
    match read_frame::<_, Response>(&mut stream).await {
        Ok(Some(Response::HookDecision { allowed: true, .. })) => PolicyAnswer::Allowed,
        Ok(Some(Response::HookDecision { reason, .. })) => PolicyAnswer::Denied(reason),
        Ok(Some(Response::Error { message })) => PolicyAnswer::Unknown(message),
        Ok(Some(other)) => PolicyAnswer::Unknown(format!("{other:?}")),
        Ok(None) => PolicyAnswer::Unknown("the daemon closed the connection".to_string()),
        Err(err) => PolicyAnswer::Unknown(err.to_string()),
    }
}
