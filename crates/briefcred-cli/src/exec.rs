//! `briefcred exec` and `briefcred get`: the two ways a credential leaves the
//! daemon.
//!
//! # Who composes the environment
//!
//! The daemon does. It is the only side that holds the profile, the minted
//! fields, and the CA path at once, and putting the substitution there means
//! there is one implementation of the `${minted...}` grammar rather than two
//! that can disagree. The client's job is narrow and mechanical:
//!
//! 1. clear the environment,
//! 2. copy the variables the daemon named in `passthrough` from its own,
//! 3. apply the daemon's `env` on top,
//! 4. spawn.
//!
//! Step 3 is last so a profile can override a passed-through variable. The
//! client never parses a template and never decides what a credential is worth.
//!
//! # Why the client clears rather than adds
//!
//! An agent's shell is full of things briefcred did not put there, including
//! whatever credentials the user already had. Starting from empty means the
//! subprocess gets what the profile granted it and nothing else, so a leaked
//! `AWS_SECRET_ACCESS_KEY` in the parent does not silently travel into a
//! process briefcred is meant to be constraining.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::Stdio;
use std::time::Instant;

use briefcred_proto::{Request, Response};

use crate::client::Connection;
use crate::error::{Error, Result};

/// What `briefcred exec` was asked to do.
pub struct ExecRequest<'a> {
    /// The profile to run under.
    pub profile: &'a str,
    /// Which credentials to mint, or all of them.
    pub credentials: Option<Vec<String>>,
    /// The program to run.
    pub argv0: &'a str,
    /// Its arguments.
    pub args: &'a [String],
}

/// Run a subprocess with freshly minted credentials, and return its exit code.
///
/// The session is closed on every path out, including the ones where the child
/// failed: a session left open is a master left resident.
pub async fn run(sock: &Path, request: ExecRequest<'_>) -> Result<u8> {
    let mut connection = Connection::open(sock).await?;

    // Never hand-built: `client::open_session` is the only thing that answers
    // the headless question, and answering it wrongly is how a prompt ends up
    // on somebody else's screen.
    let session_id = match connection
        .send(crate::client::open_session(request.profile))
        .await?
    {
        Response::SessionOpened { session_id, .. } => session_id,
        Response::Locked { reason, message } => return Err(Error::Locked { reason, message }),
        Response::Error { message } => return Err(Error::Refused(message)),
        other => return Err(Error::Unexpected(format!("{other:?}"))),
    };

    let outcome = run_in_session(&mut connection, &session_id, &request).await;

    // Best effort, and after the outcome is already in hand: a close that
    // fails must not turn a successful command into a failed one, and the
    // daemon's idle sweep will wipe the session anyway.
    let _ = connection
        .send(Request::CloseSession {
            session_id: session_id.clone(),
        })
        .await;
    outcome
}

async fn run_in_session(
    connection: &mut Connection,
    session_id: &str,
    request: &ExecRequest<'_>,
) -> Result<u8> {
    let minted = connection
        .send(Request::Exec {
            session_id: session_id.to_string(),
            credentials: request.credentials.clone(),
            argv0: request.argv0.to_string(),
            args: request.args.to_vec(),
            pid: std::process::id(),
        })
        .await?;

    let (mints, env, passthrough) = match minted {
        Response::Minted {
            mints,
            env,
            passthrough,
        } => (mints, env, passthrough),
        Response::Denied { message } => return Err(Error::Denied(message)),
        Response::Error { message } => return Err(Error::Refused(message)),
        other => return Err(Error::Unexpected(format!("{other:?}"))),
    };

    let started = Instant::now();
    let status = spawn(request.argv0, request.args, &env, &passthrough).await?;
    let duration_ms = started.elapsed().as_millis() as u64;

    // Told after the child is reaped, so the revokes are queued as soon as the
    // credentials stop being needed rather than when the shell gets round to
    // exiting.
    let _ = connection
        .send(Request::ExecDone {
            session_id: session_id.to_string(),
            mint_ids: mints.iter().map(|m| m.mint_id.clone()).collect(),
            exit_code: status,
            duration_ms,
        })
        .await;

    // A child killed by a signal has no exit code. The shell convention is
    // 128 + signal, and briefcred has no better idea, so 128 it is when the
    // signal number is not available either.
    Ok(status.map_or(128, |code| u8::try_from(code).unwrap_or(1)))
}

/// Start the child with a cleared environment and wait for it.
async fn spawn(
    argv0: &str,
    args: &[String],
    env: &BTreeMap<String, briefcred_proto::SecretString>,
    passthrough: &[String],
) -> Result<Option<i32>> {
    let mut command = tokio::process::Command::new(argv0);
    command.args(args);
    command.env_clear();
    for name in passthrough {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    for (name, value) in env {
        command.env(name, OsString::from(value.expose()));
    }
    // The child owns the terminal: `briefcred exec -- psql` has to be as usable
    // as `psql`, which means an interactive prompt and a working pager.
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = command
        .spawn()
        .map_err(|source| Error::io("run", argv0, source))?;
    let status = child
        .wait()
        .await
        .map_err(|source| Error::io("wait for", argv0, source))?;
    Ok(status.code())
}

/// Fetch one field of one credential and print it.
///
/// Refuses a terminal unless forced, because the whole value of a short-lived
/// credential is undone by it sitting in a scrollback buffer, a screen
/// recording, or a shell history that captured a copy-paste.
pub async fn get(
    sock: &Path,
    profile: &str,
    credential: &str,
    field: &str,
    force: bool,
    stdout_is_tty: bool,
) -> Result<String> {
    if stdout_is_tty && !force {
        return Err(Error::Refused(format!(
            "refusing to print `{credential}.{field}` to a terminal, where it would stay in the \
             scrollback; pipe it somewhere, or pass --force if you meant it"
        )));
    }

    let mut connection = Connection::open(sock).await?;
    let session_id = match connection
        .send(crate::client::open_session(profile))
        .await?
    {
        Response::SessionOpened { session_id, .. } => session_id,
        Response::Locked { reason, message } => return Err(Error::Locked { reason, message }),
        Response::Error { message } => return Err(Error::Refused(message)),
        other => return Err(Error::Unexpected(format!("{other:?}"))),
    };

    let value = fetch_field(&mut connection, &session_id, credential, field).await;
    let _ = connection
        .send(Request::CloseSession {
            session_id: session_id.clone(),
        })
        .await;
    value
}

async fn fetch_field(
    connection: &mut Connection,
    session_id: &str,
    credential: &str,
    field: &str,
) -> Result<String> {
    let minted = connection
        .send(Request::Exec {
            session_id: session_id.to_string(),
            credentials: Some(vec![credential.to_string()]),
            // No subprocess: see `briefcred_core::exec::GET_PSEUDO_ARGV0`.
            argv0: briefcred_core::exec::GET_PSEUDO_ARGV0.to_string(),
            args: Vec::new(),
            pid: std::process::id(),
        })
        .await?;

    let mints = match minted {
        Response::Minted { mints, .. } => mints,
        Response::Denied { message } => return Err(Error::Denied(message)),
        Response::Error { message } => return Err(Error::Refused(message)),
        other => return Err(Error::Unexpected(format!("{other:?}"))),
    };

    let mint = mints
        .iter()
        .find(|m| m.credential == credential)
        .ok_or_else(|| {
            Error::Refused(format!(
                "credential `{credential}` did not mint; the daemon log says why"
            ))
        })?;
    let value = mint
        .fields
        .get(field)
        .ok_or_else(|| {
            Error::Refused(format!(
                "credential `{credential}` has no field `{field}`; it offers {}",
                mint.fields.keys().cloned().collect::<Vec<_>>().join(", ")
            ))
        })?
        .expose()
        .to_string();

    // The credential is handed over and then immediately queued for revoke:
    // `get` is for piping a value into one command, not for holding one.
    let _ = connection
        .send(Request::ExecDone {
            session_id: session_id.to_string(),
            mint_ids: mints.iter().map(|m| m.mint_id.clone()).collect(),
            exit_code: Some(0),
            duration_ms: 0,
        })
        .await;

    Ok(value)
}

/// Split a `--cred a,b` value into names, rejecting empty entries.
pub fn parse_credentials(raw: &str) -> Result<Vec<String>> {
    let names: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .map(str::to_string)
        .collect::<Vec<_>>();
    if names.iter().any(|n| n.is_empty()) {
        return Err(Error::Refused(format!(
            "`--cred {raw}` has an empty credential name"
        )));
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_list_splits_on_commas_and_trims() {
        assert_eq!(
            parse_credentials("db, warehouse").unwrap(),
            vec!["db".to_string(), "warehouse".to_string()]
        );
        assert_eq!(parse_credentials("db").unwrap(), vec!["db".to_string()]);
    }

    #[test]
    fn an_empty_entry_is_refused_rather_than_silently_dropped() {
        for bad in ["db,", ",db", "db,,warehouse", ""] {
            assert!(
                parse_credentials(bad).is_err(),
                "`--cred {bad}` should be refused"
            );
        }
    }

    #[tokio::test]
    async fn get_refuses_a_terminal_before_it_opens_a_session() {
        // The socket does not exist, so reaching the daemon at all would be an
        // error. Getting the refusal instead proves the check runs first —
        // which matters, because opening a session prompts for Touch ID and
        // then mints something the user never gets to see.
        let err = get(
            Path::new("/nonexistent/sock"),
            "dev",
            "db",
            "PGPASSWORD",
            false,
            true,
        )
        .await
        .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("terminal"), "{text}");
        assert!(text.contains("--force"), "{text}");
    }

    #[tokio::test]
    async fn get_proceeds_past_the_tty_check_when_forced() {
        let err = get(
            Path::new("/nonexistent/sock"),
            "dev",
            "db",
            "PGPASSWORD",
            true,
            true,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, Error::NotRunning),
            "--force must get as far as the socket: {err}"
        );
    }

    #[tokio::test]
    async fn get_does_not_refuse_a_pipe() {
        let err = get(
            Path::new("/nonexistent/sock"),
            "dev",
            "db",
            "PGPASSWORD",
            false,
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::NotRunning), "{err}");
    }
}
