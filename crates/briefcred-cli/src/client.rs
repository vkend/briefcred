//! Talking to the daemon over its Unix socket.
//!
//! The CLI never starts the daemon itself. If the socket is absent or refuses
//! a connection, that is [`Error::NotRunning`] and the caller is told which
//! command fixes it, because a CLI that silently forks a daemon makes the
//! service manager and the process tree disagree about who owns it.

use std::path::Path;

use briefcred_proto::{read_frame, write_frame, Request, Response};
use tokio::net::UnixStream;

use crate::error::{Error, Result};
use crate::session_key::SessionKey;

/// One open connection to the daemon, for a command that sends several
/// requests.
///
/// `briefcred exec` sends four — open, exec, done, close — and they have to be
/// the same session's, so a connection per request would work but would make
/// four connects where one will do.
///
/// The daemon does **not** watch this socket: a wrapper that is killed leaves
/// its session behind, and what reaps it is idle eviction after
/// `session_idle_secs`, or the reconciler sweeping the mints it never reported.
/// The close on the happy path is the `CloseSession` request below, not the
/// socket going away.
pub struct Connection {
    stream: UnixStream,
}

impl Connection {
    /// Connect to the daemon's socket.
    pub async fn open(sock: &Path) -> Result<Connection> {
        let stream = UnixStream::connect(sock)
            .await
            .map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                    Error::NotRunning
                }
                _ => Error::io("connect to", sock, err),
            })?;
        Ok(Connection { stream })
    }

    /// Send one request and read its answer.
    pub async fn send(&mut self, request: Request) -> Result<Response> {
        write_frame(&mut self.stream, &request).await?;
        read_frame(&mut self.stream)
            .await?
            .ok_or_else(|| Error::Unexpected("nothing before closing the connection".into()))
    }
}

/// Send one request on a connection of its own and read one response.
pub async fn request(sock: &Path, request: Request) -> Result<Response> {
    Connection::open(sock).await?.send(request).await
}

/// Build an [`Request::OpenSession`] that reports this process's own session
/// and offers the public half of `key`.
///
/// The daemon cannot answer the headless question for us: it lives in
/// launchd's session, and only the shell the user actually typed into knows
/// whether that shell is an SSH login. Declaring it here is what lets the
/// daemon refuse with "you have no screen" instead of showing a prompt on
/// somebody else's.
///
/// `key` is generated fresh per session by the caller, which holds the private
/// half for as long as the session lives. See
/// [`crate::session_key::SessionKey`] for what the binding does and does not
/// buy.
pub fn open_session(profile: impl Into<String>, key: &SessionKey) -> Request {
    Request::OpenSession {
        profile: profile.into(),
        client_headless: briefcred_core::session_env::is_headless(),
        session_pubkey: Some(key.public_key_base64()),
    }
}

/// Ask for [`Response::Status`], rejecting any other reply.
pub async fn status(sock: &Path) -> Result<Response> {
    match request(sock, Request::Status).await? {
        status @ Response::Status { .. } => Ok(status),
        Response::Error { message } => Err(Error::Unexpected(format!("an error: {message}"))),
        other => Err(Error::Unexpected(format!("{other:?}"))),
    }
}
