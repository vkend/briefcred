//! `briefcred mcp`: a pipe between an MCP client's stdio and the daemon.
//!
//! Model Context Protocol clients start a server as a subprocess and speak
//! newline-delimited JSON-RPC to it on stdin and stdout. briefcred's MCP server
//! is not a subprocess — it is the daemon, which is where the profiles, the
//! session, the unlock gate and the helper processes already are. So this
//! command is the adaptor between the two, and it is deliberately the dumbest
//! thing that can be: it connects to the daemon's socket, sends one
//! [`Request::Mcp`] frame, reads the acknowledgement, and from then on copies
//! bytes in both directions until one end closes.
//!
//! # Why it understands nothing
//!
//! Every alternative is worse. Parsing the JSON-RPC here would mean a second
//! implementation of MCP framing that has to agree with the daemon's; wrapping
//! each message in a `Request`/`Response` pair would mean inventing a reply
//! for notifications that have none. A byte pump has no opinions to be wrong
//! about, and it means an MCP feature briefcred has never heard of works
//! anyway.
//!
//! # What it does not do
//!
//! It does not start the daemon. As everywhere else in the CLI, a daemon that
//! is not running is [`crate::Error::NotRunning`] with the command that fixes
//! it, and the MCP client shows that on its own stderr rather than silently
//! failing to connect.

use std::path::Path;

use briefcred_proto::{read_frame, write_frame, Request, Response};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixStream;

use crate::error::{Error, Result};

/// Bridge this process's stdin and stdout to the daemon's MCP server.
pub async fn bridge(sock: &Path) -> Result<()> {
    let stream = connect(sock).await?;
    pump(stream, tokio::io::stdin(), tokio::io::stdout()).await
}

/// Connect and upgrade, leaving a stream that is already speaking MCP.
///
/// Split out so a test can drive the same upgrade a real client performs.
pub async fn connect(sock: &Path) -> Result<UnixStream> {
    let mut stream = UnixStream::connect(sock)
        .await
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                Error::NotRunning
            }
            _ => Error::io("connect to", sock, err),
        })?;

    write_frame(&mut stream, &Request::Mcp).await?;
    match read_frame(&mut stream).await? {
        Some(Response::McpReady { .. }) => Ok(stream),
        Some(Response::Error { message }) => Err(Error::Unexpected(message)),
        Some(other) => Err(Error::Unexpected(format!(
            "the daemon answered an MCP upgrade with {other:?}"
        ))),
        None => Err(Error::Unexpected(
            "the daemon closed the connection instead of accepting the MCP upgrade".into(),
        )),
    }
}

/// Copy in both directions until either side finishes.
///
/// `copy_bidirectional` is exactly the right primitive and its stopping rule
/// is the one this wants: when the client closes its stdin the server is told,
/// and when the daemon closes the socket this process exits. A client that
/// exits without closing anything takes this process with it, because its
/// stdin becomes an end-of-file.
async fn pump<S, I, O>(stream: S, input: I, output: O) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let mut stream = stream;
    let mut client = tokio::io::join(input, output);
    match tokio::io::copy_bidirectional(&mut client, &mut stream).await {
        Ok(_) => Ok(()),
        // A client that goes away mid-message resets the pipe. That is how an
        // MCP session normally ends, not a failure to report.
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            Ok(())
        }
        Err(err) => Err(Error::Unexpected(format!("the MCP bridge stopped: {err}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_daemon_that_is_not_there_names_the_command_that_starts_one() {
        let dir = tempfile::tempdir().unwrap();
        let err = connect(&dir.path().join("sock")).await.unwrap_err();
        assert!(matches!(err, Error::NotRunning), "{err}");
    }

    #[tokio::test]
    async fn the_bridge_copies_in_both_directions() {
        // Stands in for the daemon: whatever it reads, it echoes back with a
        // prefix, so a byte that only travelled one way would fail this.
        let (client_side, mut daemon_side) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut buffer = [0u8; 64];
            let read = daemon_side.read(&mut buffer).await.unwrap();
            daemon_side
                .write_all(format!("saw:{}", String::from_utf8_lossy(&buffer[..read])).as_bytes())
                .await
                .unwrap();
            daemon_side.shutdown().await.unwrap();
        });

        let mut output: Vec<u8> = Vec::new();
        pump(client_side, &b"hello\n"[..], &mut output)
            .await
            .unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), "saw:hello\n");
    }
}
