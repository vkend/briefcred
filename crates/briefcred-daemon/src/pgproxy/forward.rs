//! The upstream half: opening a real connection with the real master, and then
//! getting out of the way.
//!
//! # The handover
//!
//! Two authentications happen on one client connection, and they are not the
//! same authentication. The client proves it holds a synthetic token; briefcred
//! proves, separately and with a credential the client has never seen, that it
//! holds the master. Only when the second succeeds is the first one answered —
//! [`connect`] returns before a single byte has been written to the client, so
//! a client can never be told `AuthenticationOk` for a connection that does not
//! exist.
//!
//! What the client then receives is the **upstream's** own
//! `ParameterStatus`, `BackendKeyData` and `ReadyForQuery`, relayed verbatim.
//! Synthesising those would mean inventing a `server_version`, a
//! `standard_conforming_strings`, and a cancellation key that cancels nothing;
//! passing the real ones through means a driver sees exactly the server it
//! would have seen without briefcred in the middle.
//!
//! # And then nothing
//!
//! After `ReadyForQuery` the proxy stops parsing. [`relay`] copies bytes in
//! both directions through a fixed buffer and counts them as they go. It does
//! not buffer a result set, does not look at a query, and could not record one
//! if it wanted to — which is the property the audit row's honesty rests on.

use std::collections::BTreeMap;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::pgproxy::scram::{self, ScramClient, ScramError};
use crate::pgproxy::startup::PROTOCOL_3_0;
use crate::pgproxy::wire::{self, AuthRequest, Message, WireError};

/// The buffer one direction of a relayed connection copies through.
///
/// Sixteen kibibytes: large enough that a result set is not a syscall per row,
/// small enough that ten thousand idle connections are not a hundred megabytes
/// of buffer. What matters more than the number is that there is one — a proxy
/// that grew its buffer to fit the response would be buffering the result set
/// this module exists not to see.
const RELAY_BUFFER: usize = 16 * 1024;

/// Why the upstream connection could not be established.
///
/// None of these carry the master password or anything derived from it. They
/// are logged and, where a session was resolved, they end a connection whose
/// audit row records the failure as an outcome.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The real server could not be reached.
    #[error("cannot reach `{upstream}`: {detail}")]
    Unreachable {
        /// The `host:port` that was tried.
        upstream: String,
        /// The connection error.
        detail: String,
    },

    /// The server asked for an authentication method briefcred does not do.
    #[error(
        "`{upstream}` asked for authentication method {code}, which briefcred's Postgres proxy \
         does not implement"
    )]
    UnsupportedMethod {
        /// The `host:port` that asked.
        upstream: String,
        /// The `AuthenticationRequest` code it sent.
        code: i32,
    },

    /// The server asked for MD5 and `pgproxy.allow_md5` is off.
    #[error(
        "`{upstream}` asked for MD5 authentication, which is deprecated and off by default; \
         set `pgproxy.allow_md5 = true` in daemon.toml to permit it"
    )]
    Md5Refused {
        /// The `host:port` that asked.
        upstream: String,
    },

    /// The SCRAM exchange failed.
    #[error("`{upstream}`: {source}")]
    Scram {
        /// The `host:port` the exchange was with.
        upstream: String,
        /// What went wrong.
        #[source]
        source: ScramError,
    },

    /// The server refused the credentials, or failed the connection.
    ///
    /// Carries the server's own `ErrorResponse` text, which is a message about
    /// a master the client never sees and so is not relayed to it.
    #[error("`{upstream}` refused the connection: {detail}")]
    Refused {
        /// The `host:port` that refused.
        upstream: String,
        /// The server's message.
        detail: String,
    },

    /// The server sent something the proxy could not read.
    #[error("`{upstream}` sent something briefcred could not read: {source}")]
    Protocol {
        /// The `host:port` that sent it.
        upstream: String,
        /// The framing or parsing failure.
        #[source]
        source: WireError,
    },
}

/// An authenticated upstream connection, ready to be spliced to a client.
pub struct Upstream {
    /// The socket, authenticated and sitting at `ReadyForQuery`.
    pub stream: TcpStream,
    /// Everything the server said between `AuthenticationOk` and
    /// `ReadyForQuery`, in order, to be relayed to the client verbatim.
    pub greeting: Vec<Message>,
    /// The `(pid, key)` the server issued, when it issued one.
    ///
    /// Kept so a later `CancelRequest` carrying these values can be matched to
    /// this connection's upstream and forwarded there.
    pub backend_key: Option<(i32, i32)>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("greeting_messages", &self.greeting.len())
            .field("has_backend_key", &self.backend_key.is_some())
            .finish()
    }
}

/// Open and authenticate a connection to the real server.
///
/// `user` and `database` are the credential's configured values, never the
/// client's: the client named a session and a database it had to match, and
/// what is sent upstream is what the profile authorised.
pub async fn connect(
    upstream: &str,
    user: &str,
    database: &str,
    master: &Zeroizing<String>,
    forwarded: &BTreeMap<String, String>,
    allow_md5: bool,
) -> Result<Upstream, UpstreamError> {
    let mut stream =
        TcpStream::connect(upstream)
            .await
            .map_err(|e| UpstreamError::Unreachable {
                upstream: upstream.to_string(),
                detail: e.to_string(),
            })?;
    // Small messages, and every one of them is a round trip: Nagle would add a
    // delay to each step of the authentication and to every query after it.
    let _ = stream.set_nodelay(true);

    let packet = startup_packet(user, database, forwarded);
    stream
        .write_all(&packet)
        .await
        .map_err(|e| UpstreamError::Unreachable {
            upstream: upstream.to_string(),
            detail: e.to_string(),
        })?;

    authenticate(&mut stream, upstream, user, master, allow_md5).await?;
    let (greeting, backend_key) = read_greeting(&mut stream, upstream).await?;
    Ok(Upstream {
        stream,
        greeting,
        backend_key,
    })
}

/// The startup packet briefcred sends upstream.
///
/// Built from the credential's configuration plus the handful of parameters
/// [`crate::pgproxy::startup::FORWARDED_PARAMETERS`] allows through, and
/// nothing else.
fn startup_packet(user: &str, database: &str, forwarded: &BTreeMap<String, String>) -> Vec<u8> {
    let mut body = PROTOCOL_3_0.to_be_bytes().to_vec();
    let mut push = |key: &str, value: &str| {
        body.extend_from_slice(key.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    };
    push("user", user);
    push("database", database);
    for (key, value) in forwarded {
        push(key, value);
    }
    body.push(0);

    let mut packet = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    packet.extend_from_slice(&body);
    packet
}

/// Carry the server's authentication request through to `AuthenticationOk`.
async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    upstream: &str,
    user: &str,
    master: &Zeroizing<String>,
    allow_md5: bool,
) -> Result<(), UpstreamError> {
    loop {
        let message = next_message(stream, upstream).await?;
        if message.tag != wire::TAG_AUTHENTICATION {
            return Err(UpstreamError::Protocol {
                upstream: upstream.to_string(),
                source: WireError::Malformed {
                    tag: message.tag as char,
                    detail: "expected an authentication request",
                },
            });
        }
        let request =
            AuthRequest::parse(&message.body).map_err(|source| UpstreamError::Protocol {
                upstream: upstream.to_string(),
                source,
            })?;
        match request {
            AuthRequest::Ok => return Ok(()),
            AuthRequest::Sasl(mechanisms) => {
                return sasl(stream, upstream, master, &mechanisms).await
            }
            AuthRequest::Md5Password(salt) => {
                if !allow_md5 {
                    return Err(UpstreamError::Md5Refused {
                        upstream: upstream.to_string(),
                    });
                }
                warn_md5_once(upstream);
                let hashed = postgres_protocol::authentication::md5_hash(
                    user.as_bytes(),
                    master.as_bytes(),
                    salt,
                );
                let mut payload = Zeroizing::new(hashed.into_bytes());
                payload.push(0);
                send(stream, upstream, &wire::password_message(&payload)).await?;
            }
            // Deliberately not implemented. Sending the master in the clear to
            // a server that asked for it would put it on a network briefcred
            // has no control over, which is the whole thing this proxy exists
            // to stop happening to the *client's* credential.
            AuthRequest::CleartextPassword => {
                return Err(UpstreamError::UnsupportedMethod {
                    upstream: upstream.to_string(),
                    code: wire::AUTH_CLEARTEXT_PASSWORD,
                })
            }
            AuthRequest::SaslContinue(_) | AuthRequest::SaslFinal(_) => {
                return Err(UpstreamError::Protocol {
                    upstream: upstream.to_string(),
                    source: WireError::Malformed {
                        tag: 'R',
                        detail: "a SASL continuation arrived before a SASL request",
                    },
                })
            }
            AuthRequest::Unsupported(code) => {
                return Err(UpstreamError::UnsupportedMethod {
                    upstream: upstream.to_string(),
                    code,
                })
            }
        }
    }
}

/// The whole `SCRAM-SHA-256` exchange, ending at `AuthenticationOk`.
async fn sasl<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    upstream: &str,
    master: &Zeroizing<String>,
    mechanisms: &[String],
) -> Result<(), UpstreamError> {
    let scram_error = |source| UpstreamError::Scram {
        upstream: upstream.to_string(),
        source,
    };
    let mechanism = scram::select_mechanism(mechanisms).map_err(scram_error)?;
    let mut client = ScramClient::new(master).map_err(scram_error)?;

    send(
        stream,
        upstream,
        &wire::sasl_initial_response(mechanism, client.client_first().as_bytes()),
    )
    .await?;

    let server_first = expect_auth(stream, upstream, |request| match request {
        AuthRequest::SaslContinue(body) => Some(body),
        _ => None,
    })
    .await?;
    let server_first = as_text(upstream, &server_first)?;
    let client_final = client.client_final(&server_first).map_err(scram_error)?;
    send(
        stream,
        upstream,
        &wire::password_message(client_final.as_bytes()),
    )
    .await?;

    let server_final = expect_auth(stream, upstream, |request| match request {
        AuthRequest::SaslFinal(body) => Some(body),
        _ => None,
    })
    .await?;
    // Before anything else the server says is believed. A server that cannot
    // produce this signature does not hold the master, and a session relayed
    // from it would be one nobody authenticated.
    client
        .verify_server_final(&as_text(upstream, &server_final)?)
        .map_err(scram_error)?;

    match next_auth(stream, upstream).await? {
        AuthRequest::Ok => Ok(()),
        other => Err(UpstreamError::Protocol {
            upstream: upstream.to_string(),
            source: WireError::Malformed {
                tag: 'R',
                detail: match other {
                    AuthRequest::SaslContinue(_) | AuthRequest::SaslFinal(_) => {
                        "the SASL exchange did not end after the server's signature"
                    }
                    _ => "the server did not finish authentication after a valid SASL exchange",
                },
            },
        }),
    }
}

/// Read the next message, turning an `ErrorResponse` into a refusal.
///
/// Every read during authentication goes through here, because a PostgreSQL
/// server answers a bad password with an `ErrorResponse` rather than with a
/// negative acknowledgement, and treating that as a protocol failure would
/// lose the one sentence saying what was actually wrong.
async fn next_message<S: AsyncRead + Unpin>(
    stream: &mut S,
    upstream: &str,
) -> Result<Message, UpstreamError> {
    let message = wire::read_message(stream)
        .await
        .map_err(|source| UpstreamError::Protocol {
            upstream: upstream.to_string(),
            source,
        })?;
    if message.tag == wire::TAG_ERROR_RESPONSE {
        return Err(UpstreamError::Refused {
            upstream: upstream.to_string(),
            detail: error_text(&message.body),
        });
    }
    Ok(message)
}

/// The next message, required to be an authentication request.
async fn next_auth<S: AsyncRead + Unpin>(
    stream: &mut S,
    upstream: &str,
) -> Result<AuthRequest, UpstreamError> {
    let message = next_message(stream, upstream).await?;
    if message.tag != wire::TAG_AUTHENTICATION {
        return Err(UpstreamError::Protocol {
            upstream: upstream.to_string(),
            source: WireError::Malformed {
                tag: message.tag as char,
                detail: "expected an authentication request",
            },
        });
    }
    AuthRequest::parse(&message.body).map_err(|source| UpstreamError::Protocol {
        upstream: upstream.to_string(),
        source,
    })
}

/// The next authentication request, required to be the one `want` selects.
async fn expect_auth<S, F>(
    stream: &mut S,
    upstream: &str,
    want: F,
) -> Result<Vec<u8>, UpstreamError>
where
    S: AsyncRead + Unpin,
    F: Fn(AuthRequest) -> Option<Vec<u8>>,
{
    let request = next_auth(stream, upstream).await?;
    want(request).ok_or_else(|| UpstreamError::Protocol {
        upstream: upstream.to_string(),
        source: WireError::Malformed {
            tag: 'R',
            detail: "the server broke off the SASL exchange",
        },
    })
}

/// A SASL message's bytes as text.
fn as_text(upstream: &str, bytes: &[u8]) -> Result<String, UpstreamError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| UpstreamError::Protocol {
        upstream: upstream.to_string(),
        source: WireError::Malformed {
            tag: 'R',
            detail: "a SASL message is not UTF-8",
        },
    })
}

/// Write one message upstream.
async fn send<S: AsyncWrite + Unpin>(
    stream: &mut S,
    upstream: &str,
    message: &Message,
) -> Result<(), UpstreamError> {
    wire::write_message(stream, message)
        .await
        .map_err(|source| UpstreamError::Protocol {
            upstream: upstream.to_string(),
            source,
        })
}

/// Everything between `AuthenticationOk` and `ReadyForQuery`.
///
/// Collected rather than streamed because the client is still waiting to be
/// told it is authenticated: nothing may be written to it until the upstream
/// connection is known to be complete, and `ReadyForQuery` is what says so.
async fn read_greeting<S: AsyncRead + Unpin>(
    stream: &mut S,
    upstream: &str,
) -> Result<(Vec<Message>, Option<(i32, i32)>), UpstreamError> {
    let mut greeting = Vec::new();
    let mut backend_key = None;
    loop {
        let message = next_message(stream, upstream).await?;
        if message.tag == wire::TAG_BACKEND_KEY_DATA {
            backend_key = wire::backend_key_of(&message.body);
        }
        let ready = message.tag == wire::TAG_READY_FOR_QUERY;
        greeting.push(message);
        if ready {
            return Ok((greeting, backend_key));
        }
    }
}

/// The `M` field of an `ErrorResponse`, which is the human-readable message.
pub fn error_text(body: &[u8]) -> String {
    let mut rest = body;
    while let Some((&field, tail)) = rest.split_first() {
        if field == 0 {
            break;
        }
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(tail.len());
        if field == b'M' {
            return String::from_utf8_lossy(&tail[..end]).to_string();
        }
        rest = tail.get(end + 1..).unwrap_or(&[]);
    }
    "no message".to_string()
}

/// Forward a `CancelRequest` to `upstream` on a connection of its own.
///
/// Cancellation is a separate connection by design: it has to be possible while
/// the original one is busy. Nothing is read back — the server answers a cancel
/// request by closing the socket, whether or not it did anything.
pub async fn forward_cancel(upstream: &str, pid: i32, key: i32) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(upstream).await?;
    let mut packet = 16i32.to_be_bytes().to_vec();
    packet.extend_from_slice(&crate::pgproxy::startup::CANCEL_REQUEST.to_be_bytes());
    packet.extend_from_slice(&pid.to_be_bytes());
    packet.extend_from_slice(&key.to_be_bytes());
    stream.write_all(&packet).await?;
    stream.flush().await
}

/// How many bytes crossed in each direction of a relayed connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Transferred {
    /// Bytes the client sent towards the server.
    pub client_bytes: u64,
    /// Bytes the server sent back to the client.
    pub server_bytes: u64,
}

/// Copy bytes both ways until either side closes, counting as they go.
///
/// Nothing is parsed and nothing is held: each direction owns one
/// [`RELAY_BUFFER`]-sized buffer for the life of the connection, so a query
/// returning a gigabyte costs the same memory as one returning a row.
pub async fn relay<C, U>(client: C, upstream: U) -> Transferred
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let (client_bytes, server_bytes) = tokio::join!(
        pump(client_read, upstream_write),
        pump(upstream_read, client_write),
    );
    Transferred {
        client_bytes,
        server_bytes,
    }
}

/// Copy one direction, returning the count even when it ends in an error.
///
/// The count is returned rather than propagated because a connection that
/// failed halfway still moved bytes, and an audit row reporting zero for it
/// would be worse than no row at all. The peer's write half is shut down at the
/// end, which is what makes the *other* direction's read return zero and lets
/// the pair finish together.
async fn pump<R, W>(mut reader: R, mut writer: W) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; RELAY_BUFFER];
    let mut total = 0u64;
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        if writer.write_all(&buffer[..read]).await.is_err() {
            break;
        }
        total += read as u64;
    }
    let _ = writer.shutdown().await;
    total
}

/// Say once per daemon that MD5 authentication is in use.
///
/// Once, because it is a property of the configuration rather than of a
/// connection: a line per connection would be noise an operator learns to
/// ignore, which is the opposite of what a deprecation warning is for.
fn warn_md5_once(upstream: &str) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "briefcred-daemon: `{upstream}` uses MD5 authentication, which PostgreSQL has \
             deprecated and which is enabled here only by `pgproxy.allow_md5`; move the role \
             to scram-sha-256"
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_startup_packet_carries_the_configured_role_and_database() {
        let packet = startup_packet("reporting", "analytics", &BTreeMap::new());
        assert_eq!(
            i32::from_be_bytes(packet[..4].try_into().unwrap()) as usize,
            packet.len()
        );
        assert_eq!(&packet[4..8], &PROTOCOL_3_0.to_be_bytes());
        assert_eq!(&packet[8..], b"user\0reporting\0database\0analytics\0\0");
    }

    #[test]
    fn the_startup_packet_carries_the_allowed_parameters_and_no_others() {
        // The client's `user` and `database` never reach here: the caller has
        // already checked them and passes the profile's values instead.
        let packet = startup_packet(
            "reporting",
            "analytics",
            &BTreeMap::from([("application_name".to_string(), "psql".to_string())]),
        );
        let body = String::from_utf8_lossy(&packet[8..]).to_string();
        assert!(body.contains("application_name\u{0}psql"), "{body}");
        assert!(!body.contains("options"), "{body}");
    }

    #[test]
    fn the_message_a_server_refuses_with_is_read_out_of_its_error_response() {
        let message = wire::fatal_error("password authentication failed");
        assert_eq!(error_text(&message.body), "password authentication failed");
    }

    #[test]
    fn an_error_response_with_no_message_field_still_reads() {
        assert_eq!(error_text(&[b'C', b'2', b'8', 0, 0]), "no message");
        assert_eq!(error_text(&[0]), "no message");
        assert_eq!(error_text(&[]), "no message");
    }

    #[tokio::test]
    async fn a_relay_counts_every_byte_it_moves_in_each_direction() {
        let (mut client, client_side) = tokio::io::duplex(4096);
        let (mut server, server_side) = tokio::io::duplex(4096);
        let relaying = tokio::spawn(relay(client_side, server_side));

        client.write_all(b"select 1").await.unwrap();
        let mut seen = [0u8; 8];
        server.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"select 1");

        server.write_all(b"one row here").await.unwrap();
        let mut back = [0u8; 12];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"one row here");

        drop(client);
        drop(server);
        let transferred = relaying.await.unwrap();
        assert_eq!(
            transferred,
            Transferred {
                client_bytes: 8,
                server_bytes: 12
            }
        );
    }

    #[tokio::test]
    async fn a_relay_ends_when_either_side_closes() {
        let (client, client_side) = tokio::io::duplex(64);
        let (server, server_side) = tokio::io::duplex(64);
        let relaying = tokio::spawn(relay(client_side, server_side));
        drop(client);
        drop(server);
        assert_eq!(relaying.await.unwrap(), Transferred::default());
    }

    #[tokio::test]
    async fn a_body_larger_than_the_buffer_crosses_whole_and_is_counted_whole() {
        // A hundred kibibytes through a sixteen-kibibyte buffer: the point is
        // that it arrives complete without the buffer having grown to fit it.
        let payload = vec![b'x'; 100 * 1024];
        let (mut client, client_side) = tokio::io::duplex(8192);
        let (mut server, server_side) = tokio::io::duplex(8192);
        let relaying = tokio::spawn(relay(client_side, server_side));

        let sending = tokio::spawn({
            let payload = payload.clone();
            async move {
                client.write_all(&payload).await.unwrap();
                client.shutdown().await.unwrap();
                client
            }
        });
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload);

        drop(server);
        let _client = sending.await.unwrap();
        assert_eq!(relaying.await.unwrap().client_bytes, payload.len() as u64);
    }

    /// A server that answers one startup packet with a fixed script.
    async fn scripted(script: Vec<Message>) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut length = [0u8; 4];
            stream.read_exact(&mut length).await.unwrap();
            let mut body = vec![0u8; i32::from_be_bytes(length) as usize - 4];
            stream.read_exact(&mut body).await.unwrap();
            for message in &script {
                wire::write_message(&mut stream, message).await.unwrap();
            }
            // Whatever the client sent after the startup packet, so a test can
            // assert on what briefcred replied with.
            let mut replies = Vec::new();
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                stream.read_to_end(&mut replies),
            )
            .await;
            replies
        });
        (address, handle)
    }

    fn auth_message(code: i32, rest: &[u8]) -> Message {
        let mut body = code.to_be_bytes().to_vec();
        body.extend_from_slice(rest);
        Message {
            tag: wire::TAG_AUTHENTICATION,
            body,
        }
    }

    fn ready() -> Message {
        Message {
            tag: wire::TAG_READY_FOR_QUERY,
            body: vec![b'I'],
        }
    }

    async fn connect_to(address: &str, allow_md5: bool) -> Result<Upstream, UpstreamError> {
        connect(
            address,
            "reporting",
            "analytics",
            &Zeroizing::new("hunter2".to_string()),
            &BTreeMap::new(),
            allow_md5,
        )
        .await
    }

    #[tokio::test]
    async fn a_trust_server_needs_no_password_and_its_greeting_is_kept() {
        let mut key_data = 4242i32.to_be_bytes().to_vec();
        key_data.extend_from_slice(&99i32.to_be_bytes());
        let (address, _server) = scripted(vec![
            auth_message(wire::AUTH_OK, &[]),
            Message {
                tag: b'S',
                body: b"server_version\09.6\0".to_vec(),
            },
            Message {
                tag: wire::TAG_BACKEND_KEY_DATA,
                body: key_data,
            },
            ready(),
        ])
        .await;

        let upstream = connect_to(&address, false).await.unwrap();
        assert_eq!(upstream.backend_key, Some((4242, 99)));
        assert_eq!(
            upstream.greeting.len(),
            3,
            "everything after AuthenticationOk is relayed: {upstream:?}"
        );
        assert_eq!(
            upstream.greeting.last().unwrap().tag,
            wire::TAG_READY_FOR_QUERY
        );
    }

    #[tokio::test]
    async fn md5_is_refused_by_default_and_the_message_names_the_switch() {
        let (address, _server) =
            scripted(vec![auth_message(wire::AUTH_MD5_PASSWORD, &[1, 2, 3, 4])]).await;
        let err = connect_to(&address, false).await.unwrap_err();
        assert!(matches!(err, UpstreamError::Md5Refused { .. }), "{err}");
        assert!(err.to_string().contains("pgproxy.allow_md5"), "{err}");
    }

    #[tokio::test]
    async fn md5_is_answered_with_the_hash_postgres_expects_when_it_is_allowed() {
        let (address, server) = scripted(vec![
            auth_message(wire::AUTH_MD5_PASSWORD, &[1, 2, 3, 4]),
            auth_message(wire::AUTH_OK, &[]),
            ready(),
        ])
        .await;
        connect_to(&address, true).await.unwrap();

        let replies = server.await.unwrap();
        let expected =
            postgres_protocol::authentication::md5_hash(b"reporting", b"hunter2", [1, 2, 3, 4]);
        let sent = String::from_utf8_lossy(&replies).to_string();
        assert!(sent.contains(&expected), "{sent} does not carry {expected}");
        assert!(
            !sent.contains("hunter2"),
            "the master must never go on the wire in the clear"
        );
    }

    #[tokio::test]
    async fn cleartext_upstream_authentication_is_refused_rather_than_sending_the_master() {
        let (address, _server) =
            scripted(vec![auth_message(wire::AUTH_CLEARTEXT_PASSWORD, &[])]).await;
        let err = connect_to(&address, true).await.unwrap_err();
        assert!(
            matches!(err, UpstreamError::UnsupportedMethod { code, .. } if code == 3),
            "{err}"
        );
    }

    #[tokio::test]
    async fn an_authentication_method_briefcred_does_not_implement_is_refused() {
        // 7 is GSSAPI. Treating an unknown code as success is the failure that
        // would splice a client to an unauthenticated connection.
        let (address, _server) = scripted(vec![auth_message(7, &[])]).await;
        let err = connect_to(&address, true).await.unwrap_err();
        assert!(
            matches!(err, UpstreamError::UnsupportedMethod { code: 7, .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_server_offering_only_channel_bound_scram_is_refused_not_downgraded() {
        let (address, _server) = scripted(vec![auth_message(
            wire::AUTH_SASL,
            b"SCRAM-SHA-256-PLUS\0\0",
        )])
        .await;
        let err = connect_to(&address, false).await.unwrap_err();
        assert!(
            matches!(
                err,
                UpstreamError::Scram {
                    source: ScramError::NoUsableMechanism { .. },
                    ..
                }
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_server_that_refuses_the_master_reports_what_it_said() {
        let (address, _server) = scripted(vec![wire::fatal_error(
            "password authentication failed for user \"reporting\"",
        )])
        .await;
        let err = connect_to(&address, false).await.unwrap_err();
        assert!(
            matches!(&err, UpstreamError::Refused { detail, .. }
                if detail.contains("password authentication failed")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_server_that_is_not_there_is_reported_as_unreachable() {
        // Bind and drop, so the port is one nothing is listening on.
        let port = {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.local_addr().unwrap().port()
        };
        let err = connect_to(&format!("127.0.0.1:{port}"), false)
            .await
            .unwrap_err();
        assert!(matches!(err, UpstreamError::Unreachable { .. }), "{err}");
    }

    #[tokio::test]
    async fn a_scram_exchange_that_the_server_breaks_off_is_refused() {
        let (address, _server) = scripted(vec![
            auth_message(wire::AUTH_SASL, b"SCRAM-SHA-256\0\0"),
            auth_message(wire::AUTH_OK, &[]),
        ])
        .await;
        let err = connect_to(&address, false).await.unwrap_err();
        assert!(matches!(err, UpstreamError::Protocol { .. }), "{err}");
    }

    #[tokio::test]
    async fn an_upstream_never_prints_anything_worth_stealing() {
        let (address, _server) = scripted(vec![auth_message(wire::AUTH_OK, &[]), ready()]).await;
        let upstream = connect_to(&address, false).await.unwrap();
        let rendered = format!("{upstream:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("greeting_messages"), "{rendered}");
    }
}
