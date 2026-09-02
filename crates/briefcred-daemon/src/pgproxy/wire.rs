//! The PostgreSQL v3 message frame, and the few messages briefcred writes
//! itself.
//!
//! Almost every byte the proxy handles is copied rather than understood: once
//! both ends are authenticated the two halves are spliced together and neither
//! side's messages are parsed again. What this module covers is the small
//! window before that, where briefcred is genuinely a participant — the
//! authentication request it makes of the client, the SASL messages it exchanges
//! upstream, and the error it writes when it refuses.
//!
//! # The frame
//!
//! After the startup packet, every message on the wire is:
//!
//! ```text
//! Int8 tag | Int32 length (counting itself, not the tag) | body
//! ```
//!
//! [`read_message`] returns the tag and the body with the length stripped;
//! [`write_message`] puts it back. Nothing here ever reads a length without
//! bounding it, because the length is the one field an unauthenticated peer
//! fully controls: a four-byte header could otherwise ask the daemon for four
//! gigabytes of heap.

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// The largest message briefcred will read while it is still authenticating.
///
/// Authentication messages are tens of bytes; a SASL exchange is hundreds. A
/// mebibyte is far past anything legitimate and is a bound, which is the
/// property that matters when the sender has not proved anything yet.
pub const MAX_AUTH_MESSAGE: usize = 1024 * 1024;

/// `AuthenticationOk`.
pub const AUTH_OK: i32 = 0;

/// `AuthenticationCleartextPassword`.
pub const AUTH_CLEARTEXT_PASSWORD: i32 = 3;

/// `AuthenticationMD5Password`, followed by a four-byte salt.
pub const AUTH_MD5_PASSWORD: i32 = 5;

/// `AuthenticationSASL`, followed by the mechanism names.
pub const AUTH_SASL: i32 = 10;

/// `AuthenticationSASLContinue`.
pub const AUTH_SASL_CONTINUE: i32 = 11;

/// `AuthenticationSASLFinal`.
pub const AUTH_SASL_FINAL: i32 = 12;

/// The backend message tag for an authentication request.
pub const TAG_AUTHENTICATION: u8 = b'R';

/// The backend message tag for an error.
pub const TAG_ERROR_RESPONSE: u8 = b'E';

/// The backend message tag for a notice, which is not an error.
pub const TAG_NOTICE_RESPONSE: u8 = b'N';

/// The backend message tag for `BackendKeyData`.
pub const TAG_BACKEND_KEY_DATA: u8 = b'K';

/// The backend message tag for `ReadyForQuery`.
pub const TAG_READY_FOR_QUERY: u8 = b'Z';

/// The frontend message tag for a password, a SASL initial response, and a
/// SASL response. PostgreSQL spends one tag on all three; which one it is
/// depends on what the server last asked for.
pub const TAG_PASSWORD: u8 = b'p';

/// The SQLSTATE briefcred refuses an unauthorised connection with.
///
/// `28000` is `invalid_authorization_specification`, which is what a client
/// presenting a token briefcred will not honour has done. Every *authentication*
/// refusal uses it, whatever the underlying reason: telling a caller which check
/// failed is telling an attacker which half of the credential to fix.
pub const SQLSTATE_INVALID_AUTHORIZATION: &str = "28000";

/// The SQLSTATE for a connection that was authorised and then failed anyway.
///
/// `08006` is `connection_failure`. It is the honest answer when the client's
/// credentials were fine and the real database could not be reached: a `28000`
/// there would send a user to check a token that was never the problem.
pub const SQLSTATE_CONNECTION_FAILURE: &str = "08006";

/// The SQLSTATE for a connection briefcred ends while it is in use.
///
/// `57P01` is `admin_shutdown`, which is what PostgreSQL itself sends when an
/// administrator terminates a backend — and it is what a driver already knows
/// how to interpret as "this connection is gone, reconnect if you still can".
pub const SQLSTATE_ADMIN_SHUTDOWN: &str = "57P01";

/// The SQLSTATE for a connection the session's quota refuses.
///
/// `53300` is `too_many_connections`, from the `53` class — "insufficient
/// resources". Deliberately not `28000`: a driver reads that as a credential
/// problem and stops, where the truthful answer here is that the credential is
/// fine and the client is asking for too much of it.
pub const SQLSTATE_TOO_MANY_CONNECTIONS: &str = "53300";

/// Why a message could not be read.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The peer closed the connection.
    #[error("the connection closed before the message was complete")]
    Closed,

    /// The declared length is impossible or past [`MAX_AUTH_MESSAGE`].
    #[error("a message declared a length of {0} bytes, which briefcred will not read")]
    Length(i64),

    /// The message body is not what its tag requires.
    #[error("a `{tag}` message is malformed: {detail}")]
    Malformed {
        /// The tag as it appeared on the wire.
        tag: char,
        /// What was wrong with the body.
        detail: &'static str,
    },

    /// The underlying socket failed.
    #[error("{0}")]
    Io(String),
}

impl From<std::io::Error> for WireError {
    fn from(err: std::io::Error) -> WireError {
        match err.kind() {
            std::io::ErrorKind::UnexpectedEof => WireError::Closed,
            _ => WireError::Io(err.to_string()),
        }
    }
}

/// One tagged message, body only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The message's tag byte.
    pub tag: u8,
    /// The body, with the four length bytes already removed.
    pub body: Vec<u8>,
}

impl Message {
    /// The bytes this message occupies on the wire, tag and length included.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 5);
        out.push(self.tag);
        out.extend_from_slice(&((self.body.len() + 4) as i32).to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// Read one tagged message, bounded by [`MAX_AUTH_MESSAGE`].
pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Message, WireError> {
    let mut tag = [0u8; 1];
    reader.read_exact(&mut tag).await?;
    let mut length = [0u8; 4];
    reader.read_exact(&mut length).await?;
    let declared = i32::from_be_bytes(length);
    // The length counts itself, so anything under four is a lie, and the cap
    // is what stops an unauthenticated peer choosing an allocation size.
    if declared < 4 || declared as usize - 4 > MAX_AUTH_MESSAGE {
        return Err(WireError::Length(declared as i64));
    }
    let mut body = vec![0u8; declared as usize - 4];
    reader.read_exact(&mut body).await?;
    Ok(Message { tag: tag[0], body })
}

/// Write one tagged message and flush it.
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &Message,
) -> Result<(), WireError> {
    writer.write_all(&message.encode()).await?;
    writer.flush().await?;
    Ok(())
}

/// What an `AuthenticationRequest` from a server is asking for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthRequest {
    /// Authentication is complete.
    Ok,
    /// A password in the clear.
    CleartextPassword,
    /// An MD5-hashed password, with the server's four-byte salt.
    Md5Password([u8; 4]),
    /// A SASL exchange, with the mechanisms the server offers.
    Sasl(Vec<String>),
    /// A SASL exchange continues, with the server's message.
    SaslContinue(Vec<u8>),
    /// A SASL exchange ends, with the server's final message.
    SaslFinal(Vec<u8>),
    /// Something briefcred does not implement, with the code the server sent.
    Unsupported(i32),
}

impl AuthRequest {
    /// Interpret the body of an `R` message.
    pub fn parse(body: &[u8]) -> Result<AuthRequest, WireError> {
        let malformed = |detail| WireError::Malformed { tag: 'R', detail };
        let code = body
            .get(..4)
            .map(|bytes| i32::from_be_bytes(bytes.try_into().expect("four bytes")))
            .ok_or_else(|| malformed("it carries no request code"))?;
        let rest = &body[4..];
        Ok(match code {
            AUTH_OK => AuthRequest::Ok,
            AUTH_CLEARTEXT_PASSWORD => AuthRequest::CleartextPassword,
            AUTH_MD5_PASSWORD => AuthRequest::Md5Password(
                rest.try_into()
                    .map_err(|_| malformed("an MD5 request needs a four-byte salt"))?,
            ),
            AUTH_SASL => AuthRequest::Sasl(mechanism_list(rest)?),
            AUTH_SASL_CONTINUE => AuthRequest::SaslContinue(rest.to_vec()),
            AUTH_SASL_FINAL => AuthRequest::SaslFinal(rest.to_vec()),
            other => AuthRequest::Unsupported(other),
        })
    }
}

/// The NUL-terminated mechanism names in an `AuthenticationSASL` body.
fn mechanism_list(body: &[u8]) -> Result<Vec<String>, WireError> {
    let malformed = |detail| WireError::Malformed { tag: 'R', detail };
    let mut names = Vec::new();
    let mut rest = body;
    loop {
        let end = rest
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| malformed("the mechanism list is not terminated"))?;
        if end == 0 {
            return Ok(names);
        }
        names.push(
            String::from_utf8(rest[..end].to_vec())
                .map_err(|_| malformed("a mechanism name is not UTF-8"))?,
        );
        rest = &rest[end + 1..];
    }
}

/// The `AuthenticationOk` a client is told authentication succeeded with.
pub fn authentication_ok() -> Message {
    Message {
        tag: TAG_AUTHENTICATION,
        body: AUTH_OK.to_be_bytes().to_vec(),
    }
}

/// The `AuthenticationCleartextPassword` briefcred asks a client for.
///
/// Cleartext, and only ever over loopback: see [`crate::pgproxy`] for why the
/// alternatives buy nothing here.
pub fn authentication_cleartext_password() -> Message {
    Message {
        tag: TAG_AUTHENTICATION,
        body: AUTH_CLEARTEXT_PASSWORD.to_be_bytes().to_vec(),
    }
}

/// A fatal `ErrorResponse` carrying `message` under `sqlstate`.
///
/// `message` is briefcred's own text and never a peer's: an error body is the
/// one thing a refused client always gets to read, so nothing that came off the
/// wire goes back out in it. The `sqlstate` is what a driver branches on, so it
/// has to distinguish the three things that can end a connection — the
/// credential was not good, the database could not be reached, or briefcred
/// ended a connection that was already running.
pub fn fatal_error(sqlstate: &str, message: &str) -> Message {
    let mut body = Vec::new();
    for (field, value) in [
        (b'S', "FATAL"),
        (b'V', "FATAL"),
        (b'C', sqlstate),
        (b'M', message),
    ] {
        body.push(field);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    Message {
        tag: TAG_ERROR_RESPONSE,
        body,
    }
}

/// A frontend password message, which is also how SASL responses travel.
pub fn password_message(payload: &[u8]) -> Message {
    Message {
        tag: TAG_PASSWORD,
        body: payload.to_vec(),
    }
}

/// The `SASLInitialResponse` that opens a SASL exchange.
pub fn sasl_initial_response(mechanism: &str, initial: &[u8]) -> Message {
    let mut body = Vec::with_capacity(mechanism.len() + initial.len() + 5);
    body.extend_from_slice(mechanism.as_bytes());
    body.push(0);
    body.extend_from_slice(&(initial.len() as i32).to_be_bytes());
    body.extend_from_slice(initial);
    Message {
        tag: TAG_PASSWORD,
        body,
    }
}

/// The password a client sent, as text.
///
/// The body is one NUL-terminated string; anything after the NUL is ignored,
/// which is what PostgreSQL itself does.
pub fn password_of(body: &[u8]) -> Result<String, WireError> {
    let end = body
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(body.len());
    String::from_utf8(body[..end].to_vec()).map_err(|_| WireError::Malformed {
        tag: 'p',
        detail: "the password is not UTF-8",
    })
}

/// The `(pid, key)` a `BackendKeyData` message carries.
pub fn backend_key_of(body: &[u8]) -> Option<(i32, i32)> {
    let pid = i32::from_be_bytes(body.get(..4)?.try_into().ok()?);
    let key = i32::from_be_bytes(body.get(4..8)?.try_into().ok()?);
    Some((pid, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_message_round_trips_through_its_own_encoding() {
        let message = Message {
            tag: b'Q',
            body: b"SELECT 1".to_vec(),
        };
        let encoded = message.encode();
        assert_eq!(encoded[0], b'Q');
        assert_eq!(&encoded[1..5], &(8i32 + 4).to_be_bytes());
        let mut cursor = std::io::Cursor::new(encoded);
        assert_eq!(read_message(&mut cursor).await.unwrap(), message);
    }

    #[tokio::test]
    async fn a_message_that_declares_more_than_briefcred_will_read_is_refused() {
        // The length is the one field an unauthenticated peer fully controls.
        let mut frame = vec![b'p'];
        frame.extend_from_slice(&(MAX_AUTH_MESSAGE as i32 + 5).to_be_bytes());
        let mut cursor = std::io::Cursor::new(frame);
        let err = read_message(&mut cursor).await.unwrap_err();
        assert!(matches!(err, WireError::Length(_)), "{err}");
    }

    #[tokio::test]
    async fn a_message_that_declares_less_than_its_own_header_is_refused() {
        let mut frame = vec![b'p'];
        frame.extend_from_slice(&3i32.to_be_bytes());
        let mut cursor = std::io::Cursor::new(frame);
        assert!(matches!(
            read_message(&mut cursor).await.unwrap_err(),
            WireError::Length(3)
        ));
    }

    #[tokio::test]
    async fn a_truncated_message_is_a_closed_connection_rather_than_a_short_body() {
        let mut frame = vec![b'p'];
        frame.extend_from_slice(&10i32.to_be_bytes());
        frame.extend_from_slice(b"ab");
        let mut cursor = std::io::Cursor::new(frame);
        assert!(matches!(
            read_message(&mut cursor).await.unwrap_err(),
            WireError::Closed
        ));
    }

    fn auth(code: i32, rest: &[u8]) -> Vec<u8> {
        let mut body = code.to_be_bytes().to_vec();
        body.extend_from_slice(rest);
        body
    }

    #[test]
    fn every_authentication_request_briefcred_understands_is_recognised() {
        assert_eq!(AuthRequest::parse(&auth(0, &[])).unwrap(), AuthRequest::Ok);
        assert_eq!(
            AuthRequest::parse(&auth(3, &[])).unwrap(),
            AuthRequest::CleartextPassword
        );
        assert_eq!(
            AuthRequest::parse(&auth(5, &[1, 2, 3, 4])).unwrap(),
            AuthRequest::Md5Password([1, 2, 3, 4])
        );
        assert_eq!(
            AuthRequest::parse(&auth(10, b"SCRAM-SHA-256\0SCRAM-SHA-256-PLUS\0\0")).unwrap(),
            AuthRequest::Sasl(vec![
                "SCRAM-SHA-256".to_string(),
                "SCRAM-SHA-256-PLUS".to_string()
            ])
        );
        assert_eq!(
            AuthRequest::parse(&auth(11, b"r=abc")).unwrap(),
            AuthRequest::SaslContinue(b"r=abc".to_vec())
        );
        assert_eq!(
            AuthRequest::parse(&auth(12, b"v=abc")).unwrap(),
            AuthRequest::SaslFinal(b"v=abc".to_vec())
        );
    }

    #[test]
    fn an_authentication_method_briefcred_does_not_implement_names_its_code() {
        // GSSAPI is 7. It has to be reported rather than silently treated as
        // success, which is the shape of failure that would forward a session
        // nobody authenticated.
        assert_eq!(
            AuthRequest::parse(&auth(7, &[])).unwrap(),
            AuthRequest::Unsupported(7)
        );
    }

    #[test]
    fn a_malformed_authentication_request_is_refused() {
        assert!(AuthRequest::parse(&[]).is_err());
        assert!(AuthRequest::parse(&auth(5, &[1, 2])).is_err());
        assert!(AuthRequest::parse(&auth(10, b"SCRAM-SHA-256")).is_err());
    }

    #[test]
    fn an_error_response_carries_the_sqlstate_it_was_given() {
        let message = fatal_error(SQLSTATE_INVALID_AUTHORIZATION, "no");
        assert_eq!(message.tag, TAG_ERROR_RESPONSE);
        let body = String::from_utf8_lossy(&message.body).to_string();
        assert!(body.contains("FATAL"), "{body}");
        assert!(body.contains(SQLSTATE_INVALID_AUTHORIZATION), "{body}");
        assert!(body.contains("no"), "{body}");
        assert_eq!(*message.body.last().unwrap(), 0, "the field list ends");
    }

    #[test]
    fn the_three_sqlstates_are_distinct_so_a_driver_can_branch_on_them() {
        // A client that cannot tell "your token is no good" from "the database
        // is down" from "briefcred ended this" cannot decide whether to retry.
        for (sqlstate, expected) in [
            (SQLSTATE_INVALID_AUTHORIZATION, "28000"),
            (SQLSTATE_CONNECTION_FAILURE, "08006"),
            (SQLSTATE_ADMIN_SHUTDOWN, "57P01"),
            (SQLSTATE_TOO_MANY_CONNECTIONS, "53300"),
        ] {
            assert_eq!(sqlstate, expected);
            let body = String::from_utf8_lossy(&fatal_error(sqlstate, "x").body).to_string();
            assert!(body.contains(expected), "{body}");
        }
    }

    #[test]
    fn the_two_authentication_messages_briefcred_writes_are_the_documented_ones() {
        assert_eq!(authentication_ok().body, AUTH_OK.to_be_bytes());
        assert_eq!(
            authentication_cleartext_password().body,
            AUTH_CLEARTEXT_PASSWORD.to_be_bytes()
        );
        assert_eq!(authentication_ok().tag, TAG_AUTHENTICATION);
    }

    #[test]
    fn a_password_message_is_read_up_to_its_terminator() {
        assert_eq!(password_of(b"hunter2\0").unwrap(), "hunter2");
        assert_eq!(password_of(b"hunter2\0trailing").unwrap(), "hunter2");
        assert_eq!(password_of(b"unterminated").unwrap(), "unterminated");
        assert_eq!(password_of(b"\0").unwrap(), "");
        assert!(password_of(&[0xff, 0xfe, 0]).is_err());
    }

    #[test]
    fn a_sasl_initial_response_names_its_mechanism_and_lengths_its_payload() {
        let message = sasl_initial_response("SCRAM-SHA-256", b"n,,n=,r=x");
        assert_eq!(message.tag, TAG_PASSWORD);
        assert_eq!(&message.body[..13], b"SCRAM-SHA-256");
        assert_eq!(message.body[13], 0);
        assert_eq!(&message.body[14..18], &9i32.to_be_bytes());
        assert_eq!(&message.body[18..], b"n,,n=,r=x");
    }

    #[test]
    fn a_plain_password_message_carries_only_its_payload() {
        assert_eq!(password_message(b"c=biws").body, b"c=biws");
    }

    #[test]
    fn a_backend_key_is_read_as_two_signed_integers() {
        let mut body = 4242i32.to_be_bytes().to_vec();
        body.extend_from_slice(&(-7i32).to_be_bytes());
        assert_eq!(backend_key_of(&body), Some((4242, -7)));
        assert_eq!(backend_key_of(&body[..7]), None);
    }
}
