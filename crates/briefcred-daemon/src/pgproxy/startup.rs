//! The startup packet, and the three other things a client might open with.
//!
//! A PostgreSQL connection does not begin with a tagged message. It begins with
//! a length and a four-byte code, and that code decides what the connection is:
//!
//! | code | what it is | what briefcred does |
//! | --- | --- | --- |
//! | `196608` | protocol 3.0 startup | reads the parameters and authenticates |
//! | `80877103` | `SSLRequest` | answers `N`, or `S` and terminates TLS |
//! | `80877104` | `GSSENCRequest` | answers `N` |
//! | `80877102` | `CancelRequest` | forwards it upstream, or drops it |
//!
//! The two negotiation requests are answered and the client then sends another
//! opening packet, so reading one is a loop rather than a single call — but a
//! bounded one, because a client that only ever sends `SSLRequest` must not be
//! able to keep a daemon task alive indefinitely.
//!
//! # What survives from the client's parameters
//!
//! Almost nothing. `user` becomes the session identifier to look up, `database`
//! is checked against the credential's configuration and otherwise discarded,
//! and of the rest only [`FORWARDED_PARAMETERS`] are passed on. That is not
//! laziness: a startup parameter such as `options` can set arbitrary
//! `postgresql.conf` settings for the session, and forwarding one would let a
//! subprocess reconfigure a connection authenticated with somebody else's
//! master.

use std::collections::BTreeMap;

use tokio::io::{AsyncRead, AsyncReadExt as _};

/// Protocol 3.0, the only one briefcred speaks.
pub const PROTOCOL_3_0: i32 = 196_608;

/// The code that asks to negotiate TLS.
pub const SSL_REQUEST: i32 = 80_877_103;

/// The code that asks to negotiate GSSAPI encryption.
pub const GSSENC_REQUEST: i32 = 80_877_104;

/// The code that asks to cancel a running query.
pub const CANCEL_REQUEST: i32 = 80_877_102;

/// The largest startup packet briefcred will read.
///
/// PostgreSQL's own limit. The packet arrives before anything has been
/// authenticated, so the bound is what stops a length field from choosing an
/// allocation size.
pub const MAX_STARTUP_PACKET: usize = 10_000;

/// The startup parameters briefcred passes through to the real server.
///
/// Two, both cosmetic: `application_name` is what shows in `pg_stat_activity`,
/// and `client_encoding` decides how text comes back. Everything else — and
/// `options` above all, which can set arbitrary configuration for the session —
/// is dropped, because the upstream connection is authenticated with a master
/// the client does not hold and must not get to reconfigure.
pub const FORWARDED_PARAMETERS: [&str; 2] = ["application_name", "client_encoding"];

/// How many negotiation packets a client may send before a real startup.
///
/// libpq sends at most two, `GSSENCRequest` then `SSLRequest`. Four is room to
/// spare and still a bound.
const MAX_NEGOTIATIONS: usize = 4;

/// What a client opened the connection with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opening {
    /// A protocol 3.0 startup packet.
    Startup(Startup),
    /// A request to negotiate TLS.
    Ssl,
    /// A request to negotiate GSSAPI encryption.
    GssEnc,
    /// A request to cancel a query on another connection.
    Cancel {
        /// The backend process id the client was given.
        pid: i32,
        /// The secret key it was given alongside.
        key: i32,
    },
}

/// A protocol 3.0 startup packet, reduced to what briefcred acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Startup {
    /// The `user` parameter, which for the Postgres proxy is a session id.
    pub user: String,
    /// The `database` parameter, when the client sent one.
    ///
    /// Absent means "the same as the user", which is libpq's rule. briefcred
    /// does not apply that rule — a session identifier is not a database name —
    /// so an absent `database` is checked against the credential's `dbname`
    /// like any other value and fails unless they happen to match.
    pub database: Option<String>,
    /// The parameters in [`FORWARDED_PARAMETERS`] the client sent.
    pub forwarded: BTreeMap<String, String>,
}

/// Why an opening packet could not be read or is not one briefcred serves.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartupError {
    /// The client closed before sending a complete packet.
    #[error("the client closed the connection before sending a startup packet")]
    Closed,

    /// The declared length is impossible or past [`MAX_STARTUP_PACKET`].
    #[error("the startup packet declares a length of {0} bytes, which briefcred will not read")]
    Length(i64),

    /// The protocol version is not 3.0.
    #[error(
        "this client speaks protocol {major}.{minor}; briefcred's Postgres proxy speaks only 3.0"
    )]
    UnsupportedProtocol {
        /// The major version the client asked for.
        major: u16,
        /// The minor version the client asked for.
        minor: u16,
    },

    /// The parameter list is not well formed.
    #[error("the startup packet is malformed: {0}")]
    Malformed(&'static str),

    /// The packet carries no `user`, which briefcred needs before anything else.
    #[error("the startup packet names no `user`")]
    MissingUser,

    /// The client sent nothing but negotiation requests.
    #[error("the client sent {MAX_NEGOTIATIONS} negotiation requests and no startup packet")]
    TooManyNegotiations,

    /// The underlying socket failed.
    #[error("{0}")]
    Io(String),
}

impl From<std::io::Error> for StartupError {
    fn from(err: std::io::Error) -> StartupError {
        match err.kind() {
            std::io::ErrorKind::UnexpectedEof => StartupError::Closed,
            _ => StartupError::Io(err.to_string()),
        }
    }
}

/// Read one opening packet: its length, its code, and its payload.
pub async fn read_opening<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Opening, StartupError> {
    let mut length = [0u8; 4];
    reader.read_exact(&mut length).await?;
    let declared = i32::from_be_bytes(length);
    // The length counts itself and the four-byte code, so eight is the floor.
    if declared < 8 || declared as usize > MAX_STARTUP_PACKET {
        return Err(StartupError::Length(declared as i64));
    }
    let mut rest = vec![0u8; declared as usize - 4];
    reader.read_exact(&mut rest).await?;
    parse_opening(&rest)
}

/// Interpret an opening packet's body: the four-byte code and what follows.
///
/// Split from [`read_opening`] so every shape of packet can be tested without
/// a socket.
pub fn parse_opening(body: &[u8]) -> Result<Opening, StartupError> {
    let code = body
        .get(..4)
        .map(|bytes| i32::from_be_bytes(bytes.try_into().expect("four bytes")))
        .ok_or(StartupError::Malformed("it carries no protocol code"))?;
    let payload = &body[4..];
    match code {
        SSL_REQUEST => Ok(Opening::Ssl),
        GSSENC_REQUEST => Ok(Opening::GssEnc),
        CANCEL_REQUEST => {
            let pid = payload
                .get(..4)
                .map(|b| i32::from_be_bytes(b.try_into().expect("four bytes")))
                .ok_or(StartupError::Malformed("a cancel request carries no pid"))?;
            let key = payload
                .get(4..8)
                .map(|b| i32::from_be_bytes(b.try_into().expect("four bytes")))
                .ok_or(StartupError::Malformed("a cancel request carries no key"))?;
            Ok(Opening::Cancel { pid, key })
        }
        PROTOCOL_3_0 => Ok(Opening::Startup(parse_parameters(payload)?)),
        other => Err(StartupError::UnsupportedProtocol {
            major: (other >> 16) as u16,
            minor: (other & 0xffff) as u16,
        }),
    }
}

/// The NUL-terminated key/value pairs of a startup packet.
fn parse_parameters(payload: &[u8]) -> Result<Startup, StartupError> {
    let mut user = None;
    let mut database = None;
    let mut forwarded = BTreeMap::new();

    let mut rest = payload;
    loop {
        let (key, tail) = next_string(rest)?;
        // An empty key ends the list. Anything after it is padding.
        if key.is_empty() {
            break;
        }
        let (value, tail) = next_string(tail)?;
        rest = tail;
        match key.as_str() {
            "user" => user = Some(value),
            "database" => database = Some(value),
            _ if FORWARDED_PARAMETERS.contains(&key.as_str()) => {
                forwarded.insert(key, value);
            }
            // Dropped on purpose. See the module documentation: `options` in
            // particular can set session configuration, and this connection is
            // authenticated with a master the client does not hold.
            _ => {}
        }
    }

    let user = user
        .filter(|u| !u.is_empty())
        .ok_or(StartupError::MissingUser)?;
    Ok(Startup {
        user,
        database: database.filter(|d| !d.is_empty()),
        forwarded,
    })
}

/// One NUL-terminated string and whatever follows it.
fn next_string(bytes: &[u8]) -> Result<(String, &[u8]), StartupError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(StartupError::Malformed("a parameter is not NUL-terminated"))?;
    let text = String::from_utf8(bytes[..end].to_vec())
        .map_err(|_| StartupError::Malformed("a parameter is not UTF-8"))?;
    Ok((text, &bytes[end + 1..]))
}

/// Read opening packets, answering negotiation requests, until a real one.
///
/// `negotiate` is handed the stream and the request that was made, and returns
/// the stream to carry on reading from. It takes ownership because answering
/// `SSLRequest` with `S` means the next byte is a TLS record: the stream the
/// loop reads from afterwards is a *different* stream, wrapped around the same
/// socket, and a callback that only borrowed could not perform that swap.
///
/// The loop is bounded. A client that only ever sends negotiation requests
/// would otherwise hold a daemon task open with a packet it costs nothing to
/// repeat.
pub async fn read_startup<S, F, Fut>(
    stream: S,
    mut negotiate: F,
) -> Result<(S, Opening), StartupError>
where
    S: AsyncRead + Unpin,
    F: FnMut(S, Opening) -> Fut,
    Fut: std::future::Future<Output = Result<S, StartupError>>,
{
    let mut stream = stream;
    for _ in 0..MAX_NEGOTIATIONS {
        match read_opening(&mut stream).await? {
            request @ (Opening::Ssl | Opening::GssEnc) => {
                stream = negotiate(stream, request).await?;
            }
            settled => return Ok((stream, settled)),
        }
    }
    Err(StartupError::TooManyNegotiations)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The body of a startup packet: the code, then the `key\0value\0` pairs.
    fn startup_body(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut body = PROTOCOL_3_0.to_be_bytes().to_vec();
        for (key, value) in pairs {
            body.extend_from_slice(key.as_bytes());
            body.push(0);
            body.extend_from_slice(value.as_bytes());
            body.push(0);
        }
        body.push(0);
        body
    }

    /// A whole packet, length included, as it appears on the wire.
    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = ((body.len() + 4) as i32).to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn a_startup_packet_gives_up_its_user_and_database() {
        let parsed = parse_opening(&startup_body(&[
            ("user", "0f1e2d3c"),
            ("database", "analytics"),
        ]))
        .unwrap();
        assert_eq!(
            parsed,
            Opening::Startup(Startup {
                user: "0f1e2d3c".into(),
                database: Some("analytics".into()),
                forwarded: BTreeMap::new(),
            })
        );
    }

    #[test]
    fn only_the_two_cosmetic_parameters_are_carried_forward() {
        let Opening::Startup(startup) = parse_opening(&startup_body(&[
            ("user", "s1"),
            ("database", "app"),
            ("application_name", "psql"),
            ("client_encoding", "UTF8"),
            ("options", "-c search_path=evil"),
            ("replication", "database"),
        ]))
        .unwrap() else {
            panic!("expected a startup packet");
        };
        assert_eq!(
            startup.forwarded,
            BTreeMap::from([
                ("application_name".to_string(), "psql".to_string()),
                ("client_encoding".to_string(), "UTF8".to_string()),
            ])
        );
    }

    #[test]
    fn a_parameter_that_could_reconfigure_the_session_is_dropped_not_forwarded() {
        // `options` can set arbitrary `postgresql.conf` values for the session.
        // The upstream connection is authenticated with a master the client
        // does not hold, so it does not get to configure it.
        let Opening::Startup(startup) = parse_opening(&startup_body(&[
            ("user", "s1"),
            ("options", "-c log_statement=none"),
        ]))
        .unwrap() else {
            panic!("expected a startup packet");
        };
        assert!(startup.forwarded.is_empty(), "{startup:?}");
        assert!(!FORWARDED_PARAMETERS.contains(&"options"));
    }

    #[test]
    fn a_startup_packet_with_no_database_says_so_rather_than_guessing() {
        let Opening::Startup(startup) = parse_opening(&startup_body(&[("user", "s1")])).unwrap()
        else {
            panic!("expected a startup packet");
        };
        assert_eq!(startup.database, None);
    }

    #[test]
    fn a_startup_packet_with_no_user_is_refused() {
        assert_eq!(
            parse_opening(&startup_body(&[("database", "app")])).unwrap_err(),
            StartupError::MissingUser
        );
        assert_eq!(
            parse_opening(&startup_body(&[("user", "")])).unwrap_err(),
            StartupError::MissingUser
        );
    }

    #[test]
    fn the_three_negotiation_and_cancel_codes_are_recognised() {
        assert_eq!(
            parse_opening(&SSL_REQUEST.to_be_bytes()).unwrap(),
            Opening::Ssl
        );
        assert_eq!(
            parse_opening(&GSSENC_REQUEST.to_be_bytes()).unwrap(),
            Opening::GssEnc
        );
        let mut cancel = CANCEL_REQUEST.to_be_bytes().to_vec();
        cancel.extend_from_slice(&99i32.to_be_bytes());
        cancel.extend_from_slice(&(-5i32).to_be_bytes());
        assert_eq!(
            parse_opening(&cancel).unwrap(),
            Opening::Cancel { pid: 99, key: -5 }
        );
    }

    #[test]
    fn a_cancel_request_missing_its_key_is_malformed_rather_than_zeroed() {
        let mut cancel = CANCEL_REQUEST.to_be_bytes().to_vec();
        cancel.extend_from_slice(&99i32.to_be_bytes());
        assert!(matches!(
            parse_opening(&cancel).unwrap_err(),
            StartupError::Malformed(_)
        ));
    }

    #[test]
    fn protocol_2_0_is_refused_by_version_rather_than_misread() {
        // A 2.0 startup packet has a completely different body. Reading it as
        // 3.0 would produce nonsense parameters rather than a refusal.
        let err = parse_opening(&131_072i32.to_be_bytes()).unwrap_err();
        assert_eq!(
            err,
            StartupError::UnsupportedProtocol { major: 2, minor: 0 }
        );
        assert!(err.to_string().contains("3.0"), "{err}");
    }

    #[test]
    fn a_parameter_list_that_never_ends_is_malformed() {
        let mut body = PROTOCOL_3_0.to_be_bytes().to_vec();
        body.extend_from_slice(b"user");
        assert!(matches!(
            parse_opening(&body).unwrap_err(),
            StartupError::Malformed(_)
        ));

        let mut body = PROTOCOL_3_0.to_be_bytes().to_vec();
        body.extend_from_slice(b"user\0s1");
        assert!(matches!(
            parse_opening(&body).unwrap_err(),
            StartupError::Malformed(_)
        ));
    }

    #[test]
    fn a_packet_with_no_code_at_all_is_malformed() {
        assert!(matches!(
            parse_opening(&[0, 3]).unwrap_err(),
            StartupError::Malformed(_)
        ));
    }

    #[tokio::test]
    async fn a_whole_packet_is_read_off_the_wire() {
        let body = startup_body(&[("user", "s1"), ("database", "app")]);
        let mut cursor = std::io::Cursor::new(framed(&body));
        assert_eq!(
            read_opening(&mut cursor).await.unwrap(),
            parse_opening(&body).unwrap()
        );
    }

    #[tokio::test]
    async fn a_declared_length_briefcred_will_not_read_is_refused_before_allocating() {
        for declared in [7i32, MAX_STARTUP_PACKET as i32 + 1] {
            let mut cursor = std::io::Cursor::new(declared.to_be_bytes().to_vec());
            assert_eq!(
                read_opening(&mut cursor).await.unwrap_err(),
                StartupError::Length(declared as i64),
                "{declared}"
            );
        }
    }

    #[tokio::test]
    async fn a_client_that_closes_before_sending_anything_is_not_an_error_worth_a_backtrace() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        assert_eq!(
            read_opening(&mut cursor).await.unwrap_err(),
            StartupError::Closed
        );
    }

    #[tokio::test]
    async fn negotiation_requests_are_answered_and_then_the_real_packet_is_read() {
        let mut wire = framed(&GSSENC_REQUEST.to_be_bytes());
        wire.extend_from_slice(&framed(&SSL_REQUEST.to_be_bytes()));
        wire.extend_from_slice(&framed(&startup_body(&[("user", "s1")])));

        let mut answered = Vec::new();
        let (_stream, opening) = read_startup(std::io::Cursor::new(wire), |stream, request| {
            answered.push(request);
            async move { Ok(stream) }
        })
        .await
        .unwrap();

        assert_eq!(
            answered,
            vec![Opening::GssEnc, Opening::Ssl],
            "both negotiations must be answered, in order"
        );
        let Opening::Startup(startup) = opening else {
            panic!("expected a startup packet");
        };
        assert_eq!(startup.user, "s1");
    }

    #[tokio::test]
    async fn a_client_that_only_ever_negotiates_is_cut_off() {
        // Otherwise a peer could hold a daemon task open forever with a packet
        // it costs nothing to repeat.
        let mut wire = Vec::new();
        for _ in 0..MAX_NEGOTIATIONS + 1 {
            wire.extend_from_slice(&framed(&SSL_REQUEST.to_be_bytes()));
        }
        let err = read_startup(
            std::io::Cursor::new(wire),
            |stream, _| async move { Ok(stream) },
        )
        .await
        .unwrap_err();
        assert_eq!(err, StartupError::TooManyNegotiations);
    }
}
