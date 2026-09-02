//! HTTP/2 at both ends of the proxy: the client's connection, and the
//! upstream's.
//!
//! HTTP/2 changes the framing and nothing else. Every stream on a client's
//! connection goes through the same pipeline an HTTP/1.1 request does — token,
//! proof, quota, policy, swap — and gets its own `ProxyRequest` row, because
//! each stream *is* a request and briefcred decided it as one. What this module
//! adds is the two things that only exist once framing is multiplexed:
//!
//! - [`Connection`], the shape of one client connection. A hundred streams over
//!   one connection are a hundred rows an operator otherwise has to reassemble
//!   by guessing from timestamps; every one of them carries this connection's
//!   `connection_id`, and this writes the row they point back at.
//! - [`Upstreams`], one upstream connection per session, credential, and
//!   destination. Multiplexing is the whole reason a gRPC client opens one
//!   connection and runs everything over it, and a proxy that dialled a fresh
//!   upstream per stream would take that away while appearing to work.
//!
//! # Why the upstream cache is keyed the way it is
//!
//! On `(session, credential, host, port)` and nothing looser. Two sessions hold
//! two different masters, and an upstream that treats a connection as
//! authenticated — which is exactly what HTTP/2 connection reuse invites — must
//! never be handed one session's stream on another session's connection. The
//! key makes that a type-level fact rather than a rule somebody has to
//! remember. It is also why there is no cache at all for HTTP/1.1: one request
//! at a time over a fresh connection is already correct, and pooling it would
//! be the same risk for a smaller prize.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use briefcred_core::audit::AuditEntry;
use briefcred_core::types::MintId;
use hyper::body::Incoming;
use hyper::{Request, Response};
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::server::State;

/// The body type the proxy sends upstream: the client's, counted on its way.
///
/// Named because the cache below stores a `SendRequest` parameterised on it,
/// and a cache is only ever as reusable as its concrete body type.
pub type UpstreamBody = crate::proxy::listener::Counting<Incoming>;

/// A multiplexed HTTP/2 sender for one cached upstream connection.
pub type H2Sender = hyper::client::conn::http2::SendRequest<UpstreamBody>;

/// A sender for one HTTP/1.1 upstream connection, which carries one request.
pub type H1Sender = hyper::client::conn::http1::SendRequest<UpstreamBody>;

/// What an upstream turned out to speak, once its ALPN was negotiated.
///
/// The two ends negotiate separately, so this is decided per upstream and has
/// nothing to do with what the client chose. An HTTP/2 client talking to an
/// HTTP/1.1-only vendor is an ordinary request, and an HTTP/1.1 client talking
/// to an HTTP/2 vendor is too.
pub enum Dialled {
    /// The upstream offered `h2`; the sender is multiplexed and cacheable.
    Http2(H2Sender),
    /// It did not; the sender carries this one request and is not cached.
    Http1(H1Sender),
}

/// One client HTTP/2 connection, and the totals its streams add up to.
///
/// Counters rather than a list: a connection may carry thousands of streams,
/// each of which already wrote its own row, and holding them here would be a
/// second copy of the audit log that grows for as long as the client keeps the
/// connection open.
#[derive(Debug)]
pub struct Connection {
    /// What every row of this connection names it by.
    id: String,
    /// The upstream host the `CONNECT` named, without the port.
    host: String,
    started: OffsetDateTime,
    streams: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    /// The mint of the first stream that resolved a session.
    ///
    /// First rather than last, and one rather than a set: a connection is
    /// opened by one subprocess holding one grant, so the interesting failure
    /// is a connection whose streams never resolved one at all — which is the
    /// `None` that means no row gets written.
    mint_id: Mutex<Option<MintId>>,
}

impl Connection {
    /// Open the record of a connection whose TLS handshake has just finished.
    pub fn new(host: String) -> Connection {
        Connection {
            id: identifier(),
            host,
            started: OffsetDateTime::now_utc(),
            streams: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            mint_id: Mutex::new(None),
        }
    }

    /// What this connection's rows name it by.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Count one stream, whatever is about to become of it.
    ///
    /// Counted as it opens rather than as it ends, because a refused stream is
    /// still a stream the client opened, and a count that only saw the ones
    /// that succeeded would make a connection being denied look like an idle
    /// one.
    pub fn began_stream(&self, state: &State) {
        self.streams.fetch_add(1, Ordering::Relaxed);
        state.metrics().record_h2_stream();
    }

    /// Remember the grant this connection is carrying, the first time one is
    /// resolved on it.
    pub fn note_mint(&self, mint_id: &MintId) {
        let mut held = self
            .mint_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if held.is_none() {
            *held = Some(mint_id.clone());
        }
    }

    /// Add what one finished stream moved in each direction.
    pub fn add_bytes(&self, up: u64, down: u64) {
        self.bytes_up.fetch_add(up, Ordering::Relaxed);
        self.bytes_down.fetch_add(down, Ordering::Relaxed);
    }

    /// Write the connection's row and count it. Called once, at the close.
    ///
    /// `self` by reference rather than by value because the connection is held
    /// by every in-flight stream's service future; "exactly once" is instead
    /// the one call site in [`crate::proxy::listener`] after `serve_connection`
    /// has returned, which is the only moment every stream on it has finished.
    pub fn finish(&self, state: &State) {
        let mint_id = self
            .mint_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        // A connection whose every stream was refused before one resolved a
        // session has no grant to name, on the same terms as the request rows.
        let Some(mint_id) = mint_id else {
            return;
        };
        state.audit(&AuditEntry::ProxyH2Connection {
            ts: OffsetDateTime::now_utc(),
            connection_id: self.id.clone(),
            mint_id,
            host: self.host.clone(),
            started: self.started,
            ended: OffsetDateTime::now_utc(),
            streams: self.streams.load(Ordering::Relaxed),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
        });
        state.metrics().record_h2_connection();
    }
}

/// An identifier for one client HTTP/2 connection, for its audit rows.
///
/// Random rather than a counter, for the reason every other identifier here is:
/// a counter restarts with the daemon, and two runs would then name different
/// connections the same thing.
fn identifier() -> String {
    let mut bytes = [0u8; 6];
    getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable");
    format!("h2-{}", hex::encode(bytes))
}

/// What one cached upstream connection is keyed by.
///
/// The session and the credential are in the key, not merely the destination:
/// see the module's opening note on why sharing a connection across grants
/// would be a credential mix-up rather than a performance win.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamKey {
    /// The session the token named.
    pub sid: String,
    /// The credential within it, because a revoke is on the pair.
    pub credential: String,
    /// The upstream host, without the port.
    pub host: String,
    pub port: u16,
}

/// The proxy's cache of multiplexed upstream connections.
///
/// One `tokio` mutex held across the dial, not a lock-free map. Two streams
/// racing to be the first to a host must not each open a connection: the test
/// that N concurrent calls arrive over one upstream connection is the whole
/// point, and a race that opened two would pass every other assertion while
/// quietly undoing it. A dial is rare and everything after it runs unlocked, so
/// the cost is one connection setup serialised against another.
#[derive(Debug, Default)]
pub struct Upstreams {
    connections: tokio::sync::Mutex<HashMap<UpstreamKey, H2Sender>>,
}

impl Upstreams {
    /// The connection for `key`, calling `dial` only if there is not one.
    ///
    /// A cached sender whose connection has since closed is dropped and
    /// redialled rather than returned, because a closed sender fails every
    /// request put through it. An HTTP/1.1 result is handed straight back and
    /// never cached: it carries one request, and a cache of those would be a
    /// connection pool with none of the isolation reasoning above behind it.
    pub async fn connect<D, F>(&self, key: UpstreamKey, dial: D) -> Result<Dialled>
    where
        D: FnOnce() -> F,
        F: std::future::Future<Output = Result<Dialled>>,
    {
        let mut connections = self.connections.lock().await;
        // Every closed connection goes, not just this key's: a session that
        // ended took its connections with it, and nothing else here would ever
        // notice the entries it left behind.
        connections.retain(|_, sender| !sender.is_closed());
        if let Some(sender) = connections.get(&key) {
            return Ok(Dialled::Http2(sender.clone()));
        }
        // Dialled under the lock so two streams racing to the same upstream do
        // not each open a connection; a failed dial caches nothing.
        let dialled = dial().await?;
        if let Dialled::Http2(sender) = &dialled {
            connections.insert(key, sender.clone());
        }
        Ok(dialled)
    }

    /// How many upstream connections are cached, for the tests.
    #[cfg(test)]
    async fn len(&self) -> usize {
        self.connections.lock().await.len()
    }
}

/// Send one request on a multiplexed upstream connection.
///
/// `ready` first, because a connection at its stream limit is not an error: it
/// is a connection to wait a moment for, and sending without asking would fail
/// the request instead.
pub async fn send_on(
    sender: &mut H2Sender,
    request: Request<UpstreamBody>,
) -> Result<Response<Incoming>> {
    sender
        .ready()
        .await
        .map_err(|e| Error::Proxy(format!("the upstream connection stalled: {e}")))?;
    sender
        .send_request(request)
        .await
        .map_err(|e| Error::Proxy(format!("upstream refused the request: {e}")))
}

/// The headers HTTP/2 has no place for, which a client on HTTP/1.1 may send.
///
/// Connection-specific by definition, and RFC 9113 §8.2.2 forbids all of them
/// on an HTTP/2 stream. They have to go when an HTTP/1.1 client's request is
/// forwarded over an HTTP/2 upstream connection, or the upstream resets the
/// stream. `te` is deliberately absent: gRPC sends `te: trailers`, which is the
/// one value HTTP/2 keeps, and the request that needs trailers relayed is
/// exactly the one that must not have it stripped.
const CONNECTION_SPECIFIC: [&str; 5] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// Strip the headers an HTTP/2 stream may not carry.
pub fn strip_connection_specific(headers: &mut hyper::header::HeaderMap) {
    for name in CONNECTION_SPECIFIC {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_identifier_says_what_it_identifies_and_does_not_repeat() {
        let first = identifier();
        assert!(first.starts_with("h2-"), "{first}");
        assert_ne!(first, identifier());
    }

    #[test]
    fn a_connection_keeps_the_first_grant_a_stream_of_it_resolved() {
        let connection = Connection::new("api.openai.com".to_string());
        let first = MintId::generate();
        let second = MintId::generate();
        connection.note_mint(&first);
        connection.note_mint(&second);
        assert_eq!(
            connection.mint_id.lock().unwrap().as_ref(),
            Some(&first),
            "a later stream must not rename the connection"
        );
    }

    #[test]
    fn a_connection_totals_what_its_streams_moved() {
        let connection = Connection::new("api.openai.com".to_string());
        connection.add_bytes(10, 100);
        connection.add_bytes(5, 50);
        assert_eq!(connection.bytes_up.load(Ordering::Relaxed), 15);
        assert_eq!(connection.bytes_down.load(Ordering::Relaxed), 150);
    }

    #[test]
    fn http2_has_no_place_for_a_connection_header_but_keeps_te_trailers() {
        let mut headers = hyper::header::HeaderMap::new();
        for (name, value) in [
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("proxy-connection", "keep-alive"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("te", "trailers"),
            ("content-type", "application/grpc"),
        ] {
            headers.insert(
                hyper::header::HeaderName::from_static(name),
                hyper::header::HeaderValue::from_static(value),
            );
        }
        strip_connection_specific(&mut headers);
        let mut left: Vec<&str> = headers.keys().map(|name| name.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["content-type", "te"]);
    }

    #[tokio::test]
    async fn a_cache_that_cannot_dial_keeps_nothing() {
        let upstreams = Upstreams::default();
        let key = UpstreamKey {
            sid: "s".to_string(),
            credential: "openai".to_string(),
            host: "api.openai.com".to_string(),
            port: 443,
        };
        let failed = upstreams
            .connect(key, || async { Err(Error::Proxy("no route".to_string())) })
            .await;
        assert!(failed.is_err());
        assert_eq!(upstreams.len().await, 0, "a failed dial must not be cached");
    }
}
