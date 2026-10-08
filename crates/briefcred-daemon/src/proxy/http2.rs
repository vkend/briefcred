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
use std::sync::{Arc, Mutex};

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

/// One cache entry: the connection for a key, and the lock a dial to it holds.
///
/// The lock is **per key**, which is the whole reason the slot is a type of its
/// own. Two streams racing to the same host must not each open a connection —
/// N concurrent calls arriving over one upstream connection is the point of
/// HTTP/2, and a race that opened two would pass every other assertion while
/// quietly undoing it. But serialising *all* dials behind one lock would let a
/// single blackholed host stall every other host's first request for as long as
/// the connect timeout, which trades a rare race for a daemon-wide stall.
type Slot = Arc<tokio::sync::Mutex<Option<H2Sender>>>;

/// The proxy's cache of multiplexed upstream connections.
///
/// Two locks, on purpose. The outer `std` mutex is held only long enough to
/// find or make a slot and is never held across an `await`; the inner per-key
/// lock is held across the dial. So a host that never answers delays exactly
/// the requests headed for that host.
#[derive(Debug, Default)]
pub struct Upstreams {
    slots: Mutex<HashMap<UpstreamKey, Slot>>,
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
        let slot = self.slot(key);
        // Only dials to this same key wait here.
        let mut held = slot.lock().await;
        if let Some(sender) = held.as_ref() {
            // A closed sender fails every request put through it, so it is
            // redialled rather than handed out.
            if !sender.is_closed() {
                return Ok(Dialled::Http2(sender.clone()));
            }
        }
        // A failed dial caches nothing: the slot is left empty and the next
        // request tries again.
        let dialled = dial().await?;
        *held = match &dialled {
            Dialled::Http2(sender) => Some(sender.clone()),
            Dialled::Http1(_) => None,
        };
        Ok(dialled)
    }

    /// The slot for `key`, making an empty one if there is none.
    ///
    /// The outer lock is taken and released inside this function and never held
    /// across an `await`, which is what keeps one host's dial off every other
    /// host's path.
    fn slot(&self, key: UpstreamKey) -> Slot {
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Entries whose connection has closed and which nobody is dialling go
        // now. A slot anyone else still holds is left alone: that is a dial in
        // flight, or a request that has just been handed the slot and not yet
        // locked it. Judging that second case by the lock alone would sweep the
        // slot from under it, and the next request for the same key would get
        // a fresh one and dial a second connection beside the first.
        slots.retain(|_, slot| {
            Arc::strong_count(slot) > 1
                || slot
                    .try_lock()
                    .is_ok_and(|held| held.as_ref().is_some_and(|sender| !sender.is_closed()))
        });
        Arc::clone(
            slots
                .entry(key)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None))),
        )
    }

    /// Forget every connection held for one grant.
    ///
    /// Called when a `(session, credential)` pair is revoked. Dropping the
    /// cache's sender is what lets the connection close: a stream still in
    /// flight holds a sender of its own and is ended separately by its liveness
    /// watch, so this closes the connection as soon as the last one finishes
    /// rather than cutting a response in half.
    pub fn close_grant(&self, sid: &str, credential: &str) {
        self.forget(|key| key.sid == sid && key.credential == credential);
    }

    /// Forget every connection held for one session, whatever the credential.
    pub fn close_session(&self, sid: &str) {
        self.forget(|key| key.sid == sid);
    }

    fn forget(&self, doomed: impl Fn(&UpstreamKey) -> bool) {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|key, _| !doomed(key));
    }

    /// How many slots are cached, for the tests.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
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

    #[tokio::test]
    async fn a_cache_that_cannot_dial_holds_no_connection_afterwards() {
        let upstreams = Upstreams::default();
        let failed = upstreams
            .connect(key("s1", "openai"), || async {
                Err(Error::Proxy("no route".to_string()))
            })
            .await;
        assert!(failed.is_err());
        // The slot may survive the failure; what must not survive is a
        // connection, because there never was one. The guard is dropped before
        // the `await` below, which is why the slots are cloned out first.
        let slots: Vec<Slot> = {
            let held = upstreams.slots.lock().unwrap();
            held.values().cloned().collect()
        };
        for slot in slots {
            assert!(slot.lock().await.is_none());
        }
    }

    fn key(sid: &str, credential: &str) -> UpstreamKey {
        UpstreamKey {
            sid: sid.to_string(),
            credential: credential.to_string(),
            host: "api.openai.com".to_string(),
            port: 443,
        }
    }

    /// Put a slot in the map without dialling anything.
    ///
    /// Standing in for a live connection: what the eviction tests are about is
    /// which keys are removed, and an empty slot is removed by exactly the same
    /// code a full one is.
    fn occupy(upstreams: &Upstreams, key: UpstreamKey) {
        upstreams
            .slots
            .lock()
            .unwrap()
            .insert(key, Arc::new(tokio::sync::Mutex::new(None)));
    }

    #[test]
    fn a_revoked_grant_takes_its_connections_and_leaves_every_other_alone() {
        let upstreams = Upstreams::default();
        for entry in [
            key("s1", "openai"),
            key("s1", "stripe"),
            key("s2", "openai"),
        ] {
            occupy(&upstreams, entry);
        }
        assert_eq!(upstreams.len(), 3);

        upstreams.close_grant("s1", "openai");
        assert_eq!(upstreams.len(), 2, "only the revoked pair goes");

        upstreams.close_session("s1");
        assert_eq!(
            upstreams.len(),
            1,
            "the session's other credential goes with it"
        );

        upstreams.close_session("s2");
        assert_eq!(upstreams.len(), 0);
    }

    #[test]
    fn a_slot_handed_out_but_not_yet_locked_is_the_one_the_next_request_gets() {
        let upstreams = Upstreams::default();
        let first = upstreams.slot(key("s1", "openai"));
        // `first` is empty and unlocked, exactly as it is between a request
        // being handed it and that request's dial taking the lock.
        let second = upstreams.slot(key("s1", "openai"));
        assert!(
            Arc::ptr_eq(&first, &second),
            "two requests for one key must wait on one slot, or each dials"
        );
    }

    #[test]
    fn an_empty_slot_nobody_is_dialling_is_not_kept() {
        let upstreams = Upstreams::default();
        occupy(&upstreams, key("s1", "openai"));
        // Asking for a different key sweeps the map, and a slot holding no
        // connection is what a failed dial leaves behind.
        upstreams.slot(key("s2", "openai"));
        assert_eq!(upstreams.len(), 1);
    }
}
