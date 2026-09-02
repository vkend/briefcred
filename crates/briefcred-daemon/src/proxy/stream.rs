//! Long-lived responses: server-sent events, and WebSocket.
//!
//! Both are the same request pipeline as any other — token, quota, policy,
//! swap — that then stays open for minutes or hours instead of milliseconds.
//! What is different is only what happens after the response head:
//!
//! - A `text/event-stream` response keeps its ordinary streamed body, and the
//!   bytes going past are scanned for event boundaries on the way.
//! - A `101` to an `Upgrade: websocket` handshake stops being HTTP altogether,
//!   and the two halves are byte-forwarded with frame headers parsed for the
//!   count and nothing else.
//!
//! # What is counted, and what is deliberately not looked at
//!
//! The counters here read framing and never content. [`EventCounter`] holds at
//! most the first few bytes of the line it is in the middle of, which is enough
//! to tell a `data:` field from any other and not enough to hold an event's
//! value. [`FrameCounter`] reads a WebSocket frame's opcode, mask bit, and
//! length, and then steps over the payload without unmasking it. Neither ever
//! keeps a payload, so neither can leak one into a row or a log.
//!
//! # Ending a stream that outlived its grant
//!
//! A stream lives for as long as its client keeps it, so the checks that ran
//! when the request was authorised are not enough on their own — without
//! something more, a subprocess that opened an event stream at the start of a
//! run would still be receiving from it after `briefcred exec` finished and
//! after the grant was revoked. [`until_stale`] is the same one-second poll the
//! Postgres proxy uses on a live connection, for the same reasons, and it ends
//! both halves when the answer changes.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use briefcred_core::audit::AuditEntry;
use briefcred_core::types::MintId;
use hyper::body::{Body, Bytes, Frame};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::proxy::issuer::ProxyIssuer;
use crate::server::State;

/// How often a live stream re-checks that its grant is still a grant.
///
/// The same second the Postgres proxy uses, and for the same reason: the cost
/// is a map lookup per second per live stream, and what it buys is a bound on
/// how long a revoked credential keeps delivering that can be stated in
/// seconds rather than argued from three modules at once.
const LIVENESS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// How long the second half of a WebSocket gets to finish once the first ended.
///
/// Long enough for a close frame already on the wire to arrive, short enough
/// that a peer which has stopped reading cannot hold the relay open. A second
/// is both.
const DRAIN: std::time::Duration = std::time::Duration::from_secs(1);

/// The `kind` label on an event-stream row and its metric series.
pub const KIND_SSE: &str = "sse";

/// The `kind` label on a WebSocket row and its metric series.
pub const KIND_WS: &str = "ws";

/// The longest field name [`EventCounter`] needs to recognise, `data:`.
const DATA_FIELD: &[u8] = b"data:";

/// Counts server-sent events as their bytes go past.
///
/// An event is dispatched by the blank line that ends its block, so what is
/// counted is blocks that contained at least one `data:` field. A comment
/// (`: keep-alive`) and a block of `event:`/`id:` with no data are both
/// forwarded untouched and neither is an event, which is what makes the count
/// mean "how many messages did the client actually receive".
///
/// At most [`DATA_FIELD`]`.len()` bytes of the line in flight are held, so a
/// megabyte-long line costs five bytes and an event's value is never in memory
/// here at all.
#[derive(Debug, Default)]
pub struct EventCounter {
    /// The first few bytes of the line being read, capped at [`DATA_FIELD`].
    prefix: Vec<u8>,
    /// How long that line is so far, which is what says whether it is blank.
    line_len: usize,
    /// Whether the block being read has carried a `data:` field.
    saw_data: bool,
    /// Whether the previous byte was a `\r`, so a `\r\n` ends one line.
    after_cr: bool,
    events: u64,
}

impl EventCounter {
    /// A counter that has seen nothing.
    pub fn new() -> EventCounter {
        EventCounter::default()
    }

    /// Feed the next bytes of the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            match byte {
                b'\r' => {
                    self.end_line();
                    self.after_cr = true;
                }
                // A `\n` that follows a `\r` is the second half of one
                // terminator, not an empty line of its own.
                b'\n' if self.after_cr => self.after_cr = false,
                b'\n' => self.end_line(),
                _ => {
                    self.after_cr = false;
                    if self.prefix.len() < DATA_FIELD.len() {
                        self.prefix.push(byte);
                    }
                    self.line_len += 1;
                }
            }
        }
    }

    /// A line terminator arrived: decide what the line was, and reset.
    fn end_line(&mut self) {
        if self.line_len == 0 {
            // The blank line that dispatches whatever came before it.
            if self.saw_data {
                self.events += 1;
                self.saw_data = false;
            }
        } else if self.prefix == DATA_FIELD {
            self.saw_data = true;
        }
        self.prefix.clear();
        self.line_len = 0;
    }

    /// How many complete events have gone past.
    pub fn events(&self) -> u64 {
        self.events
    }
}

/// Where a [`FrameCounter`] is in the frame it is reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameState {
    /// Collecting the two bytes every frame starts with.
    Head,
    /// Collecting the two- or eight-byte extended length.
    ExtendedLength,
    /// Collecting the four-byte masking key.
    MaskingKey,
    /// Stepping over the payload without reading it.
    Payload,
}

/// Counts WebSocket frames as their bytes go past.
///
/// Frame headers only. The opcode says whether this was a close, the mask bit
/// and the length say how many bytes to step over, and the payload is never
/// looked at — not unmasked, not buffered, not measured for anything but how
/// far ahead the next header is. A proxy that read WebSocket payloads would be
/// one whose audit log could hold whatever an agent said, which is the thing
/// these rows exist to make unnecessary.
#[derive(Debug)]
pub struct FrameCounter {
    state: FrameState,
    /// The length or masking-key bytes collected so far.
    header: [u8; 8],
    filled: usize,
    /// How many bytes the current step still needs.
    needed: usize,
    /// Whether the frame in flight is masked, so its key must be stepped over.
    masked: bool,
    /// Payload bytes still to step over.
    remaining: u64,
    frames: u64,
    closed: bool,
}

impl Default for FrameCounter {
    fn default() -> FrameCounter {
        FrameCounter {
            state: FrameState::Head,
            header: [0; 8],
            filled: 0,
            needed: 2,
            masked: false,
            remaining: 0,
            frames: 0,
            closed: false,
        }
    }
}

impl FrameCounter {
    /// A counter that has seen nothing.
    pub fn new() -> FrameCounter {
        FrameCounter::default()
    }

    /// Feed the next bytes of one direction of the connection.
    pub fn push(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.state == FrameState::Payload {
                let step = self.remaining.min(bytes.len() as u64);
                self.remaining -= step;
                bytes = &bytes[step as usize..];
                if self.remaining == 0 {
                    self.begin(FrameState::Head, 2);
                }
                continue;
            }
            let step = self.needed.min(bytes.len());
            self.header[self.filled..self.filled + step].copy_from_slice(&bytes[..step]);
            self.filled += step;
            self.needed -= step;
            bytes = &bytes[step..];
            if self.needed == 0 {
                self.step_done();
            }
        }
    }

    /// Start collecting `needed` bytes for `state`.
    fn begin(&mut self, state: FrameState, needed: usize) {
        self.state = state;
        self.filled = 0;
        self.needed = needed;
    }

    /// Move past the payload, or straight to the next header if there is none.
    fn begin_payload(&mut self) {
        if self.remaining == 0 {
            self.begin(FrameState::Head, 2);
        } else {
            self.begin(FrameState::Payload, 0);
        }
    }

    /// The bytes for the current step are all in; work out what comes next.
    fn step_done(&mut self) {
        match self.state {
            FrameState::Head => {
                // A frame exists as soon as its opcode does. Counting here
                // rather than at the end of the payload means a frame that was
                // cut off mid-body is still one the client was sent.
                self.frames += 1;
                if self.header[0] & 0x0f == 0x8 {
                    self.closed = true;
                }
                self.masked = self.header[1] & 0x80 != 0;
                match self.header[1] & 0x7f {
                    126 => self.begin(FrameState::ExtendedLength, 2),
                    127 => self.begin(FrameState::ExtendedLength, 8),
                    short => {
                        self.remaining = u64::from(short);
                        if self.masked {
                            self.begin(FrameState::MaskingKey, 4);
                        } else {
                            self.begin_payload();
                        }
                    }
                }
            }
            FrameState::ExtendedLength => {
                let wide = self.filled == 8;
                self.remaining = if wide {
                    u64::from_be_bytes(self.header)
                } else {
                    u64::from(u16::from_be_bytes([self.header[0], self.header[1]]))
                };
                if self.masked {
                    self.begin(FrameState::MaskingKey, 4);
                } else {
                    self.begin_payload();
                }
            }
            // Collected and then discarded: the key is what a payload would be
            // unmasked with, and nothing here ever unmasks one.
            FrameState::MaskingKey => self.begin_payload(),
            FrameState::Payload => self.begin(FrameState::Head, 2),
        }
    }

    /// How many frame headers have gone past.
    pub fn frames(&self) -> u64 {
        self.frames
    }

    /// Whether a close frame has gone past.
    pub fn closed(&self) -> bool {
        self.closed
    }
}

// ------------------------------------------------------- ending a live stream

/// The grant one live stream is running on, so it can be re-checked.
///
/// A copy of what the token said rather than a handle to the session: the
/// session is exactly the thing that may go away underneath, and holding it
/// would keep alive the state whose disappearance is being watched for.
#[derive(Debug)]
pub struct Liveness {
    /// The session the token names.
    pub sid: String,
    /// The credential it names, because a revoke is on the pair.
    pub credential: String,
    /// The token's own `exp`, in Unix seconds.
    pub expires_at: i64,
}

/// Wait until the grant behind a live stream stops being one.
///
/// Three questions on a one-second timer, the same as the Postgres proxy asks
/// of a live connection. Polling rather than a subscription for the same
/// reasons it does: a subscription has a window between reading the current
/// state and registering for changes, and closing that window would mean new
/// locking in two structures both proxies share. What this buys is a bound
/// stated in seconds — a revoked credential stops delivering within about one
/// — rather than an invariant spread across three modules.
///
/// The returned string is the reason, for the daemon's log.
pub async fn until_stale(state: &State, issuer: &ProxyIssuer, live: &Liveness) -> &'static str {
    let mut ticker = tokio::time::interval(LIVENESS_INTERVAL);
    // `interval` fires immediately, and the grant was checked a moment ago.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        // The token's own `exp`, with no skew allowance. The allowance exists
        // so a client whose clock runs fast can still present a token; it is
        // not an extension of what the credential is good for, and a stream
        // already open has no clock of its own to forgive.
        if now >= live.expires_at {
            return "the credential expired";
        }
        if issuer.is_revoked(&live.sid, &live.credential, now) {
            return "the credential was revoked";
        }
        if !state.sessions().contains(&live.sid).await {
            return "the session was closed";
        }
    }
}

/// Everything a [`AuditEntry::ProxyStream`] row needs, fixed when it opens.
pub struct StreamRow {
    /// Where the row and the metric go.
    pub state: Arc<State>,
    /// The synthetic token's mint.
    pub mint_id: MintId,
    /// `sse` or `ws`.
    pub kind: &'static str,
    /// The upstream host, without the port.
    pub host: String,
    /// The request path, with its query string already stripped.
    pub path: String,
    /// When the stream opened.
    pub started: OffsetDateTime,
    /// The same instant, for a duration that a clock change cannot distort.
    pub since: std::time::Instant,
}

impl StreamRow {
    /// Write the row and count the stream. Called exactly once per stream.
    fn write(self, events_or_frames: u64, bytes_up: u64, bytes_down: u64) {
        self.state.audit(&AuditEntry::ProxyStream {
            ts: OffsetDateTime::now_utc(),
            mint_id: self.mint_id,
            kind: self.kind.to_string(),
            host: self.host,
            path: self.path,
            started: self.started,
            ended: OffsetDateTime::now_utc(),
            events_or_frames,
            bytes_up,
            bytes_down,
        });
        self.state
            .metrics()
            .record_proxy_stream(self.kind, self.since.elapsed());
    }
}

// ---------------------------------------------------------- server-sent events

/// Whether a response is an event stream, from its `Content-Type`.
///
/// The media type only: `text/event-stream; charset=utf-8` is one, and the
/// comparison is case-insensitive because a `Content-Type` is.
pub fn is_event_stream(headers: &hyper::header::HeaderMap) -> bool {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"))
        })
}

/// An event-stream body: forwarded untouched, counted on the way past.
///
/// Wrapping rather than collecting is the whole point of the type. Every frame
/// the upstream produces is handed on in the same poll it arrived in, so a
/// keep-alive comment reaches the client when it is sent rather than when the
/// stream ends, and an event stream that runs for an hour costs one line
/// scanner's worth of memory rather than an hour of events.
pub struct EventStream<B> {
    inner: B,
    counter: EventCounter,
    /// Bytes of request body that went upstream, shared with the request body.
    bytes_up: Arc<AtomicU64>,
    /// Bytes of response body, shared with the `ProxyRequest` row's counter.
    bytes_down: Arc<AtomicU64>,
    /// Fires when the grant behind the stream stops being one.
    ///
    /// The whole handle, not just its receiver: the handle owns the watching
    /// task, and keeping only the receiver would abort the watcher the moment
    /// the stream was built and leave the stream unwatched for its whole life.
    stale: Option<WatchHandle>,
    /// Taken when the row is written, so it is written exactly once.
    row: Option<StreamRow>,
}

impl<B> EventStream<B> {
    /// Wrap `inner`, watching `live` for as long as the stream is open.
    pub fn new(
        inner: B,
        row: StreamRow,
        bytes_up: Arc<AtomicU64>,
        bytes_down: Arc<AtomicU64>,
        watch: WatchHandle,
    ) -> EventStream<B> {
        EventStream {
            inner,
            counter: EventCounter::new(),
            bytes_up,
            bytes_down,
            stale: Some(watch),
            row: Some(row),
        }
    }

    /// Write the row, if it has not been written already.
    fn finish(&mut self) {
        if let Some(row) = self.row.take() {
            row.write(
                self.counter.events(),
                self.bytes_up.load(Ordering::Relaxed),
                self.bytes_down.load(Ordering::Relaxed),
            );
        }
    }
}

impl<B> Body for EventStream<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Self::Error>>> {
        let this = &mut *self;
        if this.row.is_none() {
            return Poll::Ready(None);
        }
        // Asked first, and polled rather than checked, so the waker is
        // registered: a stream sitting idle between events is one nothing else
        // is going to wake, and a revocation that only took effect at the next
        // event would be no bound at all on an idle stream.
        if let Some(stale) = this.stale.as_mut() {
            match Pin::new(&mut stale.stale).poll(cx) {
                Poll::Ready(Ok(reason)) => {
                    eprintln!("briefcred-daemon: proxy closed a live event stream: {reason}");
                    this.finish();
                    return Poll::Ready(None);
                }
                // The watcher is gone, which means the daemon is shutting down.
                // Nothing more to wait on; the stream ends with its upstream.
                Poll::Ready(Err(_)) => this.stale = None,
                Poll::Pending => {}
            }
        }

        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.counter.push(data);
                }
            }
            // The upstream closed, or gave up. Either way the client's stream
            // ends here, and the close propagates by this body ending.
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => this.finish(),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.row.is_none() || self.inner.is_end_stream()
    }

    /// Deliberately unknown, whatever the upstream said.
    ///
    /// A `Content-Length` is what makes a response a fixed-size one, and an
    /// event stream has no size to state. Returning the inner hint would let an
    /// upstream that guessed wrong decide the client's framing; returning
    /// nothing makes hyper frame it as chunked, which is what a stream that
    /// ends when the upstream ends needs.
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::default()
    }
}

/// A client that walked away mid-stream still gets its row.
impl<B> Drop for EventStream<B> {
    fn drop(&mut self) {
        self.finish();
    }
}

/// The receiving half of a liveness watch, and the task that feeds it.
///
/// The task is aborted when this is dropped, so a stream that ends on its own
/// does not leave a timer ticking for the rest of the token's lifetime.
pub struct WatchHandle {
    /// Resolves with the reason the grant stopped being one.
    stale: tokio::sync::oneshot::Receiver<&'static str>,
    /// Held only so its `Drop` runs. Dropping this handle without it would
    /// leave the watcher ticking for the rest of the token's lifetime.
    _task: AbortOnDrop,
}

/// A spawned task that is cancelled when its handle goes out of scope.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Watch `live` in the background, reporting the first reason it goes stale.
pub fn watch(state: Arc<State>, issuer: Arc<ProxyIssuer>, live: Liveness) -> WatchHandle {
    let (tell, hear) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let reason = until_stale(&state, &issuer, &live).await;
        let _ = tell.send(reason);
    });
    WatchHandle {
        stale: hear,
        _task: AbortOnDrop(task),
    }
}

// ------------------------------------------------------------------ WebSocket

/// The constant RFC 6455 mixes into a key to make an accept token.
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Whether a request is asking to become a WebSocket.
///
/// Both halves are required. `Upgrade: websocket` alone is a hint a proxy may
/// ignore; it is the `Connection: Upgrade` token that makes it a hop-by-hop
/// instruction to this proxy, and treating one without the other as a handshake
/// would let a request that is not one be answered with a `101`.
pub fn is_websocket_upgrade(headers: &hyper::header::HeaderMap) -> bool {
    let names = |name: hyper::header::HeaderName, wanted: &str| {
        headers.get_all(name).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case(wanted))
            })
        })
    };
    names(hyper::header::UPGRADE, "websocket") && names(hyper::header::CONNECTION, "upgrade")
}

/// The `Sec-WebSocket-Accept` a server owes for a given `Sec-WebSocket-Key`.
///
/// Recomputed rather than trusted. briefcred forwards the client's own key
/// upstream, so a correct accept proves the `101` came from something that
/// completed the handshake for *this* request — and a `101` from something that
/// did not is a server confused about what it is speaking, which is exactly
/// when a proxy must not hand the connection over to raw byte forwarding.
pub fn accept_key(key: &str) -> String {
    use base64::Engine as _;
    use sha1::{Digest as _, Sha1};

    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// The response headers a `101` carries back to the client.
///
/// An allowlist, not a copy. Everything a WebSocket handshake concludes is in
/// these five, and forwarding the rest of an upstream's `101` would hand the
/// client whatever else that server decided to attach.
pub const HANDSHAKE_HEADERS: [&str; 5] = [
    "upgrade",
    "connection",
    "sec-websocket-accept",
    "sec-websocket-protocol",
    "sec-websocket-extensions",
];

/// Byte-forward a WebSocket in both directions until either side closes.
///
/// Bytes only. The frame headers are parsed for the count and for whether a
/// close went past; no payload is unmasked, read, or kept. A policy therefore
/// has nothing to say about what crosses a WebSocket after the handshake, which
/// is a limit worth stating plainly rather than papering over.
pub async fn relay<C, U>(client: C, upstream: U, row: StreamRow, watch: WatchHandle)
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);

    let bytes_up = Arc::new(AtomicU64::new(0));
    let bytes_down = Arc::new(AtomicU64::new(0));
    let frames_up = Arc::new(AtomicU64::new(0));
    let frames_down = Arc::new(AtomicU64::new(0));

    let up = pump(
        client_read,
        upstream_write,
        Arc::clone(&bytes_up),
        Arc::clone(&frames_up),
    );
    let down = pump(
        upstream_read,
        client_write,
        Arc::clone(&bytes_down),
        Arc::clone(&frames_down),
    );

    tokio::pin!(up, down);
    let mut watch = watch;
    tokio::select! {
        // Either direction ending ends the stream, which is what propagating a
        // close means here: the pump that ended has already shut its writer
        // down, so the peer that is still open sees end-of-stream. The other
        // half gets [`DRAIN`] to deliver whatever was already in flight —
        // a WebSocket close is a frame each way, and cutting the second one
        // off would turn an orderly close into a truncated connection.
        _ = &mut up => {
            let _ = tokio::time::timeout(DRAIN, &mut down).await;
        }
        _ = &mut down => {
            let _ = tokio::time::timeout(DRAIN, &mut up).await;
        }
        reason = &mut watch.stale => {
            if let Ok(reason) = reason {
                eprintln!("briefcred-daemon: proxy closed a live websocket: {reason}");
            }
        }
    }

    row.write(
        frames_up.load(Ordering::Relaxed) + frames_down.load(Ordering::Relaxed),
        bytes_up.load(Ordering::Relaxed),
        bytes_down.load(Ordering::Relaxed),
    );
}

/// Copy one direction, counting frames, until it ends.
async fn pump<R, W>(mut reader: R, mut writer: W, bytes: Arc<AtomicU64>, frames: Arc<AtomicU64>)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut counter = FrameCounter::new();
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        counter.push(&buffer[..read]);
        bytes.fetch_add(read as u64, Ordering::Relaxed);
        // Published as the stream runs rather than returned at the end, so the
        // row is right even when the stream was ended from underneath.
        frames.store(counter.frames(), Ordering::Relaxed);
        if writer.write_all(&buffer[..read]).await.is_err() {
            break;
        }
    }
    // Propagating the close is the whole of the shutdown protocol here: the
    // side that stopped sending is reported to the other as end-of-stream, and
    // its own pump then reads zero and follows.
    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One event, fed whole.
    #[test]
    fn an_event_is_counted_when_its_blank_line_arrives() {
        let mut counter = EventCounter::new();
        counter.push(b"data: hello\n");
        assert_eq!(counter.events(), 0, "no blank line yet, so no event yet");
        counter.push(b"\n");
        assert_eq!(counter.events(), 1);
    }

    #[test]
    fn a_hundred_events_are_a_hundred_however_the_chunks_fall() {
        let stream: Vec<u8> = (0..100)
            .flat_map(|n| format!("data: {n}\n\n").into_bytes())
            .collect();
        // Fed a byte at a time, which is the worst case for a scanner that
        // expects to see a whole line in one chunk.
        let mut byte_at_a_time = EventCounter::new();
        for byte in &stream {
            byte_at_a_time.push(std::slice::from_ref(byte));
        }
        assert_eq!(byte_at_a_time.events(), 100);

        let mut whole = EventCounter::new();
        whole.push(&stream);
        assert_eq!(whole.events(), 100);

        // And split at every offset, so no boundary is special.
        for split in 0..stream.len() {
            let mut counter = EventCounter::new();
            counter.push(&stream[..split]);
            counter.push(&stream[split..]);
            assert_eq!(counter.events(), 100, "split at {split}");
        }
    }

    #[test]
    fn an_event_ends_the_same_way_whichever_line_ending_it_uses() {
        for terminator in ["\n", "\r\n", "\r"] {
            let mut counter = EventCounter::new();
            counter.push(format!("data: one{terminator}{terminator}").as_bytes());
            assert_eq!(counter.events(), 1, "terminator {terminator:?}");
        }
    }

    #[test]
    fn a_multi_line_event_is_still_one_event() {
        let mut counter = EventCounter::new();
        counter.push(b"event: message\ndata: one\ndata: two\nid: 7\n\n");
        assert_eq!(counter.events(), 1);
    }

    #[test]
    fn a_keep_alive_comment_is_forwarded_but_is_not_an_event() {
        let mut counter = EventCounter::new();
        counter.push(b": keep-alive\n\n");
        counter.push(b":\n\n");
        assert_eq!(
            counter.events(),
            0,
            "a comment block carries no `data:`, so it is not an event"
        );
        counter.push(b"data: real\n\n");
        assert_eq!(counter.events(), 1);
    }

    #[test]
    fn an_event_the_upstream_never_terminated_is_not_counted() {
        // An event is dispatched by its blank line. A stream that closes
        // mid-event never dispatched the last one, and counting it would
        // report an event no client ever saw.
        let mut counter = EventCounter::new();
        counter.push(b"data: complete\n\ndata: cut off");
        assert_eq!(counter.events(), 1);
    }

    #[test]
    fn a_field_that_merely_starts_with_data_is_not_a_data_field() {
        let mut counter = EventCounter::new();
        counter.push(b"database: not-a-field\n\n");
        assert_eq!(counter.events(), 0);
    }

    // ------------------------------------------------------------- WebSocket

    /// One unmasked frame with a `len` of `payload.len()`, under 126 bytes.
    fn short_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x80 | opcode, payload.len() as u8];
        frame.extend_from_slice(payload);
        frame
    }

    /// The same, masked the way a client must mask.
    fn masked_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [0xa1u8, 0xb2, 0xc3, 0xd4];
        let mut frame = vec![0x80 | opcode, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        for (n, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[n % 4]);
        }
        frame
    }

    #[test]
    fn each_frame_header_is_one_frame() {
        let mut counter = FrameCounter::new();
        counter.push(&short_frame(0x1, b"hello"));
        assert_eq!(counter.frames(), 1);
        counter.push(&short_frame(0x1, b"again"));
        assert_eq!(counter.frames(), 2);
    }

    #[test]
    fn a_masked_frame_is_counted_without_being_unmasked() {
        let mut counter = FrameCounter::new();
        let frame = masked_frame(0x1, b"secret");
        counter.push(&frame);
        assert_eq!(counter.frames(), 1);
        // The counter keeps no payload at all, so there is nothing to unmask.
        assert!(
            !format!("{counter:?}").contains("secret"),
            "the counter must not hold a payload"
        );
    }

    #[test]
    fn fifty_frames_are_fifty_however_the_reads_fall() {
        let stream: Vec<u8> = (0..50)
            .flat_map(|n| masked_frame(0x1, format!("frame {n}").as_bytes()))
            .collect();
        let mut byte_at_a_time = FrameCounter::new();
        for byte in &stream {
            byte_at_a_time.push(std::slice::from_ref(byte));
        }
        assert_eq!(byte_at_a_time.frames(), 50);
        for split in 0..stream.len() {
            let mut counter = FrameCounter::new();
            counter.push(&stream[..split]);
            counter.push(&stream[split..]);
            assert_eq!(counter.frames(), 50, "split at {split}");
        }
    }

    #[test]
    fn an_extended_length_frame_is_stepped_over_correctly() {
        // A 126-byte payload uses the two-byte extended length, and a longer
        // one the eight-byte form. Getting either wrong desynchronises the
        // parser, so the frame after it is the assertion that matters.
        let mut medium = vec![0x82u8, 126, 0x01, 0x00];
        medium.extend(std::iter::repeat_n(0u8, 256));
        let mut counter = FrameCounter::new();
        counter.push(&medium);
        counter.push(&short_frame(0x1, b"after"));
        assert_eq!(counter.frames(), 2);

        let mut long = vec![0x82u8, 127, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00];
        long.extend(std::iter::repeat_n(0u8, 65536));
        let mut counter = FrameCounter::new();
        counter.push(&long);
        counter.push(&short_frame(0x1, b"after"));
        assert_eq!(counter.frames(), 2);
    }

    #[test]
    fn a_close_frame_is_seen_for_what_it_is() {
        let mut counter = FrameCounter::new();
        counter.push(&short_frame(0x1, b"hello"));
        assert!(!counter.closed());
        counter.push(&short_frame(0x8, &[0x03, 0xe8]));
        assert!(counter.closed());
        assert_eq!(counter.frames(), 2, "a close frame is still a frame");
    }

    #[test]
    fn the_accept_token_is_the_one_rfc_6455_prints() {
        // The worked example from RFC 6455 § 1.3, which is the only way to know
        // the hash, the concatenation order, and the base64 are all right.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_ne!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            accept_key("dGhlIHNhbXBsZSBub25jZQ=")
        );
    }

    fn header_map(pairs: &[(&str, &str)]) -> hyper::header::HeaderMap {
        let mut map = hyper::header::HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn a_handshake_needs_both_halves_and_neither_is_case_sensitive() {
        assert!(is_websocket_upgrade(&header_map(&[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
        ])));
        assert!(is_websocket_upgrade(&header_map(&[
            ("upgrade", "WebSocket"),
            ("connection", "keep-alive, Upgrade"),
        ])));
        assert!(
            !is_websocket_upgrade(&header_map(&[("upgrade", "websocket")])),
            "`Upgrade` alone is a hint, not an instruction to this proxy"
        );
        assert!(!is_websocket_upgrade(&header_map(&[
            ("upgrade", "h2c"),
            ("connection", "Upgrade"),
        ])));
        assert!(!is_websocket_upgrade(&header_map(&[])));
    }

    #[test]
    fn an_event_stream_is_recognised_with_or_without_its_parameters() {
        assert!(is_event_stream(&header_map(&[(
            "content-type",
            "text/event-stream"
        )])));
        assert!(is_event_stream(&header_map(&[(
            "content-type",
            "Text/Event-Stream; charset=utf-8"
        )])));
        assert!(!is_event_stream(&header_map(&[(
            "content-type",
            "application/json"
        )])));
        // A type that merely starts with the same letters is not one.
        assert!(!is_event_stream(&header_map(&[(
            "content-type",
            "text/event-stream-ish"
        )])));
        assert!(!is_event_stream(&header_map(&[])));
    }

    #[test]
    fn a_continuation_and_a_ping_are_frames_too() {
        let mut counter = FrameCounter::new();
        counter.push(&short_frame(0x0, b"more"));
        counter.push(&short_frame(0x9, b""));
        counter.push(&short_frame(0xa, b""));
        assert_eq!(counter.frames(), 3);
        assert!(!counter.closed());
    }
}
