//! The Prometheus text endpoint, on loopback only.
//!
//! Everything here is operational: how long the daemon has been up, how many
//! IPC requests it has handled by kind, how many audit rows it failed to write,
//! how long mints and revokes take by minter kind, how many revokes have
//! failed, and what each of the two proxies has carried. Nothing is derived
//! from credential material — a histogram
//! records how long a mint took and which kind served it, never what was
//! minted — and the listener is bound to `127.0.0.1` so it is not reachable
//! off the machine.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use briefcred_proto::Request;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Method, Response as HttpResponse, StatusCode};
use hyper_util::rt::TokioIo;

/// The content type Prometheus expects from a text-format exposition.
const TEXT_FORMAT: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The upper bounds of the latency histogram buckets, in seconds.
///
/// Chosen for what these operations actually cost: a mint against a loopback
/// database is single-digit milliseconds, one against a remote database over
/// TLS is tens to hundreds, and anything past a few seconds is a problem
/// somebody wants to see rather than a number to average away. The `+Inf`
/// bucket is implied and emitted from the total count.
pub const LATENCY_BUCKETS: [f64; 9] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

/// The upper bounds of the stream-duration histogram buckets, in seconds.
///
/// A separate scale because a stream is not a latency. A proxied request that
/// takes five seconds is slow; an event stream that stays open for five seconds
/// is short, and one that holds a WebSocket for an hour is a session somebody
/// left running. Measured on [`LATENCY_BUCKETS`] every stream would fall in
/// `+Inf` and the histogram would say nothing at all, so these run from a
/// second to two hours.
pub const STREAM_DURATION_BUCKETS: [f64; 9] =
    [1.0, 5.0, 30.0, 60.0, 300.0, 900.0, 1800.0, 3600.0, 7200.0];

/// One duration histogram, keyed by whatever the caller labels a `kind`.
///
/// Hand-rolled rather than pulled from a metrics crate: a handful of series is
/// not enough to justify a dependency that would also want to own the registry,
/// the exposition format, and the process's global state.
#[derive(Debug)]
struct Histogram {
    /// The bucket bounds this histogram observes against, ascending.
    bounds: &'static [f64],
    /// Per kind: one cumulative counter per bucket, plus count and sum.
    by_kind: BTreeMap<String, Series>,
}

impl Default for Histogram {
    fn default() -> Histogram {
        Histogram::new(&LATENCY_BUCKETS)
    }
}

#[derive(Debug)]
struct Series {
    /// Non-cumulative observation counts, one per bound of the histogram.
    buckets: Vec<u64>,
    /// Observations above the last bound.
    overflow: u64,
    /// Total observations.
    count: u64,
    /// Total observed seconds.
    sum: f64,
}

impl Histogram {
    /// An empty histogram observing against `bounds`.
    fn new(bounds: &'static [f64]) -> Histogram {
        Histogram {
            bounds,
            by_kind: BTreeMap::new(),
        }
    }

    fn observe(&mut self, kind: &str, seconds: f64) {
        let bounds = self.bounds;
        let series = self
            .by_kind
            .entry(kind.to_string())
            .or_insert_with(|| Series {
                buckets: vec![0; bounds.len()],
                overflow: 0,
                count: 0,
                sum: 0.0,
            });
        match bounds.iter().position(|bound| seconds <= *bound) {
            Some(index) => series.buckets[index] += 1,
            None => series.overflow += 1,
        }
        series.count += 1;
        series.sum += seconds;
    }

    /// Render as Prometheus histogram series.
    ///
    /// `le` buckets are cumulative, which is the part of the format that is
    /// easy to get wrong: each bucket counts everything at or below its bound,
    /// not just what fell in it.
    fn render(&self, name: &str, help: &str, out: &mut String) {
        out.push_str(&format!("# HELP {name} {help}\n"));
        out.push_str(&format!("# TYPE {name} histogram\n"));
        for (kind, series) in &self.by_kind {
            let mut cumulative = 0u64;
            for (index, bound) in self.bounds.iter().enumerate() {
                cumulative += series.buckets[index];
                out.push_str(&format!(
                    "{name}_bucket{{kind=\"{kind}\",le=\"{bound}\"}} {cumulative}\n"
                ));
            }
            out.push_str(&format!(
                "{name}_bucket{{kind=\"{kind}\",le=\"+Inf\"}} {}\n",
                series.count
            ));
            out.push_str(&format!("{name}_sum{{kind=\"{kind}\"}} {}\n", series.sum));
            out.push_str(&format!(
                "{name}_count{{kind=\"{kind}\"}} {}\n",
                series.count
            ));
        }
    }
}

/// The daemon's counters, gauges, and histograms.
#[derive(Debug)]
pub struct Metrics {
    started: Instant,
    requests: Mutex<BTreeMap<&'static str, u64>>,
    audit_write_errors: Arc<AtomicU64>,
    mint_duration: Mutex<Histogram>,
    revoke_duration: Mutex<Histogram>,
    revoke_failures: Mutex<BTreeMap<String, u64>>,
    proxy_requests: Mutex<BTreeMap<(String, String), u64>>,
    proxy_latency: Mutex<Histogram>,
    proxy_streams: Mutex<BTreeMap<&'static str, u64>>,
    proxy_stream_duration: Mutex<Histogram>,
    proxy_h2_connections: AtomicU64,
    proxy_h2_streams: AtomicU64,
    pgproxy_connections: Mutex<BTreeMap<String, u64>>,
    pgproxy_bytes: Mutex<BTreeMap<&'static str, u64>>,
    quota_saturation: Mutex<BTreeMap<String, f64>>,
    quota_rejections: Mutex<BTreeMap<(String, String), u64>>,
    handoffs: Mutex<BTreeMap<&'static str, u64>>,
}

/// The `outcome` labels on `briefcred_handoffs_total`.
///
/// Seeded at zero so "this daemon has never been upgraded in place" is a fact
/// a dashboard can read, rather than three series that appear the first time
/// somebody runs `briefcred daemon upgrade`.
const HANDOFF_OUTCOMES: [&str; 3] = ["handed_over", "adopted", "failed"];

/// The direction labels on `briefcred_pgproxy_bytes_total`.
///
/// Seeded at zero so a proxy nobody has connected through is distinguishable
/// from a scrape that failed.
const PGPROXY_DIRECTIONS: [&str; 2] = ["client_to_server", "server_to_client"];

/// The `kind` labels on `briefcred_proxy_streams_total`.
///
/// Seeded at zero for the same reason the directions above are: "no WebSocket
/// has ever been opened through this proxy" and "the series is missing" are
/// different facts, and only one of them is worth waking somebody for.
const PROXY_STREAM_KINDS: [&str; 3] = [
    crate::proxy::stream::KIND_H2,
    crate::proxy::stream::KIND_SSE,
    crate::proxy::stream::KIND_WS,
];

impl Metrics {
    /// Start the clock, with every request series pre-seeded at zero.
    ///
    /// Seeding matters: a counter that only appears after its first increment
    /// cannot be distinguished from a scrape failure.
    pub fn new(audit_write_errors: Arc<AtomicU64>) -> Metrics {
        let requests = Request::NAMES.iter().map(|name| (*name, 0)).collect();
        Metrics {
            started: Instant::now(),
            requests: Mutex::new(requests),
            audit_write_errors,
            mint_duration: Mutex::new(Histogram::default()),
            revoke_duration: Mutex::new(Histogram::default()),
            revoke_failures: Mutex::new(BTreeMap::new()),
            proxy_requests: Mutex::new(BTreeMap::new()),
            proxy_latency: Mutex::new(Histogram::default()),
            proxy_streams: Mutex::new(PROXY_STREAM_KINDS.iter().map(|kind| (*kind, 0)).collect()),
            proxy_stream_duration: Mutex::new(Histogram::new(&STREAM_DURATION_BUCKETS)),
            proxy_h2_connections: AtomicU64::new(0),
            proxy_h2_streams: AtomicU64::new(0),
            pgproxy_connections: Mutex::new(BTreeMap::new()),
            pgproxy_bytes: Mutex::new(PGPROXY_DIRECTIONS.iter().map(|name| (*name, 0)).collect()),
            quota_saturation: Mutex::new(BTreeMap::new()),
            quota_rejections: Mutex::new(BTreeMap::new()),
            handoffs: Mutex::new(HANDOFF_OUTCOMES.iter().map(|name| (*name, 0)).collect()),
        }
    }

    /// Count one in-place upgrade, by how it ended.
    ///
    /// `handed_over` is a daemon that gave its listeners away and stood down,
    /// `adopted` one that took them on, and `failed` an attempt that left the
    /// old daemon serving. The three are separate because a rising `failed` is
    /// somebody whose upgrades are silently not taking, which otherwise looks
    /// exactly like nobody upgrading.
    pub fn record_handoff(&self, outcome: &str) {
        let Some(label) = HANDOFF_OUTCOMES.iter().find(|known| **known == outcome) else {
            return;
        };
        *self
            .handoffs
            .lock()
            .expect("metrics mutex")
            .entry(*label)
            .or_insert(0) += 1;
    }

    /// Record how full a profile's quota bucket is *not*, from 0 to 1.
    ///
    /// Updated on every charge, so the value is what the most recent session of
    /// that profile saw. Deliberately not seeded: a series that exists is a
    /// profile somebody put a `quota:` on, and one that does not is a profile
    /// running unmetered — which is a distinction worth being able to make from
    /// a dashboard.
    ///
    /// Keyed by profile rather than by session, because a session identifier is
    /// unbounded cardinality and a per-session gauge would be a metric that
    /// grows without limit for as long as the daemon runs.
    pub fn record_quota_saturation(&self, profile: &str, saturation: f64) {
        self.quota_saturation
            .lock()
            .expect("metrics mutex")
            .insert(profile.to_string(), saturation);
    }

    /// Count one charge a quota refused, by profile and by surface.
    ///
    /// `surface` is `http`, `postgres`, `exec`, or `mcp`. Which one matters:
    /// the same bucket is spent by all four, so a profile whose rejections are
    /// all `exec` is one whose burst is too small for how often it is run, and
    /// one whose rejections are all `http` is an agent in a loop.
    pub fn record_quota_rejection(&self, profile: &str, surface: &str) {
        *self
            .quota_rejections
            .lock()
            .expect("metrics mutex")
            .entry((profile.to_string(), surface.to_string()))
            .or_insert(0) += 1;
    }

    /// Record one connection through the Postgres proxy, by how it ended.
    ///
    /// `outcome` is one of four. `allow` was authenticated and relayed;
    /// `deny` was refused because the client's token did not authorise the
    /// connection it asked for; `upstream_error` was authorised and the real
    /// server would not have it; `protocol_error` never got as far as either,
    /// because what arrived was not a PostgreSQL connection briefcred serves.
    ///
    /// The same split as the HTTP proxy's `decision`, and for the same reason:
    /// a rising `deny` means a profile or a stale token, a rising
    /// `upstream_error` means somebody should go and look at the database, and
    /// conflating them would make neither actionable.
    pub fn record_pgproxy_connection(&self, outcome: &str) {
        *self
            .pgproxy_connections
            .lock()
            .expect("metrics mutex")
            .entry(outcome.to_string())
            .or_insert(0) += 1;
    }

    /// Record the bytes one relayed connection moved, in each direction.
    pub fn record_pgproxy_bytes(&self, client_bytes: u64, server_bytes: u64) {
        let mut bytes = self.pgproxy_bytes.lock().expect("metrics mutex");
        *bytes.entry(PGPROXY_DIRECTIONS[0]).or_insert(0) += client_bytes;
        *bytes.entry(PGPROXY_DIRECTIONS[1]).or_insert(0) += server_bytes;
    }

    /// Record one request that crossed the HTTP proxy.
    ///
    /// `decision` is one of seven values. Three are policy outcomes —
    /// `allow`, `deny`, `would_deny` — and two are refusals the policy was
    /// never asked about: `quota`, where the session's budget was already
    /// spent, and `bad_request`, where what arrived was not a request anything
    /// could decide on. The last two are briefcred's own faults on a request
    /// the policy allowed: `swap_error`, where the credential could not be put
    /// into the request, and `upstream_error`, where the upstream could not be
    /// reached. Keeping the four non-policy labels out of `deny` is what lets
    /// an operator tell "widen the policy" from "raise the quota" from "look
    /// at the master" from "the vendor is down".
    ///
    /// `status_class` is the upstream's status rounded to its class
    /// (`2xx`, `4xx`, …) or `none` where the request never reached an upstream.
    /// The class rather than the code: a per-code series would let a vendor's
    /// error taxonomy decide how many series briefcred exports.
    pub fn record_proxy_request(
        &self,
        decision: &str,
        status: Option<u16>,
        elapsed: std::time::Duration,
    ) {
        let class = status_class(status);
        *self
            .proxy_requests
            .lock()
            .expect("metrics mutex")
            .entry((decision.to_string(), class.to_string()))
            .or_insert(0) += 1;
        self.proxy_latency
            .lock()
            .expect("metrics mutex")
            .observe(decision, elapsed.as_secs_f64());
    }

    /// Record one long-lived stream that has ended, by kind.
    ///
    /// `kind` is `sse` or `ws`. Counted and timed when the stream *closes*
    /// rather than when it opens, which is the only way the duration can exist
    /// — and it makes the counter read "streams that have finished", so a
    /// dashboard that wants the number currently open subtracts it from the
    /// `101`s and the event-stream responses on
    /// `briefcred_proxy_requests_total` rather than being told a number that
    /// was true when the row was written.
    pub fn record_proxy_stream(&self, kind: &'static str, elapsed: std::time::Duration) {
        *self
            .proxy_streams
            .lock()
            .expect("metrics mutex")
            .entry(kind)
            .or_insert(0) += 1;
        self.proxy_stream_duration
            .lock()
            .expect("metrics mutex")
            .observe(kind, elapsed.as_secs_f64());
    }

    /// Count one HTTP/2 connection from a client that has closed.
    ///
    /// Counted at the close rather than at the handshake, the same way a
    /// stream is and for the same reason: it is the moment the connection's
    /// `ProxyH2Connection` row exists, so the counter and the log agree.
    pub fn record_h2_connection(&self) {
        self.proxy_h2_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one stream opened on a client's HTTP/2 connection.
    ///
    /// Every stream, whatever became of it. What it is *for* is the ratio
    /// against `briefcred_proxy_h2_connections_total`: a client multiplexing
    /// well shows many streams per connection, and one that has fallen back to
    /// a connection per call shows about one — which is the difference between
    /// gRPC working through the proxy and merely not failing.
    pub fn record_h2_stream(&self) {
        self.proxy_h2_streams.fetch_add(1, Ordering::Relaxed);
    }

    /// Record how long one mint took, successful or not.
    ///
    /// Failures are timed too: a backend that takes thirty seconds to refuse is
    /// exactly the thing an operator needs the histogram to show them.
    pub fn record_mint(&self, kind: &str, elapsed: std::time::Duration) {
        self.mint_duration
            .lock()
            .expect("metrics mutex")
            .observe(kind, elapsed.as_secs_f64());
    }

    /// Record how long one revoke attempt took, and whether it failed.
    ///
    /// `failed` counts the attempt against `briefcred_revoke_failures_total`,
    /// which is the series an alert is built on: a revoke that keeps failing is
    /// a credential that is still live.
    pub fn record_revoke(&self, kind: &str, elapsed: std::time::Duration, failed: bool) {
        self.revoke_duration
            .lock()
            .expect("metrics mutex")
            .observe(kind, elapsed.as_secs_f64());
        if failed {
            *self
                .revoke_failures
                .lock()
                .expect("metrics mutex")
                .entry(kind.to_string())
                .or_insert(0) += 1;
        }
    }

    /// Count one handled IPC request.
    pub fn record_request(&self, request: &'static str) {
        *self
            .requests
            .lock()
            .expect("metrics mutex")
            .entry(request)
            .or_insert(0) += 1;
    }

    /// Whole seconds since the daemon finished starting.
    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// The exposition text for one scrape.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "# HELP briefcred_uptime_seconds Seconds since the daemon finished starting.\n",
        );
        out.push_str("# TYPE briefcred_uptime_seconds gauge\n");
        out.push_str(&format!(
            "briefcred_uptime_seconds {}\n",
            self.uptime_secs()
        ));

        out.push_str(
            "# HELP briefcred_ipc_requests_total IPC requests handled, by request kind.\n",
        );
        out.push_str("# TYPE briefcred_ipc_requests_total counter\n");
        for (request, count) in self.requests.lock().expect("metrics mutex").iter() {
            out.push_str(&format!(
                "briefcred_ipc_requests_total{{request=\"{request}\"}} {count}\n"
            ));
        }

        out.push_str(
            "# HELP briefcred_audit_write_errors_total Audit rows that could not be written.\n",
        );
        out.push_str("# TYPE briefcred_audit_write_errors_total counter\n");
        out.push_str(&format!(
            "briefcred_audit_write_errors_total {}\n",
            self.audit_write_errors.load(Ordering::Relaxed)
        ));

        self.mint_duration.lock().expect("metrics mutex").render(
            "briefcred_mint_duration_seconds",
            "Time taken to mint one credential, by minter kind.",
            &mut out,
        );
        self.revoke_duration.lock().expect("metrics mutex").render(
            "briefcred_revoke_duration_seconds",
            "Time taken by one revoke attempt, by minter kind.",
            &mut out,
        );

        out.push_str(
            "# HELP briefcred_revoke_failures_total Revoke attempts that failed, by minter kind.\n",
        );
        out.push_str("# TYPE briefcred_revoke_failures_total counter\n");
        for (kind, count) in self.revoke_failures.lock().expect("metrics mutex").iter() {
            out.push_str(&format!(
                "briefcred_revoke_failures_total{{kind=\"{kind}\"}} {count}\n"
            ));
        }

        out.push_str("# HELP briefcred_handoffs_total Zero-downtime handoffs, by outcome.\n");
        out.push_str("# TYPE briefcred_handoffs_total counter\n");
        for (outcome, count) in self.handoffs.lock().expect("metrics mutex").iter() {
            out.push_str(&format!(
                "briefcred_handoffs_total{{outcome=\"{outcome}\"}} {count}\n"
            ));
        }

        out.push_str(
            "# HELP briefcred_proxy_requests_total Requests through the HTTP proxy, by policy decision and status class.\n",
        );
        out.push_str("# TYPE briefcred_proxy_requests_total counter\n");
        for ((decision, class), count) in self.proxy_requests.lock().expect("metrics mutex").iter()
        {
            out.push_str(&format!(
                "briefcred_proxy_requests_total{{decision=\"{decision}\",status_class=\"{class}\"}} {count}\n"
            ));
        }

        self.proxy_latency.lock().expect("metrics mutex").render(
            "briefcred_proxy_latency_seconds",
            "Time taken by one proxied request, by policy decision.",
            &mut out,
        );

        out.push_str(
            "# HELP briefcred_proxy_streams_total Long-lived streams through the HTTP proxy that have ended, by kind.\n",
        );
        out.push_str("# TYPE briefcred_proxy_streams_total counter\n");
        for (kind, count) in self.proxy_streams.lock().expect("metrics mutex").iter() {
            out.push_str(&format!(
                "briefcred_proxy_streams_total{{kind=\"{kind}\"}} {count}\n"
            ));
        }

        self.proxy_stream_duration
            .lock()
            .expect("metrics mutex")
            .render(
                "briefcred_proxy_stream_duration_seconds",
                "How long one long-lived stream stayed open, by kind.",
                &mut out,
            );

        out.push_str(
            "# HELP briefcred_proxy_h2_connections_total HTTP/2 connections from wrapped subprocesses that have closed.\n",
        );
        out.push_str("# TYPE briefcred_proxy_h2_connections_total counter\n");
        out.push_str(&format!(
            "briefcred_proxy_h2_connections_total {}\n",
            self.proxy_h2_connections.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP briefcred_proxy_h2_streams_total Streams opened on those HTTP/2 connections.\n",
        );
        out.push_str("# TYPE briefcred_proxy_h2_streams_total counter\n");
        out.push_str(&format!(
            "briefcred_proxy_h2_streams_total {}\n",
            self.proxy_h2_streams.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP briefcred_pgproxy_connections_total Connections through the Postgres proxy, by outcome.\n",
        );
        out.push_str("# TYPE briefcred_pgproxy_connections_total counter\n");
        for (outcome, count) in self
            .pgproxy_connections
            .lock()
            .expect("metrics mutex")
            .iter()
        {
            out.push_str(&format!(
                "briefcred_pgproxy_connections_total{{outcome=\"{outcome}\"}} {count}\n"
            ));
        }

        out.push_str(
            "# HELP briefcred_pgproxy_bytes_total Bytes relayed by the Postgres proxy, by direction.\n",
        );
        out.push_str("# TYPE briefcred_pgproxy_bytes_total counter\n");
        for (direction, count) in self.pgproxy_bytes.lock().expect("metrics mutex").iter() {
            out.push_str(&format!(
                "briefcred_pgproxy_bytes_total{{direction=\"{direction}\"}} {count}\n"
            ));
        }

        out.push_str(
            "# HELP briefcred_quota_saturation How full a profile's session quota is, 0 to 1, where 1 is empty.\n",
        );
        out.push_str("# TYPE briefcred_quota_saturation gauge\n");
        for (profile, saturation) in self.quota_saturation.lock().expect("metrics mutex").iter() {
            out.push_str(&format!(
                "briefcred_quota_saturation{{profile=\"{profile}\"}} {saturation}\n"
            ));
        }

        out.push_str(
            "# HELP briefcred_quota_rejections_total Charges a quota refused, by profile and surface.\n",
        );
        out.push_str("# TYPE briefcred_quota_rejections_total counter\n");
        for ((profile, surface), count) in
            self.quota_rejections.lock().expect("metrics mutex").iter()
        {
            out.push_str(&format!(
                "briefcred_quota_rejections_total{{profile=\"{profile}\",surface=\"{surface}\"}} {count}\n"
            ));
        }
        out
    }
}

/// The status class a code belongs to, or `none` where there is no code.
///
/// A request denied by policy never reaches an upstream, so it has no status
/// at all; giving it a class of its own keeps "briefcred refused this" and
/// "the vendor refused this" from being the same series.
fn status_class(status: Option<u16>) -> &'static str {
    match status {
        Some(code) if (100..200).contains(&code) => "1xx",
        Some(code) if (200..300).contains(&code) => "2xx",
        Some(code) if (300..400).contains(&code) => "3xx",
        Some(code) if (400..500).contains(&code) => "4xx",
        Some(code) if (500..600).contains(&code) => "5xx",
        Some(_) => "other",
        None => "none",
    }
}

/// Serve `/metrics` on `listener` until `shutdown` resolves.
///
/// Bound to loopback by the caller. Any path other than `/metrics`, and any
/// method other than `GET`, gets a bare status code and no body worth parsing.
pub async fn serve(
    listener: tokio::net::TcpListener,
    metrics: Arc<Metrics>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        let stream = tokio::select! {
            biased;
            _ = crate::server::shutdown_requested(&mut shutdown) => return,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                // A failed accept is not worth taking the daemon down for.
                Err(_) => continue,
            },
        };

        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let metrics = Arc::clone(&metrics);
                async move { Ok::<_, std::convert::Infallible>(respond(&req, &metrics)) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

fn respond(
    request: &hyper::Request<hyper::body::Incoming>,
    metrics: &Metrics,
) -> HttpResponse<Full<Bytes>> {
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/metrics") => HttpResponse::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, TEXT_FORMAT)
            .body(Full::new(Bytes::from(metrics.render())))
            .expect("static response builds"),
        (&Method::GET, _) => empty(StatusCode::NOT_FOUND),
        _ => empty(StatusCode::METHOD_NOT_ALLOWED),
    }
}

fn empty(status: StatusCode) -> HttpResponse<Full<Bytes>> {
    HttpResponse::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .expect("static response builds")
}

/// Bind the metrics listener to loopback, letting the OS pick when `port` is 0.
pub fn bind(port: u16) -> std::io::Result<(tokio::net::TcpListener, SocketAddr)> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    Ok((tokio::net::TcpListener::from_std(listener)?, addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn every_request_series_is_present_from_the_first_scrape() {
        let metrics = Metrics::new(Arc::new(AtomicU64::new(0)));
        let text = metrics.render();
        for name in Request::NAMES {
            assert!(
                text.contains(&format!(
                    "briefcred_ipc_requests_total{{request=\"{name}\"}} 0"
                )),
                "{name} missing from:\n{text}"
            );
        }
    }

    #[test]
    fn counts_and_error_totals_are_reflected() {
        let errors = Arc::new(AtomicU64::new(3));
        let metrics = Metrics::new(Arc::clone(&errors));
        metrics.record_request("ping");
        metrics.record_request("ping");
        metrics.record_request("status");

        let text = metrics.render();
        assert!(text.contains("briefcred_ipc_requests_total{request=\"ping\"} 2"));
        assert!(text.contains("briefcred_ipc_requests_total{request=\"status\"} 1"));
        assert!(text.contains("briefcred_ipc_requests_total{request=\"shutdown\"} 0"));
        assert!(text.contains("briefcred_audit_write_errors_total 3"));
    }

    #[test]
    fn a_proxied_request_appears_with_its_decision_and_status_class() {
        let metrics = Metrics::new(Arc::new(AtomicU64::new(0)));
        metrics.record_proxy_request("allow", Some(200), Duration::from_millis(30));
        metrics.record_proxy_request("allow", Some(201), Duration::from_millis(30));
        metrics.record_proxy_request("deny", None, Duration::from_millis(1));
        metrics.record_proxy_request("would_deny", Some(503), Duration::from_millis(1));

        let text = metrics.render();
        assert!(
            text.contains(
                "briefcred_proxy_requests_total{decision=\"allow\",status_class=\"2xx\"} 2"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "briefcred_proxy_requests_total{decision=\"deny\",status_class=\"none\"} 1"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "briefcred_proxy_requests_total{decision=\"would_deny\",status_class=\"5xx\"} 1"
            ),
            "{text}"
        );
        assert!(
            text.contains("briefcred_proxy_latency_seconds_count{kind=\"allow\"} 2"),
            "{text}"
        );
    }

    #[test]
    fn a_postgres_connection_appears_with_its_outcome_and_its_byte_counts() {
        let metrics = Metrics::new(Arc::new(AtomicU64::new(0)));
        metrics.record_pgproxy_connection("allow");
        metrics.record_pgproxy_connection("allow");
        metrics.record_pgproxy_connection("deny");
        metrics.record_pgproxy_bytes(40, 900);
        metrics.record_pgproxy_bytes(2, 8);

        let text = metrics.render();
        for expected in [
            "briefcred_pgproxy_connections_total{outcome=\"allow\"} 2",
            "briefcred_pgproxy_connections_total{outcome=\"deny\"} 1",
            "briefcred_pgproxy_bytes_total{direction=\"client_to_server\"} 42",
            "briefcred_pgproxy_bytes_total{direction=\"server_to_client\"} 908",
        ] {
            assert!(text.contains(expected), "{expected} missing from:\n{text}");
        }
    }

    #[test]
    fn a_stream_appears_with_its_kind_and_on_its_own_bucket_scale() {
        let metrics = Metrics::new(Arc::new(AtomicU64::new(0)));
        metrics.record_proxy_stream("sse", Duration::from_secs(45));
        metrics.record_proxy_stream("ws", Duration::from_secs(2));
        metrics.record_proxy_stream("ws", Duration::from_secs(4000));

        let text = metrics.render();
        for expected in [
            "briefcred_proxy_streams_total{kind=\"sse\"} 1",
            "briefcred_proxy_streams_total{kind=\"ws\"} 2",
            // 45 s is over the 30 s bound and at or under the 60 s one.
            "briefcred_proxy_stream_duration_seconds_bucket{kind=\"sse\",le=\"30\"} 0",
            "briefcred_proxy_stream_duration_seconds_bucket{kind=\"sse\",le=\"60\"} 1",
            "briefcred_proxy_stream_duration_seconds_count{kind=\"sse\"} 1",
            // A stream longer than the last bound is still in the total.
            "briefcred_proxy_stream_duration_seconds_bucket{kind=\"ws\",le=\"3600\"} 1",
            "briefcred_proxy_stream_duration_seconds_bucket{kind=\"ws\",le=\"+Inf\"} 2",
        ] {
            assert!(text.contains(expected), "{expected} missing from:\n{text}");
        }
        // The request latencies keep their own, much shorter, scale.
        assert!(
            !text.contains("briefcred_proxy_latency_seconds_bucket{kind=\"allow\",le=\"3600\""),
            "a stream bound leaked onto the latency histogram:\n{text}"
        );
    }

    #[test]
    fn both_stream_kinds_are_present_from_the_first_scrape() {
        let text = Metrics::new(Arc::new(AtomicU64::new(0))).render();
        for kind in PROXY_STREAM_KINDS {
            assert!(
                text.contains(&format!(
                    "briefcred_proxy_streams_total{{kind=\"{kind}\"}} 0"
                )),
                "{kind} missing from:\n{text}"
            );
        }
    }

    #[test]
    fn both_postgres_byte_directions_are_present_from_the_first_scrape() {
        // A counter that only appears once it is non-zero cannot be told apart
        // from a scrape that failed.
        let text = Metrics::new(Arc::new(AtomicU64::new(0))).render();
        for direction in PGPROXY_DIRECTIONS {
            assert!(
                text.contains(&format!(
                    "briefcred_pgproxy_bytes_total{{direction=\"{direction}\"}} 0"
                )),
                "{direction} missing from:\n{text}"
            );
        }
    }

    #[test]
    fn every_status_maps_to_the_class_it_belongs_to() {
        assert_eq!(status_class(None), "none");
        assert_eq!(status_class(Some(100)), "1xx");
        assert_eq!(status_class(Some(204)), "2xx");
        assert_eq!(status_class(Some(301)), "3xx");
        assert_eq!(status_class(Some(429)), "4xx");
        assert_eq!(status_class(Some(503)), "5xx");
        assert_eq!(status_class(Some(999)), "other");
    }

    #[test]
    fn a_mint_appears_in_the_scrape_with_its_kind_and_its_bucket() {
        let metrics = Metrics::new(Arc::new(AtomicU64::new(0)));
        metrics.record_mint("postgres-dynamic", Duration::from_millis(30));

        let text = metrics.render();
        // 30 ms lands in the 0.05 bucket, and every bucket at or above it.
        assert!(
            text.contains(
                "briefcred_mint_duration_seconds_bucket{kind=\"postgres-dynamic\",le=\"0.05\"} 1"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "briefcred_mint_duration_seconds_bucket{kind=\"postgres-dynamic\",le=\"0.025\"} 0"
            ),
            "a 30 ms mint must not be counted in the 25 ms bucket:\n{text}"
        );
        assert!(
            text.contains(
                "briefcred_mint_duration_seconds_bucket{kind=\"postgres-dynamic\",le=\"+Inf\"} 1"
            ),
            "{text}"
        );
        assert!(
            text.contains("briefcred_mint_duration_seconds_count{kind=\"postgres-dynamic\"} 1"),
            "{text}"
        );
    }

    #[test]
    fn buckets_are_cumulative_the_way_prometheus_reads_them() {
        let metrics = Metrics::new(Arc::new(AtomicU64::new(0)));
        for millis in [1, 30, 300] {
            metrics.record_mint("postgres-dynamic", Duration::from_millis(millis));
        }
        let text = metrics.render();
        // Each `le` counts everything at or below its bound, not just its own
        // slice. Getting this wrong is the classic histogram bug.
        for (bound, expected) in [("0.005", 1), ("0.05", 2), ("0.5", 3), ("+Inf", 3)] {
            assert!(
                text.contains(&format!(
                    "briefcred_mint_duration_seconds_bucket{{kind=\"postgres-dynamic\",le=\"{bound}\"}} {expected}"
                )),
                "le={bound} should be {expected}:\n{text}"
            );
        }
        assert!(
            text.contains("briefcred_mint_duration_seconds_count{kind=\"postgres-dynamic\"} 3"),
            "{text}"
        );
    }

    #[test]
    fn a_revoke_is_timed_and_only_a_failure_is_counted_as_one() {
        let metrics = Metrics::new(Arc::new(AtomicU64::new(0)));
        metrics.record_revoke("postgres-dynamic", Duration::from_millis(8), false);
        metrics.record_revoke("postgres-dynamic", Duration::from_millis(8), true);

        let text = metrics.render();
        assert!(
            text.contains("briefcred_revoke_duration_seconds_count{kind=\"postgres-dynamic\"} 2"),
            "both attempts are timed:\n{text}"
        );
        assert!(
            text.contains("briefcred_revoke_failures_total{kind=\"postgres-dynamic\"} 1"),
            "only the failed one is counted as a failure:\n{text}"
        );
    }

    #[test]
    fn an_observation_past_the_last_bound_lands_only_in_the_infinity_bucket() {
        let metrics = Metrics::new(Arc::new(AtomicU64::new(0)));
        metrics.record_revoke("aws-sts", Duration::from_secs(30), true);
        let text = metrics.render();
        assert!(
            text.contains("briefcred_revoke_duration_seconds_bucket{kind=\"aws-sts\",le=\"5\"} 0"),
            "{text}"
        );
        assert!(
            text.contains(
                "briefcred_revoke_duration_seconds_bucket{kind=\"aws-sts\",le=\"+Inf\"} 1"
            ),
            "{text}"
        );
    }

    #[test]
    fn kinds_do_not_bleed_into_one_another() {
        let metrics = Metrics::new(Arc::new(AtomicU64::new(0)));
        metrics.record_mint("postgres-dynamic", Duration::from_millis(5));
        metrics.record_mint("aws-sts", Duration::from_millis(5));
        let text = metrics.render();
        assert!(text.contains("briefcred_mint_duration_seconds_count{kind=\"postgres-dynamic\"} 1"));
        assert!(text.contains("briefcred_mint_duration_seconds_count{kind=\"aws-sts\"} 1"));
    }

    #[test]
    fn every_series_carries_a_help_and_a_type_line() {
        let metrics = Metrics::new(Arc::new(AtomicU64::new(0)));
        metrics.record_mint("postgres-dynamic", Duration::from_millis(1));
        metrics.record_revoke("postgres-dynamic", Duration::from_millis(1), true);
        let text = metrics.render();
        for series in [
            "briefcred_uptime_seconds",
            "briefcred_ipc_requests_total",
            "briefcred_audit_write_errors_total",
            "briefcred_mint_duration_seconds",
            "briefcred_revoke_duration_seconds",
            "briefcred_revoke_failures_total",
            "briefcred_pgproxy_connections_total",
            "briefcred_pgproxy_bytes_total",
            "briefcred_proxy_streams_total",
            "briefcred_proxy_stream_duration_seconds",
            "briefcred_proxy_h2_connections_total",
            "briefcred_proxy_h2_streams_total",
        ] {
            assert!(text.contains(&format!("# HELP {series} ")), "{series}");
            assert!(text.contains(&format!("# TYPE {series} ")), "{series}");
        }
        assert!(text.ends_with('\n'));
    }

    #[tokio::test]
    async fn port_zero_binds_somewhere_on_loopback() {
        let (_listener, addr) = bind(0).unwrap();
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0);
    }
}
