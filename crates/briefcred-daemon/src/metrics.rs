//! The Prometheus text endpoint, on loopback only.
//!
//! Six series, all of them operational: how long the daemon has been up, how
//! many IPC requests it has handled by kind, how many audit rows it failed to
//! write, how long mints and revokes take by minter kind, and how many revokes
//! have failed. Nothing here is derived from credential material — a histogram
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

/// One latency histogram, keyed by minter kind.
///
/// Hand-rolled rather than pulled from a metrics crate: three series is not
/// enough to justify a dependency that would also want to own the registry,
/// the exposition format, and the process's global state.
#[derive(Debug, Default)]
struct Histogram {
    /// Per kind: one cumulative counter per bucket, plus count and sum.
    by_kind: BTreeMap<String, Series>,
}

#[derive(Debug)]
struct Series {
    /// Non-cumulative observation counts, one per bound in [`LATENCY_BUCKETS`].
    buckets: [u64; LATENCY_BUCKETS.len()],
    /// Observations above the last bound.
    overflow: u64,
    /// Total observations.
    count: u64,
    /// Total observed seconds.
    sum: f64,
}

impl Default for Series {
    fn default() -> Series {
        Series {
            buckets: [0; LATENCY_BUCKETS.len()],
            overflow: 0,
            count: 0,
            sum: 0.0,
        }
    }
}

impl Histogram {
    fn observe(&mut self, kind: &str, seconds: f64) {
        let series = self.by_kind.entry(kind.to_string()).or_default();
        match LATENCY_BUCKETS.iter().position(|bound| seconds <= *bound) {
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
            for (index, bound) in LATENCY_BUCKETS.iter().enumerate() {
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
}

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
        }
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
        out
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
