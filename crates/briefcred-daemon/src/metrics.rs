//! The Prometheus text endpoint, on loopback only.
//!
//! Three series, all of them operational: how long the daemon has been up,
//! how many IPC requests it has handled by kind, and how many audit rows it
//! failed to write. Nothing here is derived from credential material, and the
//! listener is bound to `127.0.0.1` so it is not reachable off the machine.

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

/// The daemon's counters and gauges.
#[derive(Debug)]
pub struct Metrics {
    started: Instant,
    requests: Mutex<BTreeMap<&'static str, u64>>,
    audit_write_errors: Arc<AtomicU64>,
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
            _ = shutdown.changed() => return,
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
    fn every_series_carries_a_help_and_a_type_line() {
        let metrics = Metrics::new(Arc::new(AtomicU64::new(0)));
        let text = metrics.render();
        for series in [
            "briefcred_uptime_seconds",
            "briefcred_ipc_requests_total",
            "briefcred_audit_write_errors_total",
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
