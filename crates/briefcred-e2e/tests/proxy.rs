//! The HTTP proxy, end to end, against a real daemon and a real HTTPS upstream.
//!
//! Everything here runs against the actual `briefcred-daemon` binary. The
//! client speaks the proxy protocol on a socket — `CONNECT`, then TLS, then
//! HTTP/1.1 — and the upstream is an in-process `hyper` server with a
//! certificate from a throwaway CA that only this daemon trusts, through the
//! `upstream_roots` key `daemon.toml` documents as being for exactly this.
//!
//! What is being proved is the thing that cannot be proved anywhere else: that
//! a subprocess holding only a synthetic token reaches the upstream with the
//! **real** key attached, that the upstream never sees the token, and that the
//! policy, the revocation, and the proof checks all hold on the wire.

// Beside this file rather than in `tests/` itself: a `tests/grpc.rs` would be
// a second test binary, and everything here shares one daemon fixture.
#[path = "proxy/grpc.rs"]
mod grpc;

use std::sync::Arc;
use std::time::Duration;

use briefcred_e2e::daemon_harness::Daemon;
use briefcred_proto::{Request, Response};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// The host the upstream is served as, and the only one that resolves.
const UPSTREAM_HOST: &str = "localhost";

/// The real credential. It must never appear in an audit row or a token.
const REAL_KEY: &str = "sk-the-real-openai-key";

/// A profile permitting exactly one method on one path.
fn profile(policy_mode: &str) -> String {
    quota_profile(policy_mode, "")
}

/// A profile that also permits the two streaming paths.
///
/// `enforce`, deliberately. A WebSocket handshake is a `GET` and the policy
/// decides it as one, so a profile that permits `/ws` by name is what proves
/// the handshake went through the policy rather than around it.
fn stream_profile() -> String {
    format!(
        "\
name: openai
unlock:
  policy: none
credentials:
  - name: openai
    kind: http-bearer
    ttl_secs: 300
policy_mode: enforce
policy: |
  permit(principal, action == Action::\"GET\", resource)
  when {{ resource.host == \"{UPSTREAM_HOST}\" &&
    [\"/v1/models\", \"/events\", \"/events-sized\", \"/forever\", \"/ws\"]
      .contains(resource.path) }};
env:
  OPENAI_API_KEY: ${{minted.openai.TOKEN}}
"
    )
}

/// The byte budget `a_websocket_spends_the_sessions_byte_budget` runs against.
///
/// Small enough that a handful of echoed frames passes it, large enough that
/// the `exec` and the first `/v1/models` do not.
const BYTE_BUDGET: usize = 4096;

/// A profile whose policy is a per-session byte budget.
///
/// `context.resp_bytes_so_far` counts what the session has already been given.
/// A WebSocket that did not feed it would be a budget any agent could step
/// around by asking for a socket instead of a response.
fn byte_budget_profile() -> String {
    format!(
        "\
name: openai
unlock:
  policy: none
credentials:
  - name: openai
    kind: http-bearer
    ttl_secs: 300
policy_mode: enforce
policy: |
  permit(principal, action == Action::\"GET\", resource)
  when {{ resource.host == \"{UPSTREAM_HOST}\" &&
    [\"/v1/models\", \"/ws\"].contains(resource.path) &&
    context.resp_bytes_so_far < {BYTE_BUDGET} }};
env:
  OPENAI_API_KEY: ${{minted.openai.TOKEN}}
"
    )
}

/// The same, with a `quota:` block spliced in.
///
/// `quota` is the whole YAML block or the empty string, rather than a rate and
/// a burst, so a test can say "no quota at all" in the same call.
fn quota_profile(policy_mode: &str, quota: &str) -> String {
    format!(
        "\
name: openai
unlock:
  policy: none
credentials:
  - name: openai
    kind: http-bearer
    ttl_secs: 300
{quota}policy_mode: {policy_mode}
policy: |
  permit(principal, action == Action::\"GET\", resource)
  when {{ resource.host == \"{UPSTREAM_HOST}\" && resource.path == \"/v1/models\" }};
env:
  OPENAI_API_KEY: ${{minted.openai.TOKEN}}
"
    )
}

// ---------------------------------------------------------------- the upstream

/// What one request reached the upstream carrying.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    authorization: Option<String>,
    dpop: Option<String>,
    path: String,
}

/// A throwaway CA, a listener, and the requests it has seen.
struct Upstream {
    ca_pem: String,
    port: u16,
    /// The gRPC server, on a third listener behind the same certificate.
    grpc: grpc::Server,
    /// The WebSocket server's own port, which is a separate listener.
    ws_port: u16,
    seen: Arc<std::sync::Mutex<Vec<Seen>>>,
    /// When the event stream sent its hundredth event, for the buffering test.
    last_event_sent: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    /// What each WebSocket handshake reached the upstream carrying.
    ws_seen: Arc<std::sync::Mutex<Vec<Option<String>>>>,
    /// The accept loop, so a test can take the upstream away mid-run.
    accepting: tokio::task::JoinHandle<()>,
    /// The WebSocket accept loop, kept so it lives as long as the fixture.
    #[allow(dead_code)]
    ws_accepting: tokio::task::JoinHandle<()>,
}

/// How many events `/events` sends, and the gap between them.
const SSE_EVENTS: usize = 100;

/// The gap between events, long enough that a buffering proxy is obvious.
const SSE_GAP: Duration = Duration::from_millis(10);

/// Start an in-process HTTPS server on loopback.
///
/// `/v1/models` answers `200` with a small body; `/big` answers with four
/// mebibytes sent in two halves with a pause between them, which is how the
/// streaming test tells "passed through" from "buffered whole". `/events` is an
/// event stream of a hundred events ten milliseconds apart, and `/forever` one
/// that never ends on its own, which is what a revoked-mid-stream test needs.
async fn start_upstream() -> Upstream {
    use futures_util::StreamExt as _;
    use http_body_util::{BodyExt, StreamBody};
    use hyper::body::{Bytes, Frame};
    use hyper::service::service_fn;

    let ca = briefcred_core::CertificateAuthority::generate("test-upstream").unwrap();
    let leaf = ca.issue_leaf(&[UPSTREAM_HOST.to_string()]).unwrap();
    let chain: Vec<_> = rustls_pemfile::certs(&mut leaf.cert_pem().as_bytes())
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut leaf.key_pem().as_bytes())
        .unwrap()
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .unwrap();

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<std::sync::Mutex<Vec<Seen>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let last_event_sent: Arc<std::sync::Mutex<Option<std::time::Instant>>> =
        Arc::new(std::sync::Mutex::new(None));

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let (ws_port, ws_seen, ws_accepting) = start_ws_upstream(acceptor.clone()).await;
    let grpc = grpc::start(&leaf).await;
    let recorded = Arc::clone(&seen);
    let stamped = Arc::clone(&last_event_sent);
    let accepting = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let recorded = Arc::clone(&recorded);
            let stamped = Arc::clone(&stamped);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let recorded = Arc::clone(&recorded);
                    let stamped = Arc::clone(&stamped);
                    async move {
                        let header = |name: &str| {
                            request
                                .headers()
                                .get(name)
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_string)
                        };
                        let path = request.uri().path().to_string();
                        recorded.lock().unwrap().push(Seen {
                            authorization: header("authorization"),
                            dpop: header("dpop"),
                            path: path.clone(),
                        });

                        // An event stream an upstream chose to give a length.
                        // Legal, and wrong for the client: the proxy's copy
                        // ends when the upstream stops, not at a byte count
                        // this server decided in advance.
                        if path == "/events-sized" {
                            let events: String = (1..=SSE_EVENTS)
                                .map(|n| format!("data: event {n}\n\n"))
                                .collect();
                            let response = hyper::Response::builder()
                                .header("content-type", "text/event-stream")
                                .header("content-length", events.len().to_string())
                                .body(
                                    http_body_util::Full::new(Bytes::from(events))
                                        .map_err(|never| match never {})
                                        .boxed(),
                                )
                                .unwrap();
                            return Ok::<_, std::convert::Infallible>(response);
                        }

                        // An event stream, which is the one response with a
                        // content type the proxy reads and acts on.
                        if path == "/events" || path == "/forever" {
                            let forever = path == "/forever";
                            let stamped = Arc::clone(&stamped);
                            let events = futures_util::stream::unfold(0usize, move |n| {
                                let stamped = Arc::clone(&stamped);
                                async move {
                                    if !forever && n > SSE_EVENTS {
                                        return None;
                                    }
                                    tokio::time::sleep(SSE_GAP).await;
                                    // The first thing on the wire is a
                                    // keep-alive comment, which the client must
                                    // receive and the proxy must not count.
                                    let chunk = if n == 0 {
                                        ": keep-alive\n\n".to_string()
                                    } else {
                                        format!("data: event {n}\n\n")
                                    };
                                    if !forever && n == SSE_EVENTS {
                                        *stamped.lock().unwrap() = Some(std::time::Instant::now());
                                    }
                                    Some((
                                        Ok::<_, std::convert::Infallible>(Frame::data(
                                            Bytes::from(chunk),
                                        )),
                                        n + 1,
                                    ))
                                }
                            });
                            let response = hyper::Response::builder()
                                .header("content-type", "text/event-stream")
                                .header("cache-control", "no-cache")
                                .body(BodyExt::boxed(StreamBody::new(events)))
                                .unwrap();
                            return Ok::<_, std::convert::Infallible>(response);
                        }

                        let body = if path == "/big" {
                            let chunk = Bytes::from(vec![b'x'; 2 * 1024 * 1024]);
                            let second = chunk.clone();
                            let stream = futures_util::stream::once(async move {
                                Ok::<_, std::convert::Infallible>(Frame::data(chunk))
                            })
                            .chain(futures_util::stream::once(async move {
                                // Long enough that a proxy which buffered the
                                // whole body could not have answered yet.
                                tokio::time::sleep(Duration::from_millis(600)).await;
                                Ok(Frame::data(second))
                            }));
                            BodyExt::boxed(StreamBody::new(stream))
                        } else {
                            http_body_util::Full::new(Bytes::from_static(b"{\"data\":[]}"))
                                .map_err(|never| match never {})
                                .boxed()
                        };
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(body))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                    .await;
            });
        }
    });

    Upstream {
        ca_pem: ca.cert_pem().to_string(),
        port,
        grpc,
        ws_port,
        seen,
        last_event_sent,
        ws_seen,
        accepting,
        ws_accepting,
    }
}

/// A real WebSocket server on its own port, behind the same certificate.
///
/// Its own listener rather than a route on the HTTPS server, because a
/// WebSocket server is not an HTTP server that happens to answer `101`: this
/// one does the handshake itself and then speaks frames, which is what makes it
/// a fair test of a proxy that has to do the same handshake in the middle.
///
/// Echoes every data frame back and closes when the client closes. The
/// `Authorization` each handshake carried is recorded, so a test can prove the
/// upstream saw the real key and never the synthetic token.
async fn start_ws_upstream(
    acceptor: tokio_rustls::TlsAcceptor,
) -> (
    u16,
    Arc<std::sync::Mutex<Vec<Option<String>>>>,
    tokio::task::JoinHandle<()>,
) {
    use futures_util::{SinkExt as _, StreamExt as _};

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<std::sync::Mutex<Vec<Option<String>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));

    let recorded = Arc::clone(&seen);
    let accepting = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                // The error half is tungstenite's own and never produced here;
                // this callback only looks and waves the response through.
                #[allow(clippy::result_large_err)]
                let observe = |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                               response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    recorded.lock().unwrap().push(
                        request
                            .headers()
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_string),
                    );
                    Ok(response)
                };
                let Ok(mut socket) = tokio_tungstenite::accept_hdr_async(tls, observe).await else {
                    return;
                };
                while let Some(Ok(message)) = socket.next().await {
                    if message.is_close() {
                        break;
                    }
                    if socket.send(message).await.is_err() {
                        break;
                    }
                }
                let _ = socket.close(None).await;
            });
        }
    });
    (port, seen, accepting)
}

// ------------------------------------------------------------------ the client

/// One request made through the proxy, exactly as a wrapped subprocess would.
struct ProxyClient {
    proxy_addr: String,
    briefcred_ca: String,
    upstream_port: u16,
    ws_port: u16,
    /// The gRPC server's port, which is a third listener.
    grpc_port: u16,
}

impl ProxyClient {
    /// `CONNECT`, terminate TLS against briefcred's CA, and send one request.
    async fn get(
        &self,
        path: &str,
        headers: &[(&str, String)],
    ) -> Result<(u16, Vec<u8>, Duration), String> {
        self.request("GET", path, headers).await
    }

    /// The same as [`ProxyClient::get`], also reporting one response header.
    ///
    /// A separate method rather than a fourth element on every tuple: exactly
    /// one test cares what came back in a header, and widening the common
    /// return type for it would touch every other call site.
    async fn get_with_header(
        &self,
        path: &str,
        headers: &[(&str, String)],
        header: &str,
    ) -> Result<(u16, Vec<u8>, Option<String>), String> {
        let (status, body, seen) = self.send("GET", path, headers, Some(header)).await?;
        Ok((status, body, seen.1))
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
    ) -> Result<(u16, Vec<u8>, Duration), String> {
        let (status, body, (first_byte_at, _)) = self.send(method, path, headers, None).await?;
        Ok((status, body, first_byte_at))
    }

    /// One request through the tunnel, timed, optionally reading one header.
    async fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        want_header: Option<&str>,
    ) -> Result<(u16, Vec<u8>, (Duration, Option<String>)), String> {
        let tls = self.tunnel(self.upstream_port).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("host", UPSTREAM_HOST);
        for (name, value) in headers {
            builder = builder.header(*name, value);
        }
        let request = builder
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .unwrap();

        let started = std::time::Instant::now();
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let seen_header = want_header.and_then(|name| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        });

        // Timed to the *first* body byte, which is what tells a streamed
        // response from a buffered one.
        use http_body_util::BodyExt as _;
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        let mut first_byte_at = None;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| e.to_string())?;
            if let Some(data) = frame.data_ref() {
                if first_byte_at.is_none() && !data.is_empty() {
                    first_byte_at = Some(started.elapsed());
                }
                bytes.extend_from_slice(data);
            }
        }
        Ok((
            status,
            bytes,
            (first_byte_at.unwrap_or(started.elapsed()), seen_header),
        ))
    }

    /// `CONNECT` to `port`, then terminate TLS against briefcred's own CA.
    ///
    /// Exactly what a wrapped subprocess does, and the first half of every
    /// method here: the tunnel is opened the same way whether what goes through
    /// it is one request, an event stream, or a WebSocket handshake.
    async fn tunnel(
        &self,
        port: u16,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
        self.tunnel_with_alpn(port, &[]).await
    }

    /// The same tunnel, offering `alpn` when it terminates TLS.
    ///
    /// Empty offers nothing, which is what a client that only speaks HTTP/1.1
    /// does; `[b"h2"]` is what an HTTP/2 client or a gRPC runtime sends, and
    /// is how a test says which half of the proxy's ALPN branch it is
    /// exercising.
    async fn tunnel_with_alpn(
        &self,
        port: u16,
        alpn: &[&[u8]],
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
        let mut stream = TcpStream::connect(&self.proxy_addr)
            .await
            .map_err(|e| e.to_string())?;
        let authority = format!("{UPSTREAM_HOST}:{port}");
        stream
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await
            .map_err(|e| e.to_string())?;

        // The status line and the blank line that ends the headers. Read a byte
        // at a time so nothing of the TLS that follows is consumed.
        let mut head = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            let read = stream.read(&mut byte).await.map_err(|e| e.to_string())?;
            if read == 0 {
                return Err(format!(
                    "the proxy closed the tunnel: {}",
                    String::from_utf8_lossy(&head)
                ));
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&head).to_string();
        if !head.starts_with("HTTP/1.1 200") {
            return Err(format!("CONNECT was refused: {head}"));
        }

        let mut roots = rustls::RootCertStore::empty();
        for certificate in rustls_pemfile::certs(&mut self.briefcred_ca.as_bytes()) {
            roots.add(certificate.map_err(|e| e.to_string())?).unwrap();
        }
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|name| name.to_vec()).collect();
        let name = rustls_pki_types::ServerName::try_from(UPSTREAM_HOST).unwrap();
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await
            .map_err(|e| format!("the proxy's certificate did not verify: {e}"))
    }

    /// Open an event stream and read it to its end.
    ///
    /// Every chunk is timestamped as it arrives, which is the only way to say
    /// anything about *when* the client got an event rather than only that it
    /// eventually did.
    async fn events(&self, path: &str, headers: &[(&str, String)]) -> Result<SseRun, String> {
        use http_body_util::BodyExt as _;

        let tls = self.tunnel(self.upstream_port).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut builder = hyper::Request::builder()
            .method("GET")
            .uri(path)
            .header("host", UPSTREAM_HOST)
            .header("accept", "text/event-stream");
        for (name, value) in headers {
            builder = builder.header(*name, value);
        }
        let request = builder
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .unwrap();

        let started = std::time::Instant::now();
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| e.to_string())?;
        let mut run = SseRun {
            status: response.status().as_u16(),
            content_length: response
                .headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            content_type: response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            body: Vec::new(),
            first_event_at: None,
            ended_at: started,
        };

        let mut body = response.into_body();
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else { break };
            let Some(data) = frame.data_ref() else {
                continue;
            };
            run.body.extend_from_slice(data);
            if run.first_event_at.is_none() && run.body.windows(5).any(|w| w == b"data:") {
                run.first_event_at = Some(std::time::Instant::now());
            }
        }
        run.ended_at = std::time::Instant::now();
        Ok(run)
    }

    /// Complete a WebSocket handshake through the proxy.
    ///
    /// `tokio-tungstenite` does the handshake and the framing, so what is under
    /// test is the proxy in the middle rather than this test's own idea of the
    /// protocol.
    async fn websocket(
        &self,
        path: &str,
        headers: &[(&str, String)],
    ) -> Result<
        tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>,
        String,
    > {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

        let tls = self.tunnel(self.ws_port).await?;
        let mut request = format!("ws://{UPSTREAM_HOST}{path}")
            .into_client_request()
            .map_err(|e| e.to_string())?;
        for (name, value) in headers {
            request.headers_mut().insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(value).unwrap(),
            );
        }
        let (socket, _) = tokio_tungstenite::client_async(request, tls)
            .await
            .map_err(|e| format!("the websocket handshake failed: {e}"))?;
        Ok(socket)
    }
}

/// One event stream, as the client experienced it.
struct SseRun {
    status: u16,
    content_length: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
    /// When the first `data:` reached the client.
    first_event_at: Option<std::time::Instant>,
    /// When the stream closed.
    ended_at: std::time::Instant,
}

impl SseRun {
    /// Events in the body, counted the way the proxy counts them.
    fn events(&self) -> usize {
        String::from_utf8_lossy(&self.body)
            .split("\n\n")
            .filter(|block| block.lines().any(|line| line.starts_with("data:")))
            .count()
    }
}

// ----------------------------------------------------------------- the harness

/// A daemon with a CA, a profile, a master, and a session already open.
struct Fixture {
    daemon: Daemon,
    upstream: Upstream,
    client: ProxyClient,
    session_id: String,
    token: String,
    session_key: briefcred_cli::session_key::SessionKey,
}

async fn start(policy_mode: &str) -> Fixture {
    start_with(&profile(policy_mode)).await
}

async fn start_with(profile_yaml: &str) -> Fixture {
    let upstream = start_upstream().await;

    let daemon = Daemon::prepare("");
    // A file keystore and a file master source: no keychain item is created,
    // so a test run leaves nothing on the developer's machine.
    let roots = daemon.home().join("upstream-roots.pem");
    std::fs::write(&roots, &upstream.ca_pem).unwrap();
    std::fs::write(
        daemon.home().join("daemon.toml"),
        format!(
            "metrics_enabled = true\nmetrics_port = 0\nproxy_port = 0\npg_proxy_port = 0\n\
             master_source = \"file\"\nupstream_roots = {:?}\n[ca]\nkeystore = \"file\"\n",
            roots.display().to_string()
        ),
    )
    .unwrap();

    // The proxy loads a CA, it never generates one: `briefcred install` does
    // that, and this is the test's stand-in for having run it.
    let ca = briefcred_core::CertificateAuthority::generate("test-machine").unwrap();
    let store = briefcred_core::keystore::FileKeyStore::new(daemon.home().join("ca"));
    let paths =
        briefcred_core::paths::Paths::resolve(briefcred_core::paths::Platform::MacOs, &|key| {
            (key == briefcred_core::paths::HOME_ENV)
                .then(|| std::ffi::OsString::from(daemon.home()))
        })
        .unwrap();
    ca.save(&paths, &store).unwrap();
    let briefcred_ca = ca.cert_pem().to_string();

    daemon.write_profile("openai", profile_yaml);
    daemon.write_master("openai", REAL_KEY);

    let mut daemon = daemon;
    daemon.start().await.unwrap_or_else(|e| panic!("{e}"));

    let Response::Status { proxy_addr, .. } = daemon.request(Request::Status).await.unwrap() else {
        panic!("expected a status");
    };
    let proxy_addr = proxy_addr.expect("the proxy is enabled");

    let session_key = briefcred_cli::session_key::SessionKey::generate();
    let Response::SessionOpened { session_id, .. } = daemon
        .request(Request::OpenSession {
            profile: "openai".to_string(),
            client_headless: true,
            session_pubkey: Some(session_key.public_key_base64()),
        })
        .await
        .unwrap()
    else {
        panic!("the session did not open:\n{}", daemon.log());
    };

    let Response::Minted { mints, env, .. } = daemon
        .request(Request::Exec {
            session_id: session_id.clone(),
            credentials: None,
            argv0: "curl".to_string(),
            args: Vec::new(),
            pid: std::process::id(),
        })
        .await
        .unwrap()
    else {
        panic!("nothing was minted:\n{}", daemon.log());
    };
    let token = mints[0].fields["TOKEN"].expose().to_string();
    assert_eq!(
        env["OPENAI_API_KEY"].expose(),
        token,
        "the profile's env must carry the synthetic token, not the real key"
    );

    let client = ProxyClient {
        proxy_addr,
        briefcred_ca,
        upstream_port: upstream.port,
        ws_port: upstream.ws_port,
        grpc_port: upstream.grpc.port,
    };
    Fixture {
        daemon,
        upstream,
        client,
        session_id,
        token,
        session_key,
    }
}

impl Fixture {
    /// Take the upstream away, so the next forward cannot reach it.
    ///
    /// Aborting the accept loop drops the listener with it, so the port stops
    /// answering rather than accepting and hanging — the proxy then fails to
    /// connect, which is the case under test.
    fn stop_upstream(&self) {
        self.upstream.accepting.abort();
    }
}

fn bearer(token: &str) -> Vec<(&'static str, String)> {
    vec![("authorization", format!("Bearer {token}"))]
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

// -------------------------------------------------------------------- the tests

#[tokio::test]
async fn a_permitted_request_reaches_the_upstream_with_the_real_key() {
    let fixture = start("enforce").await;
    let (status, body, _) = fixture
        .client
        .get("/v1/models", &bearer(&fixture.token))
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));

    assert_eq!(status, 200, "{}", fixture.daemon.log());
    assert_eq!(body, b"{\"data\":[]}");

    let seen = fixture.upstream.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some(format!("Bearer {REAL_KEY}").as_str()),
        "the upstream must see the real key"
    );
    assert!(
        !seen[0].authorization.as_deref().unwrap().contains("bc."),
        "no synthetic token may reach the upstream"
    );
}

#[tokio::test]
async fn a_request_the_policy_does_not_permit_is_refused_before_it_leaves() {
    let fixture = start("enforce").await;
    let (status, _, _) = fixture
        .client
        .get("/v1/chat/completions", &bearer(&fixture.token))
        .await
        .unwrap();

    assert_eq!(status, 403);
    assert!(
        fixture.upstream.seen.lock().unwrap().is_empty(),
        "a denied request must not reach the upstream at all"
    );
}

#[tokio::test]
async fn observe_mode_forwards_the_request_and_records_that_it_would_have_denied() {
    let fixture = start("observe").await;
    let (status, _, _) = fixture
        .client
        .get("/v1/chat/completions", &bearer(&fixture.token))
        .await
        .unwrap();

    assert_eq!(status, 200, "observe mode must not block");
    assert_eq!(fixture.upstream.seen.lock().unwrap().len(), 1);

    // The audit writer is a task of its own, so the row reaches the disk a
    // moment after the response reaches the client.
    assert!(
        proxy_row_written(&fixture.daemon).await,
        "no proxy_request row:\n{}",
        fixture.daemon.log()
    );
    let rows = fixture.daemon.audit_rows();
    let row = rows
        .iter()
        .find(|row| row["event"] == "proxy_request")
        .expect("a proxy_request row");
    assert_eq!(row["decision"], "would_deny");
}

#[tokio::test]
async fn a_request_with_no_token_is_refused() {
    let fixture = start("enforce").await;
    let (status, _, _) = fixture.client.get("/v1/models", &[]).await.unwrap();
    assert_eq!(status, 407);
}

#[tokio::test]
async fn a_tampered_token_is_refused() {
    let fixture = start("enforce").await;
    let mut broken = fixture.token.clone();
    let last = broken.pop().unwrap();
    broken.push(if last == 'A' { 'B' } else { 'A' });

    let (status, _, _) = fixture
        .client
        .get("/v1/models", &bearer(&broken))
        .await
        .unwrap();
    assert_eq!(status, 401);
    assert!(fixture.upstream.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_token_whose_session_is_gone_is_refused_even_though_it_still_verifies() {
    // The signature and the expiry are the token's own; the session it names is
    // not. A token that outlives its session has to stop working, or closing a
    // session would be a suggestion rather than a wipe.
    let fixture = start("enforce").await;
    let (status, _, _) = fixture
        .client
        .get("/v1/models", &bearer(&fixture.token))
        .await
        .unwrap();
    assert_eq!(
        status, 200,
        "the same token works while the session is open"
    );
    fixture.upstream.seen.lock().unwrap().clear();

    fixture
        .daemon
        .request(Request::CloseSession {
            session_id: fixture.session_id.clone(),
        })
        .await
        .unwrap();

    let (status, _, _) = fixture
        .client
        .get("/v1/models", &bearer(&fixture.token))
        .await
        .unwrap();
    // Closing a session both drops the lookup and queues the revoke of what it
    // minted, so either refusal is correct and which one arrives first is a
    // race. What must never happen is the request being forwarded.
    assert!(
        status == 401 || status == 403,
        "a token for a closed session must be refused, got {status}:\n{}",
        fixture.daemon.log()
    );
    assert!(
        fixture.upstream.seen.lock().unwrap().is_empty(),
        "no credential may be attached to a request for a session that is gone"
    );
}

#[tokio::test]
async fn a_revoked_token_stops_working_at_once() {
    let fixture = start("enforce").await;
    let (status, _, _) = fixture
        .client
        .get("/v1/models", &bearer(&fixture.token))
        .await
        .unwrap();
    assert_eq!(status, 200);

    // What `briefcred exec` sends when the child exits.
    fixture
        .daemon
        .request(Request::ExecDone {
            session_id: fixture.session_id.clone(),
            mint_ids: mint_ids(&fixture.daemon).await,
            exit_code: Some(0),
            duration_ms: 1,
            hold_until_expiry: false,
        })
        .await
        .unwrap();

    let refused = briefcred_e2e::daemon_harness::wait_until(Duration::from_secs(10), || {
        let client = &fixture.client;
        let token = fixture.token.clone();
        async move {
            client
                .get("/v1/models", &bearer(&token))
                .await
                .map(|(status, _, _)| status == 403)
                .unwrap_or(false)
        }
    })
    .await;
    assert!(refused, "a revoked grant must stop being served");
}

#[tokio::test]
async fn a_valid_dpop_proof_is_accepted_and_is_not_forwarded_upstream() {
    let fixture = start("enforce").await;
    let htu = format!("https://{UPSTREAM_HOST}/v1/models");
    let mut headers = bearer(&fixture.token);
    headers.push(("dpop", fixture.session_key.dpop_proof("GET", &htu, now())));

    let (status, _, _) = fixture
        .client
        .get("/v1/models", &headers)
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));
    assert_eq!(status, 200);

    let seen = fixture.upstream.seen.lock().unwrap().clone();
    assert_eq!(
        seen[0].dpop, None,
        "a proof is briefcred's, not the vendor's"
    );
}

#[tokio::test]
async fn a_dpop_proof_from_another_key_is_refused() {
    let fixture = start("enforce").await;
    let stranger = briefcred_cli::session_key::SessionKey::generate();
    let htu = format!("https://{UPSTREAM_HOST}/v1/models");
    let mut headers = bearer(&fixture.token);
    headers.push(("dpop", stranger.dpop_proof("GET", &htu, now())));

    let (status, _, _) = fixture.client.get("/v1/models", &headers).await.unwrap();
    assert_eq!(status, 401);
    assert!(fixture.upstream.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_dpop_proof_for_another_request_is_refused() {
    let fixture = start("enforce").await;
    let mut headers = bearer(&fixture.token);
    headers.push((
        "dpop",
        fixture
            .session_key
            .dpop_proof("GET", "https://elsewhere.test/v1/models", now()),
    ));

    let (status, _, _) = fixture.client.get("/v1/models", &headers).await.unwrap();
    assert_eq!(status, 401);
}

#[tokio::test]
async fn an_unreachable_upstream_is_not_recorded_as_a_policy_denial() {
    // The policy allowed this request; the upstream simply was not there. A
    // row saying `deny` would send whoever reads it to widen a policy that was
    // never the problem, and a `status: 502` would put briefcred's own failure
    // in the field that means "what the vendor answered".
    let fixture = start("observe").await;
    fixture.stop_upstream();

    let (status, _, _) = fixture
        .client
        .get("/v1/models", &bearer(&fixture.token))
        .await
        .unwrap();
    assert_eq!(status, 502);

    assert!(
        proxy_row_written(&fixture.daemon).await,
        "a failed forward must still be audited:\n{}",
        fixture.daemon.log()
    );
    let rows = fixture.daemon.audit_rows();
    let row = rows.iter().find(|r| r["event"] == "proxy_request").unwrap();
    assert_eq!(row["decision"], "upstream_error");
    assert!(
        row["status"].is_null(),
        "nothing reached an upstream, so there is no upstream status: {row}"
    );
    assert_eq!(row["host"], UPSTREAM_HOST);
    assert_eq!(row["path"], "/v1/models");
}

#[tokio::test]
async fn the_audit_row_carries_metadata_and_never_a_credential() {
    let fixture = start("enforce").await;
    fixture
        .client
        .get("/v1/models", &bearer(&fixture.token))
        .await
        .unwrap();

    assert!(
        proxy_row_written(&fixture.daemon).await,
        "a forwarded request must be audited:\n{}",
        fixture.daemon.log()
    );

    let rows = fixture.daemon.audit_rows();
    let row = rows.iter().find(|r| r["event"] == "proxy_request").unwrap();
    assert_eq!(row["method"], "GET");
    assert_eq!(row["host"], UPSTREAM_HOST);
    assert_eq!(row["path"], "/v1/models");
    assert_eq!(row["status"], 200);
    assert_eq!(row["decision"], "allow");
    assert!(row["mint_id"].as_str().unwrap().starts_with("briefcred_t_"));
    assert!(row["resp_bytes"].as_u64().unwrap() > 0);

    let whole = serde_json::to_string(&rows).unwrap();
    assert!(
        !whole.contains(REAL_KEY),
        "the audit log holds the real key"
    );
    assert!(
        !whole.contains("bc."),
        "the audit log holds a synthetic token"
    );
}

#[tokio::test]
async fn a_large_response_is_streamed_rather_than_buffered() {
    let fixture = start("observe").await;
    let (status, body, first_byte_at) = fixture
        .client
        .get("/big", &bearer(&fixture.token))
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));

    assert_eq!(status, 200);
    assert_eq!(body.len(), 4 * 1024 * 1024, "the whole body must arrive");
    // The upstream pauses 600 ms between the two halves. A proxy that collected
    // the body before answering could not have delivered a byte before then.
    assert!(
        first_byte_at < Duration::from_millis(500),
        "the first byte took {first_byte_at:?}; the response was buffered"
    );
}

// ------------------------------------------------------------- the streams

#[tokio::test]
async fn an_event_stream_reaches_the_client_as_it_is_produced() {
    let fixture = start_with(&stream_profile()).await;
    let run = fixture
        .client
        .events("/events", &bearer(&fixture.token))
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));

    assert_eq!(run.status, 200, "{}", fixture.daemon.log());
    assert_eq!(run.events(), SSE_EVENTS, "every event must arrive");
    assert!(
        String::from_utf8_lossy(&run.body).contains(": keep-alive"),
        "the keep-alive comment must be forwarded untouched"
    );

    // The assertion this test exists for. The upstream stamps the moment it
    // sends its hundredth event; the client stamps the moment it receives its
    // first. A proxy that collected the body before answering could only ever
    // produce the first of those before the second.
    let first_at = run.first_event_at.expect("an event reached the client");
    let last_sent = fixture
        .upstream
        .last_event_sent
        .lock()
        .unwrap()
        .expect("the upstream finished sending");
    assert!(
        first_at < last_sent,
        "the client's first event arrived after the upstream sent its last; \
         the response was buffered"
    );
}

#[tokio::test]
async fn an_event_stream_carries_no_content_length() {
    // `/events-sized` is an upstream that put a `Content-Length` on an event
    // stream, so this fails if the proxy passes the header through rather than
    // dropping it: a length would make the client wait for a byte count that a
    // stream ending when its upstream ends can never keep to.
    let fixture = start_with(&stream_profile()).await;
    let run = fixture
        .client
        .events("/events-sized", &bearer(&fixture.token))
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));

    assert_eq!(run.status, 200, "{}", fixture.daemon.log());
    assert_eq!(
        run.content_length, None,
        "the upstream's own length must not be forwarded"
    );
    assert_eq!(run.content_type.as_deref(), Some("text/event-stream"));
    assert_eq!(run.events(), SSE_EVENTS, "the whole stream must arrive");

    // And the same on a stream that never had a length in the first place.
    let run = fixture
        .client
        .events("/events", &bearer(&fixture.token))
        .await
        .unwrap();
    assert_eq!(run.content_length, None);
}

#[tokio::test]
async fn an_event_stream_is_audited_with_the_events_it_carried() {
    let fixture = start_with(&stream_profile()).await;
    let run = fixture
        .client
        .events("/events", &bearer(&fixture.token))
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));
    assert_eq!(run.events(), SSE_EVENTS);

    assert!(
        stream_row_written(&fixture.daemon).await,
        "no proxy_stream row:\n{}",
        fixture.daemon.log()
    );
    let rows = fixture.daemon.audit_rows();
    let row = rows.iter().find(|r| r["event"] == "proxy_stream").unwrap();
    assert_eq!(row["kind"], "sse");
    assert_eq!(row["host"], UPSTREAM_HOST);
    assert_eq!(row["path"], "/events");
    assert_eq!(
        row["events_or_frames"], SSE_EVENTS as u64,
        "the keep-alive comment is not an event, and every event is"
    );
    assert!(row["bytes_down"].as_u64().unwrap() > 0);
    assert!(row["mint_id"].as_str().unwrap().starts_with("briefcred_t_"));

    // The request row for the response that opened it is there too.
    assert!(
        rows.iter()
            .any(|r| r["event"] == "proxy_request" && r["path"] == "/events"),
        "the response that started the stream must be audited as a request too"
    );

    let whole = serde_json::to_string(&rows).unwrap();
    assert!(
        !whole.contains(REAL_KEY),
        "the audit log holds the real key"
    );
    assert!(!whole.contains("event 7"), "the audit log holds event data");

    let scrape = scrape(&fixture.daemon).await;
    assert!(
        scrape.contains("briefcred_proxy_streams_total{kind=\"sse\"} 1"),
        "{scrape}"
    );
    assert!(
        scrape.contains("briefcred_proxy_stream_duration_seconds_count{kind=\"sse\"} 1"),
        "{scrape}"
    );
}

#[tokio::test]
async fn an_event_stream_ends_when_its_grant_is_revoked() {
    let fixture = start_with(&stream_profile()).await;
    let mint_ids = mint_ids(&fixture.daemon).await;

    // `/forever` never ends on its own, so a stream that ends at all ended
    // because briefcred ended it.
    let streaming = {
        let client = ProxyClient {
            proxy_addr: fixture.client.proxy_addr.clone(),
            briefcred_ca: fixture.client.briefcred_ca.clone(),
            upstream_port: fixture.client.upstream_port,
            ws_port: fixture.client.ws_port,
            grpc_port: fixture.client.grpc_port,
        };
        let token = fixture.token.clone();
        tokio::spawn(async move { client.events("/forever", &bearer(&token)).await })
    };

    // Let the stream get going before taking its grant away.
    tokio::time::sleep(Duration::from_millis(300)).await;
    fixture
        .daemon
        .request(Request::ExecDone {
            session_id: fixture.session_id.clone(),
            mint_ids,
            exit_code: Some(0),
            duration_ms: 1,
            hold_until_expiry: false,
        })
        .await
        .unwrap();

    // The liveness poll runs once a second, so the stream has to be gone
    // inside about two.
    let run = tokio::time::timeout(Duration::from_secs(4), streaming)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "a revoked grant left its event stream open:\n{}",
                fixture.daemon.log()
            )
        })
        .unwrap()
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));
    assert!(
        run.events() > 0,
        "the stream must have been delivering before it was ended"
    );

    assert!(
        stream_row_written(&fixture.daemon).await,
        "an ended stream must still be audited:\n{}",
        fixture.daemon.log()
    );
    let rows = fixture.daemon.audit_rows();
    let row = rows.iter().find(|r| r["event"] == "proxy_stream").unwrap();
    assert_eq!(row["kind"], "sse");
    assert_eq!(row["path"], "/forever");
}

#[tokio::test]
async fn a_websocket_reaches_the_upstream_with_the_real_key_and_echoes_both_ways() {
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::Message;

    let fixture = start_with(&stream_profile()).await;
    let mut socket = fixture
        .client
        .websocket("/ws", &bearer(&fixture.token))
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));

    const FRAMES: usize = 50;
    for n in 0..FRAMES {
        socket
            .send(Message::Text(format!("frame {n}").into()))
            .await
            .unwrap();
        let echoed = socket.next().await.expect("an echo").unwrap();
        assert_eq!(echoed, Message::Text(format!("frame {n}").into()));
    }

    // The upstream saw the real key on the handshake, and no synthetic token.
    let seen = fixture.upstream.ws_seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(
        seen[0].as_deref(),
        Some(format!("Bearer {REAL_KEY}").as_str()),
        "the upstream must see the real key"
    );

    // Closing propagates: the upstream closes back, and the socket ends.
    socket.close(None).await.unwrap();
    while let Some(Ok(message)) = socket.next().await {
        if message.is_close() {
            break;
        }
    }

    assert!(
        stream_row_written(&fixture.daemon).await,
        "no proxy_stream row:\n{}",
        fixture.daemon.log()
    );
    let rows = fixture.daemon.audit_rows();
    let row = rows.iter().find(|r| r["event"] == "proxy_stream").unwrap();
    assert_eq!(row["kind"], "ws");
    assert_eq!(row["path"], "/ws");
    // Fifty each way, plus the close frames each side sent.
    let frames = row["events_or_frames"].as_u64().unwrap();
    assert!(
        (2 * FRAMES as u64..=2 * FRAMES as u64 + 4).contains(&frames),
        "fifty frames each way and the closes, not {frames}"
    );
    assert!(row["bytes_up"].as_u64().unwrap() > 0);
    assert!(row["bytes_down"].as_u64().unwrap() > 0);

    // The handshake itself is a request, recorded with the `101` it got.
    let handshake = rows
        .iter()
        .find(|r| r["event"] == "proxy_request" && r["path"] == "/ws")
        .expect("the handshake must be audited as a request");
    assert_eq!(handshake["method"], "GET");
    assert_eq!(handshake["status"], 101);
    assert_eq!(handshake["decision"], "allow");

    // No payload reached a row, and no credential did either.
    let whole = serde_json::to_string(&rows).unwrap();
    assert!(
        !whole.contains(REAL_KEY),
        "the audit log holds the real key"
    );
    assert!(!whole.contains("frame 7"), "the audit log holds a payload");

    let scrape = scrape(&fixture.daemon).await;
    assert!(
        scrape.contains("briefcred_proxy_streams_total{kind=\"ws\"} 1"),
        "{scrape}"
    );
}

#[tokio::test]
async fn a_websocket_spends_the_sessions_byte_budget_while_it_is_still_open() {
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::Message;

    // The bypass this test exists for: a WebSocket that never fed
    // `resp_bytes_so_far` would let an agent pull unlimited bytes through a
    // socket while a Cedar byte budget went on believing it had spent almost
    // nothing.
    let fixture = start_with(&byte_budget_profile()).await;

    let (status, _, _) = fixture
        .client
        .get("/v1/models", &bearer(&fixture.token))
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));
    assert_eq!(
        status,
        200,
        "the budget starts unspent\n{}",
        fixture.daemon.log()
    );

    let mut socket = fixture
        .client
        .websocket("/ws", &bearer(&fixture.token))
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));

    // Well past the budget, echoed back, so it is the *downstream* direction
    // that spends it.
    let payload = "x".repeat(256);
    for _ in 0..40 {
        socket
            .send(Message::Text(payload.clone().into()))
            .await
            .unwrap();
        socket.next().await.expect("an echo").unwrap();
    }

    // The socket is still open. The reporter flushes on a one-second timer as
    // well as on a byte threshold, so a stream that never reaches the
    // threshold is still visible to the policy while it runs — which is the
    // half of the fix that a close-time flush would not give.
    let denied = briefcred_e2e::daemon_harness::wait_until(Duration::from_secs(5), || {
        let client = &fixture.client;
        let token = fixture.token.clone();
        async move {
            client
                .get("/v1/models", &bearer(&token))
                .await
                .map(|(status, _, _)| status == 403)
                .unwrap_or(false)
        }
    })
    .await;
    assert!(
        denied,
        "the bytes a websocket carried must count against the session's budget:\n{}",
        fixture.daemon.log()
    );

    // And the socket really was still open throughout.
    socket
        .send(Message::Text("still open".into()))
        .await
        .expect("the websocket must not have been closed by the denial");
}

#[tokio::test]
async fn a_websocket_handshake_the_policy_does_not_permit_is_refused() {
    // `enforce`, and the profile names `/ws` and not `/nope`. A handshake is a
    // `GET`, so the policy decides it exactly as it decides any other.
    let fixture = start_with(&stream_profile()).await;
    let refused = fixture
        .client
        .websocket("/nope", &bearer(&fixture.token))
        .await;
    assert!(
        refused.is_err(),
        "a handshake the policy denies must not be upgraded"
    );
    assert!(
        fixture.upstream.ws_seen.lock().unwrap().is_empty(),
        "a denied handshake must not reach the upstream"
    );
}

#[tokio::test]
async fn a_handshake_with_no_key_is_recorded_as_malformed_and_not_as_a_denial() {
    // Nothing refused this: the policy was never given a chance to have an
    // opinion, so counting it as `deny` would put a client's own bug in the
    // series an operator reads to find a profile that is too narrow.
    let fixture = start_with(&stream_profile()).await;
    let mut headers = bearer(&fixture.token);
    headers.push(("upgrade", "websocket".to_string()));
    headers.push(("connection", "Upgrade".to_string()));

    let (status, _, _) = fixture.client.get("/ws", &headers).await.unwrap();
    assert_eq!(status, 400);
    assert!(fixture.upstream.ws_seen.lock().unwrap().is_empty());

    assert!(
        proxy_row_written(&fixture.daemon).await,
        "a malformed handshake must still be audited:\n{}",
        fixture.daemon.log()
    );
    let rows = fixture.daemon.audit_rows();
    let row = rows.iter().find(|r| r["event"] == "proxy_request").unwrap();
    assert_eq!(row["decision"], "bad_request");
    assert!(
        row["status"].is_null(),
        "nothing reached an upstream, so there is no upstream status: {row}"
    );
    assert_eq!(row["path"], "/ws");

    let scrape = scrape(&fixture.daemon).await;
    assert!(
        scrape.contains(
            "briefcred_proxy_requests_total{decision=\"bad_request\",status_class=\"none\"} 1"
        ),
        "{scrape}"
    );
    assert!(
        !scrape.contains("briefcred_proxy_requests_total{decision=\"deny\""),
        "a malformed request must not be counted as a policy denial:\n{scrape}"
    );
}

#[tokio::test]
async fn a_websocket_ends_when_its_grant_is_revoked() {
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::Message;

    let fixture = start_with(&stream_profile()).await;
    let mint_ids = mint_ids(&fixture.daemon).await;
    let mut socket = fixture
        .client
        .websocket("/ws", &bearer(&fixture.token))
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));

    socket
        .send(Message::Text("still here".into()))
        .await
        .unwrap();
    assert!(socket.next().await.expect("an echo").is_ok());

    fixture
        .daemon
        .request(Request::ExecDone {
            session_id: fixture.session_id.clone(),
            mint_ids,
            exit_code: Some(0),
            duration_ms: 1,
            hold_until_expiry: false,
        })
        .await
        .unwrap();

    // The socket has to end on its own, without the client asking it to.
    let ended = tokio::time::timeout(Duration::from_secs(4), async {
        while let Some(message) = socket.next().await {
            match message {
                Ok(message) if message.is_close() => return,
                Ok(_) => continue,
                Err(_) => return,
            }
        }
    })
    .await;
    assert!(
        ended.is_ok(),
        "a revoked grant left its websocket open:\n{}",
        fixture.daemon.log()
    );

    assert!(
        stream_row_written(&fixture.daemon).await,
        "an ended websocket must still be audited:\n{}",
        fixture.daemon.log()
    );
    let rows = fixture.daemon.audit_rows();
    let row = rows.iter().find(|r| r["event"] == "proxy_stream").unwrap();
    assert_eq!(row["kind"], "ws");
    assert!(
        row["events_or_frames"].as_u64().unwrap() >= 2,
        "the frames that did cross must still be counted: {row}"
    );
}

// --------------------------------------------------------------- the quota

/// The profile's own quota, once the `exec` in `start_with` has spent one.
///
/// `burst: 3` and a rate slow enough that nothing refills inside a test: the
/// mint takes one token, so two proxied requests succeed and the third does
/// not. Written as the number of tokens a *request* gets rather than the
/// number in the bucket, because that is what the assertions below count.
const REQUESTS_BEFORE_THROTTLING: usize = 2;

#[tokio::test]
async fn a_session_over_its_quota_gets_a_429_with_a_retry_after() {
    let fixture = start_with(&quota_profile(
        "enforce",
        // One token every ten seconds, three at once. The `exec` that opened
        // the session already spent one.
        "quota:\n  rate: 0.1\n  burst: 3\n",
    ))
    .await;

    for n in 0..REQUESTS_BEFORE_THROTTLING {
        let (status, _, _) = fixture
            .client
            .get("/v1/models", &bearer(&fixture.token))
            .await
            .unwrap_or_else(|e| panic!("request {n}: {e}\n{}", fixture.daemon.log()));
        assert_eq!(status, 200, "request {n}\n{}", fixture.daemon.log());
    }

    let (status, body, retry_after) = fixture
        .client
        .get_with_header("/v1/models", &bearer(&fixture.token), "retry-after")
        .await
        .unwrap();
    assert_eq!(status, 429, "the bucket is empty\n{}", fixture.daemon.log());
    assert_eq!(
        String::from_utf8_lossy(&body),
        r#"{"error":"briefcred quota exceeded"}"#
    );
    // Ten seconds a token, so the wait is ten — or nine, if a whole second of
    // wall clock passed between the exec that emptied the bucket and this
    // request. Parsed as a number rather than compared as a string, so a
    // header of `10s` or `0` still fails.
    let seconds = retry_after
        .as_deref()
        .expect("a throttled client must be told when to come back")
        .parse::<u64>()
        .expect("`Retry-After` must be whole seconds");
    assert!(
        (9..=10).contains(&seconds),
        "`Retry-After: {seconds}` is not the nine or ten seconds a 0.1/s bucket owes"
    );

    // The upstream never heard about the throttled request.
    assert_eq!(
        fixture.upstream.seen.lock().unwrap().len(),
        REQUESTS_BEFORE_THROTTLING,
        "a throttled request must not reach the upstream"
    );
}

#[tokio::test]
async fn a_throttled_request_is_audited_as_a_quota_refusal_and_not_a_denial() {
    let fixture = start_with(&quota_profile(
        "enforce",
        "quota:\n  rate: 0.1\n  burst: 1\n",
    ))
    .await;

    // The `exec` spent the only token, so the first request is already over.
    let (status, _, _) = fixture
        .client
        .get("/v1/models", &bearer(&fixture.token))
        .await
        .unwrap();
    assert_eq!(status, 429);

    assert!(
        proxy_row_written(&fixture.daemon).await,
        "a throttled request must be audited:\n{}",
        fixture.daemon.log()
    );
    let rows = fixture.daemon.audit_rows();
    let row = rows.iter().find(|r| r["event"] == "proxy_request").unwrap();
    assert_eq!(
        row["decision"], "quota",
        "the row must say the quota refused it, not the policy"
    );
    assert_eq!(row["method"], "GET");
    assert_eq!(row["path"], "/v1/models");
    assert!(
        row["status"].is_null(),
        "nothing reached an upstream, so there is no upstream status"
    );
}

#[tokio::test]
async fn the_scrape_shows_the_saturation_and_the_rejection() {
    let fixture = start_with(&quota_profile(
        "enforce",
        "quota:\n  rate: 0.1\n  burst: 1\n",
    ))
    .await;

    let (status, _, _) = fixture
        .client
        .get("/v1/models", &bearer(&fixture.token))
        .await
        .unwrap();
    assert_eq!(status, 429);

    let scrape = scrape(&fixture.daemon).await;
    assert!(
        scrape.contains("briefcred_quota_saturation{profile=\"openai\"} 1"),
        "an empty bucket must read 1:\n{scrape}"
    );
    assert!(
        scrape.contains("briefcred_quota_rejections_total{profile=\"openai\",surface=\"http\"} 1"),
        "{scrape}"
    );
    assert!(
        scrape
            .contains("briefcred_proxy_requests_total{decision=\"quota\",status_class=\"none\"} 1"),
        "{scrape}"
    );
}

#[tokio::test]
async fn a_profile_with_no_quota_is_not_throttled_and_is_not_measured() {
    let fixture = start("enforce").await;
    for _ in 0..12 {
        let (status, _, _) = fixture
            .client
            .get("/v1/models", &bearer(&fixture.token))
            .await
            .unwrap();
        assert_eq!(status, 200, "{}", fixture.daemon.log());
    }
    let scrape = scrape(&fixture.daemon).await;
    assert!(
        !scrape.contains("briefcred_quota_saturation{"),
        "an unmetered profile must not appear on the gauge:\n{scrape}"
    );
}

/// Scrape the daemon's Prometheus endpoint.
async fn scrape(daemon: &Daemon) -> String {
    let Response::Status { metrics_addr, .. } =
        daemon.request(Request::Status).await.expect("status")
    else {
        panic!("expected a status\n{}", daemon.log());
    };
    let addr = metrics_addr.expect("metrics are enabled for this daemon");
    let mut stream = TcpStream::connect(&addr).await.expect("connect to metrics");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("send the scrape");
    let mut body = String::new();
    stream.read_to_string(&mut body).await.expect("read it");
    body
}

/// Wait until a `ProxyRequest` row has reached the disk.
///
/// The audit writer is its own task, so a row is queued when the response is
/// answered and durable a moment later. Polling for it is the difference
/// between a test that checks the row and one that checks the scheduler.
async fn proxy_row_written(daemon: &Daemon) -> bool {
    row_written(daemon, "proxy_request").await
}

/// Wait until a row of `event` has reached the disk.
///
/// The audit writer is a task of its own, so every row lands a moment after the
/// thing it records finished.
async fn row_written(daemon: &Daemon, event: &str) -> bool {
    briefcred_e2e::daemon_harness::wait_until(Duration::from_secs(10), || async {
        daemon.audit_rows().iter().any(|row| row["event"] == event)
    })
    .await
}

/// Wait until a `ProxyStream` row has reached the disk.
async fn stream_row_written(daemon: &Daemon) -> bool {
    row_written(daemon, "proxy_stream").await
}

/// The mint identifiers the daemon recorded for this session.
async fn mint_ids(daemon: &Daemon) -> Vec<String> {
    daemon
        .audit_rows()
        .iter()
        .filter(|row| row["event"] == "mint")
        .filter_map(|row| row["mint_id"].as_str().map(str::to_string))
        .collect()
}

// ------------------------------------------------------------------- HTTP/2

/// Open an HTTP/2 connection through the tunnel and hand back its sender.
///
/// The `alpn` the client offers is `h2` and nothing else, so a proxy that had
/// not learned to speak it would fail the handshake rather than quietly answer
/// HTTP/1.1 — which is the failure this whole branch exists to prevent.
async fn http2_through_the_proxy(
    client: &ProxyClient,
    port: u16,
) -> (
    hyper::client::conn::http2::SendRequest<http_body_util::Empty<hyper::body::Bytes>>,
    tokio::task::JoinHandle<()>,
) {
    let tls = client
        .tunnel_with_alpn(port, &[b"h2"])
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "the proxy must offer h2 on the connection it terminates"
    );
    let (sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls),
    )
    .await
    .unwrap();
    (
        sender,
        tokio::spawn(async move {
            let _ = connection.await;
        }),
    )
}

#[tokio::test]
async fn an_http2_client_reaches_the_upstream_with_the_real_key() {
    let fixture = start("enforce").await;
    let (mut sender, driver) =
        http2_through_the_proxy(&fixture.client, fixture.upstream.port).await;

    // Two streams on the one connection, which is the thing HTTP/1.1 could not
    // have done and the reason the connection row exists at all.
    for _ in 0..2 {
        let request = hyper::Request::builder()
            .method("GET")
            .uri(format!("https://{UPSTREAM_HOST}/v1/models"))
            .header("authorization", format!("Bearer {}", fixture.token))
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .unwrap();
        let response = sender
            .send_request(request)
            .await
            .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));
        assert_eq!(response.status(), 200, "{}", fixture.daemon.log());
        assert_eq!(response.version(), hyper::Version::HTTP_2);
        use http_body_util::BodyExt as _;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"{\"data\":[]}");
    }

    let seen = fixture.upstream.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "{seen:?}");
    for request in &seen {
        assert_eq!(
            request.authorization.as_deref(),
            Some(format!("Bearer {REAL_KEY}").as_str()),
            "the upstream must see the real key on every stream"
        );
    }

    // The connection's row is written when the connection closes.
    drop(sender);
    let _ = driver.await;
    assert!(
        row_written(&fixture.daemon, "proxy_h2_connection").await,
        "no proxy_h2_connection row:\n{}",
        fixture.daemon.log()
    );

    let rows = fixture.daemon.audit_rows();
    let connection = rows
        .iter()
        .find(|row| row["event"] == "proxy_h2_connection")
        .expect("a proxy_h2_connection row");
    assert_eq!(connection["host"], UPSTREAM_HOST);
    assert_eq!(connection["streams"], 2);
    assert_eq!(connection["bytes_down"], 22, "two eleven-byte bodies");
    let id = connection["connection_id"].as_str().expect("an identifier");

    let requests: Vec<_> = rows
        .iter()
        .filter(|row| row["event"] == "proxy_request")
        .collect();
    assert_eq!(requests.len(), 2, "one row per stream");
    for request in requests {
        assert_eq!(request["decision"], "allow");
        assert_eq!(
            request["connection_id"], id,
            "every stream's row must name the connection it was one of"
        );
    }
}

#[tokio::test]
async fn an_http2_stream_the_policy_refuses_is_still_a_stream_on_the_connection() {
    let fixture = start("enforce").await;
    let (mut sender, driver) =
        http2_through_the_proxy(&fixture.client, fixture.upstream.port).await;

    let request = hyper::Request::builder()
        .method("GET")
        .uri(format!("https://{UPSTREAM_HOST}/v1/chat/completions"))
        .header("authorization", format!("Bearer {}", fixture.token))
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 403);
    // The body has to go before the connection can: an unread response body
    // holds its stream open, and the connection outlives its last stream.
    drop(response);
    assert!(
        fixture.upstream.seen.lock().unwrap().is_empty(),
        "a denied stream must not reach the upstream"
    );

    drop(sender);
    let _ = driver.await;
    assert!(
        row_written(&fixture.daemon, "proxy_h2_connection").await,
        "rows: {:?}
log: {}",
        fixture.daemon.audit_rows(),
        fixture.daemon.log()
    );
    let rows = fixture.daemon.audit_rows();
    let connection = rows
        .iter()
        .find(|row| row["event"] == "proxy_h2_connection")
        .expect("a proxy_h2_connection row");
    assert_eq!(
        connection["streams"], 1,
        "a refused stream is still a stream the client opened"
    );
    assert_eq!(connection["bytes_up"], 0);
    assert_eq!(connection["bytes_down"], 0);
}

#[tokio::test]
async fn an_http1_client_is_unaffected_and_gets_no_connection_row() {
    let fixture = start("enforce").await;
    let (status, _, _) = fixture
        .client
        .get("/v1/models", &bearer(&fixture.token))
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));
    assert_eq!(status, 200);

    assert!(proxy_row_written(&fixture.daemon).await);
    let rows = fixture.daemon.audit_rows();
    let request = rows
        .iter()
        .find(|row| row["event"] == "proxy_request")
        .expect("a proxy_request row");
    assert!(
        request.get("connection_id").is_none(),
        "an HTTP/1.1 request is not one stream of anything: {request}"
    );
    assert!(
        !rows.iter().any(|row| row["event"] == "proxy_h2_connection"),
        "no connection row without an HTTP/2 connection"
    );
}

// --------------------------------------------------------------------- gRPC

/// A profile permitting the test service's methods and nothing else.
///
/// `POST` and a path prefix, because that is what a gRPC call is: the method is
/// always `POST` and the service and method names are the path. Written out
/// rather than left wide open, so the tests prove a gRPC stream goes through
/// the same Cedar evaluation every other request does.
fn grpc_profile() -> String {
    format!(
        "\
name: openai
unlock:
  policy: none
credentials:
  - name: openai
    kind: http-bearer
    ttl_secs: 300
policy_mode: enforce
policy: |
  permit(principal, action == Action::\"POST\", resource)
  when {{ resource.host == \"{UPSTREAM_HOST}\" &&
    resource.path like \"/briefcred.test.Echo/*\" }};
env:
  OPENAI_API_KEY: ${{minted.openai.TOKEN}}
"
    )
}

#[tokio::test]
async fn all_four_grpc_call_shapes_work_through_the_proxy() {
    let fixture = start_with(&grpc_profile()).await;
    let transport =
        grpc::through_the_proxy(&fixture.client, fixture.upstream.grpc.port, &fixture.token).await;

    let unary = grpc::call_unary(&transport, "Unary", "one")
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));
    assert_eq!(unary.text, "echo: one");

    let server_stream = grpc::call_server_stream(&transport, "s").await.unwrap();
    assert_eq!(server_stream, ["s 1", "s 2", "s 3", "s 4", "s 5"]);

    let client_stream = grpc::call_client_stream(&transport, &["a", "b", "c"])
        .await
        .unwrap();
    assert_eq!(client_stream.text, "a,b,c");

    let bidi = grpc::call_bidi(&transport, &["x", "y"]).await.unwrap();
    assert_eq!(bidi, ["echo: x", "echo: y"]);

    // Every call arrived with the real key and never the synthetic token.
    let seen = fixture.upstream.grpc.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 4, "{seen:?}");
    for authorization in &seen {
        assert_eq!(
            authorization.as_deref(),
            Some(format!("Bearer {REAL_KEY}").as_str()),
            "the gRPC server must see the real key"
        );
    }
}

#[tokio::test]
async fn a_grpc_call_that_fails_carries_its_status_back_in_the_trailers() {
    let fixture = start_with(&grpc_profile()).await;
    let transport =
        grpc::through_the_proxy(&fixture.client, fixture.upstream.grpc.port, &fixture.token).await;

    let refused = grpc::call_unary(&transport, "Failing", "one")
        .await
        .expect_err("the method always fails");
    assert_eq!(refused.code(), grpc::REFUSED, "{refused}");
    assert_eq!(refused.message(), "the vendor said no");
}

#[tokio::test]
async fn the_grpc_status_trailer_arrives_after_the_body_and_not_in_the_headers() {
    let fixture = start_with(&grpc_profile()).await;
    let tls = fixture
        .client
        .tunnel_with_alpn(fixture.upstream.grpc.port, &[b"h2"])
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let ok = grpc::call_raw(&mut sender, &fixture.token, "Unary", "one").await;
    assert_eq!(ok.status, 200, "{}", fixture.daemon.log());
    assert_eq!(ok.content_type.as_deref(), Some("application/grpc"));
    assert!(ok.body_len > 0, "the response carried no message");
    let trailers = ok
        .trailers
        .as_ref()
        .expect("a trailer frame after the body");
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0"),
        "grpc-status must arrive after the body, not with the headers"
    );
    assert!(
        ok.headers.get("grpc-status").is_none(),
        "a call that answered must not put its status in the headers"
    );

    let refused = grpc::call_raw(&mut sender, &fixture.token, "Failing", "one").await;
    assert_eq!(
        refused.status, 200,
        "a gRPC failure is an HTTP success with a status trailer"
    );
    assert_eq!(grpc::grpc_status(&refused), Some(grpc::REFUSED as i32));
    // A unary handler that fails answers Trailers-Only, so the status and the
    // message are in the single HEADERS frame rather than in a trailer.
    assert_eq!(
        refused
            .headers
            .get("grpc-message")
            .and_then(|value| value.to_str().ok()),
        // Percent-encoded, which is how gRPC puts a message in a header.
        Some("the%20vendor%20said%20no")
    );
}

/// How many concurrent calls the multiplexing test makes.
const CONCURRENT_CALLS: usize = 8;

#[tokio::test]
async fn concurrent_grpc_calls_share_one_upstream_connection() {
    let fixture = start_with(&grpc_profile()).await;
    let transport =
        grpc::through_the_proxy(&fixture.client, fixture.upstream.grpc.port, &fixture.token).await;

    let calls = (0..CONCURRENT_CALLS).map(|n| {
        let transport = transport.clone();
        async move { grpc::call_unary(&transport, "Unary", &n.to_string()).await }
    });
    let answers = futures_util::future::join_all(calls).await;
    for (n, answer) in answers.into_iter().enumerate() {
        assert_eq!(
            answer
                .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()))
                .text,
            format!("echo: {n}")
        );
    }

    assert_eq!(
        fixture
            .upstream
            .grpc
            .accepts
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "{CONCURRENT_CALLS} concurrent streams must be multiplexed onto one \
         upstream connection, not dialled one at a time"
    );

    // And every one of them is still its own row, decided on its own.
    assert!(proxy_row_written(&fixture.daemon).await);
    briefcred_e2e::daemon_harness::wait_until(Duration::from_secs(10), || async {
        fixture
            .daemon
            .audit_rows()
            .iter()
            .filter(|row| row["event"] == "proxy_request")
            .count()
            == CONCURRENT_CALLS
    })
    .await;
    let rows = fixture.daemon.audit_rows();
    let requests: Vec<_> = rows
        .iter()
        .filter(|row| row["event"] == "proxy_request")
        .collect();
    assert_eq!(requests.len(), CONCURRENT_CALLS, "one row per stream");
    for request in requests {
        assert_eq!(request["decision"], "allow");
        assert_eq!(request["method"], "POST");
        assert!(request["connection_id"].is_string());
    }
}

#[tokio::test]
async fn a_grpc_method_the_policy_does_not_permit_never_reaches_the_upstream() {
    let fixture = start_with(&grpc_profile()).await;
    let transport =
        grpc::through_the_proxy(&fixture.client, fixture.upstream.grpc.port, &fixture.token).await;

    // A different service, so the path does not match the policy's prefix.
    let mut grpc_client = tonic::client::Grpc::with_origin(
        transport.clone(),
        format!("https://{UPSTREAM_HOST}").parse().unwrap(),
    );
    let refused = grpc_client
        .unary(
            tonic::Request::new(grpc::Echo {
                text: "one".to_string(),
            }),
            "/briefcred.other.Echo/Unary".parse().unwrap(),
            tonic_prost::ProstCodec::<grpc::Echo, grpc::Echo>::default(),
        )
        .await
        .expect_err("the policy does not permit this service");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{refused}");
    assert!(
        fixture.upstream.grpc.seen.lock().unwrap().is_empty(),
        "a denied stream must not reach the gRPC server at all"
    );
}

/// How many unary calls each side of the latency comparison makes.
const LATENCY_CALLS: usize = 200;

#[tokio::test]
async fn the_proxy_costs_less_than_a_tenth_of_the_direct_latency() {
    let fixture = start_with(&grpc_profile()).await;
    let direct = grpc::direct(fixture.upstream.grpc.port, &fixture.upstream.ca_pem).await;
    let proxied =
        grpc::through_the_proxy(&fixture.client, fixture.upstream.grpc.port, &fixture.token).await;

    // One call each first, so neither measurement pays for a connection that
    // the other had already made.
    grpc::call_unary(&direct, "Unary", "warm").await.unwrap();
    grpc::call_unary(&proxied, "Unary", "warm")
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", fixture.daemon.log()));

    let measure = |transport: &grpc::Transport| {
        let transport = transport.clone();
        async move {
            let started = std::time::Instant::now();
            for n in 0..LATENCY_CALLS {
                grpc::call_unary(&transport, "Unary", &n.to_string())
                    .await
                    .unwrap();
            }
            started.elapsed() / LATENCY_CALLS as u32
        }
    };
    let direct_each = measure(&direct).await;
    let proxied_each = measure(&proxied).await;

    // A ratio with an absolute allowance on top. On loopback a call is tens of
    // microseconds, so a debug build's scheduling jitter is a larger share of
    // it than the proxy is; without the two milliseconds this asserts the
    // machine's timer noise rather than briefcred's overhead.
    let budget = direct_each.mul_f64(1.10) + Duration::from_millis(2);
    assert!(
        proxied_each <= budget,
        "proxied {proxied_each:?} per call against direct {direct_each:?}, \
         budget {budget:?} over {LATENCY_CALLS} calls"
    );
    println!("gRPC unary: direct {direct_each:?}, proxied {proxied_each:?}");
}
