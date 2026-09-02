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
    format!(
        "\
name: openai
unlock:
  policy: none
credentials:
  - name: openai
    kind: http-bearer
    ttl_secs: 300
policy_mode: {policy_mode}
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
    seen: Arc<std::sync::Mutex<Vec<Seen>>>,
    /// The accept loop, so a test can take the upstream away mid-run.
    accepting: tokio::task::JoinHandle<()>,
}

/// Start an in-process HTTPS server on loopback.
///
/// `/v1/models` answers `200` with a small body; `/big` answers with four
/// mebibytes sent in two halves with a pause between them, which is how the
/// streaming test tells "passed through" from "buffered whole".
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

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
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
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let recorded = Arc::clone(&recorded);
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
        seen,
        accepting,
    }
}

// ------------------------------------------------------------------ the client

/// One request made through the proxy, exactly as a wrapped subprocess would.
struct ProxyClient {
    proxy_addr: String,
    briefcred_ca: String,
    upstream_port: u16,
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

    async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
    ) -> Result<(u16, Vec<u8>, Duration), String> {
        let mut stream = TcpStream::connect(&self.proxy_addr)
            .await
            .map_err(|e| e.to_string())?;
        let authority = format!("{UPSTREAM_HOST}:{}", self.upstream_port);
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
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let name = rustls_pki_types::ServerName::try_from(UPSTREAM_HOST).unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await
            .map_err(|e| format!("the proxy's certificate did not verify: {e}"))?;

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
        Ok((status, bytes, first_byte_at.unwrap_or(started.elapsed())))
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
    let upstream = start_upstream().await;

    let daemon = Daemon::prepare("");
    // A file keystore and a file master source: no keychain item is created,
    // so a test run leaves nothing on the developer's machine.
    let roots = daemon.home().join("upstream-roots.pem");
    std::fs::write(&roots, &upstream.ca_pem).unwrap();
    std::fs::write(
        daemon.home().join("daemon.toml"),
        format!(
            "metrics_enabled = false\nmetrics_port = 0\nproxy_port = 0\n\
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

    daemon.write_profile("openai", &profile(policy_mode));
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

/// Wait until a `ProxyRequest` row has reached the disk.
///
/// The audit writer is its own task, so a row is queued when the response is
/// answered and durable a moment later. Polling for it is the difference
/// between a test that checks the row and one that checks the scheduler.
async fn proxy_row_written(daemon: &Daemon) -> bool {
    briefcred_e2e::daemon_harness::wait_until(Duration::from_secs(10), || async {
        daemon
            .audit_rows()
            .iter()
            .any(|row| row["event"] == "proxy_request")
    })
    .await
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
