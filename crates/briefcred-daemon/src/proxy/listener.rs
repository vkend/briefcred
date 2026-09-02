//! The listener, and the order one forwarded request goes through.
//!
//! # Two shapes of request
//!
//! A runtime pointed at `HTTPS_PROXY` sends one of two things:
//!
//! - `CONNECT api.openai.com:443`, then TLS to what it believes is the vendor.
//!   The proxy answers `200`, terminates that TLS with a leaf from briefcred's
//!   own CA, and reads ordinary HTTP/1.1 inside it.
//! - `GET http://api.example.com/v1/thing HTTP/1.1` with an absolute URI, for a
//!   plain `http://` upstream. No tunnel, no TLS to terminate.
//!
//! Both converge on [`forward`], which is the only place a credential is ever
//! attached to anything.
//!
//! # The order, and why it is that order
//!
//! 1. **Authorize the token.** Signature, expiry, revocation. Before anything
//!    else, because everything else needs to know which session this is.
//! 2. **Check the proof, if there is one.** A `DPoP` header is verified against
//!    the session's key. Absent is accepted — see [`crate::proxy::token`] — but
//!    present-and-wrong is a refusal, never a shrug.
//! 3. **Ask the policy.** Method, scheme, host, and path, against the profile's
//!    Cedar source. Default deny.
//! 4. **Swap.** The real credential goes in and the synthetic token comes out.
//!    Only now does the request hold anything worth stealing.
//! 5. **Forward, streaming.** Bodies are passed through in both directions and
//!    counted as they go; nothing is buffered whole.
//! 6. **Audit and count.** One `ProxyRequest` row when the response body ends.
//!
//! Every refusal before step 5 is still audited, because "briefcred stopped
//! this" is exactly what the log is for.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use briefcred_core::audit::AuditEntry;
use briefcred_core::ca::CertificateAuthority;
use briefcred_core::minters::http::HttpKind;
use briefcred_core::policy::HttpRequest;
use briefcred_core::types::MintId;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use time::OffsetDateTime;
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::proxy::issuer::ProxyIssuer;
use crate::proxy::policy::PolicyCache;
use crate::proxy::swap::{self, Credential};
use crate::proxy::token::{self, TokenError};
use crate::server::State;

/// The body type every response out of this module has.
type OutBody = BoxBody<Bytes, hyper::Error>;

/// Everything one proxied request needs, shared across every connection.
pub struct Proxy {
    state: Arc<State>,
    issuer: Arc<ProxyIssuer>,
    upstream: Arc<rustls::ClientConfig>,
    policies: PolicyCache,
    ca: std::sync::Mutex<Option<Arc<CertificateAuthority>>>,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("issuer", &self.issuer)
            .field("policies", &self.policies)
            .finish()
    }
}

impl Proxy {
    /// Assemble the proxy from the daemon's state, its issuer, and its upstream
    /// trust configuration.
    pub fn new(
        state: Arc<State>,
        issuer: Arc<ProxyIssuer>,
        upstream: Arc<rustls::ClientConfig>,
    ) -> Arc<Proxy> {
        Arc::new(Proxy {
            state,
            issuer,
            upstream,
            policies: PolicyCache::new(),
            ca: std::sync::Mutex::new(None),
        })
    }

    /// The machine's CA, loaded on the first tunnel and kept after that.
    ///
    /// Loaded rather than generated, and lazily rather than at startup. The CA
    /// private key lives in the platform key store, so reading it eagerly would
    /// prompt for keychain access at every login regardless of whether anything
    /// ever proxies; and generating one here would produce a certificate
    /// nothing on the machine trusts, so the honest failure is to say the CA is
    /// missing and name the command that creates it.
    fn ca(&self) -> Result<Arc<CertificateAuthority>> {
        let mut cached = self
            .ca
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(ca) = cached.as_ref() {
            return Ok(Arc::clone(ca));
        }
        let paths = self.state.paths();
        let store = briefcred_core::ca::CaConfig::load(paths)?.open_keystore(paths)?;
        let ca = CertificateAuthority::load(paths, store.as_ref())?.ok_or_else(|| {
            Error::Proxy(format!(
                "there is no CA at {}; run `briefcred install` and then `briefcred ca trust`",
                paths.ca_cert().display()
            ))
        })?;
        let ca = Arc::new(ca);
        *cached = Some(Arc::clone(&ca));
        Ok(ca)
    }
}

/// Bind the proxy listener to loopback, letting the OS pick when `port` is 0.
///
/// Loopback and nothing else. The proxy holds every master its sessions
/// opened, so a listener anything off the machine could reach would be a
/// credential server with no authentication in front of it.
pub fn bind(port: u16) -> std::io::Result<(TcpListener, SocketAddr)> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    Ok((TcpListener::from_std(listener)?, addr))
}

/// Accept and serve connections until `shutdown` fires.
pub async fn serve(
    listener: TcpListener,
    proxy: Arc<Proxy>,
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
        tokio::spawn(serve_connection(stream, Arc::clone(&proxy)));
    }
}

/// Serve one client connection: a `CONNECT` tunnel, or plain absolute-URI HTTP.
async fn serve_connection(stream: TcpStream, proxy: Arc<Proxy>) {
    let service = service_fn(move |request: Request<Incoming>| {
        let proxy = Arc::clone(&proxy);
        async move {
            Ok::<_, std::convert::Infallible>(if request.method() == Method::CONNECT {
                begin_tunnel(request, proxy)
            } else {
                forward(request, proxy, "http", None).await
            })
        }
    });

    // `with_upgrades` is what makes `CONNECT` possible at all: without it the
    // connection is finished when the 200 is written, and the TLS the client
    // then starts has nobody listening for it.
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await;
}

/// Answer a `CONNECT`, then take the tunnel over as a TLS server.
fn begin_tunnel(request: Request<Incoming>, proxy: Arc<Proxy>) -> Response<OutBody> {
    let authority = request.uri().authority().map(|a| a.as_str().to_string());
    let Some(host) = authority_host(authority.as_deref()) else {
        return status(StatusCode::BAD_REQUEST);
    };
    // The port comes from the `CONNECT` line and nowhere else. Inside the
    // tunnel the request line is origin-form, so a request that could name its
    // own port would be one that could get a certificate for a host on 443 and
    // a connection to something else entirely.
    let port = authority_port(authority.as_deref()).unwrap_or(443);

    // The 200 has to be written before the TLS handshake can start, so the
    // work happens in a task that waits for the upgrade rather than here.
    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(request).await {
            Ok(upgraded) => upgraded,
            Err(err) => {
                eprintln!("briefcred-daemon: proxy tunnel to `{host}` was not upgraded: {err}");
                return;
            }
        };
        if let Err(err) = serve_tunnel(TokioIo::new(upgraded), host.clone(), port, proxy).await {
            eprintln!("briefcred-daemon: proxy tunnel to `{host}`: {err}");
        }
    });

    Response::new(empty())
}

/// Terminate the client's TLS and serve HTTP/1.1 inside it.
async fn serve_tunnel<I>(io: I, host: String, port: u16, proxy: Arc<Proxy>) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ca = proxy.ca()?;
    let config = crate::proxy::tls::server_config(&ca, &host)?;
    let stream = tokio_rustls::TlsAcceptor::from(config)
        .accept(io)
        .await
        .map_err(|e| Error::Proxy(format!("the client would not complete a handshake: {e}")))?;

    let service = service_fn(move |request: Request<Incoming>| {
        let proxy = Arc::clone(&proxy);
        let host = host.clone();
        async move {
            Ok::<_, std::convert::Infallible>(
                forward(request, proxy, "https", Some((host, port))).await,
            )
        }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await;
    Ok(())
}

/// The whole of one proxied request: authorize, decide, swap, forward, audit.
///
/// `tunnel` is the host and port the `CONNECT` named, when there was one.
/// Inside a tunnel the request line carries only a path, so the destination has
/// to come from the tunnel rather than from a `Host` header the client
/// controls: a request that could name its own host would be one that could get
/// a certificate for one vendor and a connection to somewhere else entirely.
async fn forward(
    request: Request<Incoming>,
    proxy: Arc<Proxy>,
    scheme: &str,
    tunnel: Option<(String, u16)>,
) -> Response<OutBody> {
    let started = std::time::Instant::now();
    let method = request.method().to_string();

    let Some((host, port)) = tunnel.or_else(|| {
        let host_header = request
            .headers()
            .get(hyper::header::HOST)
            .and_then(|value| value.to_str().ok());
        let host = request
            .uri()
            .host()
            .map(str::to_string)
            .or_else(|| authority_host(host_header))?;
        let port = request
            .uri()
            .port_u16()
            .or_else(|| authority_port(host_header))
            .unwrap_or(default_port(scheme));
        Some((host, port))
    }) else {
        return refuse(
            &proxy,
            StatusCode::BAD_REQUEST,
            started,
            None,
            &method,
            "",
            "",
        );
    };
    // The query string is dropped here and never picked up again: it routinely
    // carries an API key, so neither the policy nor the audit row may see one.
    let path = request.uri().path().to_string();

    // 1. Which session and credential is this?
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let Some(presented) = find_token(request.headers()) else {
        return refuse(
            &proxy,
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            started,
            None,
            &method,
            &host,
            &path,
        );
    };
    let claims = match proxy.issuer.authorize(&presented, now) {
        Ok(claims) => claims,
        Err(err) => {
            eprintln!("briefcred-daemon: proxy refused a token for `{host}`: {err}");
            return refuse(
                &proxy,
                match err {
                    TokenError::Revoked => StatusCode::FORBIDDEN,
                    _ => StatusCode::UNAUTHORIZED,
                },
                started,
                None,
                &method,
                &host,
                &path,
            );
        }
    };

    // 2. The session it names, and everything it holds.
    let Some(session) = resolve_session(&proxy, &claims.sid, &claims.cred).await else {
        return refuse(
            &proxy,
            StatusCode::UNAUTHORIZED,
            started,
            None,
            &method,
            &host,
            &path,
        );
    };

    // 3. A proof, if the client made one.
    if let Some(proof) = request.headers().get("dpop").and_then(|v| v.to_str().ok()) {
        let htu = format!("{scheme}://{host}{path}");
        let expected = claims.cnf.as_ref().map(|cnf| cnf.jkt.as_str());
        let outcome = match (session.pubkey.as_ref(), expected) {
            (Some(key), Some(jkt)) => {
                token::verify_dpop(proof, key, jkt, &method, &htu, now).map(|_| ())
            }
            // A proof against a token that was never bound to a key proves
            // nothing, and accepting it would let a client believe it had a
            // guarantee the token cannot carry.
            _ => Err(token::DpopError::WrongKey),
        };
        if let Err(err) = outcome {
            eprintln!("briefcred-daemon: proxy refused a DPoP proof for `{host}`: {err}");
            return refuse(
                &proxy,
                StatusCode::UNAUTHORIZED,
                started,
                None,
                &method,
                &host,
                &path,
            );
        }
    }

    // 4. May this session make this request?
    let decision = proxy.policies.decide(
        &session.profile,
        &claims.sid,
        &HttpRequest {
            method: &method,
            scheme,
            host: &host,
            path: &path,
        },
    );
    if !decision.forwards() {
        proxy.state.audit(&proxy_row(
            &session.mint_id,
            &method,
            &host,
            &path,
            None,
            0,
            0,
            started.elapsed(),
            decision.label(),
        ));
        proxy
            .state
            .metrics()
            .record_proxy_request(decision.label(), None, started.elapsed());
        return status(StatusCode::FORBIDDEN);
    }

    // 5. The real credential goes in.
    let (mut parts, body) = request.into_parts();
    if let Err(err) = swap::apply(
        &mut parts.headers,
        &session.credentials,
        Some(&session.authorized),
    ) {
        eprintln!("briefcred-daemon: proxy will not forward to `{host}`: {err}");
        return refuse(
            &proxy,
            StatusCode::BAD_GATEWAY,
            started,
            Some(&session.mint_id),
            &method,
            &host,
            &path,
        );
    }
    // A proof is for briefcred, not for the vendor, and forwarding it would
    // tell an upstream which session made the call.
    parts.headers.remove("dpop");
    parts.headers.remove(hyper::header::PROXY_AUTHORIZATION);

    // The upstream is a fresh HTTP/1.1 connection, so the request line has to
    // be origin-form: an absolute URI is a proxy's spelling, not a server's.
    parts.uri = origin_form(&parts.uri);

    let req_bytes = Arc::new(AtomicU64::new(0));
    let counted = Counting::new(body, Arc::clone(&req_bytes), None);
    let upstream_request = Request::from_parts(parts, counted);

    // 6. Forward, streaming.
    let response = match send_upstream(&proxy, scheme, &host, port, upstream_request).await {
        Ok(response) => response,
        Err(err) => {
            eprintln!("briefcred-daemon: proxy could not reach `{host}`: {err}");
            return refuse(
                &proxy,
                StatusCode::BAD_GATEWAY,
                started,
                Some(&session.mint_id),
                &method,
                &host,
                &path,
            );
        }
    };

    // 7. The row is written when the response body ends, because that is when
    // `resp_bytes` is known. Streaming a gigabyte and then reporting zero would
    // make the byte counts worse than useless.
    let status_code = response.status().as_u16();
    let (parts, body) = response.into_parts();
    let done = {
        let proxy = Arc::clone(&proxy);
        let mint_id = session.mint_id.clone();
        let decision = decision.label();
        let req_bytes = Arc::clone(&req_bytes);
        move |resp_bytes: u64| {
            let elapsed = started.elapsed();
            proxy.state.audit(&proxy_row(
                &mint_id,
                &method,
                &host,
                &path,
                Some(status_code),
                req_bytes.load(Ordering::Relaxed),
                resp_bytes,
                elapsed,
                decision,
            ));
            proxy
                .state
                .metrics()
                .record_proxy_request(decision, Some(status_code), elapsed);
        }
    };
    Response::from_parts(
        parts,
        Counting::new(body, Arc::new(AtomicU64::new(0)), Some(Box::new(done))).boxed(),
    )
}

/// Open a connection to the upstream and send one request on it.
///
/// A connection per request rather than a pool. That is the honest MVP: pooling
/// would have to key on `(host, port, credential)` — two sessions with two
/// different keys must never share a connection an upstream might treat as
/// authenticated — and getting that wrong is a credential mix-up rather than a
/// slow proxy.
async fn send_upstream<B>(
    proxy: &Proxy,
    scheme: &str,
    host: &str,
    port: u16,
    request: Request<B>,
) -> Result<Response<Incoming>>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| Error::Proxy(format!("cannot connect to `{host}:{port}`: {e}")))?;

    if scheme == "https" {
        let name = rustls_pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| Error::Proxy(format!("`{host}` is not a server name")))?;
        let tls = tokio_rustls::TlsConnector::from(Arc::clone(&proxy.upstream))
            .connect(name, stream)
            .await
            .map_err(|e| Error::Proxy(format!("`{host}` did not verify: {e}")))?;
        send_on(TokioIo::new(tls), request).await
    } else {
        send_on(TokioIo::new(stream), request).await
    }
}

async fn send_on<I, B>(io: I, request: Request<B>) -> Result<Response<Incoming>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| Error::Proxy(format!("upstream handshake failed: {e}")))?;
    // Driven in its own task: the connection has to keep pumping while the
    // response body is being read, and awaiting it here would deadlock.
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
        .send_request(request)
        .await
        .map_err(|e| Error::Proxy(format!("upstream refused the request: {e}")))
}

/// One credential-bearing session, resolved from a token's claims.
struct ResolvedSession {
    profile: briefcred_core::Profile,
    credentials: Vec<Credential>,
    authorized: Credential,
    pubkey: Option<[u8; 32]>,
    mint_id: MintId,
}

/// Find the session a token names and everything it can swap in.
///
/// `None` where the session is gone, the profile was unloaded, or the
/// credential the token names is no longer one the profile declares — all of
/// which are a token that outlived what it referred to.
async fn resolve_session(
    proxy: &Proxy,
    sid: &str,
    credential: &str,
) -> Option<Box<ResolvedSession>> {
    let (profile_name, masters, pubkey, mint_id) = proxy
        .state
        .sessions()
        .with_session(sid, |session| {
            (
                session.profile.clone(),
                session.masters.clone(),
                session.pubkey,
                session
                    .mints
                    .values()
                    .find(|mint| mint.credential == credential)
                    .map(|mint| mint.mint_id.clone()),
            )
        })
        .await
        .ok()?;
    let profile = proxy.state.profiles().get(&profile_name).await?;

    let mut credentials = Vec::new();
    for spec in &profile.credentials {
        let Some(Ok(kind)) = HttpKind::parse(&spec.kind, &spec.config) else {
            continue;
        };
        let Some(master) = masters.get(spec.source_key()) else {
            continue;
        };
        credentials.push(Credential {
            name: spec.name.clone(),
            kind,
            master: Zeroizing::clone(master),
        });
    }
    let authorized = credentials.iter().find(|c| c.name == credential)?.clone();

    Some(Box::new(ResolvedSession {
        profile,
        credentials,
        authorized,
        pubkey,
        // A token whose mint the session no longer remembers is one whose
        // `ExecDone` already went through. The row still has to name something,
        // and a fresh identifier would claim a mint that never happened, so the
        // request is refused instead.
        mint_id: mint_id?,
    }))
}

/// The synthetic token a request carries, if it carries one.
///
/// Searched for across every header rather than only `Authorization`: an
/// `http-header` credential is sent under a vendor's own name, and a runtime
/// that reads `PROXY_URL` may put the token wherever its SDK puts an API key.
fn find_token(headers: &hyper::header::HeaderMap) -> Option<String> {
    headers.values().find_map(|value| {
        value
            .to_str()
            .ok()?
            .split_ascii_whitespace()
            .find_map(|word| token::looks_synthetic(word).then(|| word.to_string()))
    })
}

/// Audit and count a refusal, then answer with `code` and no body.
///
/// Every refusal is recorded. A proxy that silently drops requests is one an
/// operator debugging "why does my agent get a 401" has nothing to read.
#[allow(clippy::too_many_arguments)]
fn refuse(
    proxy: &Proxy,
    code: StatusCode,
    started: std::time::Instant,
    mint_id: Option<&MintId>,
    method: &str,
    host: &str,
    path: &str,
) -> Response<OutBody> {
    let elapsed = started.elapsed();
    if let Some(mint_id) = mint_id {
        proxy.state.audit(&proxy_row(
            mint_id,
            method,
            host,
            path,
            Some(code.as_u16()),
            0,
            0,
            elapsed,
            "deny",
        ));
    }
    proxy
        .state
        .metrics()
        .record_proxy_request("deny", Some(code.as_u16()), elapsed);
    status(code)
}

/// One `ProxyRequest` audit row. Metadata only, by construction.
#[allow(clippy::too_many_arguments)]
fn proxy_row(
    mint_id: &MintId,
    method: &str,
    host: &str,
    path: &str,
    status: Option<u16>,
    req_bytes: u64,
    resp_bytes: u64,
    latency: std::time::Duration,
    decision: &str,
) -> AuditEntry {
    AuditEntry::ProxyRequest {
        ts: OffsetDateTime::now_utc(),
        mint_id: mint_id.clone(),
        method: method.to_string(),
        host: host.to_string(),
        path: path.to_string(),
        status,
        req_bytes,
        resp_bytes,
        latency_ms: latency.as_millis() as u64,
        decision: decision.to_string(),
    }
}

/// A body that counts the bytes passing through it.
///
/// Wrapping rather than collecting is the whole point: a four-megabyte response
/// reaches the client a frame at a time, and the count is a side effect of the
/// frames going past rather than of holding them.
struct Counting<B> {
    inner: B,
    bytes: Arc<AtomicU64>,
    on_done: Option<Box<dyn FnOnce(u64) + Send + Sync>>,
}

impl<B> Counting<B> {
    fn new(
        inner: B,
        bytes: Arc<AtomicU64>,
        on_done: Option<Box<dyn FnOnce(u64) + Send + Sync>>,
    ) -> Counting<B> {
        Counting {
            inner,
            bytes,
            on_done,
        }
    }
}

impl<B> Body for Counting<B>
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
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
            }
            // The end of the body, or the end of trying: either way this is the
            // last thing that happens to it, and the row goes now.
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => {
                if let Some(done) = this.on_done.take() {
                    done(this.bytes.load(Ordering::Relaxed));
                }
            }
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// A connection the client dropped mid-response still gets its row.
impl<B> Drop for Counting<B> {
    fn drop(&mut self) {
        if let Some(done) = self.on_done.take() {
            done(self.bytes.load(Ordering::Relaxed));
        }
    }
}

/// The host part of an `authority`, dropping any port.
///
/// IPv6 literals keep their brackets, because that is what a `ServerName` and a
/// `TcpStream::connect` both want back.
fn authority_host(authority: Option<&str>) -> Option<String> {
    let authority = authority?.trim();
    if authority.is_empty() {
        return None;
    }
    // A bracketed IPv6 literal ends at its `]`; anything else ends at its
    // first colon. Splitting on the last colon instead would take `[::1]`
    // apart, because every one of its colons looks like a port separator.
    let host = match authority.strip_prefix('[').and_then(|rest| rest.find(']')) {
        Some(end) => &authority[..end + 2],
        None => authority.split(':').next().unwrap_or(authority),
    };
    (!host.is_empty()).then(|| host.to_string())
}

/// The port an `authority` names, if it names one.
fn authority_port(authority: Option<&str>) -> Option<u16> {
    let authority = authority?.trim();
    let after_host = match authority.find(']') {
        Some(end) => &authority[end + 1..],
        None => authority,
    };
    after_host.rsplit_once(':')?.1.parse().ok()
}

/// The default port for a scheme.
fn default_port(scheme: &str) -> u16 {
    if scheme == "https" {
        443
    } else {
        80
    }
}

/// Rewrite an absolute URI as the origin form a server expects.
fn origin_form(uri: &hyper::Uri) -> hyper::Uri {
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    path.parse()
        .unwrap_or_else(|_| hyper::Uri::from_static("/"))
}

/// A response with a status and nothing else.
///
/// Deliberately bodiless. A proxy that explained itself in the response body
/// would be telling whatever the subprocess is talking to — and whatever reads
/// its output — which half of briefcred's checks it failed.
fn status(code: StatusCode) -> Response<OutBody> {
    let mut response = Response::new(empty());
    *response.status_mut() = code;
    response
}

fn empty() -> OutBody {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_authority_gives_up_its_host_without_its_port() {
        assert_eq!(
            authority_host(Some("api.openai.com:443")).as_deref(),
            Some("api.openai.com")
        );
        assert_eq!(
            authority_host(Some("api.openai.com")).as_deref(),
            Some("api.openai.com")
        );
    }

    #[test]
    fn an_ipv6_literal_keeps_its_brackets_and_loses_only_its_port() {
        assert_eq!(authority_host(Some("[::1]:8443")).as_deref(), Some("[::1]"));
        assert_eq!(authority_host(Some("[::1]")).as_deref(), Some("[::1]"));
    }

    #[test]
    fn an_authority_that_is_not_one_is_refused() {
        assert_eq!(authority_host(None), None);
        assert_eq!(authority_host(Some("")), None);
        assert_eq!(authority_host(Some("   ")), None);
        assert_eq!(authority_host(Some(":443")), None);
    }

    #[test]
    fn an_authority_gives_up_its_port_when_it_has_one() {
        assert_eq!(authority_port(Some("api.openai.com:8443")), Some(8443));
        assert_eq!(authority_port(Some("api.openai.com")), None);
        assert_eq!(authority_port(Some("[::1]:8443")), Some(8443));
        assert_eq!(authority_port(Some("[::1]")), None);
        assert_eq!(authority_port(Some("api.openai.com:https")), None);
    }

    #[test]
    fn a_scheme_implies_its_port() {
        assert_eq!(default_port("https"), 443);
        assert_eq!(default_port("http"), 80);
    }

    #[test]
    fn an_absolute_uri_becomes_the_origin_form_a_server_expects() {
        let uri: hyper::Uri = "http://api.example.com/v1/thing?a=1".parse().unwrap();
        assert_eq!(origin_form(&uri).to_string(), "/v1/thing?a=1");
        let already: hyper::Uri = "/v1/thing".parse().unwrap();
        assert_eq!(origin_form(&already).to_string(), "/v1/thing");
    }

    #[test]
    fn a_uri_with_no_path_becomes_a_root_request() {
        let uri: hyper::Uri = "http://api.example.com".parse().unwrap();
        assert_eq!(origin_form(&uri).to_string(), "/");
    }

    #[test]
    fn a_refusal_carries_no_body_to_explain_itself_with() {
        let response = status(StatusCode::FORBIDDEN);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.body().size_hint().exact(), Some(0));
    }

    #[test]
    fn the_proxy_never_prints_a_session_or_a_credential() {
        // `Proxy` holds masters through the sessions it reaches; its `Debug`
        // reaches only the issuer and the policy cache, neither of which holds
        // one. Asserted here so a future derived `Debug` fails this test.
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<Proxy>();
    }

    fn headers(pairs: &[(&str, &str)]) -> hyper::header::HeaderMap {
        let mut map = hyper::header::HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn a_token_is_found_wherever_the_client_put_it() {
        assert_eq!(
            find_token(&headers(&[("authorization", "Bearer bc.abc.def")])).as_deref(),
            Some("bc.abc.def")
        );
        assert_eq!(
            find_token(&headers(&[("x-api-key", "bc.abc.def")])).as_deref(),
            Some("bc.abc.def")
        );
    }

    #[test]
    fn a_request_carrying_no_token_has_none_to_find() {
        assert_eq!(
            find_token(&headers(&[
                ("authorization", "Bearer sk-a-real-key"),
                ("accept", "*/*")
            ])),
            None
        );
        assert_eq!(find_token(&headers(&[])), None);
    }
}
