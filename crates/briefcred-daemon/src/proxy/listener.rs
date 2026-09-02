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
//! Inside a tunnel the client may also pick HTTP/2, by ALPN. Then [`forward`]
//! is called once per stream instead of once per request, over the same
//! pipeline and with the same rows — a stream *is* a request. See
//! [`crate::proxy::http2`] for the two things that only exist once framing is
//! multiplexed: the connection's own row, and the upstream connection cache.
//!
//! # The order, and why it is that order
//!
//! 1. **Authorize the token.** Signature, expiry, revocation. Before anything
//!    else, because everything else needs to know which session this is.
//! 2. **Check the proof, if there is one.** A `DPoP` header is verified against
//!    the session's key. Absent is accepted — see [`crate::proxy::token`] — but
//!    present-and-wrong is a refusal, never a shrug.
//! 3. **Charge the quota.** One token off the session's bucket, if its profile
//!    set one. Before the policy on purpose: a denied request is still work,
//!    and a loop that is being denied is still a loop.
//! 4. **Ask the policy.** Method, scheme, host, and path, plus a context
//!    carrying the session's totals and the clock, against the profile's Cedar
//!    source. Default deny.
//! 5. **Swap.** The real credential goes in and the synthetic token comes out.
//!    Only now does the request hold anything worth stealing.
//! 6. **Forward, streaming.** Bodies are passed through in both directions and
//!    counted as they go; nothing is buffered whole.
//! 7. **Audit and count.** One `ProxyRequest` row when the response body ends.
//! 8. **Keep streaming, if it is a stream.** An event stream or a completed
//!    WebSocket handshake hands off to [`crate::proxy::stream`], which counts
//!    what crosses it and writes a `ProxyStream` row when it closes. Nothing
//!    above changes: a stream is one request and was decided as one.
//!
//! # What each refusal is recorded as
//!
//! Every refusal is *counted*, on
//! `briefcred_proxy_requests_total{decision,status_class}`. Only a refusal that
//! got as far as resolving a session is *audited*, because a `ProxyRequest` row
//! names a `mint_id` and a request whose token did not verify has no mint to
//! name. So a bad token is a metric and a line on the daemon's log, and
//! everything from the policy onwards is a row.
//!
//! The `decision` distinguishes who refused, which matters because two of these
//! are not policy decisions at all:
//!
//! | `decision` | what happened |
//! | --- | --- |
//! | `allow` | the policy permitted it and it was forwarded |
//! | `deny` | the policy refused it, or the token did not authorise |
//! | `would_deny` | the policy refused it and the profile is observing |
//! | `quota` | the session's budget was spent; the policy was never asked |
//! | `bad_request` | the request was malformed; **nothing** decided it |
//! | `swap_error` | the policy **allowed** it; the credential would not go in |
//! | `upstream_error` | the policy **allowed** it; the upstream was unreachable |
//!
//! `status` is the upstream's own code and is absent for all but `allow` and
//! `would_deny`: nothing else reached an upstream to get one, and putting
//! briefcred's `502` there would make a proxy failure indistinguishable from a
//! vendor outage.

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
use hyper::header::HeaderValue;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use time::OffsetDateTime;
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::proxy::http2;
use crate::proxy::issuer::ProxyIssuer;
use crate::proxy::policy::PolicyCache;
use crate::proxy::stream;
use crate::proxy::swap::{self, Credential};
use crate::proxy::token::{self, TokenError};
use crate::quota::TokenBucket;
use crate::server::State;
use crate::session::HttpCounters;

/// The body type every response out of this module has.
type OutBody = BoxBody<Bytes, hyper::Error>;

/// briefcred refused the request: the policy said no, or the token did not
/// authorise one.
const DECISION_DENY: &str = "deny";

/// The policy allowed the request, but the credential could not be put into it.
///
/// Distinct from `deny` because it is a briefcred fault rather than a policy
/// outcome: a profile whose `deny` count is climbing needs its policy widened,
/// and one whose `swap_error` count is climbing needs somebody to look at the
/// master it is holding.
const DECISION_SWAP_ERROR: &str = "swap_error";

/// The policy allowed the request, but the upstream could not be reached.
///
/// Also not a policy outcome. This is the series that separates "the vendor is
/// down" from "briefcred is refusing me", which are the two things a user
/// staring at a failing agent cannot otherwise tell apart.
const DECISION_UPSTREAM_ERROR: &str = "upstream_error";

/// The session's quota was spent, so the policy was never asked.
///
/// Distinct from `deny` because the request may well have been one the policy
/// permits: a profile whose `deny` count is climbing has a policy that is too
/// narrow, and one whose `quota` count is climbing has an agent doing too much.
const DECISION_QUOTA: &str = "quota";

/// The request was not one briefcred could act on, so nothing decided it.
///
/// Distinct from `deny` because nothing refused it: the policy was never given
/// a chance to have an opinion, and counting a malformed request as a denial
/// would put a client's own bug in the series an operator reads to find out
/// which profile is too narrow. Today the only way to reach it is a WebSocket
/// handshake with no `Sec-WebSocket-Key`, or one on a connection that cannot
/// be upgraded.
const DECISION_BAD_REQUEST: &str = "bad_request";

/// The body a throttled client gets back.
///
/// The one response out of this module with a body at all. Everything else
/// refuses in silence, because explaining a refusal to a subprocess tells it
/// which of briefcred's checks it failed — but a quota is not a secret, it is a
/// number the profile's own author chose, and a client that cannot tell "you
/// are going too fast" from "you are not allowed here" will retry the one case
/// where retrying is exactly wrong.
const QUOTA_BODY: &str = r#"{"error":"briefcred quota exceeded"}"#;

/// The content type of [`QUOTA_BODY`].
const APPLICATION_JSON: &str = "application/json";

/// Everything one proxied request needs, shared across every connection.
pub struct Proxy {
    state: Arc<State>,
    issuer: Arc<ProxyIssuer>,
    /// The upstream trust configuration, offering `h2` and `http/1.1`.
    upstream: Arc<rustls::ClientConfig>,
    /// The same trust, offering only `http/1.1`, for a WebSocket handshake.
    upstream_http1: Arc<rustls::ClientConfig>,
    /// One multiplexed upstream connection per session, credential, and
    /// destination, for the streams that negotiated HTTP/2.
    upstreams: http2::Upstreams,
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
            upstream_http1: crate::proxy::tls::without_http2(&upstream),
            upstream,
            upstreams: http2::Upstreams::default(),
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
        // Counted for the drain: an in-place upgrade must not exit on top of
        // a request this daemon is still answering.
        let guard = proxy.state.in_flight().guard();
        let proxy = Arc::clone(&proxy);
        tokio::spawn(async move {
            serve_connection(stream, proxy).await;
            drop(guard);
        });
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
                forward(request, proxy, "http", None, None).await
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
    //
    // The task takes a drain guard of its own, because it outlives the
    // connection future that spawned it: a `CONNECT` completes as soon as it
    // is upgraded, and the event stream inside the tunnel lives here. Without
    // this the drain would report zero while a stream was still running.
    let guard = proxy.state.in_flight().guard();
    tokio::spawn(async move {
        let _guard = guard;
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

    // What the two ends negotiated separately. The client picked this one; the
    // upstream picks its own when the first stream is forwarded, and the
    // pipeline in between is the same either way.
    let http2 = stream.get_ref().1.alpn_protocol() == Some(crate::proxy::tls::ALPN_H2);
    if http2 {
        return serve_tunnel_http2(stream, host, port, proxy).await;
    }

    let service = service_fn(move |request: Request<Incoming>| {
        let proxy = Arc::clone(&proxy);
        let host = host.clone();
        async move {
            Ok::<_, std::convert::Infallible>(
                forward(request, proxy, "https", Some((host, port)), None).await,
            )
        }
    });
    // `with_upgrades` again, and for a second reason: inside the tunnel a
    // request may be a WebSocket handshake, and without this the `101` is
    // written and the connection then closed under whatever was about to
    // start speaking frames on it.
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await;
    Ok(())
}

/// Serve HTTP/2 inside a tunnel whose client negotiated it.
///
/// The same service as HTTP/1.1, called once per stream instead of once per
/// request. Nothing in the pipeline changes and nothing needs to: a stream is a
/// request, and the token, quota, policy, swap, and row it gets are the ones
/// any other request gets. No `with_upgrades`, because HTTP/2 has no `Upgrade`
/// — a WebSocket handshake arrives on an `http/1.1` connection or not at all.
///
/// The connection's own row is written after `serve_connection` returns, which
/// is the one moment every stream on it has finished and its totals are final.
async fn serve_tunnel_http2<I>(io: I, host: String, port: u16, proxy: Arc<Proxy>) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let connection = Arc::new(http2::Connection::new(host.clone()));
    let service = {
        let connection = Arc::clone(&connection);
        let proxy = Arc::clone(&proxy);
        service_fn(move |request: Request<Incoming>| {
            let proxy = Arc::clone(&proxy);
            let host = host.clone();
            let connection = Arc::clone(&connection);
            async move {
                Ok::<_, std::convert::Infallible>(
                    forward(
                        request,
                        proxy,
                        "https",
                        Some((host, port)),
                        Some(connection),
                    )
                    .await,
                )
            }
        })
    };
    let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(TokioIo::new(io), service)
        .await;
    connection.finish(&proxy.state);
    Ok(())
}

/// The whole of one proxied request: authorize, decide, swap, forward, audit.
///
/// `tunnel` is the host and port the `CONNECT` named, when there was one.
/// Inside a tunnel the request line carries only a path, so the destination has
/// to come from the tunnel rather than from a `Host` header the client
/// controls: a request that could name its own host would be one that could get
/// a certificate for one vendor and a connection to somewhere else entirely.
///
/// `connection` is the client's HTTP/2 connection, when the request is one
/// stream of one. Every row this writes names it, so a hundred streams can be
/// read back as the one connection they were.
async fn forward(
    request: Request<Incoming>,
    proxy: Arc<Proxy>,
    scheme: &str,
    tunnel: Option<(String, u16)>,
    connection: Option<Arc<http2::Connection>>,
) -> Response<OutBody> {
    let started = std::time::Instant::now();
    let method = request.method().to_string();
    if let Some(connection) = connection.as_deref() {
        connection.began_stream(&proxy.state);
    }
    let connection_id = connection.as_deref().map(|c| c.id().to_string());

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
        return Attempt {
            proxy: &proxy,
            started,
            method: &method,
            host: "",
            path: "",
            connection_id: connection_id.as_deref(),
        }
        .refuse(StatusCode::BAD_REQUEST, None, DECISION_DENY);
    };
    // The query string is dropped here and never picked up again: it routinely
    // carries an API key, so neither the policy nor the audit row may see one.
    let path = request.uri().path().to_string();

    // Everything a row or a metric for this request needs, whatever becomes of
    // it. Assembled once so a refusal three checks further down cannot record a
    // different host from the one that was decided.
    let attempt = Attempt {
        proxy: &proxy,
        started,
        method: &method,
        host: &host,
        path: &path,
        connection_id: connection_id.as_deref(),
    };

    // 1. Which session and credential is this?
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let Some(presented) = find_token(request.headers()) else {
        return attempt.refuse(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            None,
            DECISION_DENY,
        );
    };
    let claims = match proxy.issuer.authorize(&presented, now) {
        Ok(claims) => claims,
        Err(err) => {
            eprintln!("briefcred-daemon: proxy refused a token for `{host}`: {err}");
            return attempt.refuse(
                match err {
                    TokenError::Revoked => StatusCode::FORBIDDEN,
                    _ => StatusCode::UNAUTHORIZED,
                },
                None,
                DECISION_DENY,
            );
        }
    };

    // 2. The session it names, and everything it holds.
    let Some(session) = resolve_session(&proxy, &claims.sid, &claims.cred).await else {
        return attempt.refuse(StatusCode::UNAUTHORIZED, None, DECISION_DENY);
    };
    // The connection is named by the first grant a stream of it resolved, and
    // this is the only place one is resolved.
    if let Some(connection) = connection.as_deref() {
        connection.note_mint(&session.mint_id);
    }

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
            return attempt.refuse(StatusCode::UNAUTHORIZED, None, DECISION_DENY);
        }
    }

    // 4. Count the request, then charge for it.
    //
    // Counted first so `requests_so_far` means every request this session
    // made, whatever became of it. Counting after the charge would make a
    // throttled request invisible to a policy while a policy-denied one was
    // not, and a counter that skips some refusals and not others is one no
    // budget can be written against.
    let requests_so_far = session.http.begin_request();

    // The charge is before the policy, not after: the expensive thing to
    // defend against is a loop, and a loop that is being denied is still a
    // loop. Charging afterwards would give a request the profile forbids an
    // unmetered retry channel.
    if let Err(refusal) = crate::quota::charge(
        session.quota.as_deref(),
        &session.profile.name,
        crate::quota::SURFACE_HTTP,
        proxy.state.metrics(),
    ) {
        return attempt.refuse_quota(refusal, &session.mint_id);
    }

    // 5. May this session make this request?
    //
    // The context is the session's totals *before* this request, so a policy
    // written as `context.requests_so_far < 100` permits exactly a hundred.
    let context = briefcred_core::policy::RequestContext::new(
        OffsetDateTime::now_utc(),
        requests_so_far,
        session.http.resp_bytes(),
    );
    let decision = proxy.policies.decide(
        &session.profile,
        &claims.sid,
        &HttpRequest {
            method: &method,
            scheme,
            host: &host,
            path: &path,
            context,
        },
    );
    if !decision.forwards() {
        proxy
            .state
            .audit(&attempt.row(&session.mint_id, None, 0, 0, decision.label()));
        proxy
            .state
            .metrics()
            .record_proxy_request(decision.label(), None, started.elapsed());
        return status(StatusCode::FORBIDDEN);
    }

    // 6. The real credential goes in.
    let (mut parts, body) = request.into_parts();

    // A WebSocket handshake is recognised here and not earlier, because
    // everything above this line is right for it already: the handshake is a
    // `GET`, and the token, the quota, and the policy decided it on exactly
    // those terms. What changes below is only what happens after the `101`.
    let websocket = stream::is_websocket_upgrade(&parts.headers);
    let client_upgrade = parts.extensions.remove::<hyper::upgrade::OnUpgrade>();
    let websocket_key = parts
        .headers
        .get(WEBSOCKET_KEY)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let handshake = match (websocket, client_upgrade, websocket_key) {
        (false, _, _) => None,
        (true, Some(upgrade), Some(key)) => Some((upgrade, key)),
        // A handshake with no `Sec-WebSocket-Key`, or one this connection
        // cannot be taken off, is not a handshake. Refused rather than
        // forwarded as an ordinary `GET`: an upstream answering `101` to
        // something briefcred could not then relay would leave a client
        // talking frames into a connection nobody is reading.
        (true, _, _) => {
            eprintln!(
                "briefcred-daemon: proxy refused a malformed websocket handshake for `{host}`"
            );
            return attempt.refuse(
                StatusCode::BAD_REQUEST,
                Some(&session.mint_id),
                DECISION_BAD_REQUEST,
            );
        }
    };

    if let Err(err) = swap::apply(
        &mut parts.headers,
        &session.credentials,
        Some(&session.authorized),
    ) {
        eprintln!("briefcred-daemon: proxy will not forward to `{host}`: {err}");
        return attempt.refuse(
            StatusCode::BAD_GATEWAY,
            Some(&session.mint_id),
            DECISION_SWAP_ERROR,
        );
    }
    // A proof is for briefcred, not for the vendor, and forwarding it would
    // tell an upstream which session made the call.
    parts.headers.remove("dpop");
    // Hop-by-hop headers addressed to the proxy, which is this process. An
    // upstream has no business seeing either.
    parts.headers.remove(hyper::header::PROXY_AUTHORIZATION);
    parts.headers.remove("proxy-connection");

    // Origin-form, because an absolute URI is a proxy's spelling and not a
    // server's. An HTTP/2 upstream needs the authority back and gets it in
    // `send_upstream`, which is the only place that knows what was negotiated.
    parts.uri = origin_form(&parts.uri);

    let req_bytes = Arc::new(AtomicU64::new(0));
    let counted = Counting::new(body, Arc::clone(&req_bytes), None);
    let upstream_request = Request::from_parts(parts, counted);

    // 7. Forward, streaming.
    let response = match send_upstream(
        &proxy,
        scheme,
        &host,
        port,
        http2::UpstreamKey {
            sid: claims.sid.clone(),
            credential: claims.cred.clone(),
            host: host.clone(),
            port,
        },
        upstream_request,
        handshake.is_some(),
    )
    .await
    {
        Ok(response) => response,
        Err(err) => {
            eprintln!("briefcred-daemon: proxy could not reach `{host}`: {err}");
            return attempt.refuse(
                StatusCode::BAD_GATEWAY,
                Some(&session.mint_id),
                DECISION_UPSTREAM_ERROR,
            );
        }
    };

    // The grant this request runs on, so a stream opened by it can be ended
    // when the grant stops being one. Only streams use it; an ordinary request
    // is over long before a second has passed.
    let live = stream::Liveness {
        sid: claims.sid.clone(),
        credential: claims.cred.clone(),
        expires_at: claims.exp,
    };

    // 8. The row is written when the response body ends, because that is when
    // `resp_bytes` is known. Streaming a gigabyte and then reporting zero would
    // make the byte counts worse than useless.
    let status_code = response.status().as_u16();

    // 8a. A handshake the upstream *completed* stops being HTTP here. One it
    // declined is an ordinary response and falls through to be counted and
    // audited as one, body and all: an upstream that refuses an upgrade with an
    // explanation is telling the client something, and reporting zero bytes for
    // it would be the same lie as reporting zero for any other response.
    let completed = handshake.filter(|_| response.status() == StatusCode::SWITCHING_PROTOCOLS);
    if let Some((client_upgrade, key)) = completed {
        // Only reachable on HTTP/1.1: HTTP/2 has no `Upgrade`, so a stream on
        // an h2 connection never gets here and `connection_id` is always
        // `None`. Carried anyway rather than hardcoded, so the day RFC 8441
        // arrives the row is already right.
        return upgrade_websocket(
            response,
            Handshake {
                connection_id,
                proxy,
                mint_id: session.mint_id.clone(),
                method,
                host,
                path,
                started,
                decision: decision.label(),
                key,
                client_upgrade,
                live,
                counters: Arc::clone(&session.http),
            },
        );
    }

    let (mut parts, body) = response.into_parts();
    let event_stream = stream::is_event_stream(&parts.headers);
    let resp_bytes = Arc::new(AtomicU64::new(0));
    let done = {
        let proxy = Arc::clone(&proxy);
        let mint_id = session.mint_id.clone();
        let decision = decision.label();
        let req_bytes = Arc::clone(&req_bytes);
        let counters = Arc::clone(&session.http);
        let method = method.clone();
        let host = host.clone();
        let path = path.clone();
        let connection = connection.clone();
        let connection_id = connection_id.clone();
        move |resp_bytes: u64| {
            let elapsed = started.elapsed();
            // Added when the body ends, which is the only moment the size is
            // known. So a policy's `context.resp_bytes_so_far` counts what the
            // session has already been given, never the response in flight.
            counters.add_resp_bytes(resp_bytes);
            let req_bytes = req_bytes.load(Ordering::Relaxed);
            // The connection's totals are its streams' totals, added as each
            // one finishes for the same reason: this is when they are known.
            if let Some(connection) = connection.as_deref() {
                connection.add_bytes(req_bytes, resp_bytes);
            }
            proxy.state.audit(&proxy_row(
                &mint_id,
                &method,
                &host,
                &path,
                Some(status_code),
                req_bytes,
                resp_bytes,
                elapsed,
                decision,
                connection_id.clone(),
            ));
            proxy
                .state
                .metrics()
                .record_proxy_request(decision, Some(status_code), elapsed);
        }
    };
    let counted = Counting::new(body, Arc::clone(&resp_bytes), Some(Box::new(done)));

    // 8b. An ordinary response ends here. An event stream is the same streamed
    // body with a scanner over it and a row of its own when it closes.
    if !event_stream {
        return Response::from_parts(parts, counted.boxed());
    }

    // Whatever the upstream said the length was, it is not the length of what
    // the client is about to be sent: this body ends when the upstream stops,
    // and a `Content-Length` here would make the client wait for bytes that
    // are never coming.
    parts.headers.remove(hyper::header::CONTENT_LENGTH);
    let row = stream::StreamRow {
        state: Arc::clone(&proxy.state),
        mint_id: session.mint_id.clone(),
        kind: stream::KIND_SSE,
        host,
        path,
        started: OffsetDateTime::now_utc(),
        since: std::time::Instant::now(),
        connection_id,
    };
    let watch = stream::watch(Arc::clone(&proxy.state), Arc::clone(&proxy.issuer), live);
    Response::from_parts(
        parts,
        stream::EventStream::new(counted, row, req_bytes, resp_bytes, watch).boxed(),
    )
}

/// The `Sec-WebSocket-Key` header, which is not one hyper names for us.
const WEBSOCKET_KEY: &str = "sec-websocket-key";

/// What the WebSocket branch of [`forward`] needs and the response does not
/// carry.
struct Handshake {
    /// The client's HTTP/2 connection, when there is one. See the note at the
    /// call site for why there never is one today.
    connection_id: Option<String>,
    proxy: Arc<Proxy>,
    mint_id: MintId,
    method: String,
    host: String,
    path: String,
    started: std::time::Instant,
    decision: &'static str,
    /// The client's own `Sec-WebSocket-Key`, which briefcred forwarded.
    key: String,
    client_upgrade: hyper::upgrade::OnUpgrade,
    live: stream::Liveness,
    /// The session's running totals, so what the relay carries downstream
    /// reaches the Cedar `context` of the session's next request.
    counters: Arc<HttpCounters>,
}

/// Validate the upstream's `101`, answer the client with one, and relay.
///
/// The validation is the load-bearing part. briefcred forwarded the client's
/// own key, so an upstream that completed this handshake must answer with the
/// accept token derived from it; anything else is a server that answered `101`
/// without agreeing to speak WebSocket, and handing raw byte forwarding to one
/// of those is how a proxy gets used as a tunnel to something that is not a
/// WebSocket server at all.
///
/// Only ever called with a `101`; anything else was an upstream declining the
/// upgrade and never reached here.
fn upgrade_websocket(response: Response<Incoming>, hand: Handshake) -> Response<OutBody> {
    let Handshake {
        connection_id,
        proxy,
        mint_id,
        method,
        host,
        path,
        started,
        decision,
        key,
        client_upgrade,
        live,
        counters,
    } = hand;

    let expected = stream::accept_key(&key);
    let accepted = response
        .headers()
        .get("sec-websocket-accept")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected);
    let mut response = response;
    let upstream_upgrade = response
        .extensions_mut()
        .remove::<hyper::upgrade::OnUpgrade>();
    let attempt = Attempt {
        proxy: &proxy,
        started,
        method: &method,
        host: &host,
        path: &path,
        connection_id: connection_id.as_deref(),
    };
    let Some(upstream_upgrade) = upstream_upgrade.filter(|_| accepted) else {
        eprintln!(
            "briefcred-daemon: `{host}` answered 101 without completing the handshake; not relaying"
        );
        return attempt.refuse(
            StatusCode::BAD_GATEWAY,
            Some(&mint_id),
            DECISION_UPSTREAM_ERROR,
        );
    };

    // The handshake is a request like any other and gets its row now: the
    // stream that follows gets one of its own when it closes.
    let elapsed = started.elapsed();
    proxy.state.audit(&attempt.row(
        &mint_id,
        Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
        0,
        0,
        decision,
    ));
    proxy.state.metrics().record_proxy_request(
        decision,
        Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
        elapsed,
    );

    let row = stream::StreamRow {
        state: Arc::clone(&proxy.state),
        mint_id,
        kind: stream::KIND_WS,
        host: host.clone(),
        path,
        started: OffsetDateTime::now_utc(),
        since: std::time::Instant::now(),
        connection_id: connection_id.clone(),
    };
    let watch = stream::watch(Arc::clone(&proxy.state), Arc::clone(&proxy.issuer), live);
    // A relay of its own again: the handshake response completes the tunnel's
    // connection future, and the frames go on flowing here afterwards.
    let guard = proxy.state.in_flight().guard();
    tokio::spawn(async move {
        let _guard = guard;
        let (client, upstream) = match tokio::try_join!(client_upgrade, upstream_upgrade) {
            Ok(both) => both,
            Err(err) => {
                eprintln!("briefcred-daemon: a websocket to `{host}` was not upgraded: {err}");
                // Still a row. Both sides were told the handshake succeeded, so
                // a stream that carried nothing is a different fact from one
                // that never appears in the log at all.
                row.write(0, 0, 0);
                return;
            }
        };
        stream::relay(
            TokioIo::new(client),
            TokioIo::new(upstream),
            row,
            watch,
            counters,
        )
        .await;
    });

    // The `101` the client gets is built from the upstream's, field by field:
    // a copy would forward whatever else that server chose to attach to it.
    let mut switching = Response::new(empty());
    *switching.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    for name in stream::HANDSHAKE_HEADERS {
        if let Some(value) = response.headers().get(name) {
            switching
                .headers_mut()
                .insert(hyper::header::HeaderName::from_static(name), value.clone());
        }
    }
    switching
}

/// Send one request upstream, over HTTP/2 where the upstream offers it.
///
/// The upstream's protocol is negotiated separately from the client's, by ALPN
/// on the connection this opens. A client on HTTP/2 whose upstream only speaks
/// HTTP/1.1 still gets its request forwarded, and an HTTP/1.1 client whose
/// upstream speaks HTTP/2 gets the benefit of the multiplexing without knowing
/// about it.
///
/// # Which connections are reused, and which are not
///
/// An HTTP/2 upstream connection is kept and multiplexed, keyed on the session
/// and credential as well as the destination — see [`crate::proxy::http2`] for
/// why the key has to be that narrow. HTTP/1.1 gets a fresh connection per
/// request, as it always has: one request at a time over a new connection is
/// already correct, and pooling it would carry the same credential-mix-up risk
/// for a smaller prize.
///
/// `upgrades` is set for a WebSocket handshake. It forces HTTP/1.1 outright —
/// an `Upgrade` has no HTTP/2 spelling this proxy speaks — and is what makes
/// the connection survive its own `101` so both halves can be taken over.
async fn send_upstream(
    proxy: &Proxy,
    scheme: &str,
    host: &str,
    port: u16,
    key: http2::UpstreamKey,
    mut request: Request<http2::UpstreamBody>,
    upgrades: bool,
) -> Result<Response<Incoming>> {
    // A WebSocket handshake, or a plain `http://` upstream where there is no
    // ALPN to negotiate with and h2c is not something to guess at.
    if upgrades || scheme != "https" {
        let io = connect_upstream(proxy, scheme, host, port, upgrades).await?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io.stream)
            .await
            .map_err(|e| Error::Proxy(format!("upstream handshake failed: {e}")))?;
        spawn_http1(connection, upgrades);
        return sender
            .send_request(request)
            .await
            .map_err(|e| Error::Proxy(format!("upstream refused the request: {e}")));
    }

    let dialled = proxy
        .upstreams
        .connect(key, || dial(proxy, scheme, host, port))
        .await?;
    match dialled {
        http2::Dialled::Http2(mut sender) => {
            // Connection-specific headers an HTTP/1.1 client may have sent are
            // forbidden on an HTTP/2 stream, and an upstream that sees one
            // resets the stream rather than answering it.
            http2::strip_connection_specific(request.headers_mut());
            // HTTP/2 carries the destination in `:scheme` and `:authority`,
            // which hyper takes from the URI. Origin-form is an HTTP/1.1
            // spelling and leaves it with nothing to put there.
            *request.uri_mut() = absolute_form(scheme, host, port, request.uri());
            http2::send_on(&mut sender, request).await
        }
        http2::Dialled::Http1(mut sender) => sender
            .send_request(request)
            .await
            .map_err(|e| Error::Proxy(format!("upstream refused the request: {e}"))),
    }
}

/// Open one upstream connection and complete whichever handshake ALPN chose.
async fn dial(proxy: &Proxy, scheme: &str, host: &str, port: u16) -> Result<http2::Dialled> {
    let io = connect_upstream(proxy, scheme, host, port, false).await?;
    if io.http2 {
        let (sender, connection) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io.stream)
                .await
                .map_err(|e| Error::Proxy(format!("upstream handshake failed: {e}")))?;
        // Driven in its own task, and for longer than an HTTP/1.1 connection's:
        // this one outlives the request that opened it and carries every later
        // stream the cache hands the same sender to.
        tokio::spawn(async move {
            let _ = connection.await;
        });
        return Ok(http2::Dialled::Http2(sender));
    }
    let (sender, connection) = hyper::client::conn::http1::handshake(io.stream)
        .await
        .map_err(|e| Error::Proxy(format!("upstream handshake failed: {e}")))?;
    spawn_http1(connection, false);
    Ok(http2::Dialled::Http1(sender))
}

/// A connected upstream, and what its ALPN said it speaks.
struct Connected {
    stream: TokioIo<UpstreamStream>,
    http2: bool,
}

/// Either half of what an upstream connection may be underneath.
enum UpstreamStream {
    /// A `https://` upstream, verified against the real trust store.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    /// A plain `http://` upstream, which briefcred forwards to as it is asked.
    Plain(TcpStream),
}

/// Connect to the upstream, terminating in TLS where the scheme calls for it.
///
/// `upgrades` picks the trust configuration that offers only `http/1.1`, so a
/// WebSocket handshake cannot end up on a connection that negotiated HTTP/2.
async fn connect_upstream(
    proxy: &Proxy,
    scheme: &str,
    host: &str,
    port: u16,
    upgrades: bool,
) -> Result<Connected> {
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| Error::Proxy(format!("cannot connect to `{host}:{port}`: {e}")))?;

    if scheme != "https" {
        return Ok(Connected {
            stream: TokioIo::new(UpstreamStream::Plain(stream)),
            http2: false,
        });
    }
    let name = rustls_pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| Error::Proxy(format!("`{host}` is not a server name")))?;
    let config = if upgrades {
        Arc::clone(&proxy.upstream_http1)
    } else {
        Arc::clone(&proxy.upstream)
    };
    let tls = tokio_rustls::TlsConnector::from(config)
        .connect(name, stream)
        .await
        .map_err(|e| Error::Proxy(format!("`{host}` did not verify: {e}")))?;
    let http2 = tls.get_ref().1.alpn_protocol() == Some(crate::proxy::tls::ALPN_H2);
    Ok(Connected {
        stream: TokioIo::new(UpstreamStream::Tls(Box::new(tls))),
        http2,
    })
}

/// Drive one HTTP/1.1 upstream connection in a task of its own.
///
/// It has to keep pumping while the response body is being read, so awaiting it
/// at the call site would deadlock.
fn spawn_http1<B>(
    connection: hyper::client::conn::http1::Connection<TokioIo<UpstreamStream>, B>,
    upgrades: bool,
) where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if upgrades {
        tokio::spawn(async move {
            let _ = connection.with_upgrades().await;
        });
    } else {
        tokio::spawn(async move {
            let _ = connection.await;
        });
    }
}

impl tokio::io::AsyncRead for UpstreamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Tls(tls) => Pin::new(tls.as_mut()).poll_read(cx, buf),
            UpstreamStream::Plain(plain) => Pin::new(plain).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for UpstreamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            UpstreamStream::Tls(tls) => Pin::new(tls.as_mut()).poll_write(cx, buf),
            UpstreamStream::Plain(plain) => Pin::new(plain).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Tls(tls) => Pin::new(tls.as_mut()).poll_flush(cx),
            UpstreamStream::Plain(plain) => Pin::new(plain).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Tls(tls) => Pin::new(tls.as_mut()).poll_shutdown(cx),
            UpstreamStream::Plain(plain) => Pin::new(plain).poll_shutdown(cx),
        }
    }
}

/// One credential-bearing session, resolved from a token's claims.
struct ResolvedSession {
    profile: briefcred_core::Profile,
    credentials: Vec<Credential>,
    authorized: Credential,
    pubkey: Option<[u8; 32]>,
    mint_id: MintId,
    /// The session's token bucket, when its profile sets a `quota`.
    quota: Option<Arc<TokenBucket>>,
    /// The session's running totals, for the policy's `context`.
    http: Arc<HttpCounters>,
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
    let (profile_name, masters, pubkey, mint_id, quota, http) = proxy
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
                session.quota.clone(),
                Arc::clone(&session.http),
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
        quota,
        http,
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

/// What every audit row and metric one request writes needs, however it ends.
///
/// Assembled once, as soon as the destination is known, and borrowed by every
/// refusal after it. The point is that a refusal five checks down cannot record
/// a different host or a different clock from the one the request was decided
/// against, which is exactly the drift a long argument list invites.
struct Attempt<'a> {
    proxy: &'a Proxy,
    /// When the request arrived, for the latency on every row it may write.
    started: std::time::Instant,
    method: &'a str,
    host: &'a str,
    path: &'a str,
    /// The client's HTTP/2 connection, when the request is one stream of one.
    connection_id: Option<&'a str>,
}

impl Attempt<'_> {
    /// One `ProxyRequest` row for this request, as it stands now.
    fn row(
        &self,
        mint_id: &MintId,
        status: Option<u16>,
        req_bytes: u64,
        resp_bytes: u64,
        decision: &str,
    ) -> AuditEntry {
        proxy_row(
            mint_id,
            self.method,
            self.host,
            self.path,
            status,
            req_bytes,
            resp_bytes,
            self.started.elapsed(),
            decision,
            self.connection_id.map(str::to_string),
        )
    }

    /// Audit and count a refusal, then answer with `code` and no body.
    ///
    /// Every refusal is recorded. A proxy that silently drops requests is one
    /// an operator debugging "why does my agent get a 401" has nothing to read.
    /// `mint_id` is absent where nothing resolved a session, and the row is
    /// then skipped rather than invented: a row names a grant.
    fn refuse(
        &self,
        code: StatusCode,
        mint_id: Option<&MintId>,
        decision: &str,
    ) -> Response<OutBody> {
        if let Some(mint_id) = mint_id {
            // Not `code`. `status` is the *upstream's* answer, and nothing that
            // reaches here got one — the status the client sees is briefcred's
            // own, and `decision` is what says why.
            self.proxy
                .state
                .audit(&self.row(mint_id, None, 0, 0, decision));
        }
        self.proxy
            .state
            .metrics()
            .record_proxy_request(decision, None, self.started.elapsed());
        status(code)
    }

    /// Audit and count a throttled request, then answer `429`.
    ///
    /// Audited rather than merely counted, unlike the token failures above: the
    /// session is known, so the row can name a `mint_id`, and "the quota
    /// refused this" is exactly the row somebody reading the log to work out
    /// why an agent stalled needs to find.
    fn refuse_quota(&self, refusal: crate::quota::Refusal, mint_id: &MintId) -> Response<OutBody> {
        self.proxy
            .state
            .audit(&self.row(mint_id, None, 0, 0, DECISION_QUOTA));
        self.proxy.state.metrics().record_proxy_request(
            DECISION_QUOTA,
            None,
            self.started.elapsed(),
        );

        let mut response = Response::new(
            Full::new(Bytes::from_static(QUOTA_BODY.as_bytes()))
                .map_err(|never| match never {})
                .boxed(),
        );
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        response.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static(APPLICATION_JSON),
        );
        // Absent where no wait would help: a session that has spent its
        // `total` needs a new session, and a `Retry-After` would send it round
        // the loop that got it here.
        if let Some(retry_after) = refusal.retry_after() {
            if let Ok(value) = HeaderValue::from_str(&retry_after.as_secs().to_string()) {
                response
                    .headers_mut()
                    .insert(hyper::header::RETRY_AFTER, value);
            }
        }
        response
    }
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
    connection_id: Option<String>,
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
        connection_id,
    }
}

/// A body that counts the bytes passing through it.
///
/// Wrapping rather than collecting is the whole point: a four-megabyte response
/// reaches the client a frame at a time, and the count is a side effect of the
/// frames going past rather than of holding them.
pub struct Counting<B> {
    inner: B,
    bytes: Arc<AtomicU64>,
    on_done: Option<Box<dyn FnOnce(u64) + Send + Sync>>,
}

impl<B> Counting<B> {
    pub fn new(
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

/// Rewrite an origin-form URI as the absolute form HTTP/2 needs.
///
/// HTTP/2 has no request line: the destination is carried in the `:scheme` and
/// `:authority` pseudo-headers, which hyper fills in from the URI. The port is
/// left off when it is the scheme's own, because `:authority` is what an
/// upstream compares against its certificate and its virtual hosts, and
/// `api.openai.com:443` is not the same string as `api.openai.com`.
fn absolute_form(scheme: &str, host: &str, port: u16, uri: &hyper::Uri) -> hyper::Uri {
    let authority = if port == default_port(scheme) {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    format!("{scheme}://{authority}{path}")
        .parse()
        .unwrap_or_else(|_| uri.clone())
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
    fn an_origin_form_uri_gets_its_authority_back_for_http2() {
        let uri: hyper::Uri = "/v1/models?limit=1".parse().unwrap();
        assert_eq!(
            absolute_form("https", "api.openai.com", 443, &uri).to_string(),
            "https://api.openai.com/v1/models?limit=1"
        );
    }

    #[test]
    fn a_non_default_port_stays_in_the_authority_and_a_default_one_does_not() {
        let uri: hyper::Uri = "/v1/models".parse().unwrap();
        assert_eq!(
            absolute_form("https", "localhost", 8443, &uri).to_string(),
            "https://localhost:8443/v1/models"
        );
        assert_eq!(
            absolute_form("http", "localhost", 80, &uri).to_string(),
            "http://localhost/v1/models"
        );
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
