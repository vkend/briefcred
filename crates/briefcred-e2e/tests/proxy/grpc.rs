//! gRPC through the proxy, in all four call shapes.
//!
//! gRPC is HTTP/2 with a content type and a trailer convention, and briefcred
//! has nothing gRPC-specific in it: what these tests prove is that the HTTP/2
//! path is correct enough that gRPC works over it unmodified. Three things have
//! to hold, and each is one that a proxy can break while appearing to work:
//!
//! - **All four call shapes.** Unary, server-streaming, client-streaming, and
//!   bidirectional. A proxy that buffered a body would pass the first and hang
//!   the other three.
//! - **Trailers.** `grpc-status` arrives *after* the body, so a proxy that
//!   forwarded data frames and dropped the trailer frame would deliver every
//!   byte of every response and then fail every call. Asserted twice: through
//!   `tonic`, which reads the status for us, and once on the raw frames.
//! - **Multiplexing.** A gRPC client opens one connection and runs everything
//!   over it. A proxy that dialled a fresh upstream per stream would still
//!   answer correctly, and would have thrown away the reason gRPC uses HTTP/2.
//!
//! The service is hand-written on `tonic`'s runtime rather than generated,
//! because `tonic-build` needs a `protoc` on the machine and what is under test
//! is the runtime's four call shapes, not the code generator.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::StreamExt as _;
use hyper::body::Bytes;
// The `http` types both `hyper` and `tonic` are built on, reached through
// `hyper` so the test crate does not depend on the same crate twice by name.
use http_body_util::BodyExt as _;
use hyper::http;
use tokio_stream::Stream;
use tonic::{Code, Status};
use tonic_prost::ProstCodec;

use super::{ProxyClient, UPSTREAM_HOST};

/// The gRPC service name every method below hangs off.
const SERVICE: &str = "/briefcred.test.Echo";

/// The one message the test service sends and receives.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Echo {
    #[prost(string, tag = "1")]
    pub text: String,
}

impl Echo {
    fn new(text: &str) -> Echo {
        Echo {
            text: text.to_string(),
        }
    }
}

/// The codec both ends use. `Encode` and `Decode` are the same message here.
fn codec() -> ProstCodec<Echo, Echo> {
    ProstCodec::default()
}

/// A boxed stream of responses, which is what the streaming handlers return.
type Responses = Pin<Box<dyn Stream<Item = Result<Echo, Status>> + Send>>;

// ----------------------------------------------------------------- the server

/// A gRPC server on its own port, behind the upstream's certificate.
pub struct Server {
    pub port: u16,
    /// TCP connections it has accepted, which is what multiplexing is measured
    /// by: one connection carrying many streams, rather than many connections.
    pub accepts: Arc<AtomicU64>,
    /// Connections currently open, so a test can watch one close.
    pub live: Arc<AtomicU64>,
    /// The `Authorization` each call reached it carrying.
    pub seen: Arc<std::sync::Mutex<Vec<Option<String>>>>,
    #[allow(dead_code)]
    accepting: tokio::task::JoinHandle<()>,
}

/// Start the gRPC server on loopback, using `leaf` for its certificate.
///
/// Its own `ServerConfig` rather than the one the HTTPS upstream uses, because
/// this one advertises `h2` and that one deliberately does not: an upstream
/// that offers no ALPN is how the other tests exercise the proxy's HTTP/1.1
/// fallback, and this one is how they exercise HTTP/2 upstream.
pub async fn start(leaf: &briefcred_core::ca::Leaf) -> Server {
    let chain: Vec<_> = rustls_pemfile::certs(&mut leaf.cert_pem().as_bytes())
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut leaf.key_pem().as_bytes())
        .unwrap()
        .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicU64::new(0));
    let live = Arc::new(AtomicU64::new(0));
    let seen: Arc<std::sync::Mutex<Vec<Option<String>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));

    let counted = Arc::clone(&accepts);
    let open_now = Arc::clone(&live);
    let recorded = Arc::clone(&seen);
    let accepting = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            counted.fetch_add(1, Ordering::Relaxed);
            open_now.fetch_add(1, Ordering::Relaxed);
            let acceptor = acceptor.clone();
            let recorded = Arc::clone(&recorded);
            let open = Arc::clone(&open_now);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = hyper::service::service_fn(
                    move |request: http::Request<hyper::body::Incoming>| {
                        let recorded = Arc::clone(&recorded);
                        async move {
                            recorded.lock().unwrap().push(
                                request
                                    .headers()
                                    .get("authorization")
                                    .and_then(|value| value.to_str().ok())
                                    .map(str::to_string),
                            );
                            Ok::<_, Infallible>(dispatch(request).await)
                        }
                    },
                );
                let _ =
                    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                open.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });

    Server {
        port,
        accepts,
        live,
        seen,
        accepting,
    }
}

/// Route one request to the handler its path names.
///
/// What a generated `tonic` server does, written out: the four call shapes are
/// four different methods on [`tonic::server::Grpc`], and choosing between them
/// is the whole of the generated code that matters here.
async fn dispatch(
    request: http::Request<hyper::body::Incoming>,
) -> http::Response<tonic::body::Body> {
    let mut grpc = tonic::server::Grpc::new(codec());
    match request.uri().path().rsplit('/').next().unwrap_or("") {
        "Unary" => grpc.unary(tower::service_fn(unary), request).await,
        "ServerStream" => {
            grpc.server_streaming(tower::service_fn(server_stream), request)
                .await
        }
        "ClientStream" => {
            grpc.client_streaming(tower::service_fn(client_stream), request)
                .await
        }
        "BiDi" => grpc.streaming(tower::service_fn(bidi), request).await,
        "Forever" => {
            grpc.server_streaming(tower::service_fn(forever), request)
                .await
        }
        "Failing" => grpc.unary(tower::service_fn(failing), request).await,
        _ => grpc.unary(tower::service_fn(unimplemented), request).await,
    }
}

/// How many messages the streaming methods send back per call.
const STREAMED: usize = 5;

async fn unary(request: tonic::Request<Echo>) -> Result<tonic::Response<Echo>, Status> {
    Ok(tonic::Response::new(Echo::new(&format!(
        "echo: {}",
        request.into_inner().text
    ))))
}

/// A method that always fails, so the non-zero `grpc-status` trailer is real.
async fn failing(_: tonic::Request<Echo>) -> Result<tonic::Response<Echo>, Status> {
    Err(Status::permission_denied("the vendor said no"))
}

async fn unimplemented(_: tonic::Request<Echo>) -> Result<tonic::Response<Echo>, Status> {
    Err(Status::unimplemented("no such method"))
}

async fn server_stream(
    request: tonic::Request<Echo>,
) -> Result<tonic::Response<Responses>, Status> {
    let text = request.into_inner().text;
    let stream = futures_util::stream::iter(
        (1..=STREAMED)
            .map(move |n| Ok(Echo::new(&format!("{text} {n}"))))
            .collect::<Vec<_>>(),
    );
    Ok(tonic::Response::new(Box::pin(stream) as Responses))
}

/// A server stream that never ends on its own.
///
/// So a stream that ends at all ended because briefcred ended it, which is the
/// only way to test that a revoked grant stops a gRPC call.
async fn forever(_: tonic::Request<Echo>) -> Result<tonic::Response<Responses>, Status> {
    let stream = futures_util::stream::unfold(0usize, |n| async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        Some((Ok(Echo::new(&format!("tick {n}"))), n + 1))
    });
    Ok(tonic::Response::new(Box::pin(stream) as Responses))
}

async fn client_stream(
    request: tonic::Request<tonic::Streaming<Echo>>,
) -> Result<tonic::Response<Echo>, Status> {
    let mut received = Vec::new();
    let mut stream = request.into_inner();
    while let Some(message) = stream.next().await {
        received.push(message?.text);
    }
    Ok(tonic::Response::new(Echo::new(&received.join(","))))
}

async fn bidi(
    request: tonic::Request<tonic::Streaming<Echo>>,
) -> Result<tonic::Response<Responses>, Status> {
    let stream = request
        .into_inner()
        .map(|message| message.map(|echo| Echo::new(&format!("echo: {}", echo.text))));
    Ok(tonic::Response::new(Box::pin(stream) as Responses))
}

// ----------------------------------------------------------------- the client

/// One HTTP/2 connection, presented to `tonic` as the transport it wants.
///
/// `tonic`'s own `Channel` dials for itself, and what is under test is a
/// connection that went through briefcred's `CONNECT` tunnel. So the connection
/// is opened by hand and wrapped here: everything above this is ordinary
/// `tonic`, which is the point.
#[derive(Clone)]
pub struct Transport {
    inner: hyper::client::conn::http2::SendRequest<tonic::body::Body>,
    /// The synthetic token, attached the way a runtime's API key would be.
    /// Absent for the direct client, which talks to the server with no proxy
    /// and no briefcred in between.
    token: Option<String>,
}

impl tower::Service<http::Request<tonic::body::Body>> for Transport {
    type Response = http::Response<hyper::body::Incoming>;
    type Error = hyper::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, hyper::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<tonic::body::Body>) -> Self::Future {
        if let Some(token) = &self.token {
            request.headers_mut().insert(
                http::header::AUTHORIZATION,
                http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            );
        }
        Box::pin(self.inner.send_request(request))
    }
}

/// A gRPC client whose connection goes through briefcred's tunnel.
pub async fn through_the_proxy(client: &ProxyClient, port: u16, token: &str) -> Transport {
    let tls = client
        .tunnel_with_alpn(port, &[b"h2"])
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "a gRPC client must be answered h2 or it cannot speak at all"
    );
    transport(tls, Some(token.to_string())).await
}

/// A gRPC client that talks to the server with nothing in between.
///
/// The baseline the latency assertion is a ratio against.
pub async fn direct(port: u16, ca_pem: &str) -> Transport {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let name = rustls_pki_types::ServerName::try_from(UPSTREAM_HOST).unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
        .unwrap();
    transport(tls, None).await
}

async fn transport<S>(tls: S, token: Option<String>) -> Transport
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (inner, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Transport { inner, token }
}

/// The path of one method on the test service.
fn path(method: &str) -> http::uri::PathAndQuery {
    format!("{SERVICE}/{method}").parse().unwrap()
}

/// A `tonic` client over `transport`, addressed at the test upstream.
///
/// The origin is what fills in HTTP/2's `:scheme` and `:authority`, which have
/// no request line to live on. `tonic`'s own `Channel` takes it from the
/// address it dialled; this connection was dialled through a tunnel, so it is
/// given here.
fn client(transport: &Transport) -> tonic::client::Grpc<Transport> {
    tonic::client::Grpc::with_origin(
        transport.clone(),
        format!("https://{UPSTREAM_HOST}").parse().unwrap(),
    )
}

/// One unary call.
pub async fn call_unary(transport: &Transport, method: &str, text: &str) -> Result<Echo, Status> {
    let mut grpc = client(transport);
    grpc.ready().await.map_err(unreachable)?;
    grpc.unary(tonic::Request::new(Echo::new(text)), path(method), codec())
        .await
        .map(tonic::Response::into_inner)
}

/// One server-streaming call, collected.
pub async fn call_server_stream(transport: &Transport, text: &str) -> Result<Vec<String>, Status> {
    let mut stream = open_server_stream(transport, "ServerStream", text).await?;
    let mut received = Vec::new();
    while let Some(message) = stream.next().await {
        received.push(message?.text);
    }
    Ok(received)
}

/// Open a server-streaming call and hand back the stream, unread.
///
/// Separate from collecting it because a stream that never ends cannot be
/// collected: the revocation test has to hold the stream open and watch for the
/// moment it stops.
pub async fn open_server_stream(
    transport: &Transport,
    method: &str,
    text: &str,
) -> Result<tonic::Streaming<Echo>, Status> {
    let mut grpc = client(transport);
    grpc.ready().await.map_err(unreachable)?;
    let response = grpc
        .server_streaming(tonic::Request::new(Echo::new(text)), path(method), codec())
        .await?;
    Ok(response.into_inner())
}

/// One client-streaming call.
pub async fn call_client_stream(transport: &Transport, texts: &[&str]) -> Result<Echo, Status> {
    let mut grpc = client(transport);
    grpc.ready().await.map_err(unreachable)?;
    let messages: Vec<Echo> = texts.iter().map(|text| Echo::new(text)).collect();
    grpc.client_streaming(
        tonic::Request::new(futures_util::stream::iter(messages)),
        path("ClientStream"),
        codec(),
    )
    .await
    .map(tonic::Response::into_inner)
}

/// One bidirectional call, collected.
pub async fn call_bidi(transport: &Transport, texts: &[&str]) -> Result<Vec<String>, Status> {
    let mut grpc = client(transport);
    grpc.ready().await.map_err(unreachable)?;
    let messages: Vec<Echo> = texts.iter().map(|text| Echo::new(text)).collect();
    let response = grpc
        .streaming(
            tonic::Request::new(futures_util::stream::iter(messages)),
            path("BiDi"),
            codec(),
        )
        .await?;
    collect(response.into_inner()).await
}

async fn collect(mut stream: tonic::Streaming<Echo>) -> Result<Vec<String>, Status> {
    let mut received = Vec::new();
    while let Some(message) = stream.next().await {
        received.push(message?.text);
    }
    Ok(received)
}

/// The transport's own error, which `hyper` produces and nothing here can.
fn unreachable(err: hyper::Error) -> Status {
    Status::unavailable(err.to_string())
}

// -------------------------------------------------------------- raw framing

/// One gRPC length-prefixed message: a compression flag and a big-endian length.
fn framed(message: &Echo) -> Vec<u8> {
    let encoded = prost::Message::encode_to_vec(message);
    let mut framed = vec![0u8];
    framed.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    framed.extend_from_slice(&encoded);
    framed
}

/// What one raw gRPC response carried, separated into body and trailers.
pub struct RawCall {
    pub status: http::StatusCode,
    pub content_type: Option<String>,
    /// What arrived before the body.
    pub headers: http::HeaderMap,
    /// The `grpc-status` and `grpc-message` that arrived *after* the body.
    pub trailers: Option<http::HeaderMap>,
    pub body_len: usize,
}

/// Make one unary call on a raw HTTP/2 connection and keep the frames apart.
///
/// `tonic` reads the status for us, which is exactly why this exists as well: a
/// proxy that moved `grpc-status` into the response *headers* would satisfy
/// every `tonic` assertion in this file while breaking every client that reads
/// it where gRPC says it is.
pub async fn call_raw(
    sender: &mut hyper::client::conn::http2::SendRequest<http_body_util::Full<Bytes>>,
    token: &str,
    method: &str,
    text: &str,
) -> RawCall {
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("https://{UPSTREAM_HOST}{SERVICE}/{method}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("authorization", format!("Bearer {token}"))
        .body(http_body_util::Full::new(Bytes::from(framed(&Echo::new(
            text,
        )))))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let headers = response.headers().clone();

    let mut body = response.into_body();
    let mut body_len = 0;
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.unwrap();
        if let Some(data) = frame.data_ref() {
            body_len += data.len();
        }
        if let Some(map) = frame.trailers_ref() {
            trailers = Some(map.clone());
        }
    }
    RawCall {
        status,
        content_type,
        headers,
        trailers,
        body_len,
    }
}

/// The `grpc-status` a raw call ended with, as a number.
///
/// Trailers first, then headers. A call that produced a message ends its status
/// in a trailer, which is the relay this test exists for. A call that failed
/// before sending one may instead be a gRPC "Trailers-Only" response, where the
/// whole thing is a single `HEADERS` frame with no body and no trailer frame at
/// all — legal, and what `tonic` sends for a unary handler that returns an
/// error.
pub fn grpc_status(call: &RawCall) -> Option<i32> {
    let from = |map: &http::HeaderMap| map.get("grpc-status")?.to_str().ok()?.parse::<i32>().ok();
    call.trailers
        .as_ref()
        .and_then(from)
        .or_else(|| from(&call.headers))
}

/// The gRPC code `Failing` answers with, named once for both assertions.
pub const REFUSED: Code = Code::PermissionDenied;
