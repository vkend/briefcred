//! The listener, and the order one Postgres connection goes through.
//!
//! # What the subprocess believes
//!
//! A `briefcred exec` for a profile with a `postgres-proxy` credential hands the
//! subprocess a `DATABASE_URL` pointing at `127.0.0.1:<pg_proxy_port>`, with the
//! session identifier as the user and a synthetic token as the password. As far
//! as `psql`, `libpq`, or any driver is concerned that is the database. Every
//! byte of the protocol it sees is a real PostgreSQL server's, because after
//! authentication it is talking to one.
//!
//! # The order, and why it is that order
//!
//! 1. **Read the opening packet.** `SSLRequest` and `GSSENCRequest` are
//!    answered and the client sends another; a `CancelRequest` is a different
//!    kind of connection entirely and is handled and closed.
//! 2. **Ask for a password.** `AuthenticationCleartextPassword`, which is the
//!    only method that can carry an opaque token — see below.
//! 3. **Authorize the token.** Signature, expiry, revocation. Nothing is looked
//!    up before this, because everything after it depends on knowing the
//!    session.
//! 4. **Check the connection against the grant.** The startup packet's `user`
//!    must be the session the token names, and its `database` must be the one
//!    the credential configures. A client may not use a token for one database
//!    to reach another.
//! 5. **Authenticate upstream.** With the master, over SCRAM, on a connection
//!    the client has never touched. This happens *before* the client is told
//!    anything, so a client is never told `AuthenticationOk` for a connection
//!    that does not exist.
//! 6. **Hand over.** The upstream's own greeting is relayed verbatim, and then
//!    bytes are copied both ways until either side closes.
//! 7. **Audit and count.** One `PgConnection` row when the connection ends.
//!
//! # Why the client is asked for a cleartext password
//!
//! Because the thing it is sending is not a password. It is a signed token, and
//! the point of MD5 and SCRAM is to avoid putting a *reusable secret* on the
//! wire — which a token that briefcred issued, that names one session, and that
//! expires with it, is much less of. SCRAM would also be impossible to arrange:
//! the proxy would have to hold the token's salted verifier before the client
//! connected, and the token is minted per exec.
//!
//! What makes this acceptable is the listener's address. It is bound to
//! `127.0.0.1` and nothing else, so "the wire" is a loopback socket on the
//! user's own machine — the same channel the token arrived over in the
//! subprocess's environment, and one that anything able to read it could
//! already read the environment of. `THREAT_MODEL.md` says the same at more
//! length. `pgproxy.tls = true` puts TLS underneath it for a client that
//! insists, using a leaf from briefcred's own CA.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use briefcred_core::ca::CertificateAuthority;
use briefcred_core::minters::postgres_proxy::PgProxyConfig;
use briefcred_core::types::MintId;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::pgproxy::audit::{
    OUTCOME_ALLOW, OUTCOME_DENY, OUTCOME_PROTOCOL_ERROR, OUTCOME_QUOTA, OUTCOME_UPSTREAM_ERROR,
};
use crate::pgproxy::forward;
use crate::pgproxy::startup::{self, Opening, Startup, StartupError};
use crate::pgproxy::wire;
use crate::proxy::issuer::ProxyIssuer;
use crate::quota::TokenBucket;
use crate::server::State;

/// The hostname a `pgproxy.tls` leaf is issued for.
///
/// The listener is loopback-only, so `localhost` is the only name a client can
/// have used to reach it and the only one a certificate has any business
/// claiming.
const TLS_HOSTNAME: &str = "localhost";

/// What a refused client is told, whatever it did wrong.
///
/// One message for every authentication failure. Saying which check failed —
/// "no such session", "wrong database", "expired" — would tell a caller
/// probing the proxy which half of the credential to fix.
const REFUSAL: &str = "briefcred: this connection is not authorised";

/// What a client whose connection briefcred ends mid-session is told.
///
/// Under SQLSTATE `57P01`, which is what PostgreSQL itself sends when an
/// administrator terminates a backend, so a driver already knows to treat the
/// connection as gone rather than retrying on it.
const TERMINATION: &str = "briefcred: this credential has been revoked or has expired";

/// How often a live connection's grant is re-checked.
///
/// One second. It is the bound `THREAT_MODEL.md` states, so it is a constant
/// rather than a literal: a connection outlives its grant by at most this long.
pub const LIVENESS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Everything one proxied connection needs, shared across all of them.
pub struct PgProxy {
    state: Arc<State>,
    issuer: Arc<ProxyIssuer>,
    /// Whether to answer `SSLRequest` with a CA leaf rather than with `N`.
    tls: bool,
    /// Whether an upstream may authenticate the master with MD5.
    allow_md5: bool,
    ca: Mutex<Option<Arc<CertificateAuthority>>>,
    /// The upstream each live connection's backend key belongs to.
    ///
    /// A `CancelRequest` arrives on a connection of its own carrying only the
    /// `(pid, key)` the server issued. Since briefcred relays the server's own
    /// `BackendKeyData` verbatim, that pair identifies a real backend — this
    /// map is what says *which* server to send the cancellation to.
    backends: Mutex<HashMap<(i32, i32), String>>,
}

impl std::fmt::Debug for PgProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgProxy")
            .field("issuer", &self.issuer)
            .field("tls", &self.tls)
            .field("allow_md5", &self.allow_md5)
            .field(
                "live_backends",
                &self.backends.lock().map(|map| map.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl PgProxy {
    /// Assemble the proxy from the daemon's state, its issuer, and its options.
    pub fn new(
        state: Arc<State>,
        issuer: Arc<ProxyIssuer>,
        tls: bool,
        allow_md5: bool,
    ) -> Arc<PgProxy> {
        Arc::new(PgProxy {
            state,
            issuer,
            tls,
            allow_md5,
            ca: Mutex::new(None),
            backends: Mutex::new(HashMap::new()),
        })
    }

    /// The machine's CA, loaded on the first TLS connection and kept after.
    ///
    /// Loaded rather than generated, and lazily rather than at startup, for the
    /// same reasons as the HTTP proxy's: the CA private key lives in the
    /// platform key store, and a daemon whose clients never ask for TLS should
    /// never prompt for access to it.
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

    fn count(&self, outcome: &str) {
        self.state.metrics().record_pgproxy_connection(outcome);
    }
}

/// Bind the Postgres proxy to loopback, letting the OS pick when `port` is 0.
///
/// Loopback and nothing else, and here that is not merely prudent: the client's
/// password crosses this socket in the clear, and the daemon behind it holds a
/// master that can reach a real database. A listener anything off the machine
/// could reach would be an unauthenticated route to somebody's warehouse.
pub fn bind(port: u16) -> std::io::Result<(TcpListener, SocketAddr)> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    Ok((TcpListener::from_std(listener)?, addr))
}

/// Accept and serve connections until `shutdown` fires.
pub async fn serve(
    listener: TcpListener,
    proxy: Arc<PgProxy>,
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

/// Serve one client connection from its opening packet to its close.
async fn serve_connection(stream: TcpStream, proxy: Arc<PgProxy>) {
    let _ = stream.set_nodelay(true);
    if let Err(err) = handle(stream, &proxy).await {
        // A peer that opened a socket and closed it without saying anything is
        // a port scan or a health check, not a failure worth a line: on a
        // machine with either, logging it would bury the refusals that matter.
        // It is still counted, so a burst of them is visible on the metric.
        if matches!(err, ConnectionError::Startup(StartupError::Closed)) {
            return;
        }
        // Every other path has already counted and, where there was one,
        // written its row. What is left is to say so once on the log.
        eprintln!("briefcred-daemon: postgres proxy: {err}");
    }
}

/// Why one connection ended before it was relayed.
///
/// Every variant has already been counted by the time it is returned; the
/// value exists to be logged.
#[derive(Debug, thiserror::Error)]
enum ConnectionError {
    #[error("{0}")]
    Startup(#[from] StartupError),
    #[error("{0}")]
    Wire(#[from] wire::WireError),
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Upstream(#[from] forward::UpstreamError),
    #[error("{0}")]
    Daemon(#[from] Error),
}

async fn handle(
    stream: TcpStream,
    proxy: &Arc<PgProxy>,
) -> std::result::Result<(), ConnectionError> {
    let (stream, opening) = read_opening(stream, proxy).await?;
    match opening {
        Opening::Startup(startup) => serve_session(stream, startup, proxy).await,
        Opening::Cancel { pid, key } => {
            cancel(pid, key, proxy).await;
            Ok(())
        }
        // `read_startup` answers these and reads again; reaching here would
        // mean it returned one, which it does not.
        Opening::Ssl | Opening::GssEnc => unreachable!("negotiations are answered in the loop"),
    }
}

/// Read the opening packet, answering any negotiation requests on the way.
async fn read_opening(
    stream: TcpStream,
    proxy: &Arc<PgProxy>,
) -> std::result::Result<(ClientStream, Opening), ConnectionError> {
    let result = startup::read_startup(ClientStream::Plain(stream), |stream, request| {
        let proxy = Arc::clone(proxy);
        async move { negotiate(stream, request, &proxy).await }
    })
    .await;
    match result {
        Ok(settled) => Ok(settled),
        Err(err) => {
            proxy.count(OUTCOME_PROTOCOL_ERROR);
            Err(err.into())
        }
    }
}

/// Answer one `SSLRequest` or `GSSENCRequest`.
///
/// Both are answered with a single byte before any message framing exists, and
/// `S` is the one that changes what the stream *is*: everything after it is TLS
/// records, so the wrapped stream is what the caller carries on reading from.
async fn negotiate(
    mut stream: ClientStream,
    request: Opening,
    proxy: &PgProxy,
) -> std::result::Result<ClientStream, StartupError> {
    let accept = matches!(request, Opening::Ssl) && proxy.tls;
    stream
        .write_all(if accept { b"S" } else { b"N" })
        .await
        .map_err(StartupError::from)?;
    stream.flush().await.map_err(StartupError::from)?;
    if !accept {
        return Ok(stream);
    }

    let ClientStream::Plain(plain) = stream else {
        // A second `SSLRequest` inside an established TLS session.
        return Err(StartupError::Malformed("TLS was already negotiated"));
    };
    let ca = proxy
        .ca()
        .map_err(|e| StartupError::Io(format!("cannot serve TLS: {e}")))?;
    let config = crate::proxy::tls::server_config(&ca, TLS_HOSTNAME)
        .map_err(|e| StartupError::Io(format!("cannot serve TLS: {e}")))?;
    let tls = tokio_rustls::TlsAcceptor::from(config)
        .accept(plain)
        .await
        .map_err(|e| StartupError::Io(format!("the client would not complete a handshake: {e}")))?;
    Ok(ClientStream::Tls(Box::new(tls)))
}

/// Everything one authenticated connection is: the checks, then the relay.
async fn serve_session(
    mut stream: ClientStream,
    startup: Startup,
    proxy: &Arc<PgProxy>,
) -> std::result::Result<(), ConnectionError> {
    if let Err(err) =
        wire::write_message(&mut stream, &wire::authentication_cleartext_password()).await
    {
        proxy.count(OUTCOME_PROTOCOL_ERROR);
        return Err(err.into());
    }
    let presented = read_password(&mut stream, proxy).await?;

    let grant = match authorize(&startup, &presented, proxy).await {
        Ok(grant) => grant,
        Err(reason) => return refuse(&mut stream, proxy, reason).await,
    };

    // Before the upstream connect. A connection briefcred is going to refuse
    // must not have opened a real one behind it, and a database that saw the
    // connection would have logged a login the client never got.
    if let Err(refusal) = crate::quota::charge(
        grant.quota.as_deref(),
        &grant.profile,
        crate::quota::SURFACE_POSTGRES,
        proxy.state.metrics(),
    ) {
        return throttle(&mut stream, proxy, &grant, refusal).await;
    }

    let upstream = match forward::connect(
        &grant.config.upstream(),
        &grant.config.user,
        &grant.config.dbname,
        &grant.master,
        &startup.forwarded,
        proxy.allow_md5,
    )
    .await
    {
        Ok(upstream) => upstream,
        Err(err) => {
            proxy.count(OUTCOME_UPSTREAM_ERROR);
            // The upstream's own complaint is about a master this client has
            // never held, so it is logged rather than relayed: the client is
            // told the connection failed and nothing about why.
            let _ = wire::write_message(
                &mut stream,
                &wire::fatal_error(
                    wire::SQLSTATE_CONNECTION_FAILURE,
                    "briefcred: the database could not be reached",
                ),
            )
            .await;
            let _ = stream.shutdown().await;
            return Err(err.into());
        }
    };

    // Only now, with a real connection in hand, is the client told it is in.
    // A client that has gone away between presenting its token and being told
    // it is authenticated leaves an upstream connection that was opened and
    // never used; it is dropped here, and counted as the protocol failure it
    // is rather than as a connection that was served.
    if let Err(err) = greet(&mut stream, &upstream.greeting).await {
        proxy.count(OUTCOME_PROTOCOL_ERROR);
        return Err(err.into());
    }

    let started = OffsetDateTime::now_utc();
    let upstream_address = grant.config.upstream();
    if let Some(key) = upstream.backend_key {
        register_backend(proxy, key, &upstream_address);
    }

    let relayed = forward::relay(
        stream,
        upstream.stream,
        until_stale(proxy, &grant),
        wire::fatal_error(wire::SQLSTATE_ADMIN_SHUTDOWN, TERMINATION),
    )
    .await;

    if let Some(key) = upstream.backend_key {
        forget_backend(proxy, key);
    }
    if let Some(reason) = relayed.terminated {
        eprintln!(
            "briefcred-daemon: postgres proxy closed a live connection for `{}`: {reason}{}",
            grant.credential,
            if relayed.farewell_sent {
                ""
            } else {
                " (mid-message, so the client was not told)"
            }
        );
    }
    // Counted as served either way, and audited either way: the connection was
    // authorised and did real work, and a row that vanished because briefcred
    // ended it would lose exactly the connections an investigator most wants.
    // The reason is on the log rather than in the row, because the row's field
    // list is the one this phase committed to.
    proxy.count(OUTCOME_ALLOW);
    proxy.state.metrics().record_pgproxy_bytes(
        relayed.transferred.client_bytes,
        relayed.transferred.server_bytes,
    );
    proxy.state.audit(&crate::pgproxy::audit::connection_row(
        &grant.mint_id,
        &grant.config.user,
        started,
        relayed.transferred,
    ));
    Ok(())
}

/// Tell the client it is in, then relay the server's own greeting verbatim.
///
/// Verbatim, because synthesising it would mean inventing a `server_version`, a
/// `standard_conforming_strings`, and a cancellation key that cancels nothing.
async fn greet(
    stream: &mut ClientStream,
    greeting: &[wire::Message],
) -> std::result::Result<(), wire::WireError> {
    wire::write_message(stream, &wire::authentication_ok()).await?;
    for message in greeting {
        wire::write_message(stream, message).await?;
    }
    Ok(())
}

/// The password message a client answers the authentication request with.
async fn read_password(
    stream: &mut ClientStream,
    proxy: &PgProxy,
) -> std::result::Result<Zeroizing<String>, ConnectionError> {
    let message = match wire::read_message(stream).await {
        Ok(message) => message,
        Err(err) => {
            proxy.count(OUTCOME_PROTOCOL_ERROR);
            return Err(err.into());
        }
    };
    if message.tag != wire::TAG_PASSWORD {
        proxy.count(OUTCOME_PROTOCOL_ERROR);
        return Err(wire::WireError::Malformed {
            tag: message.tag as char,
            detail: "expected a password",
        }
        .into());
    }
    match wire::password_of(&message.body) {
        Ok(password) => Ok(Zeroizing::new(password)),
        Err(err) => {
            proxy.count(OUTCOME_PROTOCOL_ERROR);
            Err(err.into())
        }
    }
}

/// One authorised connection: the credential it may open, and the master.
struct Grant {
    config: PgProxyConfig,
    master: Zeroizing<String>,
    mint_id: MintId,
    /// The profile the session was opened for, for the quota's metric label.
    profile: String,
    /// The session's token bucket, when its profile sets a `quota`.
    quota: Option<Arc<TokenBucket>>,
    /// The session the token names, so the connection can be watched for it
    /// being closed while the connection is still open.
    sid: String,
    /// The credential the token names, for the same reason: a revoke is on the
    /// `(session, credential)` pair.
    credential: String,
    /// The token's own `exp`, in Unix seconds.
    expires_at: i64,
}

/// Check the token and the connection it asks for against the grant it names.
///
/// The `Err` is the reason for the daemon's log, never for the client: the
/// client gets [`REFUSAL`] whichever of these it hit.
async fn authorize(
    startup: &Startup,
    presented: &str,
    proxy: &PgProxy,
) -> std::result::Result<Grant, String> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = proxy.issuer.authorize(presented, now).map_err(|err| {
        format!(
            "the token presented for `{}` is not good: {err}",
            startup.user
        )
    })?;

    // The startup packet's `user` is the session, and the token names one too.
    // They have to be the same session, or a token from one session could open
    // a connection labelled as another's.
    if claims.sid != startup.user {
        return Err(format!(
            "a token for session `{}` was presented as user `{}`",
            claims.sid, startup.user
        ));
    }

    let session = proxy
        .state
        .sessions()
        .with_session(&claims.sid, |session| {
            (
                session.profile.clone(),
                session.masters.clone(),
                session
                    .mints
                    .values()
                    .find(|mint| mint.credential == claims.cred)
                    .map(|mint| mint.mint_id.clone()),
                session.quota.clone(),
            )
        })
        .await
        .map_err(|err| err.to_string())?;
    let (profile_name, masters, mint_id, quota) = session;

    let profile = proxy
        .state
        .profiles()
        .get(&profile_name)
        .await
        .ok_or_else(|| format!("profile `{profile_name}` is no longer loaded"))?;
    let spec = profile.credential(&claims.cred).ok_or_else(|| {
        format!(
            "profile `{profile_name}` no longer declares `{}`",
            claims.cred
        )
    })?;
    let config = PgProxyConfig::parse(&spec.kind, &spec.config)
        .ok_or_else(|| format!("`{}` is not a Postgres proxy credential", claims.cred))?
        .map_err(|err| err.to_string())?;

    // A token for one database may not open a connection to another. libpq's
    // "an absent database means the user's name" rule is deliberately not
    // applied: a session identifier is not a database name, so an absent
    // `database` fails here rather than resolving to something surprising.
    if startup.database.as_deref() != Some(config.dbname.as_str()) {
        return Err(format!(
            "`{}` serves database `{}`; this client asked for `{}`",
            claims.cred,
            config.dbname,
            startup.database.as_deref().unwrap_or("<none>")
        ));
    }

    let master = masters
        .get(spec.source_key())
        .cloned()
        .ok_or_else(|| format!("the session holds no master for `{}`", spec.source_key()))?;
    // A token whose mint the session no longer remembers is one whose
    // `ExecDone` already went through. The row has to name something, and a
    // fresh identifier would claim a mint that never happened.
    let mint_id = mint_id.ok_or_else(|| {
        format!(
            "session `{}` no longer holds a mint for `{}`",
            claims.sid, claims.cred
        )
    })?;

    Ok(Grant {
        config,
        master,
        mint_id,
        profile: profile_name,
        quota,
        sid: claims.sid,
        credential: claims.cred,
        expires_at: claims.exp,
    })
}

/// Wait until the grant behind a live connection stops being one.
///
/// The check that runs when a connection is opened is not enough on its own. A
/// connection lives for as long as its client keeps it, so without this a
/// subprocess that connected at the start of a run would still hold
/// master-privileged access after `briefcred exec` finished, after the grant was
/// revoked, and past the token's own expiry — and the proxy would be a
/// chokepoint that checks once and then waves everything through.
///
/// # Polling, and why not a subscription
///
/// This asks three questions on a timer rather than waiting on a signal from
/// the session store and the revocation set. Two reasons. A subscription has a
/// window — between reading the current state and registering for changes, a
/// close can happen and be missed — and closing it would mean new locking in
/// two structures the HTTP proxy also uses. And the cost here is a map lookup
/// per second per live connection, which is nothing next to the connection
/// itself. What it buys is a bound stated in seconds rather than an invariant
/// spread across three modules.
///
/// The returned string is the reason, for the log and for the audit trail.
async fn until_stale(proxy: &PgProxy, grant: &Grant) -> &'static str {
    let mut ticker = tokio::time::interval(LIVENESS_INTERVAL);
    // `interval` fires immediately, and the grant was checked a moment ago.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        // The token's own `exp`, not `exp + CLOCK_SKEW_SECS`. The allowance
        // exists so a client whose clock is a minute fast can still present a
        // token; it is not an extension of what the credential is good for, and
        // a connection already open has no clock of its own to forgive.
        if now >= grant.expires_at {
            return "the credential expired";
        }
        if proxy.issuer.is_revoked(&grant.sid, &grant.credential, now) {
            return "the credential was revoked";
        }
        if !proxy.state.sessions().contains(&grant.sid).await {
            return "the session was closed";
        }
    }
}

/// Refuse the connection with a proper `ErrorResponse`, then close it.
async fn refuse(
    stream: &mut ClientStream,
    proxy: &PgProxy,
    reason: String,
) -> std::result::Result<(), ConnectionError> {
    proxy.count(OUTCOME_DENY);
    let _ = wire::write_message(
        stream,
        &wire::fatal_error(wire::SQLSTATE_INVALID_AUTHORIZATION, REFUSAL),
    )
    .await;
    let _ = stream.shutdown().await;
    Err(ConnectionError::Refused(reason))
}

/// Refuse the connection because the session's quota is spent, then close it.
///
/// SQLSTATE `53300`, `too_many_connections`, which is the code PostgreSQL
/// itself uses for "this server will not open another connection for you right
/// now". A driver already knows not to treat it as a credential problem, which
/// is exactly the distinction a client needs: retrying the same password later
/// is the right move, and re-reading the connection string is not.
///
/// Unlike [`refuse`], the client is told which limit it hit. A quota is a
/// number the profile's own author chose rather than a secret, and a client
/// that cannot tell "slow down" from "you are not authorised" will retry the
/// one case where retrying is wrong.
async fn throttle(
    stream: &mut ClientStream,
    proxy: &PgProxy,
    grant: &Grant,
    refusal: crate::quota::Refusal,
) -> std::result::Result<(), ConnectionError> {
    proxy.count(OUTCOME_QUOTA);
    let message = match refusal.retry_after() {
        Some(retry_after) => format!(
            "briefcred: this session is over its quota; try again in {}s",
            retry_after.as_secs()
        ),
        None => "briefcred: this session has spent its quota; open a new one".to_string(),
    };
    let _ = wire::write_message(
        stream,
        &wire::fatal_error(wire::SQLSTATE_TOO_MANY_CONNECTIONS, &message),
    )
    .await;
    let _ = stream.shutdown().await;
    Err(ConnectionError::Refused(format!(
        "profile `{}` is over its quota",
        grant.profile
    )))
}

/// Forward a `CancelRequest` to the server that issued the key, if it is ours.
///
/// A key nobody registered is dropped in silence. It names a backend on some
/// server briefcred has no connection to, and guessing at one would turn a
/// cancellation into an unauthenticated connection to a database.
async fn cancel(pid: i32, key: i32, proxy: &PgProxy) {
    let upstream = proxy
        .backends
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&(pid, key))
        .cloned();
    let Some(upstream) = upstream else {
        return;
    };
    if let Err(err) = forward::forward_cancel(&upstream, pid, key).await {
        eprintln!("briefcred-daemon: postgres proxy could not forward a cancellation: {err}");
    }
}

fn register_backend(proxy: &PgProxy, key: (i32, i32), upstream: &str) {
    proxy
        .backends
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(key, upstream.to_string());
}

fn forget_backend(proxy: &PgProxy, key: (i32, i32)) {
    proxy
        .backends
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&key);
}

/// The client's socket, before and after TLS.
///
/// An enum rather than a boxed trait object because there are exactly two
/// cases and one of them is the overwhelmingly common one: `pgproxy.tls` exists
/// for a client that refuses to speak to a server without it, and the address
/// this proxy listens on is already loopback.
pub enum ClientStream {
    /// A plain loopback socket.
    Plain(TcpStream),
    /// The same socket, with TLS from briefcred's CA on top.
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            ClientStream::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ClientStream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            ClientStream::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            ClientStream::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            ClientStream::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn port_zero_binds_somewhere_on_loopback() {
        let (_listener, addr) = bind(0).unwrap();
        assert!(
            addr.ip().is_loopback(),
            "the postgres proxy must never be reachable off the machine"
        );
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn a_refusal_says_nothing_about_which_check_failed() {
        // Every authentication failure produces this one message. A caller
        // probing the proxy must not learn whether the token was expired, the
        // session was gone, or the database was wrong.
        assert!(!REFUSAL.contains("session"), "{REFUSAL}");
        assert!(!REFUSAL.contains("database"), "{REFUSAL}");
        assert!(!REFUSAL.contains("token"), "{REFUSAL}");
        let error = wire::fatal_error(wire::SQLSTATE_INVALID_AUTHORIZATION, REFUSAL);
        let body = String::from_utf8_lossy(&error.body).to_string();
        assert!(
            body.contains(wire::SQLSTATE_INVALID_AUTHORIZATION),
            "{body}"
        );
    }

    #[test]
    fn a_tls_leaf_is_only_ever_issued_for_the_address_the_proxy_answers_on() {
        assert_eq!(TLS_HOSTNAME, "localhost");
    }

    #[test]
    fn the_proxy_never_prints_a_session_or_a_master() {
        // `PgProxy` reaches masters through the sessions it looks up; its own
        // `Debug` reaches only the issuer and two flags. Asserted here so a
        // future derived `Debug` fails this test.
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<PgProxy>();
    }
}
