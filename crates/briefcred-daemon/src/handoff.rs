//! Handing a running daemon's listeners and sessions to a new binary.
//!
//! `briefcred daemon upgrade` replaces the running daemon without closing a
//! single socket. The CLI starts the new binary with `--takeover <path>` and
//! then sends [`briefcred_proto::Request::Handoff`] to the old one. The old
//! daemon connects to that path and sends, in one message:
//!
//! - the **listening file descriptors** — the IPC socket, the metrics port,
//!   the HTTP proxy port and the Postgres proxy port — over `SCM_RIGHTS`, so
//!   the new daemon inherits the exact same sockets rather than unbinding and
//!   racing to rebind them. The Unix socket travels as a descriptor for the
//!   same reason: nothing unlinks `sock`, so a client connecting during the
//!   swap is never told "no such file".
//! - a **signed session-state blob**, so every open session survives with its
//!   masters, its mints, its quota and its counters intact.
//!
//! # What the blob is allowed to contain
//!
//! A master credential is the most dangerous thing the daemon holds, so the
//! blob is built around two rules that hold together:
//!
//! 1. **Every master is encrypted to the new daemon's ephemeral X25519 key**
//!    before it is serialised. The new daemon generates the key pair when it
//!    binds the handoff socket and sends the public half in its hello, so the
//!    ciphertext is readable by exactly one process — the one that is about to
//!    take over — and by nobody who later reads a core file or a socket trace.
//! 2. **The blob is signed with the token-signer key**, the same Ed25519 key
//!    the proxy signs synthetic tokens with, and the new daemon verifies it
//!    against the same key store. A same-uid process can connect to the
//!    handoff socket, but it cannot produce a blob the new daemon will adopt
//!    without first reading a key out of the login keychain.
//!
//! The blob is never written to a file. It exists in the old daemon's memory,
//! crosses a `0600` socket in a `0700` directory, and is dropped.

use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sendfd::{RecvWithFd, SendWithFd};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::proxy::token::TokenSigner;
use crate::revoke::PendingRevoke;

/// The blob format this daemon writes and is willing to read.
///
/// A new daemon that does not recognise the version refuses the handoff rather
/// than guessing, which leaves the old daemon running: an upgrade that cannot
/// be completed must fail closed, because the alternative is two daemons that
/// each believe they own the sockets.
pub const BLOB_VERSION: u32 = 1;

/// How long the old daemon waits for in-flight work to finish, by default.
pub const DEFAULT_DRAIN_SECS: u64 = 30;

/// How long each side waits for the other to say something.
///
/// Generous, because the new daemon has to read a key store — which on macOS
/// may put a keychain prompt in front of a human — and short enough that a
/// handoff to a binary that is not going to answer does not wedge the old
/// daemon for the rest of the login.
const STEP_TIMEOUT: Duration = Duration::from_secs(60);

/// The largest handoff message either side will read.
///
/// The blob grows with the number of open sessions and the mints on them, and
/// nothing else, so this is far above anything a real daemon produces. It is
/// here so a four-byte length from a confused peer cannot make either side
/// allocate the machine.
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// The domain separator mixed into the ECDH output.
///
/// Hashed together with both public keys so a shared secret derived for this
/// purpose cannot be replayed as a key for any other.
const KDF_CONTEXT: &[u8] = b"briefcred handoff v1 x25519 chacha20poly1305";

/// The command-line flag that puts a daemon into takeover mode.
pub const TAKEOVER_FLAG: &str = "--takeover";

/// Which listener a transferred descriptor belongs to.
///
/// Named rather than positional: a daemon whose `daemon.toml` has the metrics
/// endpoint switched off sends three descriptors, not four, and a receiver
/// that assumed a fixed order would adopt the HTTP proxy's socket as its
/// metrics endpoint and publish credentials on `/metrics`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Slot {
    /// The IPC Unix domain socket at `paths.sock()`.
    Ipc,
    /// The Prometheus endpoint.
    Metrics,
    /// The HTTP proxy.
    Proxy,
    /// The Postgres proxy.
    PgProxy,
}

impl Slot {
    /// The slot's name, for a log line.
    pub fn as_str(&self) -> &'static str {
        match self {
            Slot::Ipc => "ipc",
            Slot::Metrics => "metrics",
            Slot::Proxy => "proxy",
            Slot::PgProxy => "pg_proxy",
        }
    }
}

// ------------------------------------------------------------------ encryption

/// The sending half of the masters' encryption: one ECDH, then one key.
///
/// One shared secret for the whole blob rather than one per master: the
/// recipient is the same process for every one of them, and a key agreement
/// per session would be work that buys nothing. Each master still gets its own
/// nonce, which is what actually matters.
pub struct Sealer {
    cipher: ChaCha20Poly1305,
    public: [u8; 32],
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealer")
            .field("public", &hex::encode(self.public))
            .finish()
    }
}

impl Sealer {
    /// Agree a key with `recipient`, generating a fresh ephemeral pair.
    pub fn to(recipient: &[u8; 32]) -> Sealer {
        let secret = EphemeralSecret::random();
        let public = PublicKey::from(&secret);
        let recipient_key = PublicKey::from(*recipient);
        let shared = secret.diffie_hellman(&recipient_key);
        Sealer {
            cipher: cipher_from(shared.as_bytes(), public.as_bytes(), recipient),
            public: public.to_bytes(),
        }
    }

    /// The public half the recipient needs to derive the same key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Encrypt `plaintext` under a fresh nonce, as base64 of `nonce || ct`.
    pub fn seal(&self, plaintext: &[u8]) -> Result<String> {
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).expect("OS CSPRNG unavailable");
        let ciphertext = self
            .cipher
            .encrypt(&Nonce::from(nonce), plaintext)
            .map_err(|_| Error::Handoff("cannot encrypt a master for the new daemon".into()))?;
        let mut framed = Vec::with_capacity(nonce.len() + ciphertext.len());
        framed.extend_from_slice(&nonce);
        framed.extend_from_slice(&ciphertext);
        Ok(base64(&framed))
    }
}

/// The receiving half: the ephemeral secret, kept until the blob arrives.
pub struct Opener {
    secret: EphemeralSecret,
    public: [u8; 32],
}

impl std::fmt::Debug for Opener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opener")
            .field("public", &hex::encode(self.public))
            .finish()
    }
}

impl Default for Opener {
    fn default() -> Opener {
        Opener::new()
    }
}

impl Opener {
    /// A fresh ephemeral key pair, good for exactly one handoff.
    pub fn new() -> Opener {
        let secret = EphemeralSecret::random();
        let public = PublicKey::from(&secret).to_bytes();
        Opener { secret, public }
    }

    /// The public half to advertise in the hello.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Agree the key the sender used, consuming the ephemeral secret.
    pub fn unsealer(self, sender_public: &[u8; 32]) -> Unsealer {
        let mine = self.public;
        let shared = self.secret.diffie_hellman(&PublicKey::from(*sender_public));
        Unsealer {
            cipher: cipher_from(shared.as_bytes(), sender_public, &mine),
        }
    }
}

/// The agreed key, able to open every master in one blob.
pub struct Unsealer {
    cipher: ChaCha20Poly1305,
}

impl std::fmt::Debug for Unsealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unsealer").finish_non_exhaustive()
    }
}

impl Unsealer {
    /// Decrypt what [`Sealer::seal`] produced.
    pub fn open(&self, sealed: &str) -> Result<Zeroizing<Vec<u8>>> {
        let framed = unbase64(sealed)
            .ok_or_else(|| Error::Handoff("a sealed master is not base64".into()))?;
        if framed.len() < 12 {
            return Err(Error::Handoff("a sealed master is too short".into()));
        }
        let (nonce, ciphertext) = framed.split_at(12);
        let plaintext = self
            .cipher
            .decrypt(&Nonce::try_from(nonce).expect("twelve bytes"), ciphertext)
            .map_err(|_| {
                Error::Handoff(
                    "a sealed master did not decrypt; it was not encrypted to this daemon".into(),
                )
            })?;
        Ok(Zeroizing::new(plaintext))
    }
}

/// Derive the symmetric key from an ECDH output and both public keys.
///
/// Both public keys go into the hash so the key is bound to the pair that
/// agreed it: an attacker who could substitute one of them gets a different
/// key rather than the same one under a different identity.
fn cipher_from(shared: &[u8; 32], sender: &[u8; 32], recipient: &[u8; 32]) -> ChaCha20Poly1305 {
    let mut hasher = Sha256::new();
    hasher.update(KDF_CONTEXT);
    hasher.update(shared);
    hasher.update(sender);
    hasher.update(recipient);
    let key = Zeroizing::new(<[u8; 32]>::from(hasher.finalize()));
    ChaCha20Poly1305::new(&Key::from(*key))
}

// ----------------------------------------------------------------- the messages

/// What the new daemon says as soon as the old one connects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// The blob version the new daemon understands.
    pub version: u32,
    /// The new daemon's process id, so the old one can audit where it went.
    pub pid: u32,
    /// The ephemeral X25519 public key every master is encrypted to, base64.
    pub ephemeral_pubkey: String,
}

/// What the new daemon says once it has adopted everything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Ready {
    /// The listeners and sessions were adopted; the new daemon is serving.
    Ready {
        /// The new daemon's process id.
        pid: u32,
        /// How many sessions it rebuilt.
        sessions: usize,
    },
    /// The handoff was refused, and the old daemon must keep running.
    Refused {
        /// Why, in operator-readable terms. Never credential material.
        message: String,
    },
}

/// The signed envelope the state blob travels in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// The blob's exact JSON bytes, base64. Signed as they are here, so a
    /// re-serialisation on the receiving side cannot change what was verified.
    pub blob: String,
    /// Ed25519 over those bytes with the token-signer key, base64.
    pub signature: String,
}

/// One handoff's worth of state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Blob {
    /// The format version. See [`BLOB_VERSION`].
    pub version: u32,
    /// The sessions to rebuild.
    pub sessions: Vec<SessionBlob>,
    /// The `(session, credential)` grants the proxy has stopped serving.
    pub revocations: Vec<RevocationBlob>,
    /// Which listener each transferred descriptor is, in the order they were
    /// sent.
    pub listeners: Vec<Slot>,
    /// The old daemon's process id.
    pub from_pid: u32,
    /// The ephemeral X25519 public key the masters were sealed with, base64.
    pub sender_pubkey: String,
    /// When the blob was built, in Unix seconds.
    pub issued_at: i64,
}

/// One open session, as it crosses the handoff socket.
///
/// `opened_at` and `last_used` are **milliseconds before [`Blob::issued_at`]**,
/// not instants. The daemon measures both against a monotonic clock that
/// starts when the process does, so an instant from the old daemon means
/// nothing in the new one; an age converts cleanly, and the idle timer picks up
/// exactly where it left off.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionBlob {
    /// The handle the client is already presenting.
    pub id: String,
    /// The profile it was opened for.
    pub profile: String,
    /// How long ago the session was opened, in milliseconds.
    pub opened_at: u64,
    /// How long ago it was last touched, in milliseconds.
    pub last_used: u64,
    /// Credentials minted against it and not yet handed to the revoke queue.
    pub mints: Vec<PendingRevoke>,
    /// The bucket's position, when the profile declares a quota.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_state: Option<QuotaState>,
    /// What the session has done through the HTTP proxy so far.
    pub http_counters: HttpCounterState,
    /// Each master, encrypted to the new daemon's ephemeral key.
    ///
    /// Keyed by `source_key`, exactly as the session holds them. The keys are
    /// in the clear because they are names, not secrets — the same names
    /// `briefcred profile show` prints.
    pub masters_enc: BTreeMap<String, String>,
    /// The client's per-session Ed25519 public key, base64, when it sent one.
    ///
    /// Carried because every synthetic token already issued for this session
    /// carries a thumbprint of it: a new daemon that forgot the key would
    /// reject the `DPoP` proofs on requests the old one was accepting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_pubkey: Option<String>,
}

impl std::fmt::Debug for SessionBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Written by hand for the same reason `Session`'s is. `masters_enc`
        // holds ciphertext rather than masters, but a derived `Debug` would put
        // the sealed form of the machine's most valuable secrets into the first
        // error anybody formatted, and the names are the useful part anyway.
        f.debug_struct("SessionBlob")
            .field("id", &self.id)
            .field("profile", &self.profile)
            .field("opened_at", &self.opened_at)
            .field("last_used", &self.last_used)
            .field("mints", &self.mints.len())
            .field("quota_state", &self.quota_state)
            .field("http_counters", &self.http_counters)
            .field("masters", &self.masters_enc.keys().collect::<Vec<_>>())
            .field("bound_to_a_session_key", &self.session_pubkey.is_some())
            .finish()
    }
}

/// A token bucket's position, so a quota does not reset on upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct QuotaState {
    /// Tokens available at [`Blob::issued_at`].
    pub tokens: f64,
    /// Charges granted since the session opened, for the `total` cap.
    pub spent: u64,
}

/// The per-session HTTP proxy counters the Cedar `context` reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCounterState {
    /// Requests the session has made.
    pub requests: u64,
    /// Response bytes it has been given.
    pub resp_bytes: u64,
}

/// One `(session, credential)` the proxy will no longer serve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationBlob {
    /// The session the grant belonged to.
    pub session_id: String,
    /// The credential within that session's profile.
    pub credential: String,
    /// The Unix second after which the entry can be forgotten.
    pub expires_at: i64,
}

impl Blob {
    /// Serialise, then sign the exact bytes that were serialised.
    pub fn seal(&self, signer: &TokenSigner) -> Result<Envelope> {
        let bytes = serde_json::to_vec(self)
            .map_err(|err| Error::Handoff(format!("cannot serialise the handoff blob: {err}")))?;
        Ok(Envelope {
            signature: base64(&signer.sign_detached(&bytes)),
            blob: base64(&bytes),
        })
    }

    /// Check the signature, then parse — in that order.
    ///
    /// A blob whose signature does not verify never reaches the JSON parser,
    /// so a peer that can connect to the socket but cannot read the key store
    /// cannot even choose the shape of what gets deserialised.
    pub fn open(envelope: &Envelope, signer: &TokenSigner) -> Result<Blob> {
        let bytes = unbase64(&envelope.blob)
            .ok_or_else(|| Error::Handoff("the handoff blob is not base64".into()))?;
        let signature: [u8; 64] = unbase64(&envelope.signature)
            .ok_or_else(|| Error::Handoff("the handoff signature is not base64".into()))?
            .try_into()
            .map_err(|_| Error::Handoff("the handoff signature is not 64 bytes".into()))?;
        if !signer.verify_detached(&bytes, &signature) {
            return Err(Error::Handoff(
                "the handoff blob is not signed by this machine's token-signer key".into(),
            ));
        }
        let blob: Blob = serde_json::from_slice(&bytes)
            .map_err(|err| Error::Handoff(format!("the handoff blob is malformed: {err}")))?;
        if blob.version != BLOB_VERSION {
            return Err(Error::Handoff(format!(
                "the handoff blob is version {}, and this daemon speaks version {BLOB_VERSION}",
                blob.version
            )));
        }
        Ok(blob)
    }

    /// The ephemeral public key the masters were sealed with.
    pub fn sender_public_key(&self) -> Result<[u8; 32]> {
        unbase64(&self.sender_pubkey)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| Error::Handoff("the sender's ephemeral key is not 32 bytes".into()))
    }
}

// -------------------------------------------------------------------- the wire

/// Write one length-prefixed JSON message.
async fn write_message<T: Serialize>(stream: &mut UnixStream, message: &T) -> Result<()> {
    let bytes = serde_json::to_vec(message)
        .map_err(|err| Error::Handoff(format!("cannot serialise a handoff message: {err}")))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| Error::Handoff("a handoff message is too large to frame".into()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(handoff_io("write a handoff message"))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(handoff_io("write a handoff message"))?;
    stream
        .flush()
        .await
        .map_err(handoff_io("flush a handoff message"))
}

/// Read one length-prefixed JSON message, bounded by [`MAX_MESSAGE_BYTES`].
async fn read_message<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(handoff_io("read a handoff message"))?;
    let body = read_body(stream, u32::from_be_bytes(header)).await?;
    serde_json::from_slice(&body)
        .map_err(|err| Error::Handoff(format!("a handoff message is malformed: {err}")))
}

/// Read `len` bytes, refusing a length no honest peer sends.
async fn read_body(stream: &mut UnixStream, len: u32) -> Result<Vec<u8>> {
    let len = len as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(Error::Handoff(format!(
            "a handoff message claims {len} bytes, and the ceiling is {MAX_MESSAGE_BYTES}"
        )));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(handoff_io("read a handoff message"))?;
    Ok(body)
}

/// Send the envelope with the listening descriptors attached to its length.
///
/// The descriptors ride on the four header bytes rather than on the body: a
/// `SOCK_STREAM` delivers ancillary data with whatever bytes it was sent
/// alongside, and a four-byte write is one the kernel will never split, so the
/// receiver knows exactly which read carries them.
pub async fn send_state(stream: &mut UnixStream, envelope: &Envelope, fds: &[RawFd]) -> Result<()> {
    let bytes = serde_json::to_vec(envelope)
        .map_err(|err| Error::Handoff(format!("cannot serialise the handoff envelope: {err}")))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| Error::Handoff("the handoff envelope is too large to frame".into()))?;
    let header = len.to_be_bytes();

    let mut written = 0;
    while written < header.len() {
        stream
            .writable()
            .await
            .map_err(handoff_io("wait to send the handoff descriptors"))?;
        match stream.send_with_fd(&header[written..], if written == 0 { fds } else { &[] }) {
            Ok(sent) => written += sent,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(handoff_io("send the handoff descriptors")(err)),
        }
    }
    stream
        .write_all(&bytes)
        .await
        .map_err(handoff_io("write the handoff envelope"))?;
    stream
        .flush()
        .await
        .map_err(handoff_io("flush the handoff envelope"))
}

/// Receive the descriptors and the envelope the peer sent together.
pub async fn recv_state(stream: &mut UnixStream) -> Result<(Vec<OwnedFd>, Envelope)> {
    let mut header = [0u8; 4];
    let mut raw = [-1 as RawFd; 8];
    let (read, fd_count) = loop {
        stream
            .readable()
            .await
            .map_err(handoff_io("wait for the handoff descriptors"))?;
        match stream.recv_with_fd(&mut header, &mut raw) {
            Ok((0, _)) => {
                return Err(Error::Handoff(
                    "the peer closed the handoff socket before sending anything".into(),
                ))
            }
            Ok(counts) => break counts,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(handoff_io("receive the handoff descriptors")(err)),
        }
    };

    // Taken before anything can fail, so a short header or a malformed
    // envelope still closes the descriptors rather than leaking them.
    #[allow(unsafe_code)]
    let fds: Vec<OwnedFd> = raw[..fd_count]
        .iter()
        // SAFETY: each descriptor was just created by `recvmsg` for this
        // process and is owned by nothing else, which is exactly the contract
        // `from_raw_fd` asks for.
        .map(|fd| unsafe { OwnedFd::from_raw_fd(*fd) })
        .collect();

    if read != header.len() {
        return Err(Error::Handoff(format!(
            "the handoff header arrived in {read} bytes, not {}",
            header.len()
        )));
    }
    let body = read_body(stream, u32::from_be_bytes(header)).await?;
    let envelope = serde_json::from_slice(&body)
        .map_err(|err| Error::Handoff(format!("the handoff envelope is malformed: {err}")))?;
    Ok((fds, envelope))
}

// --------------------------------------------------------- the new daemon's side

/// The handoff socket, bound and waiting for the daemon being replaced.
#[derive(Debug)]
pub struct Takeover {
    listener: UnixListener,
    path: PathBuf,
    opener: Opener,
}

impl Takeover {
    /// Bind `path` privately, ready for one connection.
    ///
    /// The socket is created here rather than by the CLI so the new daemon —
    /// the only process that should ever hold the ephemeral secret — is the
    /// one that owns it, and so an upgrade that never gets as far as starting
    /// leaves no socket behind for a later one to trip over.
    pub fn bind(path: &Path) -> Result<Takeover> {
        if let Some(parent) = path.parent() {
            briefcred_core::paths::ensure_private_dir(parent)?;
        }
        // A path left by an upgrade that died before it could accept. Nothing
        // outlives one handoff, so removing it is never removing a live socket.
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(Error::io("remove the stale handoff socket", path, err)),
        }
        let listener =
            UnixListener::bind(path).map_err(|e| Error::io("bind the handoff socket", path, e))?;
        std::fs::set_permissions(
            path,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .map_err(|e| Error::io("set the mode of the handoff socket", path, e))?;
        Ok(Takeover {
            listener,
            path: path.to_path_buf(),
            opener: Opener::new(),
        })
    }

    /// Accept the old daemon, greet it, and read what it sends.
    ///
    /// Returns the descriptors, the verified blob and the connection, which the
    /// caller keeps so it can answer [`Ready`] once — and only once — it has
    /// actually adopted everything.
    pub async fn accept(self, signer: &TokenSigner) -> Result<Accepted> {
        let (mut stream, _) = tokio::time::timeout(STEP_TIMEOUT, self.listener.accept())
            .await
            .map_err(|_| {
                Error::Handoff(format!(
                    "no daemon connected to {} within {} s",
                    self.path.display(),
                    STEP_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|e| Error::io("accept on the handoff socket", &self.path, e))?;

        // The same uid check the IPC socket makes, for the same reason: the
        // mode bits are the boundary, and this is the assertion that they held.
        let expected = own_uid();
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == expected => {}
            Ok(cred) => {
                return Err(Error::Handoff(format!(
                    "the handoff socket was connected by uid {}, not {expected}",
                    cred.uid()
                )))
            }
            Err(err) => {
                return Err(Error::Handoff(format!(
                    "cannot read the handoff peer's credentials: {err}"
                )))
            }
        }

        write_message(
            &mut stream,
            &Hello {
                version: BLOB_VERSION,
                pid: std::process::id(),
                ephemeral_pubkey: base64(&self.opener.public_key()),
            },
        )
        .await?;

        let (fds, envelope) = tokio::time::timeout(STEP_TIMEOUT, recv_state(&mut stream))
            .await
            .map_err(|_| {
                Error::Handoff(format!(
                    "the daemon being replaced sent nothing within {} s",
                    STEP_TIMEOUT.as_secs()
                ))
            })??;

        let blob = Blob::open(&envelope, signer)?;
        if fds.len() != blob.listeners.len() {
            return Err(Error::Handoff(format!(
                "the handoff carried {} descriptor(s) for {} listener(s)",
                fds.len(),
                blob.listeners.len()
            )));
        }
        let unsealer = self.opener.unsealer(&blob.sender_public_key()?);
        let listeners = blob.listeners.iter().copied().zip(fds).collect();

        // Nothing else needs the socket file: both ends hold the connection,
        // and leaving it would let a later upgrade connect to a dead listener.
        let _ = std::fs::remove_file(&self.path);
        Ok(Accepted {
            stream,
            listeners,
            blob,
            unsealer,
        })
    }
}

/// A verified handoff, waiting to be adopted and acknowledged.
#[derive(Debug)]
pub struct Accepted {
    stream: UnixStream,
    /// The transferred listeners, by slot.
    pub listeners: BTreeMap<Slot, OwnedFd>,
    /// The verified state.
    pub blob: Blob,
    /// The key that opens the masters in it.
    pub unsealer: Unsealer,
}

impl Accepted {
    /// Tell the old daemon it may drain and exit.
    pub async fn accepted(mut self, sessions: usize) -> Result<()> {
        write_message(
            &mut self.stream,
            &Ready::Ready {
                pid: std::process::id(),
                sessions,
            },
        )
        .await
    }

    /// Tell the old daemon to keep running, because this one cannot take over.
    ///
    /// Sent on a best-effort basis: the new daemon is about to fail to start,
    /// and the one thing that must not happen is the old one exiting anyway.
    pub async fn refused(&mut self, message: impl Into<String>) {
        let _ = write_message(
            &mut self.stream,
            &Ready::Refused {
                message: message.into(),
            },
        )
        .await;
    }
}

// --------------------------------------------------------- the old daemon's side

/// Everything the old daemon hands over.
pub struct Outgoing {
    /// The sessions, with their masters already sealed.
    pub sessions: Vec<SessionBlob>,
    /// The proxy's revocation set.
    pub revocations: Vec<RevocationBlob>,
    /// The listening descriptors, by slot.
    pub listeners: Vec<(Slot, RawFd)>,
}

impl std::fmt::Debug for Outgoing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outgoing")
            .field("sessions", &self.sessions.len())
            .field("revocations", &self.revocations.len())
            .field(
                "listeners",
                &self
                    .listeners
                    .iter()
                    .map(|(slot, _)| slot.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Connect to a waiting `--takeover` daemon and hand everything over.
///
/// `build` is called *after* the hello arrives, because it needs the recipient's
/// ephemeral key to seal the masters — and because a handoff that never gets a
/// hello must not have copied a master anywhere at all.
pub async fn hand_over<F>(socket: &Path, signer: &TokenSigner, build: F) -> Result<u32>
where
    F: AsyncFnOnce(&Sealer) -> Result<Outgoing>,
{
    let mut stream = tokio::time::timeout(STEP_TIMEOUT, UnixStream::connect(socket))
        .await
        .map_err(|_| {
            Error::Handoff(format!(
                "connecting to {} took longer than {} s",
                socket.display(),
                STEP_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| Error::io("connect to the handoff socket", socket, e))?;

    let hello: Hello = tokio::time::timeout(STEP_TIMEOUT, read_message(&mut stream))
        .await
        .map_err(|_| {
            Error::Handoff(format!(
                "the new daemon did not greet us within {} s",
                STEP_TIMEOUT.as_secs()
            ))
        })??;
    if hello.version != BLOB_VERSION {
        return Err(Error::Handoff(format!(
            "the new daemon speaks handoff version {}, and this one speaks {BLOB_VERSION}",
            hello.version
        )));
    }
    let recipient: [u8; 32] = unbase64(&hello.ephemeral_pubkey)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| Error::Handoff("the new daemon's ephemeral key is not 32 bytes".into()))?;

    let sealer = Sealer::to(&recipient);
    let outgoing = build(&sealer).await?;
    let (slots, fds): (Vec<Slot>, Vec<RawFd>) = outgoing.listeners.iter().copied().unzip();
    let blob = Blob {
        version: BLOB_VERSION,
        sessions: outgoing.sessions,
        revocations: outgoing.revocations,
        listeners: slots,
        from_pid: std::process::id(),
        sender_pubkey: base64(&sealer.public_key()),
        issued_at: time::OffsetDateTime::now_utc().unix_timestamp(),
    };
    send_state(&mut stream, &blob.seal(signer)?, &fds).await?;

    match tokio::time::timeout(STEP_TIMEOUT, read_message(&mut stream)).await {
        Ok(Ok(Ready::Ready { pid, .. })) => Ok(pid),
        Ok(Ok(Ready::Refused { message })) => Err(Error::Handoff(format!(
            "the new daemon refused the handoff: {message}"
        ))),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(Error::Handoff(format!(
            "the new daemon did not confirm the handoff within {} s",
            STEP_TIMEOUT.as_secs()
        ))),
    }
}

// ------------------------------------------------------- systemd socket activation

/// The first descriptor systemd passes to an activated service.
pub const LISTEN_FDS_START: RawFd = 3;

/// The order the `.socket` unit lists its `ListenStream=` directives in.
///
/// systemd hands the descriptors over in the order the unit declares them and
/// says only how many there are, so the unit `briefcred install` writes and
/// this list have to agree. They are kept next to each other for that reason:
/// change one and the other is a line away.
pub const ACTIVATION_ORDER: [Slot; 4] = [Slot::Ipc, Slot::Metrics, Slot::Proxy, Slot::PgProxy];

/// Which descriptors a socket-activated start was handed.
///
/// Pure, and takes the two variables rather than reading them, so the rules —
/// `LISTEN_PID` has to name *this* process, and a count beyond the slots we
/// know about is refused rather than silently truncated — are testable on a
/// machine with no systemd on it.
pub fn activated_slots(
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
    pid: u32,
) -> Vec<(Slot, RawFd)> {
    let Some(count) = listen_fds.and_then(|value| value.trim().parse::<usize>().ok()) else {
        return Vec::new();
    };
    // `LISTEN_PID` guards against an inherited environment: a daemon that
    // adopted descriptors meant for its parent would bind nothing and answer
    // on somebody else's sockets.
    if listen_pid.and_then(|value| value.trim().parse::<u32>().ok()) != Some(pid) {
        return Vec::new();
    }
    if count == 0 || count > ACTIVATION_ORDER.len() {
        return Vec::new();
    }
    ACTIVATION_ORDER
        .iter()
        .take(count)
        .enumerate()
        .map(|(index, slot)| (*slot, LISTEN_FDS_START + index as RawFd))
        .collect()
}

/// The descriptors systemd passed this process, if any.
///
/// Empty everywhere but Linux: launchd's equivalent hands sockets over a
/// different mechanism entirely, and briefcred's macOS agent binds its own.
pub fn socket_activation() -> BTreeMap<Slot, OwnedFd> {
    if !cfg!(target_os = "linux") {
        return BTreeMap::new();
    }
    let listen_pid = std::env::var("LISTEN_PID").ok();
    let listen_fds = std::env::var("LISTEN_FDS").ok();
    let slots = activated_slots(
        listen_pid.as_deref(),
        listen_fds.as_deref(),
        std::process::id(),
    );
    // The variables are removed once read, so a helper this daemon spawns does
    // not inherit them and try to adopt the same sockets.
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");

    #[allow(unsafe_code)]
    slots
        .into_iter()
        // SAFETY: systemd passes these descriptors to this process and to
        // nothing else, and they are read exactly once because the variables
        // that name them are removed above.
        .map(|(slot, fd)| (slot, unsafe { OwnedFd::from_raw_fd(fd) }))
        .collect()
}

/// How far back the oldest session in `blob` was opened.
///
/// The new daemon's monotonic clock is backdated by this, so every age the blob
/// carries lands at a non-negative instant and the idle timers resume where the
/// old daemon left them. See [`crate::clock::SystemClock::started_ago`].
pub fn oldest_age(blob: &Blob) -> Duration {
    let oldest = blob
        .sessions
        .iter()
        .map(|session| session.opened_at.max(session.last_used))
        .max()
        .unwrap_or(0);
    Duration::from_millis(oldest)
}

/// Turn a verified blob back into live sessions.
///
/// A session whose profile the new daemon cannot find is dropped rather than
/// adopted: its masters would then be resident with nothing able to say what
/// they are for, and the client is told its session is gone the next time it
/// asks — which is the same answer an eviction gives, and one every client
/// already handles.
pub async fn rebuild_sessions(
    blob: &Blob,
    unsealer: &Unsealer,
    clock: &std::sync::Arc<dyn crate::clock::Clock>,
    profiles: &crate::profiles::ProfileStore,
    helper_dirs: &[PathBuf],
) -> Result<Vec<crate::session::Session>> {
    let now = clock.now();
    let mut out = Vec::with_capacity(blob.sessions.len());
    for carried in &blob.sessions {
        let Some(profile) = profiles.get(&carried.profile).await else {
            eprintln!(
                "briefcred-daemon: dropping handed-over session for `{}`: no such profile here",
                carried.profile
            );
            continue;
        };

        let mut masters = BTreeMap::new();
        for (key, sealed) in &carried.masters_enc {
            let plaintext = unsealer.open(sealed)?;
            let master = Zeroizing::new(String::from_utf8(plaintext.to_vec()).map_err(|_| {
                Error::Handoff(format!("the master for `{key}` is not valid UTF-8"))
            })?);
            masters.insert(key.clone(), master);
        }

        let pubkey = match &carried.session_pubkey {
            None => None,
            Some(encoded) => Some(
                unbase64(encoded)
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .ok_or_else(|| {
                        Error::Handoff("a session's public key is not 32 bytes".into())
                    })?,
            ),
        };

        out.push(crate::session::Session {
            id: carried.id.clone(),
            profile: carried.profile.clone(),
            opened_at: now.saturating_sub(Duration::from_millis(carried.opened_at)),
            last_used: now.saturating_sub(Duration::from_millis(carried.last_used)),
            masters,
            mints: carried
                .mints
                .iter()
                .map(|mint| (mint.mint_id.clone(), mint.clone()))
                .collect(),
            pubkey,
            helpers: std::sync::Arc::new(crate::helper::MinterSet::new(helper_dirs.to_vec())),
            // The bucket comes from the profile as this daemon has it, filled
            // to what the old daemon had left: an upgrade is not a reason to
            // widen a quota, and a profile edited since is not a reason to
            // ignore the edit.
            quota: match (&profile.quota, carried.quota_state) {
                (Some(quota), Some(state)) => {
                    Some(std::sync::Arc::new(crate::quota::TokenBucket::resume(
                        quota,
                        std::sync::Arc::clone(clock),
                        state.tokens,
                        state.spent,
                    )))
                }
                (Some(quota), None) => Some(std::sync::Arc::new(crate::quota::TokenBucket::new(
                    quota,
                    std::sync::Arc::clone(clock),
                ))),
                (None, _) => None,
            },
            http: std::sync::Arc::new(crate::session::HttpCounters::resumed(
                carried.http_counters.requests,
                carried.http_counters.resp_bytes,
            )),
        });
    }
    Ok(out)
}

/// The uid this process runs as, and the only one a handoff is accepted from.
#[allow(unsafe_code)]
fn own_uid() -> u32 {
    // SAFETY: `getuid` takes no arguments, touches no memory, and is
    // documented as always succeeding.
    unsafe { libc::getuid() }
}

/// Turn a raw descriptor back into a listening socket.
///
/// The one place `from_raw_fd` is used for an adopted listener, so the safety
/// argument is written once: the descriptor came out of [`recv_state`], which
/// produced it from `recvmsg` and handed over ownership.
pub fn adopt_fd(fd: OwnedFd) -> std::os::unix::net::UnixListener {
    std::os::unix::net::UnixListener::from(fd)
}

fn handoff_io(action: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |err| Error::Handoff(format!("cannot {action}: {err}"))
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unbase64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

/// Every listening descriptor a daemon holds, for [`Outgoing::listeners`].
pub fn listener_fds(
    ipc: &UnixListener,
    metrics: Option<&tokio::net::TcpListener>,
    proxy: Option<&tokio::net::TcpListener>,
    pg_proxy: Option<&tokio::net::TcpListener>,
) -> Vec<(Slot, RawFd)> {
    let mut fds = vec![(Slot::Ipc, ipc.as_raw_fd())];
    for (slot, listener) in [
        (Slot::Metrics, metrics),
        (Slot::Proxy, proxy),
        (Slot::PgProxy, pg_proxy),
    ] {
        if let Some(listener) = listener {
            fds.push((slot, listener.as_raw_fd()));
        }
    }
    fds
}

#[cfg(test)]
mod tests {
    use super::*;
    use briefcred_core::keystore::FileKeyStore;

    fn signer() -> TokenSigner {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileKeyStore::new(dir.path());
        let signer = TokenSigner::load_or_create(&store).expect("a signer");
        // The directory is dropped here; the signer holds the key in memory,
        // which is all these tests need.
        signer
    }

    fn blob() -> Blob {
        Blob {
            version: BLOB_VERSION,
            sessions: vec![SessionBlob {
                id: "abc123".to_string(),
                profile: "dev".to_string(),
                opened_at: 5_000,
                last_used: 100,
                mints: Vec::new(),
                quota_state: Some(QuotaState {
                    tokens: 2.5,
                    spent: 7,
                }),
                http_counters: HttpCounterState {
                    requests: 3,
                    resp_bytes: 4096,
                },
                masters_enc: BTreeMap::from([("db".to_string(), "c2VhbGVk".to_string())]),
                session_pubkey: None,
            }],
            revocations: vec![RevocationBlob {
                session_id: "abc123".to_string(),
                credential: "openai".to_string(),
                expires_at: 1_700_000_000,
            }],
            listeners: vec![Slot::Ipc, Slot::Proxy],
            from_pid: 4242,
            sender_pubkey: base64(&[7u8; 32]),
            issued_at: 1_699_999_999,
        }
    }

    #[test]
    fn a_blob_never_debug_prints_a_sealed_master() {
        let opener = Opener::new();
        let sealer = Sealer::to(&opener.public_key());
        let mut blob = blob();
        blob.sessions[0].masters_enc =
            BTreeMap::from([("db".to_string(), sealer.seal(b"master-secret").unwrap())]);

        let rendered = format!("{blob:?}");
        assert!(
            !rendered.contains(&blob.sessions[0].masters_enc["db"]),
            "{rendered}"
        );
        assert!(rendered.contains("\"db\""), "{rendered}");
    }

    #[test]
    fn a_blob_round_trips_through_its_signature() {
        let signer = signer();
        let envelope = blob().seal(&signer).unwrap();
        assert_eq!(Blob::open(&envelope, &signer).unwrap(), blob());
    }

    #[test]
    fn a_tampered_blob_is_refused() {
        let signer = signer();
        let envelope = blob().seal(&signer).unwrap();

        let mut edited = blob();
        edited.from_pid = 1;
        let forged = Envelope {
            blob: base64(&serde_json::to_vec(&edited).unwrap()),
            signature: envelope.signature.clone(),
        };
        let err = Blob::open(&forged, &signer).unwrap_err();
        assert!(err.to_string().contains("token-signer"), "{err}");
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let signer = signer();
        let mut envelope = blob().seal(&signer).unwrap();
        let mut bytes = unbase64(&envelope.signature).unwrap();
        bytes[0] ^= 0x01;
        envelope.signature = base64(&bytes);
        assert!(Blob::open(&envelope, &signer).is_err());
    }

    #[test]
    fn a_blob_signed_by_another_machine_is_refused() {
        let envelope = blob().seal(&signer()).unwrap();
        let err = Blob::open(&envelope, &signer()).unwrap_err();
        assert!(err.to_string().contains("token-signer"), "{err}");
    }

    #[test]
    fn a_blob_of_an_unknown_version_is_refused_rather_than_guessed() {
        let signer = signer();
        let mut future = blob();
        future.version = BLOB_VERSION + 1;
        let envelope = future.seal(&signer).unwrap();
        let err = Blob::open(&envelope, &signer).unwrap_err();
        assert!(err.to_string().contains("version"), "{err}");
    }

    #[test]
    fn a_master_sealed_to_a_daemon_opens_only_for_that_daemon() {
        let opener = Opener::new();
        let sealer = Sealer::to(&opener.public_key());
        let sealed = sealer.seal(b"master-secret").unwrap();
        assert!(
            !sealed.contains("master-secret"),
            "the ciphertext must not be the plaintext: {sealed}"
        );

        let unsealer = opener.unsealer(&sealer.public_key());
        assert_eq!(&unsealer.open(&sealed).unwrap()[..], b"master-secret");
    }

    #[test]
    fn a_master_sealed_to_one_daemon_does_not_open_for_another() {
        let intended = Opener::new();
        let sealer = Sealer::to(&intended.public_key());
        let sealed = sealer.seal(b"master-secret").unwrap();

        let eavesdropper = Opener::new();
        let err = eavesdropper
            .unsealer(&sealer.public_key())
            .open(&sealed)
            .unwrap_err();
        assert!(err.to_string().contains("did not decrypt"), "{err}");
    }

    #[test]
    fn a_tampered_ciphertext_does_not_open() {
        let opener = Opener::new();
        let sealer = Sealer::to(&opener.public_key());
        let sealed = sealer.seal(b"master-secret").unwrap();
        let mut bytes = unbase64(&sealed).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;

        let err = opener
            .unsealer(&sealer.public_key())
            .open(&base64(&bytes))
            .unwrap_err();
        assert!(err.to_string().contains("did not decrypt"), "{err}");
    }

    #[test]
    fn sealing_the_same_master_twice_produces_two_different_ciphertexts() {
        // Nonce reuse under one key is the way to lose a stream cipher, so the
        // nonce has to be fresh per seal rather than per handoff.
        let opener = Opener::new();
        let sealer = Sealer::to(&opener.public_key());
        assert_ne!(
            sealer.seal(b"master-secret").unwrap(),
            sealer.seal(b"master-secret").unwrap()
        );
    }

    #[tokio::test]
    async fn descriptors_and_an_envelope_cross_a_socket_pair_together() {
        let (mut sender, mut receiver) = UnixStream::pair().expect("a socket pair");

        // Two real listeners, so what arrives can be proved to be the same
        // sockets rather than merely two numbers.
        let first = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let second = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addrs = [first.local_addr().unwrap(), second.local_addr().unwrap()];

        let signer = signer();
        let envelope = blob().seal(&signer).unwrap();
        let fds = [first.as_raw_fd(), second.as_raw_fd()];

        let sent = tokio::spawn({
            let envelope = envelope.clone();
            let fds = fds.to_vec();
            async move { send_state(&mut sender, &envelope, &fds).await }
        });
        let (received_fds, received) = recv_state(&mut receiver).await.unwrap();
        sent.await.unwrap().unwrap();

        assert_eq!(received, envelope);
        assert_eq!(received_fds.len(), 2);
        for (fd, addr) in received_fds.into_iter().zip(addrs) {
            let adopted = std::net::TcpListener::from(fd);
            assert_eq!(adopted.local_addr().unwrap(), addr);
            // The original still works too: `SCM_RIGHTS` duplicates rather
            // than moves, which is what lets both daemons accept during the
            // instant between the handoff and the old one standing down.
            assert!(adopted.local_addr().is_ok());
        }
        drop((first, second));
    }

    #[tokio::test]
    async fn a_message_claiming_more_than_the_ceiling_is_refused() {
        let (mut sender, mut receiver) = UnixStream::pair().expect("a socket pair");
        sender
            .write_all(&u32::MAX.to_be_bytes())
            .await
            .expect("write");
        let err = read_message::<Envelope>(&mut receiver).await.unwrap_err();
        assert!(err.to_string().contains("ceiling"), "{err}");
    }

    #[test]
    fn the_activation_variables_are_honoured_only_when_they_name_this_process() {
        assert_eq!(
            activated_slots(Some("42"), Some("4"), 42),
            vec![
                (Slot::Ipc, 3),
                (Slot::Metrics, 4),
                (Slot::Proxy, 5),
                (Slot::PgProxy, 6)
            ]
        );
        assert_eq!(
            activated_slots(Some("42"), Some("1"), 42),
            vec![(Slot::Ipc, 3)]
        );

        // An inherited environment names the parent, and adopting the parent's
        // descriptors would make this daemon answer on somebody else's sockets.
        assert!(activated_slots(Some("41"), Some("4"), 42).is_empty());
        assert!(activated_slots(None, Some("4"), 42).is_empty());
        assert!(activated_slots(Some("42"), None, 42).is_empty());
        assert!(activated_slots(Some("42"), Some("0"), 42).is_empty());
        // More descriptors than there are listeners: refused rather than
        // truncated, because the extra one would be a socket nobody serves.
        assert!(activated_slots(Some("42"), Some("5"), 42).is_empty());
        assert!(activated_slots(Some("42"), Some("two"), 42).is_empty());
    }
}
