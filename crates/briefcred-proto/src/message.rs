//! The request and response vocabulary.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::secret::SecretString;

/// A message from a client to the daemon.
///
/// The enum is tagged, so adding a variant in a later phase does not change
/// how existing messages deserialise. [`Request::name`] is the key the daemon's
/// dispatch table is built on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    /// Liveness check. Answered with [`Response::Pong`].
    Ping,
    /// Ask what the daemon is and how long it has been up.
    Status,
    /// Ask the daemon to shut down gracefully.
    Shutdown,
    /// List the profiles the daemon currently has loaded.
    ListProfiles,
    /// Ask for one profile as the daemon parsed it.
    ShowProfile {
        /// The profile's `name`.
        name: String,
    },
    /// Prove presence and open a session for a profile.
    ///
    /// Opening a session runs the profile's unlock gate and fetches the master
    /// credential for every credential it declares. It mints nothing yet:
    /// minting is Phase 3b, and it happens against an already-open session.
    OpenSession {
        /// The profile to open a session for.
        profile: String,
        /// Whether the *client* has no graphical session to be prompted in.
        ///
        /// The daemon cannot see this. It is started by launchd and sits in
        /// launchd's session; the client may be an SSH login on a machine
        /// whose console user is sitting in front of a screen. Only the client
        /// knows which it is, so it says, and the daemon refuses if either
        /// this or its own check reports headless.
        ///
        /// Deliberately has no serde default. A client that has not thought
        /// about the question must fail to serialise rather than quietly
        /// declare "I have a screen", which is the weaker of the two answers.
        /// It is a declaration and not a proof: a same-uid caller can lie, and
        /// briefcred cannot stop one that is already inside every boundary it
        /// has. What it buys is an honest client getting an accurate refusal.
        client_headless: bool,
    },
    /// Close a session, zeroising its master credentials at once.
    CloseSession {
        /// The identifier from [`Response::SessionOpened`].
        session_id: String,
    },
    /// Run the unlock gate for a profile without opening a session.
    ///
    /// Used by `briefcred profile bootstrap` before it writes a master: the
    /// master itself never crosses this socket, so the CLI writes it straight
    /// to the platform key store, and this is how it still proves presence
    /// first. Nothing is fetched and nothing is retained.
    Unlock {
        /// The profile whose policy and cache window apply.
        profile: String,
        /// Whether the *client* has no graphical session. See
        /// [`Request::OpenSession`].
        client_headless: bool,
    },
    /// Mint the credentials an already-open session's profile declares, and
    /// compose the environment the subprocess will run with.
    ///
    /// The allowlists are enforced here, before anything is minted: a command
    /// the profile does not permit must not cause a role to be created at all.
    Exec {
        /// The handle from [`Response::SessionOpened`].
        session_id: String,
        /// Which declared credentials to mint. `None` means all of them.
        credentials: Option<Vec<String>>,
        /// The program the client is about to run.
        argv0: String,
        /// Its arguments, in order.
        args: Vec<String>,
        /// The pid of the client process that will spawn and own the child.
        ///
        /// The daemon cannot obtain this itself: `SO_PEERCRED` is not portable
        /// and macOS's `LOCAL_PEERCRED` reports only uid and gid. It is also
        /// the pid an operator can act on — the child does not exist yet when
        /// this request is answered, and killing the wrapper takes the child
        /// with it.
        pid: u32,
    },
    /// Report that the subprocess has exited, so its mints can be revoked.
    ///
    /// Sent after the child is reaped. The daemon enqueues the revokes and
    /// writes the `ExecEnd` audit row; the client does not wait for either.
    ExecDone {
        /// The session the mints belong to.
        session_id: String,
        /// The principals to revoke.
        mint_ids: Vec<String>,
        /// The child's exit status, absent when a signal killed it.
        exit_code: Option<i32>,
        /// How long the child ran.
        duration_ms: u64,
    },
    /// Ask whether a command *would* be permitted, minting nothing.
    ///
    /// The hook's question. It runs before the agent's tool call, so it must
    /// not create a principal that the tool call might never use.
    HookCheck {
        /// The profile whose `exec` policy applies.
        profile: String,
        /// The program that would run.
        argv0: String,
        /// The arguments that would be passed.
        args: Vec<String>,
    },
    /// Ask the daemon to scan its own memory for a known 32-byte marker.
    ///
    /// Compiled only into a daemon built with the `debug-heapscan` feature,
    /// and used by exactly one test: the memory-hygiene check that asserts a
    /// master is gone from the daemon's address space after a revoke. It takes
    /// a digest rather than the needle so the needle itself never crosses the
    /// socket.
    #[cfg(feature = "debug-heapscan")]
    HeapScan {
        /// Lowercase hex SHA-256 of the 32-byte marker to look for.
        needle_sha256: String,
    },
}

impl Request {
    /// The variant's wire name, used as the dispatch-table key.
    ///
    /// This is the same string the serde tag uses, so the table and the wire
    /// format cannot drift apart.
    pub fn name(&self) -> &'static str {
        match self {
            Request::Ping => "ping",
            Request::Status => "status",
            Request::Shutdown => "shutdown",
            Request::ListProfiles => "list_profiles",
            Request::ShowProfile { .. } => "show_profile",
            Request::OpenSession { .. } => "open_session",
            Request::CloseSession { .. } => "close_session",
            Request::Unlock { .. } => "unlock",
            Request::Exec { .. } => "exec",
            Request::ExecDone { .. } => "exec_done",
            Request::HookCheck { .. } => "hook_check",
            #[cfg(feature = "debug-heapscan")]
            Request::HeapScan { .. } => "heap_scan",
        }
    }

    /// Every variant name the daemon must have a handler for.
    pub const NAMES: &'static [&'static str] = &[
        "ping",
        "status",
        "shutdown",
        "list_profiles",
        "show_profile",
        "open_session",
        "close_session",
        "unlock",
        "exec",
        "exec_done",
        "hook_check",
        #[cfg(feature = "debug-heapscan")]
        "heap_scan",
    ];
}

/// A message from the daemon back to a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
    /// Answer to [`Request::Ping`].
    Pong,
    /// Answer to [`Request::Status`]. Metadata only.
    Status {
        /// The daemon binary's crate version.
        version: String,
        /// The daemon's process id.
        pid: u32,
        /// Seconds since the daemon finished starting.
        uptime_secs: u64,
        /// When the daemon finished starting.
        #[serde(with = "time::serde::rfc3339")]
        started_at: OffsetDateTime,
        /// The audit log file currently being appended to.
        audit_path: PathBuf,
        /// Where the Prometheus endpoint is listening, if it is enabled.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metrics_addr: Option<String>,
    },
    /// Acknowledgement of [`Request::Shutdown`], sent before the daemon stops.
    ShuttingDown,
    /// Answer to [`Request::ListProfiles`], in name order.
    Profiles {
        /// One summary per loaded profile.
        profiles: Vec<ProfileSummary>,
    },
    /// Answer to [`Request::ShowProfile`].
    Profile {
        /// The profile, as the daemon parsed it.
        profile: ProfileSummary,
    },
    /// Answer to [`Request::OpenSession`].
    ///
    /// Carries no credential material: the session id is a handle the client
    /// presents on later requests, and the minted secrets never leave the
    /// daemon on this path.
    SessionOpened {
        /// Opaque handle for this session.
        session_id: String,
        /// When the daemon will evict the session if it goes idle.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
    /// Answer to [`Request::CloseSession`].
    SessionClosed {
        /// The session that was closed.
        session_id: String,
    },
    /// Answer to [`Request::Unlock`]: presence was proved and cached.
    Unlocked {
        /// The profile the unlock applies to.
        profile: String,
    },
    /// Answer to [`Request::Exec`]: what was minted, and the environment.
    ///
    /// This is the one reply that carries credential material, and it is why
    /// the socket is mode `0600` inside a `0700` directory and why the daemon
    /// checks the peer's uid before reading a single frame. It is never
    /// written to disk, and it is never logged: `SecretString` redacts itself.
    Minted {
        /// One entry per credential that was minted, in declaration order.
        mints: Vec<MintSummary>,
        /// The environment the subprocess is to run with, already composed
        /// from the profile's `env` templates and its trust environment.
        ///
        /// The daemon composes this rather than the client because it is the
        /// only side that holds the profile, the minted fields, and the CA
        /// path at once. The client's job is to apply it verbatim on top of a
        /// cleared environment.
        env: BTreeMap<String, SecretString>,
        /// Variable names the client should copy from its own environment.
        ///
        /// The client's environment is the one thing the daemon cannot see,
        /// so the daemon names what may pass through and the client fills it.
        passthrough: Vec<String>,
    },
    /// Answer to [`Request::ExecDone`]: the revokes are queued.
    ExecRecorded {
        /// How many principals were enqueued for revoke.
        queued: usize,
    },
    /// Answer to [`Request::HookCheck`].
    HookDecision {
        /// Whether the profile's `exec` policy permits the command.
        allowed: bool,
        /// Why, in words a user can act on. Present for both answers.
        reason: String,
    },
    /// Answer to [`Request::HeapScan`].
    #[cfg(feature = "debug-heapscan")]
    HeapScanned {
        /// Whether a window matching the digest was found.
        present: bool,
        /// How many readable private regions were examined.
        regions_scanned: usize,
        /// How many bytes those regions covered.
        bytes_scanned: u64,
    },
    /// The profile's `exec` policy refused the command, so nothing was minted.
    ///
    /// Distinct from [`Response::Error`] because it is a policy decision rather
    /// than a fault, and the client turns it into its own exit code so a script
    /// can tell "not allowed" from "something broke".
    Denied {
        /// What was refused and why, naming the offending value.
        message: String,
    },
    /// The unlock gate refused, so nothing was opened.
    ///
    /// Distinct from [`Response::Error`] because a cancelled Touch ID prompt is
    /// a normal outcome the client reports calmly rather than a daemon fault.
    Locked {
        /// Machine-readable reason: `cancelled`, `failed`, `no_aqua_session`,
        /// or `unsupported`.
        reason: String,
        /// What the user should do about it.
        message: String,
    },
    /// The request could not be served. Carries no credential material.
    Error {
        /// What went wrong, in operator-readable terms.
        message: String,
    },
}

/// One credential the daemon minted for an [`Request::Exec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintSummary {
    /// The credential's name within its profile.
    pub credential: String,
    /// The principal that was created, for the later [`Request::ExecDone`].
    pub mint_id: String,
    /// The minter's own fields, for `briefcred get --field`.
    pub fields: BTreeMap<String, SecretString>,
}

/// A loaded profile, reduced to what a client is allowed to see.
///
/// Deliberately a wire type of its own rather than the daemon's `Profile`:
/// this struct can only ever grow fields somebody chose to expose, so a future
/// profile field holding a secret cannot leak across the socket by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSummary {
    /// The profile's name, as passed to `briefcred exec`.
    pub name: String,
    /// Its description, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The unlock policy: `biometric`, `passcode`, or `none`.
    pub unlock_policy: String,
    /// How long a successful unlock is honoured, in seconds.
    pub unlock_cache_secs: u64,
    /// The credentials the profile declares, in declaration order.
    pub credentials: Vec<CredentialSummary>,
}

/// One declared credential, reduced to what a client is allowed to see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSummary {
    /// The credential's name within its profile.
    pub name: String,
    /// The minter kind that serves it.
    pub kind: String,
    /// Its configured lifetime in seconds.
    pub ttl_secs: u64,
    /// The master-source key its master is filed under.
    ///
    /// The key, never the master: naming where a secret lives is what makes
    /// `briefcred profile show` useful for diagnosing a missing one.
    pub source_key: String,
}
