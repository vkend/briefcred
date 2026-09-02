//! The request and response vocabulary.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

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
