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
        }
    }

    /// Every variant name the daemon must have a handler for.
    pub const NAMES: &'static [&'static str] = &["ping", "status", "shutdown"];
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
    /// The request could not be served. Carries no credential material.
    Error {
        /// What went wrong, in operator-readable terms.
        message: String,
    },
}
