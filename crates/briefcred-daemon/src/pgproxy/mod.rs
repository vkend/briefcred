//! The Postgres proxy: where a synthetic token becomes a database connection.
//!
//! The HTTP proxy under [`crate::proxy`] answers "what does the outgoing
//! request carry instead". This one answers a different question, because a
//! PostgreSQL connection is not a request: there is no header to swap, the
//! credential is exchanged once at the start of a long-lived session, and
//! whether that exchange succeeds is decided by a protocol with two parties in
//! it. So the proxy does not rewrite anything. It performs the authentication
//! **itself**, twice, and then gets out of the way:
//!
//! ```text
//! subprocess ──token──▶ briefcred ──master (SCRAM)──▶ the real database
//!            ◀──────────── bytes, in both directions, uncounted ─────────▶
//! ```
//!
//! # Why this exists next to `postgres-dynamic`
//!
//! [`postgres-dynamic`] mints a role, which is strictly better: the credential
//! the subprocess holds is real, short-lived, and independently revocable at
//! the backend. But it needs `CREATEROLE` on the master and a cluster where
//! role churn is acceptable, and plenty of real databases are neither. For
//! those, the master password is the only thing that will ever authenticate,
//! and the choice is between handing it to the agent and standing in front of
//! it. This module is standing in front of it.
//!
//! [`postgres-dynamic`]: briefcred_core::minters::postgres
//!
//! # The modules
//!
//! | module | what it owns |
//! | --- | --- |
//! | [`startup`] | the opening packet, and the three things that are not one |
//! | [`wire`] | the message frame, and the few messages briefcred writes |
//! | [`scram`] | proving the master to the real server |
//! | [`tls`] | encrypting the upstream connection the master crosses |
//! | [`forward`] | opening the upstream connection, and relaying bytes |
//! | [`audit`] | the one row a connection leaves behind |
//! | [`listener`] | the loop that puts all of it in order |
//!
//! # What this proxy does not do
//!
//! It does not apply the profile's Cedar policy. The policy vocabulary is
//! HTTP's — method, host, path — and a connection has none of those; the only
//! thing that could be decided per statement is the statement, and this proxy
//! deliberately never parses one. What bounds a `postgres-proxy` credential is
//! therefore the upstream role's own privileges, the credential's `ttl_secs`,
//! and the session it is bound to. `THREAT_MODEL.md` states that plainly rather
//! than leaving it to be discovered.

pub mod audit;
pub mod forward;
pub mod listener;
pub mod scram;
pub mod startup;
pub mod tls;
pub mod wire;
