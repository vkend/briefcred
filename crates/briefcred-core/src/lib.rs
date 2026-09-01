//! Core types for briefcred: filesystem layout, the profile schema, the
//! minter/master-source contracts, and the Postgres dynamic-role minter.
//!
//! Everything in this crate obeys two rules that the rest of the workspace
//! depends on:
//!
//! 1. Secret material lives in [`zeroize::Zeroizing`] and never reaches a
//!    `Debug` output, a log line, or a serialised form.
//! 2. Audit records carry metadata only — never headers, bodies, query
//!    strings, or secrets.

#![forbid(unsafe_code)]

pub mod audit;
pub mod error;
pub mod minters;
pub mod paths;
pub mod profile;
pub mod traits;
pub mod types;

pub use error::{Error, Result};
pub use profile::Profile;
pub use traits::{MasterSource, Minter};
pub use types::{MintCtx, MintId, MintedCredential, RevokeCtx, RevokeOutcome};
