//! Core types for briefcred: filesystem layout, the profile schema, the
//! minter/master-source contracts, the Postgres dynamic-role minter, and the
//! per-machine root CA with the key store that holds its private key.
//!
//! Everything in this crate obeys two rules that the rest of the workspace
//! depends on:
//!
//! 1. Secret material lives in [`zeroize::Zeroizing`] and never reaches a
//!    `Debug` output, a log line, or a serialised form.
//! 2. Audit records carry metadata only — never headers, bodies, query
//!    strings, or secrets.

// `deny` rather than `forbid`: `session_env` needs one `extern "C"` call into
// the Security framework to ask whether this process has a graphical session,
// and there is no safe binding for it. Every other module is unsafe-free, and
// `deny` still fails the build on any `unsafe` that is not explicitly allowed
// and justified at the site.
#![deny(unsafe_code)]

pub mod audit;
pub mod ca;
pub mod error;
pub mod exec;
pub mod helper_adapter;
pub mod keystore;
pub mod minters;
pub mod paths;
pub mod policy;
pub mod profile;
pub mod registry;
pub mod session_env;
pub mod source;
pub mod traits;
pub mod types;

pub use ca::CertificateAuthority;
pub use error::{Error, Result};
pub use helper_adapter::MinterAdapter;
pub use keystore::{KeyStore, KeystoreKind};
pub use profile::Profile;
pub use registry::{Hosting, MinterFactory, Registry};
pub use source::SourceKind;
pub use traits::{MasterSource, Minter};
pub use types::{
    MintCtx, MintId, MintedCredential, ReconcileCtx, ReconcileReport, RevokeCtx, RevokeOutcome,
};
