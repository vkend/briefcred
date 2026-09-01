//! The two contracts the daemon programs against.

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::error::Result;
use crate::types::{MintCtx, MintedCredential, RevokeCtx, RevokeOutcome};

/// Where a master credential comes from.
///
/// Phase 3 supplies a Keychain-backed implementation. The returned string is
/// zeroised when the caller drops it.
#[async_trait]
pub trait MasterSource: Send + Sync {
    /// Fetch the master credential stored under `key`.
    async fn fetch(&self, key: &str) -> Result<Zeroizing<String>>;
}

/// A backend that can create and destroy short-lived principals.
///
/// Revoke returns a [`RevokeOutcome`] rather than a `Result` because "the
/// revoke failed" is a normal, auditable state that the daemon retries, not an
/// exceptional one.
#[async_trait]
pub trait Minter: Send + Sync {
    /// The `kind` string profiles use to select this minter.
    fn kind(&self) -> &'static str;

    /// Create a principal and return its credential material.
    async fn mint(&self, ctx: MintCtx) -> Result<MintedCredential>;

    /// Remove a principal previously created by [`Minter::mint`].
    async fn revoke(&self, ctx: RevokeCtx) -> RevokeOutcome;
}
