//! The two contracts the daemon programs against.

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::error::Result;
use crate::types::{
    MintCtx, MintedCredential, ReconcileCtx, ReconcileReport, RevokeCtx, RevokeOutcome,
};

/// Where a master credential comes from.
///
/// Implementations live in [`crate::source`]. The returned string is zeroised
/// when the caller drops it, and no implementation may log, `Debug`-print, or
/// serialise what it returns.
#[async_trait]
pub trait MasterSource: Send + Sync {
    /// Fetch the master credential stored under `key`.
    ///
    /// A key that is simply absent must be
    /// [`crate::Error::MasterNotFound`] rather than a generic failure, so the
    /// daemon can tell "you have not set this up" from "the backend broke".
    async fn fetch(&self, key: &str) -> Result<Zeroizing<String>>;

    /// Where this backend looks, for diagnostics and `briefcred doctor`.
    ///
    /// Must name the location only, never the secret kept there.
    fn location(&self) -> String;
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

    /// Remove principals this minter created that nothing is using any more.
    ///
    /// The default is "this backend cannot be swept", which is honest for a
    /// minter whose credentials expire on their own and leave nothing behind.
    /// A minter that creates a durable object — a role, a user, a key — must
    /// override it, because otherwise a `SIGKILL` mid-`exec` leaks that object
    /// permanently.
    async fn reconcile(&self, _ctx: ReconcileCtx) -> Result<ReconcileReport> {
        Ok(ReconcileReport::default())
    }
}

impl std::fmt::Debug for dyn Minter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Minter")
            .field("kind", &self.kind())
            .finish()
    }
}
