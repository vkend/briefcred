//! Serving one [`Minter`] behind the daemon-to-helper protocol.
//!
//! Three places need this and they must not drift apart: each helper binary,
//! which is the whole of its `main`, and the daemon itself for the one minter
//! kind it runs in-process. A second copy of the conversion is a second chance
//! to report an expiry in the wrong format, or to turn a refused revoke into a
//! protocol error, and only one of those two mistakes is visible in a test.
//!
//! The adapter deliberately deals in [`HelperError`] rather than in a caller's
//! own failure type. A helper turns one into a JSON-RPC error object; the
//! daemon turns one into a `HelperFailure::Refused`. Both are one `map_err`.
//!
//! # The one distinction it preserves
//!
//! A `revoke` that the backend refused comes back as a *result* whose outcome
//! is `failed`, not as an error. The daemon has to be able to tell "the
//! backend said no" — which belongs on the retry queue — from "the minter is
//! broken", and this is where that distinction is made.

use std::sync::Arc;

use briefcred_proto::helper::{
    HelperError, HelperParams, HelperResult, MintParams, MintResult, ReconcileFailure,
    ReconcileParams, ReconcileResult, RevokeParams, RevokeResult, ShutdownResult, CODE_BACKEND,
    CODE_INVALID_PARAMS,
};
use briefcred_proto::SecretString;
use time::format_description::well_known::Rfc3339;

use crate::traits::Minter;
use crate::types::{MintCtx, MintId, ReconcileCtx, RevokeCtx, RevokeOutcome};

/// One minter, answering the helper protocol.
pub struct MinterAdapter {
    minter: Arc<dyn Minter>,
}

impl std::fmt::Debug for MinterAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MinterAdapter")
            .field("kind", &self.minter.kind())
            .finish()
    }
}

impl MinterAdapter {
    /// Wrap `minter`.
    pub fn new(minter: Arc<dyn Minter>) -> MinterAdapter {
        MinterAdapter { minter }
    }

    /// The kind this adapter serves.
    pub fn kind(&self) -> &'static str {
        self.minter.kind()
    }

    /// Answer one call.
    pub async fn dispatch(&self, params: HelperParams) -> Result<HelperResult, HelperError> {
        match params {
            HelperParams::Mint(params) => self.mint(params).await.map(HelperResult::Mint),
            HelperParams::Revoke(params) => self.revoke(params).await.map(HelperResult::Revoke),
            HelperParams::Reconcile(params) => {
                self.reconcile(params).await.map(HelperResult::Reconcile)
            }
            HelperParams::Shutdown(_) => {
                Ok(HelperResult::Shutdown(ShutdownResult { stopping: true }))
            }
        }
    }

    async fn mint(&self, params: MintParams) -> Result<MintResult, HelperError> {
        let ctx = MintCtx {
            mint_id: mint_id(&params.mint_id)?,
            profile: params.profile,
            credential: params.credential,
            config: to_yaml(params.config)?,
            master: params.master.into_zeroizing(),
            ttl: std::time::Duration::from_secs(params.ttl_secs),
        };
        let minted = self.minter.mint(ctx).await.map_err(backend)?;

        let expires_at = minted
            .expires_at
            .format(&Rfc3339)
            .map_err(|e| HelperError {
                code: CODE_BACKEND,
                message: format!("cannot format the expiry: {e}"),
            })?;
        Ok(MintResult {
            mint_id: minted.mint_id.as_str().to_string(),
            fields: minted
                .fields
                .into_iter()
                .map(|(name, value)| (name, SecretString::from(value)))
                .collect(),
            expires_at,
            revoke_token: minted.revoke_token,
        })
    }

    async fn revoke(&self, params: RevokeParams) -> Result<RevokeResult, HelperError> {
        let ctx = RevokeCtx {
            mint_id: mint_id(&params.mint_id)?,
            config: to_yaml(params.config)?,
            master: params.master.into_zeroizing(),
            revoke_token: params.revoke_token,
        };
        Ok(describe_outcome(self.minter.revoke(ctx).await))
    }

    async fn reconcile(&self, params: ReconcileParams) -> Result<ReconcileResult, HelperError> {
        let ctx = ReconcileCtx {
            config: to_yaml(params.config)?,
            master: params.master.into_zeroizing(),
        };
        let report = self.minter.reconcile(ctx).await.map_err(backend)?;
        Ok(ReconcileResult {
            revoked: report
                .revoked
                .iter()
                .map(|id| id.as_str().to_string())
                .collect(),
            failed: report
                .failed
                .into_iter()
                .map(|(mint_id, detail)| ReconcileFailure {
                    mint_id: mint_id.as_str().to_string(),
                    detail,
                })
                .collect(),
        })
    }
}

/// Render a [`RevokeOutcome`] as the wire shape, keeping every detail.
pub fn describe_outcome(outcome: RevokeOutcome) -> RevokeResult {
    let label = outcome.label().to_string();
    match outcome {
        RevokeOutcome::Failed { detail } => RevokeResult {
            outcome: label,
            detail: Some(detail),
            propagation_estimate_ms: None,
        },
        RevokeOutcome::EventuallyConsistent {
            propagation_estimate,
        } => RevokeResult {
            outcome: label,
            detail: None,
            propagation_estimate_ms: Some(propagation_estimate.as_millis() as u64),
        },
        RevokeOutcome::Revoked | RevokeOutcome::AlreadyGone => RevokeResult {
            outcome: label,
            detail: None,
            propagation_estimate_ms: None,
        },
    }
}

fn mint_id(raw: &str) -> Result<MintId, HelperError> {
    raw.parse().map_err(|e| HelperError {
        code: CODE_INVALID_PARAMS,
        message: format!("{e}"),
    })
}

/// The wire carries a credential's `config` as JSON and a minter reads YAML.
///
/// Every JSON document is a YAML document, so this is a re-encoding rather
/// than a conversion, and a config that does not survive it was never valid.
fn to_yaml(value: serde_json::Value) -> Result<serde_yaml_ng::Value, HelperError> {
    serde_yaml_ng::to_value(value).map_err(|e| HelperError {
        code: CODE_INVALID_PARAMS,
        message: format!("config is not a usable document: {e}"),
    })
}

fn backend(error: crate::Error) -> HelperError {
    HelperError {
        code: CODE_BACKEND,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::minters::ssh_cert::SshCertMinter;
    use briefcred_proto::helper::ShutdownParams;

    fn adapter() -> MinterAdapter {
        MinterAdapter::new(Arc::new(SshCertMinter::new()))
    }

    #[test]
    fn every_outcome_keeps_the_detail_that_makes_it_actionable() {
        let failed = describe_outcome(RevokeOutcome::failed("42501: permission denied"));
        assert_eq!(failed.outcome, "failed");
        assert_eq!(failed.detail.as_deref(), Some("42501: permission denied"));

        let eventual = describe_outcome(RevokeOutcome::EventuallyConsistent {
            propagation_estimate: std::time::Duration::from_secs(5),
        });
        assert_eq!(eventual.propagation_estimate_ms, Some(5_000));
        assert!(eventual.detail.is_none());

        let gone = describe_outcome(RevokeOutcome::AlreadyGone);
        assert_eq!(gone.outcome, "already_gone");
        assert!(gone.detail.is_none());
    }

    #[tokio::test]
    async fn shutdown_is_answered_rather_than_passed_to_the_minter() {
        let result = adapter()
            .dispatch(HelperParams::Shutdown(ShutdownParams {}))
            .await
            .unwrap();
        assert!(matches!(result, HelperResult::Shutdown(_)), "{result:?}");
    }

    #[tokio::test]
    async fn a_malformed_mint_id_is_refused_before_the_minter_is_reached() {
        let err = adapter()
            .dispatch(HelperParams::Mint(MintParams {
                mint_id: "not-a-mint-id".into(),
                profile: "dev".into(),
                credential: "c".into(),
                config: serde_json::json!({}),
                master: SecretString::new("m"),
                ttl_secs: 900,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code, CODE_INVALID_PARAMS);
        assert!(err.message.contains("not-a-mint-id"), "{err}");
    }

    #[tokio::test]
    async fn a_refused_revoke_is_a_result_rather_than_an_error() {
        // An empty revoke token, which the SSH minter refuses. The daemon has
        // to see this as a `failed` outcome it can retry, not as a broken
        // minter it should discard.
        let result = adapter()
            .dispatch(HelperParams::Revoke(RevokeParams {
                mint_id: MintId::generate().as_str().to_string(),
                config: serde_json::json!({ "principals": ["ubuntu"] }),
                master: SecretString::new("m"),
                revoke_token: String::new(),
            }))
            .await
            .unwrap();
        let HelperResult::Revoke(result) = result else {
            panic!("{result:?}");
        };
        assert_eq!(result.outcome, "failed");
        assert!(result.detail.is_some());
    }

    #[test]
    fn the_adapter_debug_prints_its_kind_and_nothing_else() {
        assert_eq!(
            format!("{:?}", adapter()),
            "MinterAdapter { kind: \"ssh-cert\" }"
        );
    }
}
