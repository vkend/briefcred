//! Running a minter inside the daemon.
//!
//! Almost every minter gets a helper process, because almost every minter
//! opens a network connection with a master credential and that is work the
//! daemon should not be doing in its own address space. A minter registered as
//! [`Hosting::Daemon`] is the exception: it talks to nothing, so a process of
//! its own would buy only the cost of one. `ssh-cert` is the case that exists.
//!
//! # Why this speaks the helper protocol
//!
//! An in-daemon minter answers [`HelperParams`] and returns [`HelperResult`],
//! exactly as a helper process does, so `crate::exec` and `crate::reconcile`
//! have one code path rather than two. Where a credential is minted is then a
//! property of the *registration*, not something every caller has to remember
//! to branch on — and a minter that later moves into a helper, or out of one,
//! changes one line of its own registration and nothing else.
//!
//! The conversion below therefore mirrors the one a helper binary does on its
//! side of the pipe. They are deliberately separate: this one is inside the
//! trust boundary and reports a `briefcred_core::Error` as it is, while a
//! helper's has to turn one into a JSON-RPC error object first.

use std::sync::Arc;

use briefcred_core::registry::Registry;
use briefcred_core::types::{MintCtx, MintId, ReconcileCtx, RevokeCtx, RevokeOutcome};
use briefcred_core::Minter;
use briefcred_proto::helper::{
    HelperError, HelperParams, HelperResult, MintParams, MintResult, ReconcileFailure,
    ReconcileParams, ReconcileResult, RevokeParams, RevokeResult, ShutdownResult, CODE_BACKEND,
    CODE_INVALID_PARAMS,
};
use briefcred_proto::SecretString;
use time::format_description::well_known::Rfc3339;

use crate::helper::{HelperFailure, MintChannel};

/// A minter the daemon runs itself, behind the helper protocol.
pub struct InDaemonMinter {
    kind: String,
    minter: Arc<dyn Minter>,
}

impl std::fmt::Debug for InDaemonMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InDaemonMinter")
            .field("kind", &self.kind)
            .finish()
    }
}

impl InDaemonMinter {
    /// Build the minter `kind` from `config`, through the registry.
    ///
    /// The config is the credential's own, exactly as it reaches a helper.
    /// [`Registry::build`] validates it, so a credential whose config is wrong
    /// fails here rather than at the first mint — the same guarantee profile
    /// loading already gives, applied again because this is the other place a
    /// minter is constructed.
    pub fn build(
        kind: &str,
        config: &serde_yaml::Value,
        registry: &Registry,
    ) -> Result<InDaemonMinter, HelperFailure> {
        let minter = registry.build(kind, config).map_err(|e| refused(kind, e))?;
        Ok(InDaemonMinter {
            kind: kind.to_string(),
            minter,
        })
    }
}

#[async_trait::async_trait]
impl MintChannel for InDaemonMinter {
    async fn call(&self, params: HelperParams) -> Result<HelperResult, HelperFailure> {
        match params {
            HelperParams::Mint(params) => self.mint(params).await.map(HelperResult::Mint),
            HelperParams::Revoke(params) => self.revoke(params).await.map(HelperResult::Revoke),
            HelperParams::Reconcile(params) => {
                self.reconcile(params).await.map(HelperResult::Reconcile)
            }
            // There is no process to stop. Answered rather than refused so a
            // session close does not have to know which kinds have one.
            HelperParams::Shutdown(_) => {
                Ok(HelperResult::Shutdown(ShutdownResult { stopping: true }))
            }
        }
    }

    async fn stop(&self) {}
}

impl InDaemonMinter {
    async fn mint(&self, params: MintParams) -> Result<MintResult, HelperFailure> {
        let ctx = MintCtx {
            mint_id: self.mint_id(&params.mint_id)?,
            profile: params.profile,
            credential: params.credential,
            config: self.to_yaml(params.config)?,
            master: params.master.into_zeroizing(),
            ttl: std::time::Duration::from_secs(params.ttl_secs),
        };
        let minted = self
            .minter
            .mint(ctx)
            .await
            .map_err(|e| refused(&self.kind, e))?;

        let expires_at = minted
            .expires_at
            .format(&Rfc3339)
            .map_err(|e| self.failure(CODE_BACKEND, format!("cannot format the expiry: {e}")))?;
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

    async fn revoke(&self, params: RevokeParams) -> Result<RevokeResult, HelperFailure> {
        let ctx = RevokeCtx {
            mint_id: self.mint_id(&params.mint_id)?,
            config: self.to_yaml(params.config)?,
            master: params.master.into_zeroizing(),
            revoke_token: params.revoke_token,
        };
        // A refused revoke is a result, not a failure: only the first belongs
        // on the retry queue, and the caller tells them apart by which of the
        // two it gets back.
        Ok(describe_outcome(self.minter.revoke(ctx).await))
    }

    async fn reconcile(&self, params: ReconcileParams) -> Result<ReconcileResult, HelperFailure> {
        let ctx = ReconcileCtx {
            config: self.to_yaml(params.config)?,
            master: params.master.into_zeroizing(),
        };
        let report = self
            .minter
            .reconcile(ctx)
            .await
            .map_err(|e| refused(&self.kind, e))?;
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

    fn mint_id(&self, raw: &str) -> Result<MintId, HelperFailure> {
        raw.parse()
            .map_err(|e| self.failure(CODE_INVALID_PARAMS, format!("{e}")))
    }

    /// The wire carries the config as JSON and a minter reads YAML.
    ///
    /// Every JSON document is a YAML document, so this is a re-encoding rather
    /// than a conversion.
    fn to_yaml(&self, value: serde_json::Value) -> Result<serde_yaml::Value, HelperFailure> {
        serde_yaml::to_value(value).map_err(|e| {
            self.failure(
                CODE_INVALID_PARAMS,
                format!("config is not a usable document: {e}"),
            )
        })
    }

    fn failure(&self, code: i64, message: String) -> HelperFailure {
        HelperFailure::Refused {
            kind: self.kind.clone(),
            source: HelperError { code, message },
        }
    }
}

/// Render a [`RevokeOutcome`] as the wire shape, keeping every detail.
fn describe_outcome(outcome: RevokeOutcome) -> RevokeResult {
    let outcome_label = outcome.label().to_string();
    match outcome {
        RevokeOutcome::Failed { detail } => RevokeResult {
            outcome: outcome_label,
            detail: Some(detail),
            propagation_estimate_ms: None,
        },
        RevokeOutcome::EventuallyConsistent {
            propagation_estimate,
        } => RevokeResult {
            outcome: outcome_label,
            detail: None,
            propagation_estimate_ms: Some(propagation_estimate.as_millis() as u64),
        },
        RevokeOutcome::Revoked | RevokeOutcome::AlreadyGone => RevokeResult {
            outcome: outcome_label,
            detail: None,
            propagation_estimate_ms: None,
        },
    }
}

fn refused(kind: &str, error: briefcred_core::Error) -> HelperFailure {
    HelperFailure::Refused {
        kind: kind.to_string(),
        source: HelperError {
            code: CODE_BACKEND,
            message: error.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use briefcred_core::minters::ssh_cert;

    fn ssh_cert_channel() -> InDaemonMinter {
        InDaemonMinter::build(
            ssh_cert::KIND,
            &serde_yaml::from_str("principals: [ubuntu]\n").unwrap(),
            &Registry::discover(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn an_in_daemon_minter_answers_shutdown_without_a_process_to_stop() {
        let channel = ssh_cert_channel();
        let result = channel
            .call(HelperParams::Shutdown(
                briefcred_proto::helper::ShutdownParams {},
            ))
            .await
            .unwrap();
        assert!(matches!(result, HelperResult::Shutdown(_)), "{result:?}");
        channel.stop().await;
    }

    #[test]
    fn a_config_the_minter_rejects_fails_when_the_channel_is_built() {
        let err = InDaemonMinter::build(
            ssh_cert::KIND,
            &serde_yaml::from_str("principals: []\n").unwrap(),
            &Registry::discover(),
        )
        .unwrap_err();
        assert!(matches!(err, HelperFailure::Refused { .. }), "{err}");
    }

    #[tokio::test]
    async fn a_malformed_mint_id_is_refused_before_the_minter_is_reached() {
        let err = ssh_cert_channel()
            .call(HelperParams::Mint(MintParams {
                mint_id: "not-a-mint-id".into(),
                profile: "dev".into(),
                credential: "bastion".into(),
                config: serde_json::json!({ "principals": ["ubuntu"] }),
                master: SecretString::new("irrelevant"),
                ttl_secs: 900,
            }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not-a-mint-id"), "{err}");
    }

    #[tokio::test]
    async fn a_backend_failure_comes_back_as_a_refusal_naming_the_kind() {
        // A master that is not an OpenSSH private key: the minter's own error,
        // surfaced through the channel rather than swallowed.
        let err = ssh_cert_channel()
            .call(HelperParams::Mint(MintParams {
                mint_id: MintId::generate().as_str().to_string(),
                profile: "dev".into(),
                credential: "bastion".into(),
                config: serde_json::json!({ "principals": ["ubuntu"] }),
                master: SecretString::new("hunter2"),
                ttl_secs: 900,
            }))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains(ssh_cert::KIND), "{text}");
        assert!(text.contains("OpenSSH private key"), "{text}");
        assert!(
            !text.contains("hunter2"),
            "a master must not reach an error"
        );
    }

    #[test]
    fn the_channel_never_debug_prints_a_config_or_a_master() {
        assert_eq!(
            format!("{:?}", ssh_cert_channel()),
            "InDaemonMinter { kind: \"ssh-cert\" }"
        );
    }
}
