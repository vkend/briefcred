//! The PostgreSQL minting helper.
//!
//! One process per `(profile, postgres-dynamic)` pair, spawned by the daemon
//! and spoken to over stdio with [`briefcred_proto::helper`]. It exists so
//! that `tokio-postgres`, `rustls`, and the master database password live in
//! an address space the daemon does not share: a panic here costs one helper,
//! and a memory disclosure here exposes one backend's master rather than
//! every backend's.
//!
//! The helper is a thin shell around [`PostgresDynamicMinter`], which keeps
//! its master connection open across calls and reopens it when it drops. All
//! the SQL, and all the reasoning about revoke ordering, stays in
//! `briefcred-core` where it is unit-tested without a cluster.

#![deny(unsafe_code)]

use std::collections::BTreeMap;

use briefcred_core::minters::postgres::PostgresDynamicMinter;
use briefcred_core::types::{MintCtx, MintId, ReconcileCtx, RevokeCtx, RevokeOutcome};
use briefcred_core::Minter;
use briefcred_proto::helper::{
    HelperError, HelperParams, HelperResult, MintParams, MintResult, ReconcileFailure,
    ReconcileParams, ReconcileResult, RevokeParams, RevokeResult, ShutdownResult, StdioHandler,
    CODE_BACKEND, CODE_INVALID_PARAMS,
};
use briefcred_proto::SecretString;
use time::format_description::well_known::Rfc3339;

/// The helper, holding the one minter it serves.
#[derive(Debug, Default)]
pub struct PostgresHelper {
    minter: PostgresDynamicMinter,
}

impl PostgresHelper {
    /// A helper with no connection open yet.
    pub fn new() -> PostgresHelper {
        PostgresHelper::default()
    }
}

impl StdioHandler for PostgresHelper {
    async fn handle(&self, params: HelperParams) -> Result<HelperResult, HelperError> {
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
}

impl PostgresHelper {
    async fn mint(&self, params: MintParams) -> Result<MintResult, HelperError> {
        let ctx = MintCtx {
            mint_id: parse_mint_id(&params.mint_id)?,
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
        let fields: BTreeMap<String, SecretString> = minted
            .fields
            .into_iter()
            .map(|(name, value)| (name, SecretString::from(value)))
            .collect();

        Ok(MintResult {
            mint_id: minted.mint_id.as_str().to_string(),
            fields,
            expires_at,
            revoke_token: minted.revoke_token,
        })
    }

    async fn revoke(&self, params: RevokeParams) -> Result<RevokeResult, HelperError> {
        let ctx = RevokeCtx {
            mint_id: parse_mint_id(&params.mint_id)?,
            config: to_yaml(params.config)?,
            master: params.master.into_zeroizing(),
            revoke_token: params.revoke_token,
        };
        // A refused revoke is a result, not a JSON-RPC error: the daemon has to
        // be able to tell "the backend said no" from "the helper is broken",
        // because only the first one belongs on the retry queue.
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

/// The config block arrives as JSON and the minter reads YAML.
///
/// Every JSON document is a YAML document, so this is a re-parse rather than a
/// conversion, and a config that does not survive it was never valid.
fn to_yaml(value: serde_json::Value) -> Result<serde_yaml::Value, HelperError> {
    serde_yaml::to_value(value).map_err(|e| HelperError {
        code: CODE_INVALID_PARAMS,
        message: format!("config is not a usable document: {e}"),
    })
}

fn parse_mint_id(raw: &str) -> Result<MintId, HelperError> {
    raw.parse().map_err(|e| HelperError {
        code: CODE_INVALID_PARAMS,
        message: format!("{e}"),
    })
}

fn backend(error: briefcred_core::Error) -> HelperError {
    HelperError {
        code: CODE_BACKEND,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use briefcred_proto::helper::{encode_line, HelperRequest, HelperResponse, ShutdownParams};

    #[test]
    fn every_outcome_keeps_the_detail_that_makes_it_actionable() {
        let failed = describe_outcome(RevokeOutcome::failed("42501: permission denied"));
        assert_eq!(failed.outcome, "failed");
        assert_eq!(failed.detail.as_deref(), Some("42501: permission denied"));

        let eventual = describe_outcome(RevokeOutcome::EventuallyConsistent {
            propagation_estimate: std::time::Duration::from_secs(30),
        });
        assert_eq!(eventual.propagation_estimate_ms, Some(30_000));
        assert!(eventual.detail.is_none());

        let gone = describe_outcome(RevokeOutcome::AlreadyGone);
        assert_eq!(gone.outcome, "already_gone");
        assert!(gone.detail.is_none());
    }

    #[tokio::test]
    async fn the_helper_stops_when_it_is_told_to() {
        let mut output: Vec<u8> = Vec::new();
        let line = encode_line(&HelperRequest::new(
            1,
            HelperParams::Shutdown(ShutdownParams {}),
        ))
        .unwrap();
        briefcred_proto::helper::serve_stdio(
            &PostgresHelper::new(),
            tokio::io::BufReader::new(line.as_bytes()),
            &mut output,
        )
        .await
        .unwrap();

        let reply: HelperResponse =
            serde_json::from_str(String::from_utf8(output).unwrap().trim_end()).unwrap();
        assert!(reply.error.is_none(), "{reply:?}");
    }

    #[tokio::test]
    async fn a_malformed_mint_id_is_refused_before_a_connection_is_attempted() {
        // Reaching the backend would need a cluster; being refused first is
        // both the correct behaviour and what makes this testable.
        let err = PostgresHelper::new()
            .mint(MintParams {
                mint_id: "not-a-mint-id".into(),
                profile: "dev".into(),
                credential: "db".into(),
                config: serde_json::json!({}),
                master: SecretString::new("m"),
                ttl_secs: 900,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, CODE_INVALID_PARAMS);
        assert!(err.message.contains("not-a-mint-id"), "{err}");
    }
}
