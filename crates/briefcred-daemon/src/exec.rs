//! Minting for one `briefcred exec`, and the revoke that undoes it.
//!
//! This is where the daemon's parts meet: a session holding masters, a helper
//! process per minter kind, a profile saying what may run and what environment
//! it gets, and a queue that takes the credentials away again.
//!
//! # The order, and why it is that order
//!
//! 1. **Check the command.** Before anything is minted. A `briefcred exec` of
//!    a command the profile forbids must not leave a role behind.
//! 2. **Mint, best effort.** A credential whose mint fails is reported and left
//!    out rather than failing the whole run: a profile with a database and an
//!    object store should still give a working database when the object store
//!    is down. What is *not* best effort is the environment — a template
//!    naming a credential that did not mint fails the run, because a command
//!    that silently runs without half its credentials is worse than one that
//!    does not run.
//! 3. **Compose the environment.** From the profile's templates, the minted
//!    fields, and the CA trust variables.
//! 4. **Answer.** The client spawns the child; the daemon has already recorded
//!    the mints against the session, so they are revocable even if the client
//!    never comes back.

use std::collections::BTreeMap;

use briefcred_core::audit::{hash_arg, AuditEntry};
use briefcred_core::exec::{compose_env, passthrough_names, MintedFields};
use briefcred_core::profile::{CredentialSpec, Profile};
use briefcred_core::types::{MintId, RevokeOutcome};
use briefcred_proto::helper::{HelperParams, HelperResult, MintParams, RevokeParams, RevokeResult};
use briefcred_proto::{MintSummary, SecretString};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::helper::MinterSet;
use crate::revoke::PendingRevoke;

/// What one `Exec` produced.
pub struct Minted {
    /// One summary per credential that was minted, for the reply.
    pub mints: Vec<MintSummary>,
    /// The composed environment.
    pub env: BTreeMap<String, SecretString>,
    /// The variable names the client should copy from its own environment.
    pub passthrough: Vec<String>,
    /// What has to happen when the run finishes.
    pub pending: Vec<PendingRevoke>,
    /// Audit rows the caller must write. Returned rather than written here so
    /// this function stays free of the daemon's shared state and testable.
    pub rows: Vec<AuditEntry>,
}

/// Why an exec could not be served.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// The profile's `exec` policy refused the command.
    #[error(transparent)]
    Denied(#[from] briefcred_core::exec::CommandDenied),

    /// `--cred` named something the profile does not declare.
    #[error("profile `{profile}` declares no credential `{credential}`; it has {declared}")]
    NoSuchCredential {
        /// The profile that was asked.
        profile: String,
        /// The name that was asked for.
        credential: String,
        /// What it does declare, comma separated.
        declared: String,
    },

    /// The environment could not be composed.
    #[error(transparent)]
    Env(#[from] briefcred_core::exec::EnvError),

    /// The session has no master filed under a credential's `source_key`.
    ///
    /// Opening the session fetches one per key, so reaching this means the
    /// profile was reloaded between the open and the exec.
    #[error("the session holds no master for `{source_key}`; reopen the session")]
    NoMaster {
        /// The key that was missing.
        source_key: String,
    },
}

/// Which credentials this run wants, in the profile's declaration order.
pub fn select<'a>(
    profile: &'a Profile,
    wanted: Option<&[String]>,
) -> Result<Vec<&'a CredentialSpec>, ExecError> {
    let Some(wanted) = wanted else {
        return Ok(profile.credentials.iter().collect());
    };
    // Named credentials are validated first and all at once, so `--cred a,typo`
    // complains about the typo rather than minting `a` and then failing.
    for name in wanted {
        if profile.credential(name).is_none() {
            return Err(ExecError::NoSuchCredential {
                profile: profile.name.clone(),
                credential: name.clone(),
                declared: profile
                    .credentials
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
    }
    Ok(profile
        .credentials
        .iter()
        .filter(|spec| wanted.iter().any(|name| name == &spec.name))
        .collect())
}

/// Mint the selected credentials and compose the environment.
///
/// `masters` is the session's map from `source_key` to master credential;
/// `trust` is [`briefcred_core::ca::trust_env`] for this profile.
#[allow(clippy::too_many_arguments)]
pub async fn mint(
    profile: &Profile,
    specs: &[&CredentialSpec],
    masters: &BTreeMap<String, Zeroizing<String>>,
    helpers: &MinterSet,
    trust: &BTreeMap<String, String>,
    session_id: &str,
    argv0: &str,
    args: &[String],
    pid: u32,
    raw_args: bool,
    metrics: &crate::metrics::Metrics,
) -> Result<Minted, ExecError> {
    let mut rows: Vec<AuditEntry> = Vec::new();
    let mut summaries: Vec<MintSummary> = Vec::new();
    let mut fields: MintedFields = MintedFields::new();
    let mut pending: Vec<PendingRevoke> = Vec::new();

    for spec in specs {
        let master = masters
            .get(spec.source_key())
            .ok_or_else(|| ExecError::NoMaster {
                source_key: spec.source_key().to_string(),
            })?;

        // Timed around the whole helper round trip, and recorded whether it
        // succeeded or not: a backend that takes thirty seconds to refuse is
        // exactly what the histogram has to show.
        let started = std::time::Instant::now();
        let outcome = mint_one(profile, spec, master, helpers).await;
        metrics.record_mint(&spec.kind, started.elapsed());

        match outcome {
            Ok((summary, minted_fields, entry)) => {
                rows.push(AuditEntry::Mint {
                    ts: OffsetDateTime::now_utc(),
                    mint_id: entry.mint_id.clone(),
                    profile: profile.name.clone(),
                    credential: spec.name.clone(),
                    kind: spec.kind.clone(),
                    ttl_secs: spec.ttl_secs,
                });
                fields.insert(spec.name.clone(), minted_fields);
                summaries.push(summary);
                pending.push(entry);
            }
            // Best effort: say so loudly and carry on. If the profile's `env`
            // needed this credential, `compose_env` below fails the run.
            Err(detail) => {
                eprintln!(
                    "briefcred-daemon: profile `{}` credential `{}` did not mint: {detail}",
                    profile.name, spec.name
                );
            }
        }
    }

    let env = compose_env(profile, trust, &fields, &BTreeMap::new())?;
    let env: BTreeMap<String, SecretString> = env
        .into_iter()
        .map(|(k, v)| (k, SecretString::from(v)))
        .collect();

    rows.push(AuditEntry::ExecStart {
        ts: OffsetDateTime::now_utc(),
        session_id: session_id.to_string(),
        mint_ids: pending.iter().map(|p| p.mint_id.clone()).collect(),
        profile: profile.name.clone(),
        argv0: argv0.to_string(),
        args_sha256: args.iter().map(|a| hash_arg(a)).collect(),
        args: raw_args.then(|| args.to_vec()),
        pid,
    });

    Ok(Minted {
        mints: summaries,
        env,
        passthrough: passthrough_names(profile),
        pending,
        rows,
    })
}

/// Mint one credential through its helper.
///
/// The failure type is a plain string because every caller treats it the same
/// way: report it and leave the credential out.
async fn mint_one(
    profile: &Profile,
    spec: &CredentialSpec,
    master: &Zeroizing<String>,
    helpers: &MinterSet,
) -> Result<
    (
        MintSummary,
        BTreeMap<String, Zeroizing<String>>,
        PendingRevoke,
    ),
    String,
> {
    let config = to_json(&spec.config)?;
    let mint_id = MintId::generate();

    let helper = helpers
        .get(&spec.kind, &spec.config)
        .await
        .map_err(|e| e.to_string())?;
    let result = helper
        .call(HelperParams::Mint(MintParams {
            mint_id: mint_id.as_str().to_string(),
            profile: profile.name.clone(),
            credential: spec.name.clone(),
            config: config.clone(),
            master: SecretString::from(master.clone()),
            ttl_secs: spec.ttl_secs,
        }))
        .await;

    let result = match result {
        Ok(result) => result,
        Err(err) => {
            // The helper is dead or wedged; the next mint must start a fresh
            // one rather than write into a broken pipe.
            helpers.discard(&spec.kind).await;
            return Err(err.to_string());
        }
    };

    let HelperResult::Mint(minted) = result else {
        helpers.discard(&spec.kind).await;
        return Err(format!(
            "`{}` answered a mint with something else",
            spec.kind
        ));
    };
    // The helper chose the identifier it reports; trusting it blindly would
    // let a buggy helper have the daemon revoke a principal it never made.
    if minted.mint_id != mint_id.as_str() {
        return Err(format!(
            "`{}` minted `{}` when it was asked for `{mint_id}`",
            spec.kind, minted.mint_id
        ));
    }

    // Parsed here rather than carried as a string, so a helper that reports a
    // malformed expiry degrades to "revoke at once" rather than to a panic or
    // to a credential nobody ever schedules.
    let expires_at = OffsetDateTime::parse(
        &minted.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map(|at| (at.unix_timestamp_nanos() / 1_000_000) as i64)
    .unwrap_or_default();

    let field_values: BTreeMap<String, Zeroizing<String>> = minted
        .fields
        .iter()
        .map(|(name, value)| (name.clone(), Zeroizing::new(value.expose().to_string())))
        .collect();

    Ok((
        MintSummary {
            credential: spec.name.clone(),
            mint_id: mint_id.as_str().to_string(),
            fields: minted.fields,
        },
        field_values,
        PendingRevoke {
            mint_id,
            kind: spec.kind.clone(),
            profile: profile.name.clone(),
            credential: spec.name.clone(),
            source_key: spec.source_key().to_string(),
            config,
            revoke_token: minted.revoke_token,
            expires_at_unix_ms: expires_at,
            attempts: 0,
            // Due at once: the common case is a healthy backend, and making
            // every exec's revoke wait would leave a window where the
            // credential is still live for no reason.
            not_before_unix_ms: 0,
        },
    ))
}

/// Ask a helper to revoke one entry.
pub async fn revoke_one(
    helpers: &MinterSet,
    entry: &PendingRevoke,
    master: &Zeroizing<String>,
) -> RevokeOutcome {
    // The queue persists a credential's config as JSON; a minter reads YAML,
    // and an in-daemon one is built from it. Every JSON document is a YAML
    // document, so a config that does not survive this was never valid.
    let config = match serde_yaml::to_value(&entry.config) {
        Ok(config) => config,
        Err(err) => return RevokeOutcome::failed(err.to_string()),
    };
    let helper = match helpers.get(&entry.kind, &config).await {
        Ok(helper) => helper,
        Err(err) => return RevokeOutcome::failed(err.to_string()),
    };
    let result = helper
        .call(HelperParams::Revoke(RevokeParams {
            mint_id: entry.mint_id.as_str().to_string(),
            config: entry.config.clone(),
            master: SecretString::from(master.clone()),
            revoke_token: entry.revoke_token.clone(),
        }))
        .await;

    match result {
        Ok(HelperResult::Revoke(result)) => outcome_of(result),
        Ok(_) => RevokeOutcome::failed(format!(
            "`{}` answered a revoke with something else",
            entry.kind
        )),
        Err(err) => {
            helpers.discard(&entry.kind).await;
            RevokeOutcome::failed(err.to_string())
        }
    }
}

/// Turn a helper's revoke result back into the outcome the audit log records.
///
/// An outcome label the daemon does not recognise is a failure rather than a
/// silent success: a helper that answers `"ok"` must not be read as having
/// revoked anything.
pub fn outcome_of(result: RevokeResult) -> RevokeOutcome {
    match result.outcome.as_str() {
        "revoked" => RevokeOutcome::Revoked,
        "already_gone" => RevokeOutcome::AlreadyGone,
        "eventually_consistent" => RevokeOutcome::EventuallyConsistent {
            propagation_estimate: std::time::Duration::from_millis(
                result.propagation_estimate_ms.unwrap_or_default(),
            ),
        },
        "failed" => RevokeOutcome::failed(
            result
                .detail
                .unwrap_or_else(|| "the helper reported a failure with no detail".to_string()),
        ),
        other => RevokeOutcome::failed(format!("unknown revoke outcome `{other}`")),
    }
}

/// Convert a credential's YAML `config` to the JSON the helper wire carries.
fn to_json(config: &serde_yaml::Value) -> Result<serde_json::Value, String> {
    serde_json::to_value(config).map_err(|e| format!("config is not representable as JSON: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(yaml: &str) -> Profile {
        Profile::from_yaml_str(yaml).unwrap()
    }

    const TWO: &str = "\
name: dev
credentials:
  - name: db
    kind: postgres-dynamic
  - name: warehouse
    kind: postgres-dynamic
";

    #[test]
    fn no_filter_selects_every_credential_in_declaration_order() {
        let p = profile(TWO);
        let names: Vec<&str> = select(&p, None)
            .unwrap()
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(names, vec!["db", "warehouse"]);
    }

    #[test]
    fn a_filter_keeps_declaration_order_rather_than_the_order_it_was_given() {
        let p = profile(TWO);
        let wanted = vec!["warehouse".to_string(), "db".to_string()];
        let names: Vec<&str> = select(&p, Some(&wanted))
            .unwrap()
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(names, vec!["db", "warehouse"]);
    }

    #[test]
    fn an_unknown_credential_is_refused_and_lists_the_real_ones() {
        let p = profile(TWO);
        let wanted = vec!["db".to_string(), "wharehouse".to_string()];
        let err = select(&p, Some(&wanted)).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("wharehouse"), "{text}");
        assert!(text.contains("db, warehouse"), "{text}");
    }

    #[test]
    fn every_documented_outcome_label_maps_back_to_its_variant() {
        assert_eq!(
            outcome_of(RevokeResult {
                outcome: "revoked".into(),
                detail: None,
                propagation_estimate_ms: None,
            }),
            RevokeOutcome::Revoked
        );
        assert_eq!(
            outcome_of(RevokeResult {
                outcome: "already_gone".into(),
                detail: None,
                propagation_estimate_ms: None,
            }),
            RevokeOutcome::AlreadyGone
        );
        assert_eq!(
            outcome_of(RevokeResult {
                outcome: "eventually_consistent".into(),
                detail: None,
                propagation_estimate_ms: Some(30_000),
            }),
            RevokeOutcome::EventuallyConsistent {
                propagation_estimate: std::time::Duration::from_secs(30)
            }
        );
        match outcome_of(RevokeResult {
            outcome: "failed".into(),
            detail: Some("42501".into()),
            propagation_estimate_ms: None,
        }) {
            RevokeOutcome::Failed { detail } => assert_eq!(detail, "42501"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_unrecognised_outcome_is_a_failure_rather_than_a_silent_success() {
        match outcome_of(RevokeResult {
            outcome: "ok".into(),
            detail: None,
            propagation_estimate_ms: None,
        }) {
            RevokeOutcome::Failed { detail } => assert!(detail.contains("`ok`"), "{detail}"),
            other => panic!("an unknown label must not be read as success: {other:?}"),
        }
    }

    #[test]
    fn a_failed_outcome_with_no_detail_still_gets_one() {
        match outcome_of(RevokeResult {
            outcome: "failed".into(),
            detail: None,
            propagation_estimate_ms: None,
        }) {
            RevokeOutcome::Failed { detail } => assert!(!detail.trim().is_empty()),
            other => panic!("{other:?}"),
        }
    }
}
