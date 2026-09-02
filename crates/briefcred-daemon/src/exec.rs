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
use crate::proxy::issuer::ProxyIssuer;
use crate::revoke::PendingRevoke;

/// The session context a proxy-served credential is minted against.
///
/// Only the proxy kinds need it, and only they can use it: a synthetic token
/// names the session it was issued to, and no minter that runs behind the
/// [`briefcred_core::Minter`] contract has any way to know what that is.
#[derive(Clone, Copy)]
pub struct ProxyGrant<'a> {
    /// The daemon's token authority, shared by both proxies.
    pub issuer: &'a ProxyIssuer,
    /// The session the tokens are issued to.
    pub session_id: &'a str,
    /// The client's per-session public key, when it offered one.
    pub session_pubkey: Option<&'a [u8; 32]>,
    /// Where the Postgres proxy is listening, when it is running.
    ///
    /// Separate from the issuer because the two proxies share one signing key
    /// but not one address, and because either can be switched off: a
    /// `postgres-proxy` credential minted with `None` here would publish a
    /// `DATABASE_URL` pointing at nothing.
    pub pg_proxy_addr: Option<&'a str>,
}

impl std::fmt::Debug for ProxyGrant<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyGrant")
            .field("session_id", &self.session_id)
            .field("bound_to_a_session_key", &self.session_pubkey.is_some())
            .finish()
    }
}

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

    /// An HTTP credential was reached on a path that has no session to bind to.
    ///
    /// Every real caller passes a [`ProxyGrant`]; this is what a future one
    /// that forgot sees, instead of a token nobody can present.
    #[error("credential `{credential}` is served by the HTTP proxy, which this request has no session for")]
    NoProxyGrant {
        /// The credential that could not be issued.
        credential: String,
    },

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
    proxy: Option<ProxyGrant<'_>>,
) -> Result<Minted, ExecError> {
    let mut minted = mint_only(profile, specs, masters, helpers, trust, metrics, proxy).await?;
    minted.rows.push(AuditEntry::ExecStart {
        ts: OffsetDateTime::now_utc(),
        session_id: session_id.to_string(),
        mint_ids: minted.pending.iter().map(|p| p.mint_id.clone()).collect(),
        profile: profile.name.clone(),
        argv0: argv0.to_string(),
        args_sha256: args.iter().map(|a| hash_arg(a)).collect(),
        args: raw_args.then(|| args.to_vec()),
        pid,
    });
    Ok(minted)
}

/// Mint and compose, without claiming a subprocess is about to start.
///
/// [`mint`] is this plus an `ExecStart` row, and `briefcred exec` wants both.
/// The MCP server wants only this half: `briefcred_db_query` runs a query
/// inside the daemon and spawns nothing, so an `ExecStart` naming a program
/// that does not exist would be a fabricated row in a log whose whole value is
/// that it is not fabricated. It writes an `McpCall` row instead.
pub async fn mint_only(
    profile: &Profile,
    specs: &[&CredentialSpec],
    masters: &BTreeMap<String, Zeroizing<String>>,
    helpers: &MinterSet,
    trust: &BTreeMap<String, String>,
    metrics: &crate::metrics::Metrics,
    proxy: Option<ProxyGrant<'_>>,
) -> Result<Minted, ExecError> {
    let mut rows: Vec<AuditEntry> = Vec::new();
    let mut summaries: Vec<MintSummary> = Vec::new();
    let mut fields: MintedFields = MintedFields::new();
    let mut pending: Vec<PendingRevoke> = Vec::new();
    let registry = briefcred_core::Registry::discover();

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
        // An HTTP credential is not minted at a backend at all: the daemon
        // signs a token for it and keeps the real key in the session. It is
        // still timed and audited exactly like the others, because from the
        // profile's point of view it is one more credential this run produced.
        let outcome = if registry.is_proxy(&spec.kind) {
            match proxy {
                Some(grant) => issue_synthetic(profile, spec, grant),
                None => {
                    return Err(ExecError::NoProxyGrant {
                        credential: spec.name.clone(),
                    })
                }
            }
        } else {
            mint_one(profile, spec, master, helpers).await
        };
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

    Ok(Minted {
        mints: summaries,
        env,
        passthrough: passthrough_names(profile),
        pending,
        rows,
    })
}

/// What one credential's mint produced: its summary, its field values, and the
/// entry that will take it away again.
type MintOutcome = (
    MintSummary,
    BTreeMap<String, Zeroizing<String>>,
    PendingRevoke,
);

/// Issue one proxy-served credential's synthetic token.
///
/// The same shape as [`mint_one`] so the loop above does not care which it
/// called, but nothing here talks to a backend: the "principal" is a signed
/// statement, and the real credential stays in the session's master map where
/// whichever proxy the token is presented to will look it up.
///
/// Which proxy that is decides only what *fields* are published — the token
/// itself is the same signed statement either way, because both proxies verify
/// it with the same key.
fn issue_synthetic(
    profile: &Profile,
    spec: &CredentialSpec,
    grant: ProxyGrant<'_>,
) -> Result<MintOutcome, String> {
    let fields = if spec.kind == briefcred_core::minters::postgres_proxy::KIND {
        pg_proxy_fields(spec, grant)?
    } else {
        // Parsed rather than assumed: reaching here means the registry said
        // this kind is a proxy's, and a config that does not resolve to a kind
        // is a profile that should not have loaded.
        briefcred_core::minters::http::HttpKind::parse(&spec.kind, &spec.config)
            .ok_or_else(|| format!("`{}` is not a proxy-served credential kind", spec.kind))?
            .map_err(|e| e.to_string())?;
        HttpFields::Http
    };
    issue(profile, spec, grant, fields)
}

/// Which set of fields a proxy-served credential publishes.
enum HttpFields {
    /// `TOKEN` and `PROXY_URL`, for the HTTP proxy's three kinds.
    Http,
    /// The six a PostgreSQL client reads, for `postgres-proxy`.
    Postgres(
        briefcred_core::minters::postgres_proxy::PgProxyConfig,
        String,
    ),
}

/// The Postgres proxy's configuration and address, or why it cannot be served.
fn pg_proxy_fields(spec: &CredentialSpec, grant: ProxyGrant<'_>) -> Result<HttpFields, String> {
    let config =
        briefcred_core::minters::postgres_proxy::PgProxyConfig::parse(&spec.kind, &spec.config)
            .ok_or_else(|| format!("`{}` is not a Postgres proxy credential", spec.kind))?
            .map_err(|e| e.to_string())?;
    let address = grant.pg_proxy_addr.ok_or_else(|| {
        "the Postgres proxy is not running; set `pg_proxy_enabled = true` in daemon.toml"
            .to_string()
    })?;
    Ok(HttpFields::Postgres(config, address.to_string()))
}

/// Sign the token and publish the fields the credential's proxy expects.
fn issue(
    profile: &Profile,
    spec: &CredentialSpec,
    grant: ProxyGrant<'_>,
    fields: HttpFields,
) -> Result<MintOutcome, String> {
    let config = to_json(&spec.config)?;
    let mint_id = MintId::generate();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let issued = grant
        .issuer
        .issue(
            grant.session_id,
            grant.session_pubkey,
            &spec.name,
            spec.ttl_secs,
            now,
        )
        .map_err(|e| e.to_string())?;

    let values = match fields {
        HttpFields::Http => http_fields(&issued.token, grant.issuer.proxy_url()),
        HttpFields::Postgres(pg, address) => {
            postgres_fields(&issued.token, grant.session_id, &pg, &address)
        }
    };

    Ok((
        MintSummary {
            credential: spec.name.clone(),
            mint_id: mint_id.as_str().to_string(),
            fields: values
                .iter()
                .map(|(name, value)| (name.clone(), SecretString::from(value.clone())))
                .collect(),
        },
        values,
        PendingRevoke {
            mint_id,
            kind: spec.kind.clone(),
            profile: profile.name.clone(),
            credential: spec.name.clone(),
            source_key: spec.source_key().to_string(),
            config,
            // The session, so the revoke knows which grant to retire. Not a
            // secret — session ids are already in every audit row — but it
            // rides in the field a minter's opaque state uses, which is the
            // one the queue already redacts and never logs.
            revoke_token: grant.session_id.to_string(),
            expires_at_unix_ms: issued.expires_at.saturating_mul(1_000),
            attempts: 0,
            not_before_unix_ms: 0,
        },
    ))
}

/// The two fields an `http-*` credential publishes.
fn http_fields(token: &Zeroizing<String>, proxy_url: &str) -> BTreeMap<String, Zeroizing<String>> {
    BTreeMap::from([
        (
            briefcred_core::minters::http::TOKEN_FIELD.to_string(),
            token.clone(),
        ),
        (
            briefcred_core::minters::http::PROXY_URL_FIELD.to_string(),
            Zeroizing::new(proxy_url.to_string()),
        ),
    ])
}

/// The six fields a `postgres-proxy` credential publishes.
///
/// Every one of them points at the proxy rather than at the real server, and
/// the only password among them is the synthetic token. The session identifier
/// is the user, because the proxy has to know which session is connecting
/// before it has seen a password and the startup packet's `user` is the only
/// field that arrives that early.
///
/// Nothing here is percent-encoded, and nothing needs to be: a session id is
/// hexadecimal and a token is `bc.` followed by two unpadded base64url strings,
/// so neither can carry a character that would end the userinfo early. The
/// assertion in this module's tests is what keeps that true.
fn postgres_fields(
    token: &Zeroizing<String>,
    session_id: &str,
    config: &briefcred_core::minters::postgres_proxy::PgProxyConfig,
    address: &str,
) -> BTreeMap<String, Zeroizing<String>> {
    use briefcred_core::minters::postgres_proxy as pg;

    let (host, port) = address
        .rsplit_once(':')
        .map(|(host, port)| (host.to_string(), port.to_string()))
        .unwrap_or_else(|| (address.to_string(), String::new()));
    BTreeMap::from([
        (
            pg::DATABASE_URL_FIELD.to_string(),
            Zeroizing::new(format!(
                "postgresql://{session_id}:{}@{address}/{}",
                token.as_str(),
                config.dbname
            )),
        ),
        (pg::PGHOST_FIELD.to_string(), Zeroizing::new(host)),
        (pg::PGPORT_FIELD.to_string(), Zeroizing::new(port)),
        (
            pg::PGDATABASE_FIELD.to_string(),
            Zeroizing::new(config.dbname.clone()),
        ),
        (
            pg::PGUSER_FIELD.to_string(),
            Zeroizing::new(session_id.to_string()),
        ),
        (pg::PGPASSWORD_FIELD.to_string(), token.clone()),
    ])
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
) -> Result<MintOutcome, String> {
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

/// Retire one entry: through its helper, or through the proxy's issuer.
///
/// `issuer` is consulted only for the proxy's own kinds. Revoking one of those
/// is not a call to a backend — there is nothing out there to remove — it is
/// the daemon deciding to stop honouring a token it signed, which is why it
/// cannot fail and why the outcome is always `revoked`.
pub async fn revoke_one(
    helpers: &MinterSet,
    entry: &PendingRevoke,
    master: &Zeroizing<String>,
    issuer: Option<&ProxyIssuer>,
) -> RevokeOutcome {
    if briefcred_core::Registry::discover().is_proxy(&entry.kind) {
        let Some(issuer) = issuer else {
            return RevokeOutcome::failed(format!(
                "`{}` is served by the HTTP proxy, which is not running",
                entry.kind
            ));
        };
        // `revoke_token` is the session the grant was issued to; see
        // `issue_http`.
        issuer.revoke(
            &entry.revoke_token,
            &entry.credential,
            entry.expires_at_unix_ms / 1_000,
        );
        return RevokeOutcome::Revoked;
    }
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

    /// A profile with one credential of `kind`, configured with `config`.
    fn one_credential(kind: &str, config: &str) -> Profile {
        profile(&format!(
            "name: dev\ncredentials:\n  - name: warehouse\n    kind: {kind}\n    ttl_secs: 900\n{config}"
        ))
    }

    const PG_CONFIG: &str = "    config:\n      host: db.internal\n      port: 6432\n      dbname: analytics\n      user: reporting\n";

    /// An issuer backed by a throwaway file key store.
    fn issuer() -> (tempfile::TempDir, std::sync::Arc<ProxyIssuer>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Box::new(briefcred_core::keystore::FileKeyStore::new(dir.path()));
        (dir, ProxyIssuer::open(store, "http://127.0.0.1:9318"))
    }

    fn mint_proxy_credential(
        profile: &Profile,
        pg_proxy_addr: Option<&str>,
    ) -> Result<MintOutcome, String> {
        let (_dir, issuer) = issuer();
        issue_synthetic(
            profile,
            &profile.credentials[0],
            ProxyGrant {
                issuer: &issuer,
                session_id: "0f1e2d3c4b5a6978",
                session_pubkey: None,
                pg_proxy_addr,
            },
        )
    }

    #[test]
    fn a_postgres_proxy_credential_publishes_the_six_fields_a_client_reads() {
        let profile = one_credential("postgres-proxy", PG_CONFIG);
        let (summary, values, pending) =
            mint_proxy_credential(&profile, Some("127.0.0.1:9319")).unwrap();

        let names: Vec<&str> = values.keys().map(String::as_str).collect();
        let mut expected = briefcred_core::minters::postgres_proxy::FIELDS;
        expected.sort_unstable();
        assert_eq!(
            names, expected,
            "the map is ordered, so sort the expectation"
        );

        assert_eq!(&*values["PGHOST"], "127.0.0.1");
        assert_eq!(&*values["PGPORT"], "9319");
        assert_eq!(&*values["PGDATABASE"], "analytics");
        assert_eq!(&*values["PGUSER"], "0f1e2d3c4b5a6978");
        // The password is the synthetic token, never the master.
        assert!(
            values["PGPASSWORD"].starts_with("bc."),
            "{:?}",
            summary.credential
        );
        assert_eq!(
            &*values["DATABASE_URL"],
            &format!(
                "postgresql://0f1e2d3c4b5a6978:{}@127.0.0.1:9319/analytics",
                values["PGPASSWORD"].as_str()
            )
        );
        assert_eq!(pending.credential, "warehouse");
        assert_eq!(pending.revoke_token, "0f1e2d3c4b5a6978");
    }

    #[test]
    fn nothing_in_the_connection_string_needs_percent_encoding() {
        // A session id is hexadecimal and a token is `bc.` plus two unpadded
        // base64url strings. If either ever grew a `@`, a `/`, or a `:`, the
        // URL would silently point somewhere else.
        let profile = one_credential("postgres-proxy", PG_CONFIG);
        let (_summary, values, _pending) =
            mint_proxy_credential(&profile, Some("127.0.0.1:9319")).unwrap();
        let userinfo = format!("{}:{}", &*values["PGUSER"], &*values["PGPASSWORD"]);
        assert!(
            userinfo
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":.-_".contains(&b)),
            "{userinfo} carries a character a URL would read as a delimiter"
        );
    }

    #[test]
    fn a_postgres_proxy_credential_cannot_be_minted_without_a_proxy_to_point_at() {
        // Publishing a `DATABASE_URL` for a port nothing answers on would turn
        // a configuration mistake into a connection refused with no explanation.
        let profile = one_credential("postgres-proxy", PG_CONFIG);
        let err = mint_proxy_credential(&profile, None).unwrap_err();
        assert!(err.contains("pg_proxy_enabled"), "{err}");
    }

    #[test]
    fn an_http_credential_still_publishes_only_its_token_and_proxy_url() {
        let profile = one_credential("http-bearer", "");
        let (_summary, values, _pending) = mint_proxy_credential(&profile, None).unwrap();
        assert_eq!(
            values.keys().map(String::as_str).collect::<Vec<_>>(),
            ["PROXY_URL", "TOKEN"]
        );
        assert_eq!(&*values["PROXY_URL"], "http://127.0.0.1:9318");
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
