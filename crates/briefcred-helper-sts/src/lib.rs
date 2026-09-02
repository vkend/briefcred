//! The AWS STS minting helper.
//!
//! One process per `(profile, aws-sts)` pair, spawned by the daemon and spoken
//! to over stdio with [`briefcred_proto::helper`]. It is a separate crate as
//! well as a separate process: the AWS SDK is a large dependency and the
//! daemon, the CLI, and the hook would all pay for it to use none of it. The
//! *schema* lives in [`briefcred_core::minters::aws_sts`], so a profile naming
//! `aws-sts` is still validated wherever profiles are read.
//!
//! # Mint
//!
//! One `sts:AssumeRole`, with `RoleSessionName` set to the mint id. That is
//! the whole point of naming sessions after mints: every CloudTrail event the
//! session produces carries `briefcred_t_...` in its user identity, so "who
//! ran this" resolves to a briefcred audit row rather than to a shared human.
//!
//! # Revoke, and what it really does
//!
//! STS sessions cannot be withdrawn. A set of temporary credentials is valid
//! until it expires and AWS offers no call that ends one early. The documented
//! technique — the one the console's "Revoke sessions" button uses — is to
//! attach an inline policy to the *role* denying everything to any session
//! issued before a chosen instant.
//!
//! That is blunt in a way this crate cannot soften, and the documentation must
//! not pretend otherwise: revoking one briefcred mint denies **every** session
//! of that role issued before now, including sessions belonging to other
//! people and other tools. `README.md` says so where an operator will read it
//! before configuring a role, and `THREAT_MODEL.md` records it as a residual
//! risk. Use a role briefcred is the only user of.
//!
//! Propagation is not instant either, so the outcome is
//! [`RevokeOutcome::EventuallyConsistent`] with a five-second estimate rather
//! than a claim to have revoked anything.

#![deny(unsafe_code)]

use std::sync::Arc;

use aws_config::BehaviorVersion;
use aws_sdk_sts::config::{Credentials, Region};
use aws_smithy_runtime_api::client::http::SharedHttpClient;
use briefcred_core::minters::aws_sts::{AwsStsConfig, CallerSource, KIND, REVOKE_POLICY_NAME};
use briefcred_core::traits::Minter;
use briefcred_core::types::{MintCtx, MintedCredential, RevokeCtx, RevokeOutcome};
use briefcred_core::{Error, MinterAdapter, Result};
use briefcred_proto::helper::{HelperError, HelperParams, HelperResult, StdioHandler};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// How long a revoke's deny takes to be honoured everywhere.
///
/// IAM is eventually consistent and AWS gives no bound. Five seconds is the
/// figure the SDK's own guidance uses for a policy change to be visible, and
/// it is reported to the caller rather than assumed: the daemon writes it into
/// the audit row, so "the credential may still have worked for five seconds"
/// is a recorded fact rather than an unstated one.
pub const PROPAGATION_ESTIMATE: std::time::Duration = std::time::Duration::from_secs(5);

/// The `Version` every IAM policy document briefcred writes carries.
const POLICY_VERSION: &str = "2012-10-17";

/// The helper, holding the one minter it serves.
#[derive(Debug)]
pub struct StsHelper {
    adapter: MinterAdapter,
}

impl Default for StsHelper {
    fn default() -> StsHelper {
        StsHelper::new()
    }
}

impl StsHelper {
    /// A helper with no AWS client built yet.
    pub fn new() -> StsHelper {
        StsHelper {
            adapter: MinterAdapter::new(Arc::new(AwsStsMinter::new())),
        }
    }
}

impl StdioHandler for StsHelper {
    async fn handle(&self, params: HelperParams) -> Result<HelperResult, HelperError> {
        self.adapter.dispatch(params).await
    }
}

/// The state a mint records so its revoke is exactly symmetric.
///
/// Both fields could be re-derived from the profile's config, and deliberately
/// are not: the profile may have been edited between the mint and the revoke,
/// and a revoke that follows the *new* config would attach a deny to a role
/// that never issued this session.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RevokeToken {
    role_arn: String,
    region: String,
}

/// Mints short-lived AWS STS sessions by assuming a role.
#[derive(Default)]
pub struct AwsStsMinter {
    /// The clients, and the configuration they were built for.
    ///
    /// Cached because building one loads the credential provider chain and, in
    /// the `ambient` case, may talk to the network. Rebuilt whenever the
    /// config changes, so reuse can never sign a request for the wrong region
    /// or the wrong account.
    clients: tokio::sync::Mutex<Option<Clients>>,
    /// Replaces the HTTP layer. Only a test sets this; production is `None`.
    http_client: Option<SharedHttpClient>,
}

struct Clients {
    key: CacheKey,
    sts: aws_sdk_sts::Client,
    iam: aws_sdk_iam::Client,
}

/// Everything about a config that changes which clients are correct.
///
/// The master is included as a *fingerprint* rather than as itself: rotating
/// the master must rebuild the clients, and nothing here may hold a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheKey {
    region: String,
    source: CallerSource,
    master_fingerprint: [u8; 32],
}

impl std::fmt::Debug for AwsStsMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately does not report whether a client is built: that would
        // need the lock, and a `Debug` impl that can block is a trap.
        f.debug_struct("AwsStsMinter").field("kind", &KIND).finish()
    }
}

impl AwsStsMinter {
    /// Construct the minter with no client yet. The first call builds one.
    pub fn new() -> AwsStsMinter {
        AwsStsMinter::default()
    }

    /// A minter whose HTTP layer is `http_client`, for tests.
    ///
    /// Everything above the socket is the real thing: the real signer, the
    /// real request serialiser, the real response parser. Only the bytes on
    /// the wire are canned.
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_http_client(http_client: SharedHttpClient) -> AwsStsMinter {
        AwsStsMinter {
            clients: tokio::sync::Mutex::new(None),
            http_client: Some(http_client),
        }
    }

    /// The clients for `config`, building them if they are not current.
    async fn clients(
        &self,
        config: &AwsStsConfig,
        master: &Zeroizing<String>,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<Clients>>> {
        let key = CacheKey {
            region: config.region.clone(),
            source: config.source,
            master_fingerprint: fingerprint(master),
        };
        let mut slot = self.clients.lock().await;
        if slot.as_ref().is_some_and(|c| c.key == key) {
            return Ok(slot);
        }
        let (sts, iam) = self.build_clients(config, master).await?;
        *slot = Some(Clients { key, sts, iam });
        Ok(slot)
    }

    /// Build the two clients for `config`.
    ///
    /// The two sources are built by deliberately different routes.
    /// `static` assembles the client from what the profile and the master
    /// say and nothing else: no shared config file, no environment, no
    /// instance metadata. A credential briefcred was told to use must not be
    /// silently supplemented — or overridden — by whatever happens to be in
    /// `~/.aws/config` on the machine. `ambient` is the opposite request, and
    /// gets the SDK's default chain, which is exactly what it asked for.
    async fn build_clients(
        &self,
        config: &AwsStsConfig,
        master: &Zeroizing<String>,
    ) -> Result<(aws_sdk_sts::Client, aws_sdk_iam::Client)> {
        let region = Region::new(config.region.clone());
        match config.source {
            CallerSource::Static => {
                let credentials = static_credentials(master)?;
                let sts = {
                    let mut builder = aws_sdk_sts::Config::builder()
                        .behavior_version(BehaviorVersion::latest())
                        .region(region.clone())
                        .credentials_provider(credentials.clone());
                    if let Some(http_client) = &self.http_client {
                        builder = builder.http_client(http_client.clone());
                    }
                    aws_sdk_sts::Client::from_conf(builder.build())
                };
                let iam = {
                    let mut builder = aws_sdk_iam::Config::builder()
                        .behavior_version(BehaviorVersion::latest())
                        .region(region)
                        .credentials_provider(credentials);
                    if let Some(http_client) = &self.http_client {
                        builder = builder.http_client(http_client.clone());
                    }
                    aws_sdk_iam::Client::from_conf(builder.build())
                };
                Ok((sts, iam))
            }
            CallerSource::Ambient => {
                let mut loader = aws_config::defaults(BehaviorVersion::latest()).region(region);
                if let Some(http_client) = &self.http_client {
                    loader = loader.http_client(http_client.clone());
                }
                let shared = loader.load().await;
                Ok((
                    aws_sdk_sts::Client::new(&shared),
                    aws_sdk_iam::Client::new(&shared),
                ))
            }
        }
    }
}

/// Split the master into an access key id and a secret.
///
/// On the **first** colon: an AWS secret access key is base64-ish and may
/// contain `/` and `+`, and while it does not contain `:` today, splitting on
/// the last one would make that a silent truncation rather than an error.
fn static_credentials(master: &Zeroizing<String>) -> Result<Credentials> {
    let master = master.trim();
    let (access_key_id, secret) = master.split_once(':').ok_or_else(|| {
        Error::Aws(
            "the master for an `aws-sts` credential with `source: static` must be \
             `AKIA...:secret`, an access key id and its secret separated by a colon"
                .into(),
        )
    })?;
    if access_key_id.is_empty() || secret.is_empty() {
        return Err(Error::Aws(
            "the master for an `aws-sts` credential has an empty access key id or secret".into(),
        ));
    }
    Ok(Credentials::new(
        access_key_id,
        secret,
        None,
        None,
        "briefcred-master",
    ))
}

/// A digest of the master, so the client cache notices a rotation.
fn fingerprint(master: &Zeroizing<String>) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(master.as_bytes());
    hasher.finalize().into()
}

#[async_trait::async_trait]
impl Minter for AwsStsMinter {
    fn kind(&self) -> &'static str {
        KIND
    }

    async fn mint(&self, ctx: MintCtx) -> Result<MintedCredential> {
        let config = AwsStsConfig::from_value(&ctx.config)?;
        // Checked again here rather than trusted from profile load: this
        // process receives the config over a pipe, and a session policy AWS
        // will refuse must be refused before a request is signed and sent.
        // `from_value` already ran it; this is the assertion that says so.
        if let Some(policy) = &config.session_policy {
            briefcred_core::minters::aws_sts::check_session_policy(policy)?;
        }

        let mut guard = self.clients(&config, &ctx.master).await?;
        let clients = guard.as_mut().expect("clients() always fills the slot");

        let mut request = clients
            .sts
            .assume_role()
            .role_arn(&config.role_arn)
            .role_session_name(ctx.mint_id.as_str())
            .duration_seconds(config.duration_seconds());
        if let Some(policy) = &config.session_policy {
            request = request.policy(policy);
        }
        let assumed = request.send().await.map_err(describe)?;

        let credentials = assumed
            .credentials()
            .ok_or_else(|| Error::Aws("STS returned a session with no credentials".into()))?;
        let expires_at = OffsetDateTime::from_unix_timestamp(credentials.expiration().secs())
            .map_err(|e| {
                Error::Aws(format!("STS returned an expiry briefcred cannot read: {e}"))
            })?;

        let mut fields: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
        fields.insert(
            "AWS_ACCESS_KEY_ID".into(),
            Zeroizing::new(credentials.access_key_id().to_string()),
        );
        fields.insert(
            "AWS_SECRET_ACCESS_KEY".into(),
            Zeroizing::new(credentials.secret_access_key().to_string()),
        );
        fields.insert(
            "AWS_SESSION_TOKEN".into(),
            Zeroizing::new(credentials.session_token().to_string()),
        );
        fields.insert("AWS_REGION".into(), Zeroizing::new(config.region.clone()));

        let revoke_token = serde_json::to_string(&RevokeToken {
            role_arn: config.role_arn.clone(),
            region: config.region.clone(),
        })
        .map_err(|e| Error::Aws(format!("cannot encode the revoke token: {e}")))?;

        Ok(MintedCredential {
            mint_id: ctx.mint_id,
            fields,
            expires_at,
            revoke_token,
        })
    }

    async fn revoke(&self, ctx: RevokeCtx) -> RevokeOutcome {
        let config = match AwsStsConfig::from_value(&ctx.config) {
            Ok(config) => config,
            Err(e) => return RevokeOutcome::failed(e.to_string()),
        };
        // The token crossed a persistence boundary, so it is not trusted
        // input. Without a readable one the role this session came from is
        // unknown, and attaching a deny to whatever the config now says would
        // cut off a role that never issued it.
        let token: RevokeToken = match serde_json::from_str(&ctx.revoke_token) {
            Ok(token) => token,
            Err(e) => {
                return RevokeOutcome::failed(format!(
                    "the revoke token for `{}` is unreadable ({e}), so the role that \
                     issued the session is unknown",
                    ctx.mint_id
                ))
            }
        };
        let Some(role_name) = role_name(&token.role_arn) else {
            return RevokeOutcome::failed(format!(
                "the revoke token for `{}` names `{}`, which is not a role ARN",
                ctx.mint_id, token.role_arn
            ));
        };

        // The clients are built for the region the *mint* used, not the one
        // the config names now.
        let mut for_revoke = config.clone();
        for_revoke.region = token.region.clone();
        let mut guard = match self.clients(&for_revoke, &ctx.master).await {
            Ok(guard) => guard,
            Err(e) => return RevokeOutcome::failed(e.to_string()),
        };
        let clients = guard.as_mut().expect("clients() always fills the slot");

        let cutoff = match OffsetDateTime::now_utc().format(&Rfc3339) {
            Ok(cutoff) => cutoff,
            Err(e) => return RevokeOutcome::failed(format!("cannot format the cutoff: {e}")),
        };
        let document = match revoke_policy(&cutoff) {
            Ok(document) => document,
            Err(e) => return RevokeOutcome::failed(e.to_string()),
        };

        match clients
            .iam
            .put_role_policy()
            .role_name(role_name)
            .policy_name(REVOKE_POLICY_NAME)
            .policy_document(document)
            .send()
            .await
        {
            // Accepted, not applied: IAM is eventually consistent, and a
            // credential that keeps working for a few seconds is the truth.
            Ok(_) => RevokeOutcome::EventuallyConsistent {
                propagation_estimate: PROPAGATION_ESTIMATE,
            },
            Err(e) => RevokeOutcome::failed(describe(e).to_string()),
        }
    }
}

/// The role name `iam:PutRolePolicy` wants, from a role ARN.
///
/// A role at a path has an ARN of `.../role/team/name` and a `RoleName` of
/// `name`, so the last segment is the answer and the path is not part of it.
fn role_name(role_arn: &str) -> Option<&str> {
    let resource = role_arn.split(':').nth(5)?;
    let path = resource.strip_prefix("role/")?;
    let name = path.rsplit('/').next()?;
    (!name.is_empty()).then_some(name)
}

/// The one rolling deny briefcred attaches to a role.
///
/// `aws:TokenIssueTime` is present on every request made with temporary
/// credentials and holds the moment the session was issued, so a
/// `DateLessThan` on it denies exactly the sessions that already existed. One
/// policy per role, rewritten rather than added to: two of these would each
/// name a different instant and only the later one would matter.
fn revoke_policy(cutoff_rfc3339: &str) -> Result<String> {
    serde_json::to_string(&serde_json::json!({
        "Version": POLICY_VERSION,
        "Statement": [{
            "Sid": "BriefcredRevokeOlderSessions",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "DateLessThan": { "aws:TokenIssueTime": cutoff_rfc3339 }
            }
        }]
    }))
    .map_err(|e| Error::Aws(format!("cannot encode the revoke policy: {e}")))
}

/// Reduce an SDK error to something an operator can act on.
///
/// The SDK's `Display` is a single sentence that omits the service's own
/// message, which is where the useful part is: "not authorized to perform
/// sts:AssumeRole on resource ...". The source chain carries it.
fn describe<E, R>(error: aws_sdk_sts::error::SdkError<E, R>) -> Error
where
    E: std::error::Error + aws_sdk_sts::error::ProvideErrorMetadata,
    R: std::fmt::Debug,
{
    // A transport failure — DNS, a refused connection, a timeout — carries no
    // service error at all, and reporting it as `unknown:` would hide the one
    // thing that says what to fix.
    let Some(service) = error.as_service_error() else {
        return Error::Aws(error.to_string());
    };
    let code = service.code().unwrap_or("unknown");
    let message = service
        .message()
        .map(str::to_string)
        .unwrap_or_else(|| service.to_string());
    Error::Aws(format!("{code}: {message}"))
}

#[cfg(test)]
mod tests;
