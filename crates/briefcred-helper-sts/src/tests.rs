//! Replay tests: the real signer, serialiser and parser, with canned bytes.
//!
//! [`StaticReplayClient`] replaces only the socket. Everything above it is the
//! shipping code path, so these tests fail if the request briefcred builds is
//! wrong — the wrong role, the wrong session name, a policy it forgot to send
//! — and not merely if its own bookkeeping is wrong. What comes back is the
//! XML AWS actually returns for these operations.

use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
use aws_smithy_runtime_api::client::http::SharedHttpClient;
use aws_smithy_runtime_api::shared::IntoShared as _;
use aws_smithy_types::body::SdkBody;
use briefcred_core::types::MintId;

use super::*;

const ROLE: &str = "arn:aws:iam::123456789012:role/briefcred-dev";
const MASTER: &str = "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn config(yaml: &str) -> serde_yaml::Value {
    serde_yaml::from_str(yaml).unwrap()
}

fn minimal() -> serde_yaml::Value {
    config(&format!("role_arn: {ROLE}\nregion: eu-west-1\n"))
}

fn master() -> Zeroizing<String> {
    Zeroizing::new(MASTER.to_string())
}

/// A canned `AssumeRole` success, expiring at `expiration`.
fn assume_role_ok(expiration: &str) -> String {
    format!(
        r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <AssumedRoleUser>
      <AssumedRoleId>AROAEXAMPLEID:session</AssumedRoleId>
      <Arn>arn:aws:sts::123456789012:assumed-role/briefcred-dev/session</Arn>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>the-minted-secret</SecretAccessKey>
      <SessionToken>the-minted-session-token</SessionToken>
      <Expiration>{expiration}</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata><RequestId>req-assume</RequestId></ResponseMetadata>
</AssumeRoleResponse>"#
    )
}

const PUT_ROLE_POLICY_OK: &str = r#"<PutRolePolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ResponseMetadata><RequestId>req-put</RequestId></ResponseMetadata>
</PutRolePolicyResponse>"#;

fn error_xml(code: &str, message: &str) -> String {
    format!(
        r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>{code}</Code><Message>{message}</Message></Error>
  <RequestId>req-error</RequestId>
</ErrorResponse>"#
    )
}

/// A replay client that answers every request with `status` and `body`.
///
/// The request half of each event is a placeholder: these tests read the
/// requests briefcred actually sent out of [`StaticReplayClient`] afterwards,
/// which says more than matching them up front would.
fn replay(responses: &[(u16, String)]) -> (StaticReplayClient, SharedHttpClient) {
    let events: Vec<ReplayEvent> = responses
        .iter()
        .map(|(status, body)| {
            ReplayEvent::new(
                http::Request::builder()
                    .uri("https://example.invalid/")
                    .body(SdkBody::empty())
                    .unwrap(),
                http::Response::builder()
                    .status(*status)
                    .header("content-type", "text/xml")
                    .body(SdkBody::from(body.as_str()))
                    .unwrap(),
            )
        })
        .collect();
    let client = StaticReplayClient::new(events);
    let shared = client.clone().into_shared();
    (client, shared)
}

/// The form-encoded body of the request at `index`, as a string.
fn sent_body(client: &StaticReplayClient, index: usize) -> String {
    let request = client
        .actual_requests()
        .nth(index)
        .unwrap_or_else(|| panic!("no request at index {index}"));
    String::from_utf8(request.body().bytes().unwrap_or(&[]).to_vec()).unwrap()
}

fn sent_uri(client: &StaticReplayClient, index: usize) -> String {
    client
        .actual_requests()
        .nth(index)
        .unwrap()
        .uri()
        .to_string()
}

fn mint_ctx(config: serde_yaml::Value) -> MintCtx {
    MintCtx {
        mint_id: MintId::generate(),
        profile: "dev".into(),
        credential: "aws".into(),
        config,
        master: master(),
        ttl: std::time::Duration::from_secs(900),
    }
}

#[tokio::test]
async fn assume_role_names_the_session_after_the_mint_and_returns_its_credentials() {
    let (recorder, http) = replay(&[(200, assume_role_ok("2030-01-01T00:00:00Z"))]);
    let minter = AwsStsMinter::with_http_client(http);

    let ctx = mint_ctx(minimal());
    let mint_id = ctx.mint_id.clone();
    let minted = minter.mint(ctx).await.unwrap();

    // The request that actually went out.
    let body = sent_body(&recorder, 0);
    assert!(body.contains("Action=AssumeRole"), "{body}");
    assert!(
        body.contains(&format!("RoleSessionName={mint_id}")),
        "every CloudTrail line must name the mint: {body}"
    );
    assert!(
        body.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fbriefcred-dev"),
        "{body}"
    );
    assert!(body.contains("DurationSeconds=900"), "{body}");
    assert!(
        !body.contains("Policy="),
        "a profile with no session policy must not send one: {body}"
    );
    assert!(
        sent_uri(&recorder, 0).contains("eu-west-1"),
        "the call must go to the region the profile named: {}",
        sent_uri(&recorder, 0)
    );

    // And what came back.
    assert_eq!(minted.mint_id, mint_id);
    assert_eq!(
        minted.fields["AWS_ACCESS_KEY_ID"].as_str(),
        "ASIAIOSFODNN7EXAMPLE"
    );
    assert_eq!(
        minted.fields["AWS_SECRET_ACCESS_KEY"].as_str(),
        "the-minted-secret"
    );
    assert_eq!(
        minted.fields["AWS_SESSION_TOKEN"].as_str(),
        "the-minted-session-token"
    );
    assert_eq!(minted.fields["AWS_REGION"].as_str(), "eu-west-1");
    assert_eq!(
        minted.expires_at,
        OffsetDateTime::parse("2030-01-01T00:00:00Z", &Rfc3339).unwrap(),
        "the expiry the daemon schedules the revoke off must be AWS's own"
    );
}

#[tokio::test]
async fn a_session_policy_is_sent_verbatim() {
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*"}]}"#;
    let (recorder, http) = replay(&[(200, assume_role_ok("2030-01-01T00:00:00Z"))]);
    let minter = AwsStsMinter::with_http_client(http);

    let yaml = format!(
        "role_arn: {ROLE}\nregion: eu-west-1\nduration_secs: 3600\nsession_policy: '{policy}'\n"
    );
    minter.mint(mint_ctx(config(&yaml))).await.unwrap();

    let body = sent_body(&recorder, 0);
    assert!(body.contains("Policy=%7B%22Version%22"), "{body}");
    assert!(body.contains("s3%3AGetObject"), "{body}");
    assert!(body.contains("DurationSeconds=3600"), "{body}");
}

#[tokio::test]
async fn a_session_policy_over_the_limit_is_refused_before_a_request_is_made() {
    // No replay events at all: reaching the network would panic, which is what
    // makes "before any network call" an assertion rather than a hope.
    let (recorder, http) = replay(&[]);
    let minter = AwsStsMinter::with_http_client(http);

    let filler = "a".repeat(2048);
    let policy = format!(r#"{{"Version":"2012-10-17","Sid":"{filler}"}}"#);
    let yaml = format!(
        "role_arn: {ROLE}\nregion: eu-west-1\nsession_policy: '{}'\n",
        policy.replace('\'', "''")
    );

    let err = minter.mint(mint_ctx(config(&yaml))).await.unwrap_err();
    assert!(err.to_string().contains("2048"), "{err}");
    assert_eq!(
        recorder.actual_requests().count(),
        0,
        "nothing may be sent to AWS for a policy AWS would refuse"
    );
}

#[tokio::test]
async fn a_master_that_is_not_a_key_pair_is_refused_before_a_request_is_made() {
    let (recorder, http) = replay(&[]);
    let minter = AwsStsMinter::with_http_client(http);

    let mut ctx = mint_ctx(minimal());
    ctx.master = Zeroizing::new("just-a-secret-with-no-key-id".into());
    let err = minter.mint(ctx).await.unwrap_err();

    assert!(err.to_string().contains("AKIA...:secret"), "{err}");
    assert!(
        !err.to_string().contains("just-a-secret"),
        "a master must never reach an error message: {err}"
    );
    assert_eq!(recorder.actual_requests().count(), 0);
}

#[tokio::test]
async fn the_secret_may_contain_a_colon_because_the_split_is_on_the_first_one() {
    let (recorder, http) = replay(&[(200, assume_role_ok("2030-01-01T00:00:00Z"))]);
    let minter = AwsStsMinter::with_http_client(http);

    let mut ctx = mint_ctx(minimal());
    ctx.master = Zeroizing::new("AKIAIOSFODNN7EXAMPLE:secret:with:colons".into());
    minter.mint(ctx).await.unwrap();

    // The access key id reaches the signature, so a wrong split shows up as a
    // wrong `Credential=` scope in the Authorization header.
    let authorization = recorder
        .actual_requests()
        .next()
        .unwrap()
        .headers()
        .get("authorization")
        .unwrap()
        .to_string();
    assert!(
        authorization.contains("Credential=AKIAIOSFODNN7EXAMPLE/"),
        "{authorization}"
    );
}

#[tokio::test]
async fn a_refused_assume_role_reports_the_services_own_code_and_message() {
    let (_recorder, http) = replay(&[(
        403,
        error_xml(
            "AccessDenied",
            "User: arn:aws:iam::123456789012:user/ada is not authorized to perform: sts:AssumeRole",
        ),
    )]);
    let minter = AwsStsMinter::with_http_client(http);

    let err = minter
        .mint(mint_ctx(minimal()))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("AccessDenied"), "{err}");
    assert!(err.contains("sts:AssumeRole"), "{err}");
}

#[tokio::test]
async fn revoke_attaches_one_rolling_deny_keyed_on_the_token_issue_time() {
    let (recorder, http) = replay(&[
        (200, assume_role_ok("2030-01-01T00:00:00Z")),
        (200, PUT_ROLE_POLICY_OK.to_string()),
    ]);
    let minter = AwsStsMinter::with_http_client(http);

    let ctx = mint_ctx(minimal());
    let mint_id = ctx.mint_id.clone();
    let minted = minter.mint(ctx).await.unwrap();

    let before = OffsetDateTime::now_utc();
    let outcome = minter
        .revoke(RevokeCtx {
            mint_id,
            config: minimal(),
            master: master(),
            revoke_token: minted.revoke_token,
        })
        .await;

    assert_eq!(
        outcome,
        RevokeOutcome::EventuallyConsistent {
            propagation_estimate: PROPAGATION_ESTIMATE
        },
        "IAM is eventually consistent; claiming `Revoked` would be a lie"
    );

    let body = sent_body(&recorder, 1);
    assert!(body.contains("Action=PutRolePolicy"), "{body}");
    assert!(
        body.contains("RoleName=briefcred-dev"),
        "the role name, not the ARN: {body}"
    );
    assert!(
        body.contains(&format!("PolicyName={REVOKE_POLICY_NAME}")),
        "{body}"
    );
    // The policy document is form-encoded; decoding the interesting parts is
    // enough to prove the deny is the one that was intended.
    assert!(body.contains("%22Effect%22%3A%22Deny%22"), "{body}");
    assert!(body.contains("aws%3ATokenIssueTime"), "{body}");
    assert!(body.contains("DateLessThan"), "{body}");

    // And the cutoff really is "now", not some fixed value.
    let cutoff = extract_cutoff(&body);
    let cutoff = OffsetDateTime::parse(&cutoff, &Rfc3339).expect("the cutoff must be RFC 3339");
    assert!(
        cutoff >= before && cutoff <= OffsetDateTime::now_utc(),
        "the cutoff {cutoff} must be the moment of the revoke"
    );
}

/// Pull the `aws:TokenIssueTime` value back out of a form-encoded body.
fn extract_cutoff(body: &str) -> String {
    let marker = "aws%3ATokenIssueTime%22%3A%22";
    let start = body.find(marker).expect("the condition must be present") + marker.len();
    let rest = &body[start..];
    let end = rest.find("%22").expect("the value must be terminated");
    // The only escaped characters an RFC 3339 instant carries are its colons.
    rest[..end].replace("%3A", ":")
}

#[tokio::test]
async fn a_revoke_whose_token_is_unreadable_says_what_it_could_not_find() {
    let (recorder, http) = replay(&[]);
    let minter = AwsStsMinter::with_http_client(http);

    let outcome = minter
        .revoke(RevokeCtx {
            mint_id: MintId::generate(),
            config: minimal(),
            master: master(),
            revoke_token: String::new(),
        })
        .await;

    match outcome {
        RevokeOutcome::Failed { detail } => assert!(detail.contains("role"), "{detail}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(recorder.actual_requests().count(), 0);
}

#[tokio::test]
async fn a_refused_put_role_policy_is_a_failed_outcome_rather_than_a_silent_success() {
    let (_recorder, http) = replay(&[
        (200, assume_role_ok("2030-01-01T00:00:00Z")),
        (
            403,
            error_xml(
                "AccessDenied",
                "not authorized to perform: iam:PutRolePolicy",
            ),
        ),
    ]);
    let minter = AwsStsMinter::with_http_client(http);

    let ctx = mint_ctx(minimal());
    let mint_id = ctx.mint_id.clone();
    let minted = minter.mint(ctx).await.unwrap();

    let outcome = minter
        .revoke(RevokeCtx {
            mint_id,
            config: minimal(),
            master: master(),
            revoke_token: minted.revoke_token,
        })
        .await;

    match outcome {
        RevokeOutcome::Failed { detail } => {
            assert!(detail.contains("iam:PutRolePolicy"), "{detail}");
        }
        other => panic!("a refused revoke must be retryable, not success: {other:?}"),
    }
}

#[tokio::test]
async fn the_revoke_follows_the_token_rather_than_a_config_edited_since_the_mint() {
    let (recorder, http) = replay(&[
        (200, assume_role_ok("2030-01-01T00:00:00Z")),
        (200, PUT_ROLE_POLICY_OK.to_string()),
    ]);
    let minter = AwsStsMinter::with_http_client(http);

    let ctx = mint_ctx(minimal());
    let mint_id = ctx.mint_id.clone();
    let minted = minter.mint(ctx).await.unwrap();

    // Somebody repointed the profile at another role in another region.
    let edited =
        config("role_arn: arn:aws:iam::123456789012:role/somebody-elses-role\nregion: us-east-1\n");
    minter
        .revoke(RevokeCtx {
            mint_id,
            config: edited,
            master: master(),
            revoke_token: minted.revoke_token,
        })
        .await;

    let body = sent_body(&recorder, 1);
    assert!(
        body.contains("RoleName=briefcred-dev"),
        "the deny must land on the role that issued the session: {body}"
    );
    // IAM is a global service with one endpoint per partition, so the region
    // does not appear in the URI. It is still what the revoke's client is
    // built for, which is what selects the partition and, in `aws-cn` or
    // `aws-us-gov`, a different endpoint entirely.
    assert_eq!(sent_uri(&recorder, 1), "https://iam.amazonaws.com/");
}

#[test]
fn a_role_name_is_the_last_segment_of_the_arn() {
    assert_eq!(role_name(ROLE), Some("briefcred-dev"));
    assert_eq!(
        role_name("arn:aws:iam::123456789012:role/team/nested"),
        Some("nested"),
        "a role at a path has a RoleName without the path"
    );
    assert_eq!(role_name("arn:aws:iam::123456789012:user/ada"), None);
    assert_eq!(role_name("not-an-arn"), None);
    assert_eq!(role_name("arn:aws:iam::123456789012:role/"), None);
}

#[test]
fn the_revoke_policy_is_the_document_aws_expects() {
    let document = revoke_policy("2026-09-01T12:00:00Z").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&document).unwrap();
    assert_eq!(parsed["Version"], POLICY_VERSION);
    let statement = &parsed["Statement"][0];
    assert_eq!(statement["Effect"], "Deny");
    assert_eq!(statement["Action"], "*");
    assert_eq!(statement["Resource"], "*");
    assert_eq!(
        statement["Condition"]["DateLessThan"]["aws:TokenIssueTime"],
        "2026-09-01T12:00:00Z"
    );
    assert!(
        parsed["Statement"].as_array().unwrap().len() == 1,
        "one statement: a second would only disagree with the first"
    );
}

#[test]
fn the_minter_never_debug_prints_a_master() {
    let minter = AwsStsMinter::new();
    assert_eq!(format!("{minter:?}"), "AwsStsMinter { kind: \"aws-sts\" }");
}

#[tokio::test]
async fn the_helper_shell_answers_shutdown() {
    use briefcred_proto::helper::ShutdownParams;
    let result = StsHelper::new()
        .handle(HelperParams::Shutdown(ShutdownParams {}))
        .await
        .unwrap();
    assert!(matches!(result, HelperResult::Shutdown(_)), "{result:?}");
}

/// The one test that talks to AWS, and only when told to.
///
/// `BRIEFCRED_AWS_LIVE=1` plus `BRIEFCRED_AWS_ROLE_ARN`,
/// `BRIEFCRED_AWS_REGION` and a master in `BRIEFCRED_AWS_MASTER`. It mints and
/// then deliberately does **not** revoke: a revoke denies every session of the
/// role issued before now, and a test must not do that to somebody's account.
#[tokio::test]
async fn a_live_assume_role_works_when_it_is_asked_for() {
    if std::env::var("BRIEFCRED_AWS_LIVE").as_deref() != Ok("1") {
        eprintln!("skipping: set BRIEFCRED_AWS_LIVE=1 to run this against real AWS");
        return;
    }
    let role_arn = std::env::var("BRIEFCRED_AWS_ROLE_ARN")
        .expect("BRIEFCRED_AWS_ROLE_ARN must name the role to assume");
    let region = std::env::var("BRIEFCRED_AWS_REGION").unwrap_or_else(|_| "eu-west-1".to_string());
    let master = Zeroizing::new(
        std::env::var("BRIEFCRED_AWS_MASTER")
            .expect("BRIEFCRED_AWS_MASTER must be `AKIA...:secret`"),
    );

    let mut ctx = mint_ctx(config(&format!("role_arn: {role_arn}\nregion: {region}\n")));
    ctx.master = master;
    let minted = AwsStsMinter::new().mint(ctx).await.unwrap();

    assert!(minted.fields["AWS_ACCESS_KEY_ID"].starts_with("ASIA"));
    assert!(!minted.fields["AWS_SESSION_TOKEN"].is_empty());
    assert!(minted.expires_at > OffsetDateTime::now_utc());
}
