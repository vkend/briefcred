//! The `aws-sts` credential schema.
//!
//! Only the schema. The minter itself is `briefcred-helper-sts`, because it
//! needs the AWS SDK and nothing else in briefcred does — the CLI, the hook,
//! and the daemon would all pay for that dependency to use none of it.
//!
//! What has to be here is the *contract*: the daemon validates every profile
//! it loads, so it must be able to say whether `role_arn` is an ARN and
//! whether a session policy will fit, long before any helper is started. So
//! this module registers the kind with a `validate` and no `construct`, and
//! `briefcred-helper-aws-sts` builds the minter directly.
//!
//! # What is minted
//!
//! One `sts:AssumeRole` session, with `RoleSessionName` set to the mint id so
//! every CloudTrail line naming the session names the briefcred mint that
//! created it. The credentials are `AWS_ACCESS_KEY_ID`,
//! `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` and `AWS_REGION`.
//!
//! # What cannot be minted
//!
//! A session policy over [`MAX_SESSION_POLICY_CHARS`] plaintext characters.
//! AWS refuses it, and it refuses it *after* the request has been signed and
//! sent, with a message about "packed policy size" that names a percentage
//! rather than the limit. briefcred refuses it at profile load, where the
//! policy is on the screen in front of whoever wrote it.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The `kind` string profiles use to select this minter.
pub const KIND: &str = "aws-sts";

/// The longest session policy AWS accepts, in plaintext characters.
///
/// The documented limit on `AssumeRole`'s `Policy` parameter. AWS compresses
/// the policy before transmitting it and reports the compressed size as a
/// percentage of a separate budget, so the plaintext limit is the only one
/// that can be checked before the call.
pub const MAX_SESSION_POLICY_CHARS: usize = 2048;

/// The shortest session AWS will issue.
pub const MIN_DURATION_SECS: u64 = 900;

/// The longest session AWS will issue for a role, subject to the role's own
/// `MaxSessionDuration`, which briefcred cannot see from here.
pub const MAX_DURATION_SECS: u64 = 43_200;

/// The inline policy revoke attaches to a role.
///
/// One policy per role, rewritten rather than added to: the deny is expressed
/// in terms of a timestamp, so a second revoke supersedes the first and two
/// policies would only ever disagree.
pub const REVOKE_POLICY_NAME: &str = "briefcred-revoke-older-sessions";

/// Where the credentials that call `AssumeRole` come from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CallerSource {
    /// From the master credential, as `AKIA...:secret` split on the first `:`.
    ///
    /// The default, because it is the one briefcred can reason about: the
    /// credential is in the platform key store, the session holds it only
    /// while it is open, and closing the session takes it away.
    #[default]
    Static,
    /// From the AWS default provider chain — environment, shared config file,
    /// SSO cache, instance metadata.
    ///
    /// Weaker on purpose, and never the default. Whatever the chain finds is
    /// outside briefcred's control: it is not in the key store, it is not
    /// bounded by the session, and briefcred cannot say what it is. A profile
    /// that wants it has to say so.
    Ambient,
}

/// The `config` block of an `aws-sts` credential spec.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AwsStsConfig {
    /// The role to assume, as a full ARN.
    pub role_arn: String,
    /// The region the STS and IAM calls are made in.
    pub region: String,
    /// An inline policy narrowing the session, as JSON.
    ///
    /// A session policy can only take permissions away, so it is the right
    /// place to say "this session may read one bucket" even when the role
    /// itself can do more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_policy: Option<String>,
    /// Where the credentials that call `AssumeRole` come from.
    #[serde(default)]
    pub source: CallerSource,
    /// The session's lifetime, in seconds.
    ///
    /// Separate from the credential's `ttl_secs` because AWS enforces its own
    /// bounds on it and the role has a `MaxSessionDuration` of its own.
    #[serde(default = "default_duration_secs")]
    pub duration_secs: u64,
}

fn default_duration_secs() -> u64 {
    MIN_DURATION_SECS
}

impl AwsStsConfig {
    /// Interpret a credential spec's `config` block.
    pub fn from_value(value: &serde_yaml::Value) -> Result<AwsStsConfig> {
        let config: AwsStsConfig =
            serde_yaml::from_value(value.clone()).map_err(|e| Error::MinterConfig {
                kind: KIND,
                message: e.to_string(),
            })?;
        config.validate()?;
        Ok(config)
    }

    /// Everything that can be checked without talking to AWS.
    pub fn validate(&self) -> Result<()> {
        if !is_role_arn(&self.role_arn) {
            return Err(config_error(format!(
                "`role_arn: {}` is not an IAM role ARN; it must look like \
                 `arn:aws:iam::123456789012:role/my-role`",
                self.role_arn
            )));
        }
        if !is_region(&self.region) {
            return Err(config_error(format!(
                "`region: {}` is not an AWS region code such as `eu-west-1`",
                self.region
            )));
        }
        if !(MIN_DURATION_SECS..=MAX_DURATION_SECS).contains(&self.duration_secs) {
            return Err(config_error(format!(
                "`duration_secs: {}` is outside the {MIN_DURATION_SECS}..={MAX_DURATION_SECS} \
                 seconds AWS will issue; the role's own MaxSessionDuration may be shorter still",
                self.duration_secs
            )));
        }
        if let Some(policy) = &self.session_policy {
            check_session_policy(policy)?;
        }
        Ok(())
    }

    /// The session's lifetime as AWS wants it: whole seconds, as an `i32`.
    ///
    /// Infallible because [`AwsStsConfig::validate`] has already bounded it.
    pub fn duration_seconds(&self) -> i32 {
        self.duration_secs as i32
    }
}

/// Refuse a session policy AWS would refuse, before anything is sent.
///
/// Two checks, and both matter. The length is the documented limit. The JSON
/// parse is because an unparsable policy is refused by AWS with
/// `MalformedPolicyDocument` and no indication of where, whereas `serde_json`
/// reports the line and column.
pub fn check_session_policy(policy: &str) -> Result<()> {
    if policy.chars().count() > MAX_SESSION_POLICY_CHARS {
        return Err(config_error(format!(
            "`session_policy` is {} characters; AWS accepts at most {MAX_SESSION_POLICY_CHARS}",
            policy.chars().count()
        )));
    }
    let parsed: serde_json::Value = serde_json::from_str(policy)
        .map_err(|e| config_error(format!("`session_policy` is not valid JSON: {e}")))?;
    if !parsed.is_object() {
        return Err(config_error(
            "`session_policy` must be a JSON policy document, which is an object",
        ));
    }
    Ok(())
}

/// `arn:<partition>:iam::<account>:role/<path>`.
///
/// Deliberately strict about the service and the resource type: an ARN for a
/// user, or for a role in a service briefcred does not call, would be accepted
/// by this crate and then refused by AWS with a signature error that says
/// nothing about the ARN.
fn is_role_arn(value: &str) -> bool {
    let mut parts = value.splitn(6, ':');
    let (Some("arn"), Some(partition), Some("iam"), Some(""), Some(account), Some(resource)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    let path = match resource.strip_prefix("role/") {
        Some(path) => path,
        None => return false,
    };
    !partition.is_empty()
        && partition
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && account.len() == 12
        && account.chars().all(|c| c.is_ascii_digit())
        && !path.is_empty()
}

/// `eu-west-1`, `us-gov-east-1`, `cn-north-1`: lowercase words and a digit.
fn is_region(value: &str) -> bool {
    let mut parts = value.split('-');
    let enough = parts.clone().count() >= 3;
    let last_is_number = parts
        .next_back()
        .is_some_and(|last| !last.is_empty() && last.chars().all(|c| c.is_ascii_digit()));
    enough
        && last_is_number
        && parts.all(|word| !word.is_empty() && word.chars().all(|c| c.is_ascii_lowercase()))
}

fn config_error(message: impl Into<String>) -> Error {
    Error::MinterConfig {
        kind: KIND,
        message: message.into(),
    }
}

// Registered with a schema and no implementation: see the module docs. The
// daemon can therefore load a profile naming `aws-sts` and tell an operator
// exactly what is wrong with it, while the minting itself happens in
// `briefcred-helper-aws-sts`.
inventory::submit! {
    crate::registry::MinterFactory {
        kind: KIND,
        hosting: crate::registry::Hosting::Helper,
        validate: |config| {
            AwsStsConfig::from_value(config)?;
            Ok(())
        },
        construct: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry;

    const ROLE: &str = "arn:aws:iam::123456789012:role/briefcred-dev";

    fn config(yaml: &str) -> serde_yaml::Value {
        serde_yaml::from_str(yaml).unwrap()
    }

    fn minimal() -> serde_yaml::Value {
        config(&format!("role_arn: {ROLE}\nregion: eu-west-1\n"))
    }

    #[test]
    fn a_minimal_config_parses_with_the_documented_defaults() {
        let parsed = AwsStsConfig::from_value(&minimal()).unwrap();
        assert_eq!(parsed.role_arn, ROLE);
        assert_eq!(parsed.region, "eu-west-1");
        assert_eq!(parsed.source, CallerSource::Static);
        assert_eq!(parsed.duration_secs, MIN_DURATION_SECS);
        assert!(parsed.session_policy.is_none());
    }

    #[test]
    fn the_ambient_source_has_to_be_asked_for_by_name() {
        let parsed = AwsStsConfig::from_value(&config(&format!(
            "role_arn: {ROLE}\nregion: eu-west-1\nsource: ambient\n"
        )))
        .unwrap();
        assert_eq!(parsed.source, CallerSource::Ambient);
    }

    #[test]
    fn a_typo_in_the_config_is_refused_and_names_itself() {
        let err = AwsStsConfig::from_value(&config(&format!(
            "role_arn: {ROLE}\nregion: eu-west-1\nsession_polcy: '{{}}'\n"
        )))
        .unwrap_err();
        assert!(matches!(err, Error::MinterConfig { kind, .. } if kind == KIND));
        assert!(err.to_string().contains("session_polcy"), "{err}");
    }

    #[test]
    fn something_that_is_not_a_role_arn_is_refused() {
        for bad in [
            "briefcred-dev",
            "arn:aws:iam::123456789012:user/ada",
            "arn:aws:s3:::a-bucket",
            "arn:aws:iam::12345:role/short-account",
            "arn:aws:iam::123456789012:role/",
            "arn::iam::123456789012:role/no-partition",
        ] {
            let yaml = format!("role_arn: \"{bad}\"\nregion: eu-west-1\n");
            let err = AwsStsConfig::from_value(&config(&yaml))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("role ARN"),
                "`{bad}` was accepted or misreported: {err}"
            );
        }
    }

    #[test]
    fn a_role_arn_in_another_partition_is_still_a_role_arn() {
        for good in [
            "arn:aws-us-gov:iam::123456789012:role/gov",
            "arn:aws-cn:iam::123456789012:role/team/nested-path",
        ] {
            let yaml = format!("role_arn: \"{good}\"\nregion: us-gov-east-1\n");
            AwsStsConfig::from_value(&config(&yaml))
                .unwrap_or_else(|e| panic!("`{good}` should be accepted: {e}"));
        }
    }

    #[test]
    fn something_that_is_not_a_region_is_refused() {
        for bad in ["", "EU-WEST-1", "eu-west", "eu--1", "somewhere"] {
            let yaml = format!("role_arn: {ROLE}\nregion: \"{bad}\"\n");
            assert!(
                AwsStsConfig::from_value(&config(&yaml)).is_err(),
                "`{bad}` must not be accepted as a region"
            );
        }
    }

    #[test]
    fn a_duration_aws_will_not_issue_is_refused_with_the_bounds() {
        for bad in [0, 899, MAX_DURATION_SECS + 1] {
            let yaml = format!("role_arn: {ROLE}\nregion: eu-west-1\nduration_secs: {bad}\n");
            let err = AwsStsConfig::from_value(&config(&yaml))
                .unwrap_err()
                .to_string();
            assert!(err.contains("900..=43200"), "{err}");
        }
    }

    #[test]
    fn a_session_policy_over_the_limit_is_refused_before_anything_is_sent() {
        // A policy document that is syntactically fine and simply too long.
        let filler = "a".repeat(MAX_SESSION_POLICY_CHARS);
        let policy = format!("{{\"Sid\":\"{filler}\"}}");
        let err = check_session_policy(&policy).unwrap_err().to_string();
        assert!(err.contains(&policy.chars().count().to_string()), "{err}");
        assert!(err.contains("2048"), "{err}");
    }

    #[test]
    fn a_session_policy_exactly_at_the_limit_is_accepted() {
        let prefix = "{\"Sid\":\"";
        let suffix = "\"}";
        let filler = "a".repeat(MAX_SESSION_POLICY_CHARS - prefix.len() - suffix.len());
        let policy = format!("{prefix}{filler}{suffix}");
        assert_eq!(policy.chars().count(), MAX_SESSION_POLICY_CHARS);
        check_session_policy(&policy).unwrap();
    }

    #[test]
    fn the_limit_is_characters_rather_than_bytes() {
        // AWS counts the policy in characters. A policy of multi-byte
        // characters that is under the limit must not be refused for being
        // over it in bytes.
        let filler = "é".repeat(MAX_SESSION_POLICY_CHARS - 12);
        let policy = format!("{{\"Sid\":\"{filler}\"}}");
        assert!(
            policy.len() > MAX_SESSION_POLICY_CHARS,
            "the bytes exceed it"
        );
        check_session_policy(&policy).unwrap();
    }

    #[test]
    fn a_session_policy_that_is_not_a_json_object_is_refused() {
        assert!(check_session_policy("not json at all").is_err());
        assert!(check_session_policy("[]").is_err());
        assert!(check_session_policy("\"a string\"").is_err());
        check_session_policy("{\"Version\":\"2012-10-17\"}").unwrap();
    }

    #[test]
    fn the_registry_knows_the_kind_but_not_how_to_build_it() {
        let registry = Registry::discover();
        assert!(registry.contains(KIND), "{registry:?}");
        registry.validate(KIND, &minimal()).unwrap();

        // Every binary can reject a bad profile...
        let bad = config("role_arn: nonsense\nregion: eu-west-1\n");
        assert!(registry.validate(KIND, &bad).is_err());

        // ...but only the helper can mint, and the daemon says so plainly
        // rather than pretending it has a minter.
        let err = registry.build(KIND, &minimal()).unwrap_err().to_string();
        assert!(err.contains("briefcred-helper-aws-sts"), "{err}");
    }
}
