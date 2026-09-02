//! The Cedar policy a profile attaches to its HTTP traffic.
//!
//! The proxy has to answer one question per request: may *this session* make
//! *this request*. Everything briefcred knows about the request that is safe to
//! decide on — the method, the scheme, the host, and the path — is put into a
//! Cedar request, and the profile's own policy text decides.
//!
//! Three rules shape the whole module:
//!
//! - **The schema is fixed.** It lives here, not in the profile, so a policy
//!   cannot invent an attribute the proxy does not populate and then silently
//!   never match.
//! - **A policy is validated when the profile is loaded**, against that schema,
//!   so a typo is a startup error next to the file rather than a request that
//!   is quietly denied at three in the morning.
//! - **Default deny.** No policy, or no `permit` that matches, is a denial. The
//!   only escape is [`PolicyMode::Observe`], which logs the denial it would
//!   have made and lets the request through.
//!
//! The query string is deliberately absent. It routinely carries credential
//! material, and a policy that could match on it would be a policy whose
//! evaluation had to hold that material.

use std::collections::HashMap;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityUid, PolicySet, RestrictedExpression,
    Schema, ValidationMode, Validator,
};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The Cedar schema every briefcred policy is written against.
///
/// One principal type, one resource type, and one action per HTTP method that
/// the proxy forwards. The methods are grouped under `Action::"http"` so a
/// policy can permit all of them in one clause without listing seven.
pub const SCHEMA_SOURCE: &str = r#"
entity Session;

entity Http = {
  host: String,
  path: String,
  scheme: String,
};

action http;

action GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS in [http]
  appliesTo {
    principal: [Session],
    resource: [Http]
  };
"#;

/// The HTTP methods the proxy will forward at all.
///
/// A method that is not here has no action in the schema, so no policy could
/// ever permit it and the proxy refuses it before it reaches Cedar. That is a
/// deliberate allowlist: `TRACE` and `CONNECT`-in-`CONNECT` are not things a
/// credential-bearing agent has any business sending.
pub const METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/// Whether a policy decision is enforced or merely recorded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    /// A denial stops the request. The default, and the only safe default.
    #[default]
    Enforce,
    /// A denial is written to the audit log as `would_deny` and the request is
    /// forwarded anyway.
    ///
    /// This is how a policy is written for a real workload: run in observe,
    /// read the `would_deny` rows, widen the policy until they stop, then
    /// promote to `enforce`. It is not a mode to leave a profile in.
    Observe,
}

impl PolicyMode {
    /// The name used in the profile schema and in audit rows.
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyMode::Enforce => "enforce",
            PolicyMode::Observe => "observe",
        }
    }
}

/// What the proxy does with one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A policy permitted it. Forward it.
    Allow,
    /// Nothing permitted it, and the profile is enforcing. Refuse it.
    Deny,
    /// Nothing permitted it, but the profile is observing. Forward it, and
    /// record that enforcing would have refused.
    WouldDeny,
}

impl Outcome {
    /// The label the audit row and the metrics counter carry.
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Deny => "deny",
            Outcome::WouldDeny => "would_deny",
        }
    }

    /// Whether the request is forwarded upstream.
    pub fn forwards(&self) -> bool {
        matches!(self, Outcome::Allow | Outcome::WouldDeny)
    }
}

/// The one request the proxy asks a policy about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest<'a> {
    /// The uppercase HTTP method.
    pub method: &'a str,
    /// The scheme the client asked for: `http` or `https`.
    pub scheme: &'a str,
    /// The host, without the port.
    pub host: &'a str,
    /// The path, with the query string already stripped.
    pub path: &'a str,
}

/// A profile's compiled policy.
///
/// Compiled once at profile load and evaluated per request: parsing Cedar
/// source on every forwarded request would put a parser on the hot path for no
/// benefit, and would let a policy that stopped compiling become a runtime
/// failure rather than a load-time one.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    policies: PolicySet,
}

/// The fixed schema, parsed once.
///
/// `expect` rather than a fallible accessor: [`SCHEMA_SOURCE`] is a constant in
/// this file, and a schema that does not parse is a bug that every test in the
/// module catches before anything ships.
fn schema() -> &'static Schema {
    static SCHEMA: std::sync::OnceLock<Schema> = std::sync::OnceLock::new();
    SCHEMA.get_or_init(|| {
        Schema::from_cedarschema_str(SCHEMA_SOURCE)
            .expect("the built-in Cedar schema parses")
            .0
    })
}

impl CompiledPolicy {
    /// Parse `source` and validate every policy in it against the schema.
    ///
    /// Validation is strict: a policy that references an entity type or an
    /// attribute the schema does not have is rejected here rather than being
    /// carried to production as a clause that can never match.
    pub fn parse(source: &str) -> Result<CompiledPolicy> {
        let policies = PolicySet::from_str(source)
            .map_err(|e| Error::profile(format!("`policy` is not valid Cedar: {e}")))?;

        let result = Validator::new(schema().clone()).validate(&policies, ValidationMode::Strict);
        if !result.validation_passed() {
            let complaints: Vec<String> =
                result.validation_errors().map(|e| e.to_string()).collect();
            return Err(Error::profile(format!(
                "`policy` does not match the briefcred Cedar schema: {}",
                complaints.join("; ")
            )));
        }
        Ok(CompiledPolicy { policies })
    }

    /// Decide one request for the session `sid`, under `mode`.
    ///
    /// A request the schema cannot express — an unknown method, a host or path
    /// Cedar will not accept as an entity id — is a denial rather than an
    /// error. The proxy has to answer every request one way or the other, and
    /// "briefcred could not form the question" is not a reason to forward a
    /// credential.
    pub fn decide(&self, sid: &str, request: &HttpRequest<'_>, mode: PolicyMode) -> Outcome {
        match self.permits(sid, request) {
            Some(true) => Outcome::Allow,
            _ => deny(mode),
        }
    }

    /// `Some(true)` when a policy permits, `Some(false)` when none does, and
    /// `None` when the request could not be formed at all.
    fn permits(&self, sid: &str, request: &HttpRequest<'_>) -> Option<bool> {
        if !METHODS.contains(&request.method) {
            return None;
        }
        let principal = uid("Session", sid)?;
        let action = EntityUid::from_str(&format!("Action::\"{}\"", request.method)).ok()?;
        let resource = uid("Http", &format!("{}{}", request.host, request.path))?;

        let attrs = HashMap::from([
            ("host".to_string(), string_expr(request.host)),
            ("path".to_string(), string_expr(request.path)),
            ("scheme".to_string(), string_expr(request.scheme)),
        ]);
        let entities = Entities::from_entities(
            [
                Entity::new_no_attrs(principal.clone(), Default::default()),
                Entity::new(resource.clone(), attrs, Default::default()).ok()?,
            ],
            Some(schema()),
        )
        .ok()?;

        let cedar_request = cedar_policy::Request::new(
            principal,
            action,
            resource,
            Context::empty(),
            Some(schema()),
        )
        .ok()?;
        let response = Authorizer::new().is_authorized(&cedar_request, &self.policies, &entities);
        Some(response.decision() == Decision::Allow)
    }
}

/// The decision when nothing permitted the request.
///
/// The one place the observe/enforce split is applied, so the two modes cannot
/// drift apart: observing changes what happens to a denial, never whether one
/// was reached.
pub fn deny(mode: PolicyMode) -> Outcome {
    match mode {
        PolicyMode::Enforce => Outcome::Deny,
        PolicyMode::Observe => Outcome::WouldDeny,
    }
}

/// A Cedar entity uid, or `None` if the id is not one Cedar accepts.
fn uid(entity_type: &str, id: &str) -> Option<EntityUid> {
    let type_name = cedar_policy::EntityTypeName::from_str(entity_type).ok()?;
    let id = cedar_policy::EntityId::from_str(id).ok()?;
    Some(EntityUid::from_type_name_and_id(type_name, id))
}

/// A Cedar string literal, escaped.
///
/// Built through `serde_json` rather than by hand: a host or path is attacker-
/// influenced text, and hand-escaping it into a Cedar expression is exactly the
/// kind of quoting bug that turns "match this path" into "match anything".
fn string_expr(value: &str) -> RestrictedExpression {
    RestrictedExpression::new_string(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW_MODELS: &str = r#"
permit(
  principal,
  action in [Action::"http"],
  resource
) when {
  resource.host == "api.openai.com" && resource.path == "/v1/models"
};
"#;

    fn request<'a>(method: &'a str, host: &'a str, path: &'a str) -> HttpRequest<'a> {
        HttpRequest {
            method,
            scheme: "https",
            host,
            path,
        }
    }

    #[test]
    fn the_built_in_schema_parses() {
        assert!(
            schema().action_groups().count() > 0,
            "the `http` action group must exist"
        );
    }

    #[test]
    fn a_policy_that_matches_permits() {
        let policy = CompiledPolicy::parse(ALLOW_MODELS).unwrap();
        assert_eq!(
            policy.decide(
                "s1",
                &request("GET", "api.openai.com", "/v1/models"),
                PolicyMode::Enforce
            ),
            Outcome::Allow
        );
    }

    #[test]
    fn a_path_the_policy_does_not_name_is_denied() {
        let policy = CompiledPolicy::parse(ALLOW_MODELS).unwrap();
        assert_eq!(
            policy.decide(
                "s1",
                &request("GET", "api.openai.com", "/v1/chat/completions"),
                PolicyMode::Enforce
            ),
            Outcome::Deny
        );
    }

    #[test]
    fn a_host_the_policy_does_not_name_is_denied() {
        let policy = CompiledPolicy::parse(ALLOW_MODELS).unwrap();
        assert_eq!(
            policy.decide(
                "s1",
                &request("GET", "evil.example", "/v1/models"),
                PolicyMode::Enforce
            ),
            Outcome::Deny
        );
    }

    #[test]
    fn observe_mode_turns_a_denial_into_a_would_deny_that_still_forwards() {
        let policy = CompiledPolicy::parse(ALLOW_MODELS).unwrap();
        let outcome = policy.decide(
            "s1",
            &request("POST", "api.openai.com", "/v1/chat/completions"),
            PolicyMode::Observe,
        );
        assert_eq!(outcome, Outcome::WouldDeny);
        assert!(outcome.forwards(), "observe mode must not block");
        assert!(!Outcome::Deny.forwards());
        assert!(Outcome::Allow.forwards());
    }

    #[test]
    fn observe_mode_does_not_change_an_allow() {
        let policy = CompiledPolicy::parse(ALLOW_MODELS).unwrap();
        assert_eq!(
            policy.decide(
                "s1",
                &request("GET", "api.openai.com", "/v1/models"),
                PolicyMode::Observe
            ),
            Outcome::Allow
        );
    }

    #[test]
    fn an_empty_policy_denies_everything() {
        let policy = CompiledPolicy::parse("").unwrap();
        assert_eq!(
            policy.decide(
                "s1",
                &request("GET", "api.openai.com", "/v1/models"),
                PolicyMode::Enforce
            ),
            Outcome::Deny
        );
    }

    #[test]
    fn a_forbid_beats_a_permit() {
        let source = format!(
            "{ALLOW_MODELS}\nforbid(principal, action, resource) when {{ resource.host == \"api.openai.com\" }};\n"
        );
        let policy = CompiledPolicy::parse(&source).unwrap();
        assert_eq!(
            policy.decide(
                "s1",
                &request("GET", "api.openai.com", "/v1/models"),
                PolicyMode::Enforce
            ),
            Outcome::Deny
        );
    }

    #[test]
    fn a_policy_may_name_one_session_and_not_another() {
        let source = r#"
permit(principal == Session::"s1", action in [Action::"http"], resource);
"#;
        let policy = CompiledPolicy::parse(source).unwrap();
        let req = request("GET", "api.openai.com", "/v1/models");
        assert_eq!(
            policy.decide("s1", &req, PolicyMode::Enforce),
            Outcome::Allow
        );
        assert_eq!(
            policy.decide("s2", &req, PolicyMode::Enforce),
            Outcome::Deny
        );
    }

    #[test]
    fn a_policy_may_match_on_the_scheme() {
        let source = r#"
permit(principal, action in [Action::"http"], resource)
when { resource.scheme == "https" };
"#;
        let policy = CompiledPolicy::parse(source).unwrap();
        assert_eq!(
            policy.decide("s1", &request("GET", "a.test", "/"), PolicyMode::Enforce),
            Outcome::Allow
        );
        let plain = HttpRequest {
            method: "GET",
            scheme: "http",
            host: "a.test",
            path: "/",
        };
        assert_eq!(
            policy.decide("s1", &plain, PolicyMode::Enforce),
            Outcome::Deny
        );
    }

    #[test]
    fn one_action_permits_only_that_method() {
        let source = r#"permit(principal, action == Action::"GET", resource);"#;
        let policy = CompiledPolicy::parse(source).unwrap();
        assert_eq!(
            policy.decide("s1", &request("GET", "a.test", "/"), PolicyMode::Enforce),
            Outcome::Allow
        );
        assert_eq!(
            policy.decide("s1", &request("POST", "a.test", "/"), PolicyMode::Enforce),
            Outcome::Deny
        );
    }

    #[test]
    fn a_method_the_schema_does_not_have_is_denied_rather_than_erroring() {
        let source = r#"permit(principal, action in [Action::"http"], resource);"#;
        let policy = CompiledPolicy::parse(source).unwrap();
        assert_eq!(
            policy.decide("s1", &request("TRACE", "a.test", "/"), PolicyMode::Enforce),
            Outcome::Deny
        );
    }

    #[test]
    fn a_host_containing_a_quote_cannot_smuggle_a_clause_past_the_policy() {
        // `resource.host` is an attribute value, not a fragment of source
        // text: a host that tries to close the string must simply not match.
        let policy = CompiledPolicy::parse(ALLOW_MODELS).unwrap();
        assert_eq!(
            policy.decide(
                "s1",
                &request("GET", "\" || true || \"", "/v1/models"),
                PolicyMode::Enforce
            ),
            Outcome::Deny
        );
    }

    #[test]
    fn a_policy_that_does_not_parse_is_rejected_by_name() {
        let err = CompiledPolicy::parse("permit(principal").unwrap_err();
        assert!(err.to_string().contains("not valid Cedar"), "{err}");
    }

    #[test]
    fn a_policy_naming_an_attribute_the_schema_lacks_is_rejected_at_parse() {
        let source = r#"permit(principal, action in [Action::"http"], resource) when { resource.query == "x" };"#;
        let err = CompiledPolicy::parse(source).unwrap_err();
        assert!(err.to_string().contains("Cedar schema"), "{err}");
    }

    #[test]
    fn a_policy_naming_an_entity_type_the_schema_lacks_is_rejected_at_parse() {
        let source = r#"permit(principal == User::"bob", action, resource);"#;
        assert!(CompiledPolicy::parse(source).is_err());
    }

    #[test]
    fn the_mode_names_match_the_profile_schema_spelling() {
        assert_eq!(PolicyMode::default(), PolicyMode::Enforce);
        assert_eq!(PolicyMode::Enforce.as_str(), "enforce");
        assert_eq!(PolicyMode::Observe.as_str(), "observe");
    }

    #[test]
    fn the_outcome_labels_are_the_ones_the_audit_row_documents() {
        assert_eq!(Outcome::Allow.label(), "allow");
        assert_eq!(Outcome::Deny.label(), "deny");
        assert_eq!(Outcome::WouldDeny.label(), "would_deny");
    }
}
