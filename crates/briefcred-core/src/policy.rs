//! The Cedar policy a profile attaches to its HTTP traffic.
//!
//! The proxy has to answer one question per request: may *this session* make
//! *this request*. Everything briefcred knows about the request that is safe to
//! decide on — the method, the scheme, the host, and the path — is put into a
//! Cedar request, along with a [`RequestContext`] saying what the session has
//! already done and what time it is, and the profile's own policy text decides.
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
use time::OffsetDateTime;

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
    resource: [Http],
    context: {
      hour: Long,
      weekday: Long,
      resp_bytes_so_far: Long,
      requests_so_far: Long,
    }
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
    /// What the session has done up to now, and what time it is.
    pub context: RequestContext,
}

/// The Cedar `context` a request carries.
///
/// Everything here is about the *session* and the *clock* rather than about
/// the request, which is what makes it worth having as a separate thing: the
/// resource attributes say what is being asked for, and this says whether the
/// session is still in a position to be asking.
///
/// All four are `Long` in the schema, because Cedar has no unsigned type and
/// no clock of its own. A byte count that overflowed an `i64` would be nine
/// exabytes through one proxy session, so the saturating conversion below is
/// arithmetic hygiene rather than a case anyone will meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RequestContext {
    /// Hour of the day in UTC, 0 to 23.
    ///
    /// UTC and not local time. A policy that meant "business hours" and got
    /// them from whatever timezone the daemon happened to be started in would
    /// be a policy that silently changed meaning when a laptop travelled.
    pub hour: i64,
    /// Day of the week, 0 for Monday through 6 for Sunday, in UTC.
    pub weekday: i64,
    /// Response bytes returned to this session before this request.
    ///
    /// Before, not including: the size of the response being decided on is not
    /// known until it has been sent, so a budget written against this counts
    /// what the session has already been given.
    pub resp_bytes_so_far: i64,
    /// Requests this session has made through the proxy before this one.
    ///
    /// So the first request of a session sees `0`, and
    /// `context.requests_so_far < 100` permits exactly one hundred.
    pub requests_so_far: i64,
}

impl RequestContext {
    /// The context for a session that has made `requests` requests and been
    /// sent `resp_bytes` bytes, at `now`.
    pub fn new(now: OffsetDateTime, requests: u64, resp_bytes: u64) -> RequestContext {
        RequestContext {
            hour: i64::from(now.hour()),
            // `time` numbers Monday from one; the schema numbers it from zero,
            // because `0..6` is what somebody writing `context.weekday <= 4`
            // for "weekdays" expects.
            weekday: i64::from(now.weekday().number_from_monday()) - 1,
            resp_bytes_so_far: clamp_to_long(resp_bytes),
            requests_so_far: clamp_to_long(requests),
        }
    }

    /// The four attributes, as Cedar restricted expressions.
    fn attrs(&self) -> HashMap<String, RestrictedExpression> {
        HashMap::from([
            (
                "hour".to_string(),
                RestrictedExpression::new_long(self.hour),
            ),
            (
                "weekday".to_string(),
                RestrictedExpression::new_long(self.weekday),
            ),
            (
                "resp_bytes_so_far".to_string(),
                RestrictedExpression::new_long(self.resp_bytes_so_far),
            ),
            (
                "requests_so_far".to_string(),
                RestrictedExpression::new_long(self.requests_so_far),
            ),
        ])
    }
}

/// A counter as the `Long` Cedar can hold, saturating rather than wrapping.
fn clamp_to_long(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
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

        let context = Context::from_pairs(request.context.attrs()).ok()?;
        let cedar_request =
            cedar_policy::Request::new(principal, action, resource, context, Some(schema()))
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
            context: RequestContext::default(),
        }
    }

    /// The same request, with a context a test has set up.
    fn in_context<'a>(
        method: &'a str,
        host: &'a str,
        path: &'a str,
        context: RequestContext,
    ) -> HttpRequest<'a> {
        HttpRequest {
            context,
            ..request(method, host, path)
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
            scheme: "http",
            ..request("GET", "a.test", "/")
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
    fn a_policy_may_hold_a_request_to_a_window_of_the_day() {
        let source = r#"
permit(principal, action in [Action::"http"], resource)
when { context.hour >= 9 && context.hour < 18 };
"#;
        let policy = CompiledPolicy::parse(source).unwrap();
        let at = |hour: i64| {
            let context = RequestContext {
                hour,
                ..RequestContext::default()
            };
            policy.decide(
                "s1",
                &in_context("GET", "a.test", "/", context),
                PolicyMode::Enforce,
            )
        };
        assert_eq!(at(9), Outcome::Allow);
        assert_eq!(at(17), Outcome::Allow);
        assert_eq!(at(18), Outcome::Deny);
        assert_eq!(at(3), Outcome::Deny);
    }

    #[test]
    fn a_policy_may_hold_a_session_to_a_byte_budget() {
        let source = r#"
permit(principal, action in [Action::"http"], resource)
when { context.resp_bytes_so_far < 1048576 };
"#;
        let policy = CompiledPolicy::parse(source).unwrap();
        let after = |bytes: i64| {
            let context = RequestContext {
                resp_bytes_so_far: bytes,
                ..RequestContext::default()
            };
            policy.decide(
                "s1",
                &in_context("GET", "a.test", "/", context),
                PolicyMode::Enforce,
            )
        };
        assert_eq!(after(0), Outcome::Allow);
        assert_eq!(after(1_048_575), Outcome::Allow);
        assert_eq!(after(1_048_576), Outcome::Deny);
    }

    #[test]
    fn a_policy_counting_requests_permits_exactly_the_number_it_names() {
        let source = r#"
permit(principal, action in [Action::"http"], resource)
when { context.requests_so_far < 3 };
"#;
        let policy = CompiledPolicy::parse(source).unwrap();
        let outcomes: Vec<Outcome> = (0..5)
            .map(|n| {
                let context = RequestContext {
                    requests_so_far: n,
                    ..RequestContext::default()
                };
                policy.decide(
                    "s1",
                    &in_context("GET", "a.test", "/", context),
                    PolicyMode::Enforce,
                )
            })
            .collect();
        assert_eq!(
            outcomes,
            [
                Outcome::Allow,
                Outcome::Allow,
                Outcome::Allow,
                Outcome::Deny,
                Outcome::Deny
            ],
            "`requests_so_far` counts what came before, so `< 3` is three requests"
        );
    }

    #[test]
    fn a_policy_naming_a_context_attribute_the_schema_lacks_is_rejected_at_parse() {
        let source = r#"permit(principal, action in [Action::"http"], resource) when { context.minute == 0 };"#;
        let err = CompiledPolicy::parse(source).unwrap_err();
        assert!(err.to_string().contains("Cedar schema"), "{err}");
    }

    #[test]
    fn the_context_numbers_the_week_from_monday_and_the_day_from_midnight() {
        // 2026-09-02 is a Wednesday.
        let wednesday = time::macros::datetime!(2026-09-02 14:30:00 UTC);
        let context = RequestContext::new(wednesday, 7, 4096);
        assert_eq!(context.hour, 14);
        assert_eq!(context.weekday, 2, "Monday is 0, so Wednesday is 2");
        assert_eq!(context.requests_so_far, 7);
        assert_eq!(context.resp_bytes_so_far, 4096);

        let monday = time::macros::datetime!(2026-08-31 00:00:00 UTC);
        assert_eq!(RequestContext::new(monday, 0, 0).weekday, 0);
        assert_eq!(RequestContext::new(monday, 0, 0).hour, 0);
        let sunday = time::macros::datetime!(2026-09-06 23:00:00 UTC);
        assert_eq!(RequestContext::new(sunday, 0, 0).weekday, 6);
        assert_eq!(RequestContext::new(sunday, 0, 0).hour, 23);
    }

    #[test]
    fn a_counter_too_large_for_cedar_saturates_rather_than_wrapping() {
        // A negative byte count would make `context.resp_bytes_so_far < N`
        // true again, which is the one way a budget could fail open.
        let context = RequestContext::new(OffsetDateTime::UNIX_EPOCH, u64::MAX, u64::MAX);
        assert_eq!(context.resp_bytes_so_far, i64::MAX);
        assert_eq!(context.requests_so_far, i64::MAX);
    }

    #[test]
    fn the_outcome_labels_are_the_ones_the_audit_row_documents() {
        assert_eq!(Outcome::Allow.label(), "allow");
        assert_eq!(Outcome::Deny.label(), "deny");
        assert_eq!(Outcome::WouldDeny.label(), "would_deny");
    }
}
