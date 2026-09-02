//! Deciding one request, and not recompiling Cedar to do it.
//!
//! A profile's `policy` is Cedar source text. Parsing and validating it costs
//! far more than evaluating it, and the proxy evaluates it once per forwarded
//! request — so the compiled form is cached, keyed by the profile it came from.
//!
//! The cache is keyed by profile *name* and checked against the source it was
//! built from. A profile the user edits gets reloaded by the daemon's watcher,
//! and the next request through the proxy sees source that does not match what
//! was compiled and recompiles it. That is one comparison per request in
//! exchange for never serving a decision from a policy the file no longer says.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use briefcred_core::policy::{CompiledPolicy, HttpRequest, Outcome};
use briefcred_core::Profile;

/// One profile's compiled policy, and the source it was compiled from.
struct Entry {
    source: Option<String>,
    compiled: Option<Arc<CompiledPolicy>>,
}

/// Compiled policies, one per profile.
#[derive(Default)]
pub struct PolicyCache {
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}

impl std::fmt::Debug for PolicyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f.debug_struct("PolicyCache")
            .field("profiles", &entries.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl PolicyCache {
    /// An empty cache.
    pub fn new() -> PolicyCache {
        PolicyCache::default()
    }

    /// Decide `request` for session `sid` under `profile`.
    ///
    /// A profile with no `policy` denies everything, and a policy that no
    /// longer compiles denies everything too. Both are the same answer for the
    /// same reason: the proxy is about to attach a real credential to this
    /// request, and "briefcred does not currently know whether this is allowed"
    /// is not a permission.
    pub fn decide(&self, profile: &Profile, sid: &str, request: &HttpRequest<'_>) -> Outcome {
        match self.compiled(profile) {
            Some(policy) => policy.decide(sid, request, profile.policy_mode),
            None => briefcred_core::policy::deny(profile.policy_mode),
        }
    }

    /// The compiled policy for `profile`, compiling it if it has changed.
    fn compiled(&self, profile: &Profile) -> Option<Arc<CompiledPolicy>> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = entries.get(&profile.name) {
            if entry.source == profile.policy {
                return entry.compiled.clone();
            }
        }

        // A policy that will not compile here already failed at profile load,
        // so the file the daemon is serving cannot contain one. Reaching this
        // means something changed underneath a running proxy, and the honest
        // answer is to cache the failure and deny rather than to recompile on
        // every request for as long as it stays broken.
        let compiled = match profile.compiled_policy() {
            Ok(compiled) => compiled.map(Arc::new),
            Err(err) => {
                eprintln!(
                    "briefcred-daemon: profile `{}` has a policy that no longer compiles, \
                     so the proxy is denying its requests: {err}",
                    profile.name
                );
                None
            }
        };
        entries.insert(
            profile.name.clone(),
            Arc::new(Entry {
                source: profile.policy.clone(),
                compiled: compiled.clone(),
            }),
        );
        compiled
    }

    /// How many profiles are cached. For tests.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Whether nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use briefcred_core::policy::PolicyMode;

    const ALLOW_MODELS: &str = r#"
permit(principal, action in [Action::"http"], resource)
when { resource.host == "api.openai.com" && resource.path == "/v1/models" };
"#;

    fn profile(policy: Option<&str>, mode: PolicyMode) -> Profile {
        let mut profile = Profile::from_yaml_str("name: openai\n").unwrap();
        profile.policy = policy.map(str::to_string);
        profile.policy_mode = mode;
        profile
    }

    fn models() -> HttpRequest<'static> {
        HttpRequest {
            method: "GET",
            scheme: "https",
            host: "api.openai.com",
            path: "/v1/models",
            context: briefcred_core::policy::RequestContext::default(),
        }
    }

    #[test]
    fn a_matching_policy_allows_and_is_compiled_once() {
        let cache = PolicyCache::new();
        let profile = profile(Some(ALLOW_MODELS), PolicyMode::Enforce);
        for _ in 0..3 {
            assert_eq!(cache.decide(&profile, "s1", &models()), Outcome::Allow);
        }
        assert_eq!(cache.len(), 1, "one profile, one cache entry");
    }

    #[test]
    fn a_profile_with_no_policy_denies_everything() {
        let cache = PolicyCache::new();
        let profile = profile(None, PolicyMode::Enforce);
        assert_eq!(cache.decide(&profile, "s1", &models()), Outcome::Deny);
        assert!(!cache.is_empty(), "the absence is cached too");
    }

    #[test]
    fn a_profile_with_no_policy_in_observe_mode_would_deny_and_forwards() {
        let cache = PolicyCache::new();
        let profile = profile(None, PolicyMode::Observe);
        let outcome = cache.decide(&profile, "s1", &models());
        assert_eq!(outcome, Outcome::WouldDeny);
        assert!(outcome.forwards());
    }

    #[test]
    fn editing_the_policy_takes_effect_on_the_next_request() {
        let cache = PolicyCache::new();
        let allowing = profile(Some(ALLOW_MODELS), PolicyMode::Enforce);
        assert_eq!(cache.decide(&allowing, "s1", &models()), Outcome::Allow);

        let narrowed = profile(
            Some(r#"permit(principal, action == Action::"POST", resource);"#),
            PolicyMode::Enforce,
        );
        assert_eq!(cache.decide(&narrowed, "s1", &models()), Outcome::Deny);
        assert_eq!(cache.len(), 1, "the stale entry is replaced, not added to");
    }

    #[test]
    fn two_profiles_do_not_share_a_decision() {
        let cache = PolicyCache::new();
        let allowing = profile(Some(ALLOW_MODELS), PolicyMode::Enforce);
        let mut denying = profile(None, PolicyMode::Enforce);
        denying.name = "other".to_string();

        assert_eq!(cache.decide(&allowing, "s1", &models()), Outcome::Allow);
        assert_eq!(cache.decide(&denying, "s1", &models()), Outcome::Deny);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn a_policy_that_stopped_compiling_denies_rather_than_allowing() {
        let cache = PolicyCache::new();
        let broken = profile(Some("permit(principal"), PolicyMode::Enforce);
        assert_eq!(cache.decide(&broken, "s1", &models()), Outcome::Deny);
        // And again, from the cached failure rather than a second compile.
        assert_eq!(cache.decide(&broken, "s1", &models()), Outcome::Deny);
    }

    #[test]
    fn the_cache_never_prints_a_policy_it_holds() {
        let cache = PolicyCache::new();
        cache.decide(
            &profile(Some(ALLOW_MODELS), PolicyMode::Enforce),
            "s1",
            &models(),
        );
        let rendered = format!("{cache:?}");
        assert!(rendered.contains("openai"), "{rendered}");
        assert!(!rendered.contains("permit("), "{rendered}");
    }
}
