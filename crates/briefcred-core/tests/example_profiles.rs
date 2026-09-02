//! Every profile in `examples/profiles/` is a real profile, and every Cedar
//! block in `docs/policy-cookbook.md` is one of theirs.
//!
//! An example that does not load is worse than no example: it is copied,
//! pasted, and then debugged as if the copy were at fault. These load and
//! validate them exactly as the daemon does when it reads its profile
//! directory, against the same registry — and then compile every policy against
//! the Cedar schema, which is the check that catches an example widened by hand
//! into something that can never match.
//!
//! The cookbook is held to the same standard by
//! [`every_cookbook_recipe_is_a_policy_an_example_actually_ships`]: a recipe
//! that has drifted from the profile it claims to come from is a recipe nobody
//! can trust, and drift is the normal fate of documentation that is not tested.

use std::path::PathBuf;

use briefcred_core::policy::{HttpRequest, Outcome, PolicyMode, RequestContext};
use briefcred_core::{Profile, Registry};

fn repo_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `crates/briefcred-core`.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root must exist")
}

fn examples_dir() -> PathBuf {
    repo_root().join("examples/profiles")
}

fn examples() -> Vec<(PathBuf, String)> {
    let mut found: Vec<(PathBuf, String)> = std::fs::read_dir(examples_dir())
        .expect("examples/profiles must be readable")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "yaml"))
        .map(|path| {
            let yaml = std::fs::read_to_string(&path).unwrap();
            (path, yaml)
        })
        .collect();
    found.sort();
    assert!(!found.is_empty(), "there must be example profiles to check");
    found
}

/// One example, loaded and validated.
fn example(name: &str) -> Profile {
    let yaml = std::fs::read_to_string(examples_dir().join(format!("{name}.yaml")))
        .unwrap_or_else(|e| panic!("{name}.yaml must exist: {e}"));
    let profile = Profile::from_yaml_str(&yaml).unwrap_or_else(|e| panic!("{name}.yaml: {e}"));
    profile
        .validate(&Registry::discover())
        .unwrap_or_else(|e| panic!("{name}.yaml: {e}"));
    profile
}

/// Whether `profile` permits one request, in a context a test has set up.
fn permits(
    profile: &Profile,
    method: &str,
    host: &str,
    path: &str,
    context: RequestContext,
) -> bool {
    let policy = profile
        .compiled_policy()
        .expect("the policy compiles")
        .expect("the profile carries a policy");
    policy.decide(
        "s1",
        &HttpRequest {
            method,
            scheme: "https",
            host,
            path,
            context,
        },
        profile.policy_mode,
    ) == Outcome::Allow
}

/// The same, for a session that has just started.
fn permits_fresh(profile: &Profile, method: &str, host: &str, path: &str) -> bool {
    permits(profile, method, host, path, RequestContext::default())
}

#[test]
fn every_example_profile_loads_and_validates() {
    let registry = Registry::discover();
    for (path, yaml) in examples() {
        let profile = Profile::from_yaml_str(&yaml)
            .unwrap_or_else(|e| panic!("{} does not parse: {e}", path.display()));
        profile
            .validate(&registry)
            .unwrap_or_else(|e| panic!("{} does not validate: {e}", path.display()));
    }
}

#[test]
fn every_example_policy_compiles_against_the_schema() {
    let mut with_a_policy = 0;
    for (path, yaml) in examples() {
        let profile = Profile::from_yaml_str(&yaml).unwrap();
        let compiled = profile.compiled_policy().unwrap_or_else(|e| {
            panic!("{} has a policy that does not compile: {e}", path.display())
        });
        if compiled.is_some() {
            with_a_policy += 1;
            assert_eq!(
                profile.policy_mode,
                PolicyMode::Enforce,
                "{} ships in observe mode, which is a profile with no policy",
                path.display()
            );
        }
    }
    assert!(
        with_a_policy >= 4,
        "the cookbook claims four profiles carry a policy, and only {with_a_policy} do"
    );
}

/// Every fenced `cedar` block in the cookbook, in order.
fn cookbook_recipes() -> Vec<String> {
    let text = std::fs::read_to_string(repo_root().join("docs/policy-cookbook.md"))
        .expect("docs/policy-cookbook.md must exist");
    let mut recipes = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in text.lines() {
        match (&mut current, line.trim_end()) {
            (None, "```cedar") => current = Some(Vec::new()),
            (Some(_), "```") => {
                recipes.push(current.take().unwrap().join("\n").trim_end().to_string())
            }
            (Some(block), _) => block.push(line),
            (None, _) => {}
        }
    }
    assert!(current.is_none(), "an unterminated ```cedar block");
    recipes
}

#[test]
fn every_cookbook_recipe_is_a_policy_an_example_actually_ships() {
    let policies: Vec<String> = examples()
        .into_iter()
        .filter_map(|(_, yaml)| Profile::from_yaml_str(&yaml).unwrap().policy)
        .collect();

    let recipes = cookbook_recipes();
    assert_eq!(
        recipes.len(),
        5,
        "the cookbook documents five recipes; it has {}",
        recipes.len()
    );
    for recipe in recipes {
        assert!(
            policies.iter().any(|policy| policy.contains(&recipe)),
            "no example profile ships this recipe verbatim:\n{recipe}"
        );
    }
}

#[test]
fn the_kubectl_example_tunnels_through_a_short_lived_ssh_certificate() {
    let profile = example("kubectl-bastion");

    assert_eq!(profile.name, "kubectl-bastion");
    let credential = profile
        .credential("bastion")
        .expect("the example declares one credential named `bastion`");
    assert_eq!(credential.kind, briefcred_core::minters::ssh_cert::KIND);
    assert!(
        credential.ttl_secs <= 900,
        "an example that tunnels into a cluster must be short-lived, not {}s",
        credential.ttl_secs
    );

    // The certificate can open a port forward anywhere the bastion can reach,
    // so the example must not ship without an allowlist around it.
    assert!(
        !profile.exec.allow_argv0.is_empty(),
        "the example must constrain what it will run"
    );
    assert!(profile
        .exec
        .allow_argv0
        .iter()
        .all(|argv0| argv0.ends_with("/kubectl")));

    // And the tunnel needs port forwarding, which is not in the default set.
    let config = briefcred_core::minters::ssh_cert::SshCertConfig::from_value(&credential.config)
        .expect("the example's config must be one the minter accepts");
    assert!(
        config
            .extensions()
            .contains(&"permit-port-forwarding".to_string()),
        "{:?}",
        config.extensions()
    );
    assert!(
        config.critical_options.contains_key("source-address"),
        "the example shows the server-side restriction that makes a leaked \
         certificate useless elsewhere"
    );
}

#[test]
fn the_openai_example_puts_a_synthetic_token_in_the_variable_the_sdk_reads() {
    let profile = example("openai");

    assert_eq!(profile.name, "openai");
    let credential = profile
        .credential("openai")
        .expect("the example declares one credential named `openai`");
    assert_eq!(
        credential.kind,
        briefcred_core::minters::http::BEARER_KIND,
        "the point of the example is that the real key never leaves the daemon"
    );

    // The variable every OpenAI SDK reads must hold the token and nothing else.
    assert_eq!(
        profile.env.get("OPENAI_API_KEY").map(String::as_str),
        Some("${minted.openai.TOKEN}")
    );
    assert!(
        profile.wants_proxy(),
        "the example must route through the proxy"
    );

    // An allowlist rather than a whole host: the point of the example is that
    // `/v1/models` and `/v1/chat/completions` are permitted and fine-tuning
    // and file uploads are not.
    assert!(permits_fresh(
        &profile,
        "GET",
        "api.openai.com",
        "/v1/models"
    ));
    assert!(permits_fresh(
        &profile,
        "POST",
        "api.openai.com",
        "/v1/chat/completions"
    ));
    assert!(!permits_fresh(
        &profile,
        "POST",
        "api.openai.com",
        "/v1/files"
    ));
    assert!(!permits_fresh(
        &profile,
        "POST",
        "api.openai.com",
        "/v1/fine_tuning/jobs"
    ));
    assert!(!permits_fresh(
        &profile,
        "DELETE",
        "api.openai.com",
        "/v1/models"
    ));
}

#[test]
fn the_anthropic_example_only_works_inside_its_window() {
    let profile = example("anthropic");
    assert_eq!(
        profile.credential("anthropic").unwrap().kind,
        briefcred_core::minters::http::HEADER_KIND,
        "the Anthropic API reads its key from `x-api-key`, not a bearer header"
    );

    let at = |weekday: i64, hour: i64| {
        permits(
            &profile,
            "POST",
            "api.anthropic.com",
            "/v1/messages",
            RequestContext {
                weekday,
                hour,
                ..RequestContext::default()
            },
        )
    };
    // Wednesday, mid-afternoon.
    assert!(at(2, 14));
    assert!(at(0, 8), "08:00 is inside the window");
    assert!(at(4, 18), "18:59 is inside the window");
    assert!(!at(4, 19), "19:00 is outside it");
    assert!(!at(2, 7), "07:00 is outside it");
    assert!(!at(5, 14), "Saturday is outside it");
    assert!(!at(6, 14), "Sunday is outside it");
}

#[test]
fn the_github_example_is_read_only_and_stops_after_five_hundred_requests() {
    let profile = example("github");

    let after = |requests: i64, method: &str, path: &str| {
        permits(
            &profile,
            method,
            "api.github.com",
            path,
            RequestContext {
                requests_so_far: requests,
                ..RequestContext::default()
            },
        )
    };
    assert!(after(0, "GET", "/repos/acme/widgets/contents/README.md"));
    assert!(after(499, "GET", "/repos/acme/widgets"));
    assert!(
        !after(500, "GET", "/repos/acme/widgets"),
        "`< 500` must permit exactly five hundred requests"
    );

    // Read-only, and inside one organisation.
    assert!(!after(0, "POST", "/repos/acme/widgets/issues"));
    assert!(!after(0, "DELETE", "/repos/acme/widgets"));
    assert!(!after(0, "GET", "/repos/other/widgets"));
    assert!(!after(0, "GET", "/user"));
}

#[test]
fn the_stripe_example_bounds_reads_by_bytes_and_refunds_by_count() {
    let profile = example("stripe");

    let mebibyte = 1024 * 1024;
    let read_after = |bytes: i64| {
        permits(
            &profile,
            "GET",
            "api.stripe.com",
            "/v1/charges",
            RequestContext {
                resp_bytes_so_far: bytes,
                ..RequestContext::default()
            },
        )
    };
    assert!(read_after(0));
    assert!(read_after(9 * mebibyte));
    assert!(!read_after(10 * mebibyte), "the budget is ten mebibytes");

    let refund_after = |requests: i64| {
        permits(
            &profile,
            "POST",
            "api.stripe.com",
            "/v1/refunds",
            RequestContext {
                requests_so_far: requests,
                ..RequestContext::default()
            },
        )
    };
    assert!(refund_after(0));
    assert!(refund_after(19));
    assert!(!refund_after(20), "twenty refunds, and then no more");

    // A byte budget must not become a licence to write.
    assert!(!permits_fresh(
        &profile,
        "POST",
        "api.stripe.com",
        "/v1/charges"
    ));
    assert!(!permits_fresh(
        &profile,
        "POST",
        "api.stripe.com",
        "/v1/payouts"
    ));
}

#[test]
fn the_stripe_example_ships_the_quota_the_cookbook_prints() {
    // The cookbook prints this block as YAML rather than Cedar, so the
    // verbatim check above cannot reach it. Asserted here instead, so the two
    // cannot drift.
    let quota = example("stripe").quota.expect("the example sets a quota");
    assert_eq!(quota.rate, 0.5);
    assert_eq!(quota.burst, 5);
    assert_eq!(quota.total, Some(50));

    let cookbook = std::fs::read_to_string(repo_root().join("docs/policy-cookbook.md")).unwrap();
    assert!(
        cookbook.contains("quota:\n  rate: 0.5\n  burst: 5\n  total: 50\n"),
        "the cookbook must print the quota the example ships"
    );
}

#[test]
fn every_profile_the_cookbook_names_carries_a_quota() {
    for name in ["openai", "anthropic", "github", "stripe"] {
        let profile = example(name);
        let quota = profile
            .quota
            .unwrap_or_else(|| panic!("{name}.yaml must show a quota"));
        assert!(quota.rate > 0.0, "{name}");
        assert!(quota.burst >= 1, "{name}");
    }
}

#[test]
fn the_warehouse_example_hands_the_agent_a_token_where_a_password_would_be() {
    let profile = example("warehouse");

    assert_eq!(profile.name, "warehouse");
    let credential = profile
        .credential("analytics")
        .expect("the example declares one credential named `analytics`");
    assert_eq!(
        credential.kind,
        briefcred_core::minters::postgres_proxy::KIND,
        "the point of the example is that the master never leaves the daemon"
    );

    // Every published field is wired up, and every one of them is a template
    // rather than a literal: a hard-coded port or password in an example is an
    // invitation to hard-code one in a real profile.
    for field in briefcred_core::minters::postgres_proxy::FIELDS {
        assert_eq!(
            profile.env.get(field).map(String::as_str),
            Some(format!("${{minted.analytics.{field}}}").as_str()),
            "{field}"
        );
    }

    // A `postgres-proxy` credential is not an HTTP one, so the subprocess must
    // not be pointed at the HTTP proxy for it.
    assert!(
        !profile.wants_proxy(),
        "a database profile has no business setting HTTPS_PROXY"
    );

    // The role the daemon authenticates as must not be the superuser: it is the
    // only thing bounding what the agent can do, since no policy applies.
    let config: briefcred_core::minters::postgres_proxy::PgProxyConfig =
        serde_yaml_ng::from_value(credential.config.clone()).unwrap();
    assert_ne!(
        config.user, "postgres",
        "an example must not model a superuser"
    );
    assert!(!config.dbname.is_empty());
}
