//! Every profile in `examples/profiles/` is a real profile.
//!
//! An example that does not load is worse than no example: it is copied,
//! pasted, and then debugged as if the copy were at fault. These load and
//! validate them exactly as the daemon does when it reads its profile
//! directory, against the same registry.

use std::path::PathBuf;

use briefcred_core::{Profile, Registry};

fn examples_dir() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `crates/briefcred-core`.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/profiles")
        .canonicalize()
        .expect("examples/profiles must exist")
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
fn the_kubectl_example_tunnels_through_a_short_lived_ssh_certificate() {
    let yaml = std::fs::read_to_string(examples_dir().join("kubectl-bastion.yaml")).unwrap();
    let profile = Profile::from_yaml_str(&yaml).unwrap();

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
    let yaml = std::fs::read_to_string(examples_dir().join("openai.yaml")).unwrap();
    let profile = Profile::from_yaml_str(&yaml).unwrap();

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

    // An example whose whole subject is the policy has to ship one, has to
    // enforce it, and has to have it compile.
    assert!(
        profile.wants_proxy(),
        "the example must route through the proxy"
    );
    assert_eq!(
        profile.policy_mode,
        briefcred_core::policy::PolicyMode::Enforce,
        "an example left in observe mode is an example with no policy"
    );
    assert!(
        profile.compiled_policy().unwrap().is_some(),
        "the example must carry a policy"
    );

    // And it has to be an allowlist rather than a whole host: the point of the
    // example is that `/v1/models` and `/v1/chat/completions` are permitted and
    // fine-tuning and file uploads are not.
    let policy = profile.compiled_policy().unwrap().unwrap();
    let allowed = |method: &str, path: &str| {
        policy.decide(
            "s1",
            &briefcred_core::policy::HttpRequest {
                method,
                scheme: "https",
                host: "api.openai.com",
                path,
            },
            profile.policy_mode,
        ) == briefcred_core::policy::Outcome::Allow
    };
    assert!(allowed("GET", "/v1/models"));
    assert!(allowed("POST", "/v1/chat/completions"));
    assert!(!allowed("POST", "/v1/files"));
    assert!(!allowed("POST", "/v1/fine_tuning/jobs"));
    assert!(!allowed("DELETE", "/v1/models"));
}

#[test]
fn the_warehouse_example_hands_the_agent_a_token_where_a_password_would_be() {
    let yaml = std::fs::read_to_string(examples_dir().join("warehouse.yaml")).unwrap();
    let profile = Profile::from_yaml_str(&yaml).unwrap();

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
        serde_yaml::from_value(credential.config.clone()).unwrap();
    assert_ne!(
        config.user, "postgres",
        "an example must not model a superuser"
    );
    assert!(!config.dbname.is_empty());
}
