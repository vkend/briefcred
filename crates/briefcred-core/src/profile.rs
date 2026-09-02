//! The profile schema and its YAML loader.
//!
//! A profile is the work envelope: which credentials to mint, how the user is
//! asked to unlock them, what the subprocess is allowed to be, and how the
//! minted material reaches its environment.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::policy::PolicyMode;

/// Default credential lifetime when a spec does not set `ttl_secs`.
pub const DEFAULT_TTL_SECS: u64 = 900;

/// How long a successful unlock is honoured when a profile says nothing.
///
/// Five minutes: long enough that a burst of `briefcred exec` calls prompts
/// once, short enough that an unattended laptop stops minting quickly.
pub const DEFAULT_UNLOCK_CACHE_SECS: u64 = 300;

/// One profile document.
///
/// Unknown keys are rejected at every level: a typo in a profile must fail
/// loudly rather than silently disable a control.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Profile name, as passed to `briefcred exec`.
    pub name: String,
    /// Human-facing description. Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// How the user proves presence before this profile mints anything.
    #[serde(default)]
    pub unlock: Unlock,
    /// The credentials this profile mints, in declaration order.
    #[serde(default)]
    pub credentials: Vec<CredentialSpec>,
    /// What the wrapped subprocess is allowed to be.
    #[serde(default)]
    pub exec: ExecPolicy,
    /// Environment handed to the subprocess, with `${...}` templates.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Extra variables the subprocess may inherit from the caller.
    ///
    /// The child starts with a cleared environment, so anything it needs has to
    /// be named. [`crate::exec::DEFAULT_PASSTHROUGH`] is always included; this
    /// list adds to it. Naming a variable here says only "copy it if the caller
    /// has it", never "set it".
    #[serde(default)]
    pub env_passthrough: Vec<String>,
    /// Which of [`crate::ca::TRUST_ENV_VARS`] to set for the subprocess.
    ///
    /// Absent means all of them, which is what almost every profile wants. An
    /// explicit list narrows it, and an explicit empty list opts the profile
    /// out of the trust environment entirely — useful for a subprocess that
    /// must keep talking to the real internet through its own trust store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_env: Option<Vec<String>>,
    /// Cedar policy source governing this profile's HTTP traffic.
    ///
    /// Parsed and validated against [`crate::policy::SCHEMA_SOURCE`] when the
    /// profile is loaded. Absent is not "allow everything": the proxy denies by
    /// default, so a profile with HTTP credentials and no policy forwards
    /// nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Whether a policy denial stops the request or is only recorded.
    #[serde(default)]
    pub policy_mode: PolicyMode,
    /// How much work one session of this profile may do.
    ///
    /// Absent means unmetered. A policy says what a session may do; this says
    /// how much of it, which no allowlist of hosts and paths can express.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<Quota>,
    /// When the subprocess is pointed at briefcred's HTTP proxy.
    #[serde(default)]
    pub proxy: ProxyMode,
}

/// A per-session token bucket: a sustained rate, a burst, and a hard cap.
///
/// Charged one token per HTTP proxy request, per Postgres proxy connection, and
/// per `briefcred exec` or `briefcred get` that mints. The bucket is created
/// when the session opens and dies with it, so two concurrent runs of the same
/// profile get a budget each rather than competing for one.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Quota {
    /// Tokens added per second, sustained. Must be greater than zero.
    ///
    /// Fractional on purpose: `rate: 0.1` is six an hour, which is the shape a
    /// quota on something expensive wants.
    pub rate: f64,
    /// Tokens the bucket holds, and how many may be spent at once. At least 1.
    pub burst: u32,
    /// A hard cap for the whole session, if there is one.
    ///
    /// Once spent, every charge fails until the session closes: no waiting
    /// brings it back, because the budget is the session's rather than the
    /// minute's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

/// When `briefcred exec` sets `HTTPS_PROXY` and friends for a profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    /// Only when the profile declares at least one HTTP credential.
    ///
    /// The right answer almost always: a profile that mints nothing the proxy
    /// serves has nothing to gain from routing its traffic through it, and
    /// routing it anyway would break a subprocess whose upstream briefcred has
    /// no leaf for.
    #[default]
    Auto,
    /// Always, even when the profile declares no HTTP credential.
    ///
    /// For a profile whose value is the *policy* rather than a credential:
    /// pointing a subprocess at the proxy with a Cedar allowlist and no
    /// credentials at all is a usable egress control.
    Always,
}

/// Per-profile unlock policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Unlock {
    /// The presence check to run. Defaults to [`UnlockPolicy::Biometric`].
    #[serde(default)]
    pub policy: UnlockPolicy,
    /// How long a successful unlock is honoured for this profile, in seconds.
    ///
    /// Zero means every session prompts. The cache is per profile, so
    /// unlocking a low-value profile never opens a high-value one.
    #[serde(default = "default_unlock_cache_secs")]
    pub cache_secs: u64,
}

impl Default for Unlock {
    fn default() -> Unlock {
        Unlock {
            policy: UnlockPolicy::default(),
            cache_secs: DEFAULT_UNLOCK_CACHE_SECS,
        }
    }
}

impl Unlock {
    /// The configured cache window as a [`Duration`].
    pub fn cache_for(&self) -> Duration {
        Duration::from_secs(self.cache_secs)
    }
}

fn default_unlock_cache_secs() -> u64 {
    DEFAULT_UNLOCK_CACHE_SECS
}

/// How the user proves presence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UnlockPolicy {
    /// Touch ID / Face ID, falling back to the device passcode.
    #[default]
    Biometric,
    /// Device passcode only.
    Passcode,
    /// No presence check. For unattended profiles; weakens the guarantee.
    None,
}

/// One credential to mint for a profile.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSpec {
    /// Name used in `${minted.<name>.<field>}` templates. Unique per profile.
    pub name: String,
    /// Minter kind, resolved against the minter registry at load time.
    pub kind: String,
    /// Lifetime of the minted credential in seconds.
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
    /// Key this credential's master is filed under in the master source.
    ///
    /// Absent means the credential's own [`CredentialSpec::name`], which is
    /// what a profile with one master per credential wants. Naming it
    /// explicitly lets several credentials share one master, or lets a
    /// credential be renamed without moving the secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_key: Option<String>,
    /// Minter-specific configuration, interpreted by the minter for `kind`.
    #[serde(default)]
    pub config: serde_yaml_ng::Value,
}

impl CredentialSpec {
    /// The configured lifetime as a [`Duration`].
    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.ttl_secs)
    }

    /// The master-source key this credential's master is fetched under.
    pub fn source_key(&self) -> &str {
        self.source_key.as_deref().unwrap_or(&self.name)
    }
}

fn default_ttl_secs() -> u64 {
    DEFAULT_TTL_SECS
}

/// Allowlists constraining the subprocess a profile may wrap.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecPolicy {
    /// Permitted `argv[0]` values, matched literally. Empty means "any".
    #[serde(default)]
    pub allow_argv0: Vec<String>,
    /// Regular expressions every argument must match one of. Empty means "any".
    #[serde(default)]
    pub allow_args: Vec<String>,
}

/// One piece of an environment-value template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvSegment {
    /// Text copied through verbatim.
    Literal(String),
    /// `${minted.<credential>.<field>}` — a field of a minted credential.
    Minted {
        /// The credential name, which must be declared by the profile.
        credential: String,
        /// The field name, defined by the minter that produced it.
        field: String,
    },
    /// `${config.<key>}` — a value resolved from configuration at exec time.
    Config {
        /// Everything after `config.`; may itself be dotted.
        key: String,
    },
}

/// Split an environment value into literals and `${...}` references.
///
/// `$` that is not followed by `{` is a literal. An unterminated `${` is an
/// error, as is a reference in a namespace other than `minted` or `config`.
pub fn parse_env_template(value: &str) -> Result<Vec<EnvSegment>> {
    let mut out = Vec::new();
    let mut literal = String::new();
    let mut rest = value;

    while let Some(idx) = rest.find("${") {
        literal.push_str(&rest[..idx]);
        let after = &rest[idx + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| Error::profile(format!("unterminated `${{` in env value `{value}`")))?;
        let reference = &after[..end];
        if !literal.is_empty() {
            out.push(EnvSegment::Literal(std::mem::take(&mut literal)));
        }
        out.push(parse_reference(reference, value)?);
        rest = &after[end + 1..];
    }

    literal.push_str(rest);
    if !literal.is_empty() {
        out.push(EnvSegment::Literal(literal));
    }
    Ok(out)
}

fn parse_reference(reference: &str, value: &str) -> Result<EnvSegment> {
    let (namespace, remainder) = reference.split_once('.').ok_or_else(|| {
        Error::profile(format!(
            "`${{{reference}}}` in env value `{value}` is not `${{minted.<credential>.<field>}}` or `${{config.<key>}}`"
        ))
    })?;
    match namespace {
        "minted" => {
            let (credential, field) = remainder.split_once('.').ok_or_else(|| {
                Error::profile(format!(
                    "`${{{reference}}}` must be `${{minted.<credential>.<field>}}`"
                ))
            })?;
            if credential.is_empty() || field.is_empty() || field.contains('.') {
                return Err(Error::profile(format!(
                    "`${{{reference}}}` must be `${{minted.<credential>.<field>}}`"
                )));
            }
            Ok(EnvSegment::Minted {
                credential: credential.to_string(),
                field: field.to_string(),
            })
        }
        "config" => {
            if remainder.is_empty() {
                return Err(Error::profile(format!(
                    "`${{{reference}}}` must be `${{config.<key>}}`"
                )));
            }
            Ok(EnvSegment::Config {
                key: remainder.to_string(),
            })
        }
        other => Err(Error::profile(format!(
            "unknown template namespace `{other}` in `${{{reference}}}`; expected `minted` or `config`"
        ))),
    }
}

impl Profile {
    /// Parse one profile document and check everything that does not need a
    /// minter registry.
    ///
    /// The registry check is separate because the schema is meaningful on its
    /// own: `briefcred profile lint` can validate a file without linking the
    /// minters, and the daemon runs [`Profile::validate`] on top.
    pub fn from_yaml_str(yaml: &str) -> Result<Profile> {
        let profile: Profile =
            serde_yaml_ng::from_str(yaml).map_err(|e| Error::profile(e.to_string()))?;
        profile.validate_schema()?;
        Ok(profile)
    }

    /// Check every credential against the minter registry.
    ///
    /// Resolving `kind` and building each minter here rather than at mint time
    /// means a typo or a malformed `config` block is caught when the file is
    /// loaded, while the user is still looking at it.
    pub fn validate(&self, registry: &crate::registry::Registry) -> Result<()> {
        self.validate_schema()?;
        for spec in &self.credentials {
            if !registry.contains(&spec.kind) {
                return Err(Error::profile(registry.unknown_kind(&spec.kind)));
            }
            registry.validate(&spec.kind, &spec.config)?;
        }
        Ok(())
    }

    /// Load every `*.yaml` file in `dir`, keyed by [`Profile::name`].
    ///
    /// A missing directory yields an empty map; the daemon provisions it
    /// lazily. Any unreadable or invalid file is an error naming the file, and
    /// every profile is checked against `registry`.
    pub fn load_dir(
        dir: impl AsRef<Path>,
        registry: &crate::registry::Registry,
    ) -> Result<BTreeMap<String, Profile>> {
        let dir = dir.as_ref();
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(source) => {
                return Err(Error::Io {
                    path: dir.to_path_buf(),
                    source,
                })
            }
        };

        let mut files: Vec<PathBuf> = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| Error::Io {
                path: dir.to_path_buf(),
                source,
            })?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "yaml") && path.is_file() {
                files.push(path);
            }
        }
        files.sort();

        let mut out: BTreeMap<String, Profile> = BTreeMap::new();
        for path in files {
            let text = std::fs::read_to_string(&path).map_err(|source| Error::Io {
                path: path.clone(),
                source,
            })?;
            let profile = Profile::from_yaml_str(&text).map_err(|e| e.at_path(&path))?;
            profile.validate(registry).map_err(|e| e.at_path(&path))?;
            if let Some(previous) = out.insert(profile.name.clone(), profile) {
                return Err(Error::Profile {
                    path: Some(path),
                    message: format!("duplicate profile name `{}`", previous.name),
                });
            }
        }
        Ok(out)
    }

    /// Look up a declared credential by name.
    pub fn credential(&self, name: &str) -> Option<&CredentialSpec> {
        self.credentials.iter().find(|c| c.name == name)
    }

    /// Compile this profile's `policy`, or `None` when it has none.
    ///
    /// Called once when the profile is loaded and again by the proxy when it
    /// caches the compiled form. Both go through here so there is one answer to
    /// "does this policy compile", and a profile that would fail at request
    /// time fails at load time instead.
    pub fn compiled_policy(&self) -> Result<Option<crate::policy::CompiledPolicy>> {
        self.policy
            .as_deref()
            .map(crate::policy::CompiledPolicy::parse)
            .transpose()
    }

    /// Whether this profile declares any credential the HTTP proxy serves.
    pub fn has_http_credentials(&self) -> bool {
        self.credentials
            .iter()
            .any(|spec| crate::minters::http::KINDS.contains(&spec.kind.as_str()))
    }

    /// Whether the subprocess should be pointed at the HTTP proxy.
    pub fn wants_proxy(&self) -> bool {
        self.proxy == ProxyMode::Always || self.has_http_credentials()
    }

    /// Check every invariant the type system does not already enforce and
    /// that does not need the minter registry.
    fn validate_schema(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(Error::profile("`name` must not be empty"));
        }

        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for spec in &self.credentials {
            if spec.name.trim().is_empty() {
                return Err(Error::profile("credential `name` must not be empty"));
            }
            if spec.kind.trim().is_empty() {
                return Err(Error::profile(format!(
                    "credential `{}` has an empty `kind`",
                    spec.name
                )));
            }
            if spec.ttl_secs == 0 {
                return Err(Error::profile(format!(
                    "credential `{}` has `ttl_secs: 0`",
                    spec.name
                )));
            }
            if spec
                .source_key
                .as_ref()
                .is_some_and(|k| k.trim().is_empty())
            {
                return Err(Error::profile(format!(
                    "credential `{}` has an empty `source_key`; omit the key to use the credential name",
                    spec.name
                )));
            }
            if !seen.insert(spec.name.as_str()) {
                return Err(Error::profile(format!(
                    "duplicate credential name `{}`",
                    spec.name
                )));
            }
        }

        for pattern in &self.exec.allow_args {
            regex::Regex::new(pattern).map_err(|e| {
                Error::profile(format!(
                    "`exec.allow_args` entry `{pattern}` is not a valid regex: {e}"
                ))
            })?;
        }

        // A name briefcred does not know is a typo, not a feature: silently
        // ignoring it would leave the user believing a runtime was covered.
        if let Some(names) = &self.trust_env {
            for name in names {
                if !crate::ca::TRUST_ENV_VARS.contains(&name.as_str()) {
                    return Err(Error::profile(format!(
                        "`trust_env` entry `{name}` is not one of {}",
                        crate::ca::TRUST_ENV_VARS.join(", ")
                    )));
                }
            }
        }

        // A quota that cannot refill, or that holds nothing, is a profile that
        // refuses everything after its first charge. Caught here rather than
        // discovered at three in the morning as a proxy returning 429s.
        if let Some(quota) = &self.quota {
            if !quota.rate.is_finite() || quota.rate <= 0.0 {
                return Err(Error::profile(format!(
                    "`quota.rate` must be a positive number of tokens per second, not {}",
                    quota.rate
                )));
            }
            if quota.burst == 0 {
                return Err(Error::profile(
                    "`quota.burst` must be at least 1; a bucket that holds nothing refuses everything",
                ));
            }
        }

        // Compiled here rather than at the first request: a Cedar typo has to
        // be an error next to the file that has it, not a request the proxy
        // silently denies once the profile is already in production.
        self.compiled_policy()?;

        for (key, value) in &self.env {
            for segment in parse_env_template(value)? {
                if let EnvSegment::Minted { credential, .. } = segment {
                    if !seen.contains(credential.as_str()) {
                        return Err(Error::profile(format!(
                            "env `{key}` references undeclared credential `{credential}`"
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "name: dev\n";

    /// Everything this binary registered, which includes `postgres-dynamic`.
    fn registry() -> crate::registry::Registry {
        crate::registry::Registry::discover()
    }

    #[test]
    fn minimal_profile_applies_every_default() {
        let profile = Profile::from_yaml_str(MINIMAL).unwrap();
        assert_eq!(profile.name, "dev");
        assert_eq!(profile.description, None);
        assert_eq!(profile.unlock.policy, UnlockPolicy::Biometric);
        assert_eq!(profile.unlock.cache_secs, DEFAULT_UNLOCK_CACHE_SECS);
        assert_eq!(profile.unlock.cache_for(), Duration::from_secs(300));
        assert!(profile.credentials.is_empty());
        assert!(profile.exec.allow_argv0.is_empty());
        assert!(profile.env.is_empty());
        assert_eq!(profile.policy, None);
        assert_eq!(profile.policy_mode, crate::policy::PolicyMode::Enforce);
        assert_eq!(profile.proxy, ProxyMode::Auto);
        assert!(!profile.wants_proxy());
    }

    const OPENAI: &str = "\
name: openai
credentials:
  - name: openai
    kind: http-bearer
";

    #[test]
    fn a_profile_with_an_http_credential_wants_the_proxy() {
        let profile = Profile::from_yaml_str(OPENAI).unwrap();
        assert!(profile.has_http_credentials());
        assert!(profile.wants_proxy());
    }

    #[test]
    fn a_profile_without_one_wants_the_proxy_only_if_it_asks() {
        let profile = Profile::from_yaml_str(MINIMAL).unwrap();
        assert!(!profile.wants_proxy());
        let always = Profile::from_yaml_str("name: dev\nproxy: always\n").unwrap();
        assert_eq!(always.proxy, ProxyMode::Always);
        assert!(always.wants_proxy(), "`proxy: always` means always");
        assert!(!always.has_http_credentials());
    }

    #[test]
    fn a_policy_is_compiled_when_the_profile_is_parsed() {
        let yaml = format!(
            "{OPENAI}policy: |\n  permit(principal, action in [Action::\"http\"], resource)\n  when {{ resource.host == \"api.openai.com\" }};\npolicy_mode: observe\n"
        );
        let profile = Profile::from_yaml_str(&yaml).unwrap();
        assert_eq!(profile.policy_mode, crate::policy::PolicyMode::Observe);
        assert!(profile.compiled_policy().unwrap().is_some());
    }

    #[test]
    fn a_policy_that_does_not_compile_fails_the_profile_rather_than_the_request() {
        let yaml = format!("{OPENAI}policy: |\n  permit(principal\n");
        let err = Profile::from_yaml_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("not valid Cedar"), "{err}");
    }

    #[test]
    fn a_profile_with_no_quota_is_unmetered() {
        assert_eq!(Profile::from_yaml_str(MINIMAL).unwrap().quota, None);
    }

    #[test]
    fn a_quota_is_read_with_its_total_optional() {
        let profile =
            Profile::from_yaml_str("name: dev\nquota:\n  rate: 10\n  burst: 20\n").unwrap();
        let quota = profile.quota.expect("the profile declares a quota");
        assert_eq!(quota.rate, 10.0);
        assert_eq!(quota.burst, 20);
        assert_eq!(quota.total, None);

        let capped =
            Profile::from_yaml_str("name: dev\nquota:\n  rate: 0.5\n  burst: 1\n  total: 40\n")
                .unwrap();
        assert_eq!(capped.quota.unwrap().total, Some(40));
    }

    #[test]
    fn a_quota_that_cannot_refill_is_rejected_by_name() {
        for rate in ["0", "-1", "0.0"] {
            let err =
                Profile::from_yaml_str(&format!("name: dev\nquota:\n  rate: {rate}\n  burst: 1\n"))
                    .unwrap_err();
            assert!(err.to_string().contains("quota.rate"), "{rate}: {err}");
        }
    }

    #[test]
    fn a_quota_that_holds_nothing_is_rejected_by_name() {
        let err = Profile::from_yaml_str("name: dev\nquota:\n  rate: 1\n  burst: 0\n").unwrap_err();
        assert!(err.to_string().contains("quota.burst"), "{err}");
    }

    #[test]
    fn a_misspelt_quota_key_is_rejected_rather_than_ignored() {
        let err = Profile::from_yaml_str("name: dev\nquota:\n  rate: 1\n  burst: 1\n  totl: 4\n")
            .unwrap_err();
        assert!(err.to_string().contains("totl"), "{err}");
    }

    #[test]
    fn a_policy_naming_something_the_schema_lacks_fails_the_profile() {
        let yaml = format!(
            "{OPENAI}policy: |\n  permit(principal, action in [Action::\"http\"], resource)\n  when {{ resource.querystring == \"x\" }};\n"
        );
        let err = Profile::from_yaml_str(&yaml).unwrap_err();
        assert!(err.to_string().contains("Cedar schema"), "{err}");
    }

    #[test]
    fn an_unknown_policy_mode_is_rejected() {
        assert!(Profile::from_yaml_str("name: dev\npolicy_mode: maybe\n").is_err());
        assert!(Profile::from_yaml_str("name: dev\nproxy: sometimes\n").is_err());
    }

    #[test]
    fn an_http_header_credential_must_name_its_header() {
        let yaml = "name: dev\ncredentials:\n  - name: k\n    kind: http-header\n";
        let profile = Profile::from_yaml_str(yaml).unwrap();
        let err = profile.validate(&registry()).unwrap_err();
        assert!(matches!(err, Error::MinterConfig { .. }), "{err}");

        let good = "name: dev\ncredentials:\n  - name: k\n    kind: http-header\n    config:\n      name: X-Api-Key\n";
        Profile::from_yaml_str(good)
            .unwrap()
            .validate(&registry())
            .unwrap();
    }

    #[test]
    fn credential_ttl_defaults_to_fifteen_minutes() {
        let yaml = "\
name: dev
credentials:
  - name: db
    kind: postgres-dynamic
";
        let profile = Profile::from_yaml_str(yaml).unwrap();
        let spec = profile.credential("db").unwrap();
        assert_eq!(spec.ttl_secs, 900);
        assert_eq!(spec.ttl(), Duration::from_secs(900));
        assert_eq!(spec.config, serde_yaml_ng::Value::Null);
    }

    #[test]
    fn a_credentials_master_key_defaults_to_its_own_name() {
        let yaml = "\
name: dev
credentials:
  - name: db
    kind: postgres-dynamic
  - name: warehouse
    kind: postgres-dynamic
    source_key: shared-master
";
        let profile = Profile::from_yaml_str(yaml).unwrap();
        assert_eq!(profile.credential("db").unwrap().source_key(), "db");
        assert_eq!(
            profile.credential("warehouse").unwrap().source_key(),
            "shared-master"
        );
    }

    #[test]
    fn an_empty_source_key_is_rejected_rather_than_silently_ignored() {
        let yaml =
            "name: dev\ncredentials:\n  - name: db\n    kind: postgres-dynamic\n    source_key: ''\n";
        let err = Profile::from_yaml_str(yaml).unwrap_err();
        assert!(err.to_string().contains("empty `source_key`"), "{err}");
    }

    #[test]
    fn the_unlock_cache_window_is_configurable_including_off() {
        let profile = Profile::from_yaml_str("name: dev\nunlock:\n  cache_secs: 0\n").unwrap();
        assert_eq!(profile.unlock.cache_secs, 0);
        assert_eq!(profile.unlock.cache_for(), Duration::ZERO);
    }

    #[test]
    fn a_credential_naming_an_unregistered_minter_is_rejected_by_name() {
        let yaml = "name: dev\ncredentials:\n  - name: db\n    kind: postgres-dynamik\n";
        let profile = Profile::from_yaml_str(yaml).unwrap();
        let registry = registry();
        let err = profile.validate(&registry).unwrap_err();
        assert!(
            err.to_string().contains(&format!(
                "unknown minter kind \"postgres-dynamik\" (registered: {})",
                registry.kinds().join(", ")
            )),
            "{err}"
        );
    }

    #[test]
    fn a_registered_minter_with_a_malformed_config_is_rejected_at_load() {
        let yaml = "\
name: dev
credentials:
  - name: db
    kind: postgres-dynamic
    config:
      host: 127.0.0.1
";
        let profile = Profile::from_yaml_str(yaml).unwrap();
        let err = profile.validate(&registry()).unwrap_err();
        assert!(
            matches!(err, Error::MinterConfig { .. }),
            "expected a minter config error, got {err}"
        );
    }

    #[test]
    fn load_dir_names_the_file_whose_minter_kind_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("bad.yaml"),
            "name: dev\ncredentials:\n  - name: db\n    kind: nope\n",
        )
        .unwrap();
        let err = Profile::load_dir(dir.path(), &registry()).unwrap_err();
        assert!(err.to_string().contains("bad.yaml"), "{err}");
        assert!(err.to_string().contains("unknown minter kind"), "{err}");
    }

    #[test]
    fn full_profile_parses_every_field() {
        let yaml = "\
name: analytics
description: read-only analytics shell
unlock:
  policy: passcode
credentials:
  - name: db
    kind: postgres-dynamic
    ttl_secs: 300
    config:
      host: 127.0.0.1
      port: 5432
exec:
  allow_argv0: [psql]
  allow_args: ['^-c$', '^SELECT ']
env:
  PGUSER: ${minted.db.PGUSER}
  PGHOST: ${config.db_host}
  PGAPPNAME: briefcred-${minted.db.PGUSER}-shell
";
        let profile = Profile::from_yaml_str(yaml).unwrap();
        assert_eq!(
            profile.description.as_deref(),
            Some("read-only analytics shell")
        );
        assert_eq!(profile.unlock.policy, UnlockPolicy::Passcode);
        assert_eq!(profile.exec.allow_argv0, vec!["psql".to_string()]);
        assert_eq!(profile.exec.allow_args.len(), 2);
        let spec = profile.credential("db").unwrap();
        assert_eq!(spec.ttl_secs, 300);
        assert_eq!(spec.config["host"].as_str(), Some("127.0.0.1"));
        assert_eq!(profile.env.len(), 3);
    }

    #[test]
    fn unknown_top_level_key_is_rejected() {
        let err = Profile::from_yaml_str("name: dev\ncredentails: []\n").unwrap_err();
        assert!(err.to_string().contains("credentails"), "{err}");
    }

    #[test]
    fn unknown_nested_key_is_rejected() {
        let yaml = "name: dev\nunlock:\n  polcy: biometric\n";
        let err = Profile::from_yaml_str(yaml).unwrap_err();
        assert!(err.to_string().contains("polcy"), "{err}");
    }

    #[test]
    fn unknown_unlock_policy_is_rejected() {
        let yaml = "name: dev\nunlock:\n  policy: vibes\n";
        let err = Profile::from_yaml_str(yaml).unwrap_err();
        assert!(err.to_string().contains("vibes"), "{err}");
    }

    #[test]
    fn duplicate_credential_names_are_rejected() {
        let yaml = "\
name: dev
credentials:
  - name: db
    kind: postgres-dynamic
  - name: db
    kind: aws-sts
";
        let err = Profile::from_yaml_str(yaml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate credential name `db`"),
            "{err}"
        );
    }

    #[test]
    fn zero_ttl_is_rejected() {
        let yaml = "name: dev\ncredentials:\n  - name: db\n    kind: k\n    ttl_secs: 0\n";
        let err = Profile::from_yaml_str(yaml).unwrap_err();
        assert!(err.to_string().contains("ttl_secs: 0"), "{err}");
    }

    #[test]
    fn env_referencing_an_undeclared_credential_is_rejected() {
        let yaml = "name: dev\nenv:\n  PGUSER: ${minted.db.PGUSER}\n";
        let err = Profile::from_yaml_str(yaml).unwrap_err();
        assert!(
            err.to_string().contains("undeclared credential `db`"),
            "{err}"
        );
    }

    #[test]
    fn env_with_an_unknown_namespace_is_rejected() {
        let yaml = "name: dev\nenv:\n  X: ${secret.db.PGUSER}\n";
        let err = Profile::from_yaml_str(yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown template namespace `secret`"),
            "{err}"
        );
    }

    #[test]
    fn env_with_an_unterminated_reference_is_rejected() {
        let yaml = "name: dev\nenv:\n  X: \"${minted.db.PGUSER\"\n";
        let err = Profile::from_yaml_str(yaml).unwrap_err();
        assert!(err.to_string().contains("unterminated"), "{err}");
    }

    #[test]
    fn uncompilable_allow_args_regex_is_rejected() {
        let yaml = "name: dev\nexec:\n  allow_args: ['[unclosed']\n";
        let err = Profile::from_yaml_str(yaml).unwrap_err();
        assert!(err.to_string().contains("not a valid regex"), "{err}");
    }

    #[test]
    fn env_template_splits_into_literals_and_references() {
        let segments =
            parse_env_template("host=${config.db_host} user=${minted.db.PGUSER}!").unwrap();
        assert_eq!(
            segments,
            vec![
                EnvSegment::Literal("host=".into()),
                EnvSegment::Config {
                    key: "db_host".into()
                },
                EnvSegment::Literal(" user=".into()),
                EnvSegment::Minted {
                    credential: "db".into(),
                    field: "PGUSER".into()
                },
                EnvSegment::Literal("!".into()),
            ]
        );
    }

    #[test]
    fn a_bare_dollar_sign_is_literal() {
        let segments = parse_env_template("costs $5").unwrap();
        assert_eq!(segments, vec![EnvSegment::Literal("costs $5".into())]);
    }

    #[test]
    fn load_dir_reads_yaml_files_keyed_by_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.yaml"), "name: alpha\n").unwrap();
        std::fs::write(dir.path().join("b.yaml"), "name: beta\n").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "name: ignored\n").unwrap();

        let profiles = Profile::load_dir(dir.path(), &registry()).unwrap();
        assert_eq!(profiles.keys().collect::<Vec<_>>(), vec!["alpha", "beta"]);
    }

    #[test]
    fn load_dir_on_a_missing_directory_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = Profile::load_dir(dir.path().join("profiles"), &registry()).unwrap();
        assert!(profiles.is_empty());
    }

    #[test]
    fn load_dir_rejects_duplicate_profile_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.yaml"), "name: alpha\n").unwrap();
        std::fs::write(dir.path().join("b.yaml"), "name: alpha\n").unwrap();
        let err = Profile::load_dir(dir.path(), &registry()).unwrap_err();
        assert!(
            err.to_string().contains("duplicate profile name `alpha`"),
            "{err}"
        );
    }

    #[test]
    fn load_dir_errors_name_the_offending_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("broken.yaml"), "name: dev\nbogus: 1\n").unwrap();
        let err = Profile::load_dir(dir.path(), &registry()).unwrap_err();
        assert!(err.to_string().contains("broken.yaml"), "{err}");
    }
}
