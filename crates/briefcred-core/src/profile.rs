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

/// Default credential lifetime when a spec does not set `ttl_secs`.
pub const DEFAULT_TTL_SECS: u64 = 900;

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
}

/// Per-profile unlock policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Unlock {
    /// The presence check to run. Defaults to [`UnlockPolicy::Biometric`].
    #[serde(default)]
    pub policy: UnlockPolicy,
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
    /// Minter-specific configuration, interpreted by the minter for `kind`.
    #[serde(default)]
    pub config: serde_yaml::Value,
}

impl CredentialSpec {
    /// The configured lifetime as a [`Duration`].
    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.ttl_secs)
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
    /// Parse and validate one profile document.
    pub fn from_yaml_str(yaml: &str) -> Result<Profile> {
        let profile: Profile =
            serde_yaml::from_str(yaml).map_err(|e| Error::profile(e.to_string()))?;
        profile.validate()?;
        Ok(profile)
    }

    /// Load every `*.yaml` file in `dir`, keyed by [`Profile::name`].
    ///
    /// A missing directory yields an empty map; the daemon provisions it
    /// lazily. Any unreadable or invalid file is an error naming the file.
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<BTreeMap<String, Profile>> {
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

    /// Check every invariant the type system does not already enforce.
    fn validate(&self) -> Result<()> {
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

    #[test]
    fn minimal_profile_applies_every_default() {
        let profile = Profile::from_yaml_str(MINIMAL).unwrap();
        assert_eq!(profile.name, "dev");
        assert_eq!(profile.description, None);
        assert_eq!(profile.unlock.policy, UnlockPolicy::Biometric);
        assert!(profile.credentials.is_empty());
        assert!(profile.exec.allow_argv0.is_empty());
        assert!(profile.env.is_empty());
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
        assert_eq!(spec.config, serde_yaml::Value::Null);
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

        let profiles = Profile::load_dir(dir.path()).unwrap();
        assert_eq!(profiles.keys().collect::<Vec<_>>(), vec!["alpha", "beta"]);
    }

    #[test]
    fn load_dir_on_a_missing_directory_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = Profile::load_dir(dir.path().join("profiles")).unwrap();
        assert!(profiles.is_empty());
    }

    #[test]
    fn load_dir_rejects_duplicate_profile_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.yaml"), "name: alpha\n").unwrap();
        std::fs::write(dir.path().join("b.yaml"), "name: alpha\n").unwrap();
        let err = Profile::load_dir(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("duplicate profile name `alpha`"),
            "{err}"
        );
    }

    #[test]
    fn load_dir_errors_name_the_offending_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("broken.yaml"), "name: dev\nbogus: 1\n").unwrap();
        let err = Profile::load_dir(dir.path()).unwrap_err();
        assert!(err.to_string().contains("broken.yaml"), "{err}");
    }
}
