//! The two decisions `briefcred exec` makes before a subprocess ever starts:
//! whether the command is allowed, and what environment it gets.
//!
//! Both are pure functions of a profile plus the minted credentials, which is
//! the point. The daemon holds the profile and the mints, so the daemon decides
//! — but the decision itself has no I/O in it, so it can be tested exhaustively
//! without a database, a keychain, or a child process.
//!
//! # Order
//!
//! [`check_command`] runs **before** anything is minted. A command the profile
//! does not permit must not cause a role to be created, or a typo in a
//! `briefcred exec` becomes a role that has to be revoked.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::profile::{parse_env_template, EnvSegment, Profile};

/// The variables every profile passes through from the caller's environment.
///
/// The subprocess starts from an empty environment, so anything it needs has
/// to be named. These five are the ones without which ordinary programs do not
/// work at all: `PATH` to find anything, `HOME` for dotfiles, `TERM` for a
/// terminal UI, `LANG` for text, `TMPDIR` for scratch files. A profile's
/// `env_passthrough` adds to this list; nothing removes from it.
pub const DEFAULT_PASSTHROUGH: [&str; 5] = ["PATH", "HOME", "TERM", "LANG", "TMPDIR"];

/// Why a command is not allowed to run under a profile.
///
/// Every variant names the offending value, because "denied" without the
/// offending argument sends the user to read the profile and guess.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandDenied {
    /// `argv[0]` is not in `exec.allow_argv0`.
    #[error(
        "`{argv0}` is not permitted by profile `{profile}`; `exec.allow_argv0` lists {allowed}"
    )]
    Argv0 {
        /// The profile whose policy refused.
        profile: String,
        /// The program that was asked for.
        argv0: String,
        /// The permitted values, comma separated.
        allowed: String,
    },

    /// An argument matched none of the `exec.allow_args` patterns.
    #[error("argument `{arg}` is not permitted by profile `{profile}`; it matches none of the {count} `exec.allow_args` patterns")]
    Arg {
        /// The profile whose policy refused.
        profile: String,
        /// The offending argument, verbatim.
        arg: String,
        /// How many patterns it was tried against.
        count: usize,
    },

    /// A pattern in the profile did not compile.
    ///
    /// The loader compiles every pattern, so reaching this means the profile
    /// changed underneath a running check rather than that a user typed
    /// something wrong.
    #[error(
        "profile `{profile}` has an uncompilable `exec.allow_args` pattern `{pattern}`: {detail}"
    )]
    Pattern {
        /// The profile the pattern came from.
        profile: String,
        /// The pattern that would not compile.
        pattern: String,
        /// The regex crate's complaint.
        detail: String,
    },
}

/// Check `argv0` and `args` against a profile's `exec` allowlists.
///
/// `allow_argv0` matches on the **basename** of an absolute path as well as on
/// the path itself, so a profile that permits `psql` permits
/// `/opt/homebrew/bin/psql` without having to know where it is installed. It
/// never matches the other way round: a profile that names an absolute path
/// permits only that path, which is how an operator pins a specific binary.
///
/// An empty `allow_argv0` or `allow_args` means "any", which is the documented
/// default for a profile that has not thought about it yet.
pub fn check_command(profile: &Profile, argv0: &str, args: &[String]) -> Result<(), CommandDenied> {
    if !profile.exec.allow_argv0.is_empty() {
        let base = basename(argv0);
        let permitted = profile
            .exec
            .allow_argv0
            .iter()
            .any(|allowed| allowed == argv0 || (!allowed.contains('/') && allowed == base));
        if !permitted {
            return Err(CommandDenied::Argv0 {
                profile: profile.name.clone(),
                argv0: argv0.to_string(),
                allowed: profile.exec.allow_argv0.join(", "),
            });
        }
    }

    if profile.exec.allow_args.is_empty() {
        return Ok(());
    }
    let mut patterns = Vec::with_capacity(profile.exec.allow_args.len());
    for pattern in &profile.exec.allow_args {
        patterns.push(
            regex::Regex::new(pattern).map_err(|e| CommandDenied::Pattern {
                profile: profile.name.clone(),
                pattern: pattern.clone(),
                detail: e.to_string(),
            })?,
        );
    }
    for arg in args {
        if !patterns.iter().any(|p| p.is_match(arg)) {
            return Err(CommandDenied::Arg {
                profile: profile.name.clone(),
                arg: arg.clone(),
                count: patterns.len(),
            });
        }
    }
    Ok(())
}

/// The last path component of `argv0`, or the whole thing when it has none.
fn basename(argv0: &str) -> &str {
    argv0.rsplit('/').next().unwrap_or(argv0)
}

/// Why an environment could not be composed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvError {
    /// A template names a credential that was not minted for this run.
    ///
    /// The loader guarantees the credential is *declared*; this fires when
    /// `--cred` narrowed the run to a subset that leaves the template dangling.
    #[error("env `{key}` needs credential `{credential}`, which this run did not mint; drop it from `--cred` or from the profile's `env`")]
    MissingCredential {
        /// The environment variable being composed.
        key: String,
        /// The credential the template referenced.
        credential: String,
    },

    /// A template names a field the minter did not produce.
    #[error("env `{key}` needs field `{field}` of credential `{credential}`, which that minter does not produce; it offers {available}")]
    MissingField {
        /// The environment variable being composed.
        key: String,
        /// The credential that was minted.
        credential: String,
        /// The field the template asked for.
        field: String,
        /// The field names the minter did produce, comma separated.
        available: String,
    },

    /// A `${config.<key>}` reference had nothing to resolve against.
    #[error("env `{key}` references `${{config.{config_key}}}`, which nothing defines")]
    MissingConfig {
        /// The environment variable being composed.
        key: String,
        /// The configuration key that was referenced.
        config_key: String,
    },

    /// The template did not parse. The loader checks this too.
    #[error("env `{key}` is not a valid template: {detail}")]
    Template {
        /// The environment variable being composed.
        key: String,
        /// The parser's complaint.
        detail: String,
    },
}

/// One credential's minted fields, keyed by the credential's profile name.
pub type MintedFields = BTreeMap<String, BTreeMap<String, Zeroizing<String>>>;

/// Build the environment a subprocess runs with.
///
/// The result is the *whole* environment bar the passthrough list: the child is
/// started with `env_clear()`, so anything absent here is absent there. Three
/// sources are merged, in this order, later ones winning:
///
/// 1. `trust_env` — the CA bundle variables, so the child trusts the local CA.
/// 2. the profile's `env` block, with `${minted...}` and `${config...}`
///    substituted.
///
/// The passthrough list is deliberately *not* merged here. The daemon composing
/// this cannot see the client's environment, so it names what may pass through
/// and the client fills those in itself.
pub fn compose_env(
    profile: &Profile,
    trust_env: &BTreeMap<String, String>,
    minted: &MintedFields,
    config: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, Zeroizing<String>>, EnvError> {
    let mut out: BTreeMap<String, Zeroizing<String>> = trust_env
        .iter()
        .map(|(k, v)| (k.clone(), Zeroizing::new(v.clone())))
        .collect();

    for (key, template) in &profile.env {
        let segments = parse_env_template(template).map_err(|e| EnvError::Template {
            key: key.clone(),
            detail: e.to_string(),
        })?;
        let mut value = Zeroizing::new(String::new());
        for segment in segments {
            match segment {
                EnvSegment::Literal(text) => value.push_str(&text),
                EnvSegment::Minted { credential, field } => {
                    let fields =
                        minted
                            .get(&credential)
                            .ok_or_else(|| EnvError::MissingCredential {
                                key: key.clone(),
                                credential: credential.clone(),
                            })?;
                    let found = fields.get(&field).ok_or_else(|| EnvError::MissingField {
                        key: key.clone(),
                        credential: credential.clone(),
                        field: field.clone(),
                        available: fields.keys().cloned().collect::<Vec<_>>().join(", "),
                    })?;
                    value.push_str(found);
                }
                EnvSegment::Config { key: config_key } => {
                    let found = config
                        .get(&config_key)
                        .ok_or_else(|| EnvError::MissingConfig {
                            key: key.clone(),
                            config_key: config_key.clone(),
                        })?;
                    value.push_str(found);
                }
            }
        }
        out.insert(key.clone(), value);
    }

    Ok(out)
}

/// The variable names a subprocess may inherit from the caller.
///
/// [`DEFAULT_PASSTHROUGH`] plus the profile's own `env_passthrough`, sorted and
/// deduplicated so the list is stable to assert on.
pub fn passthrough_names(profile: &Profile) -> Vec<String> {
    let mut names: Vec<String> = DEFAULT_PASSTHROUGH
        .iter()
        .map(|n| (*n).to_string())
        .collect();
    names.extend(profile.env_passthrough.iter().cloned());
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(yaml: &str) -> Profile {
        Profile::from_yaml_str(yaml).unwrap()
    }

    fn minted(pairs: &[(&str, &[(&str, &str)])]) -> MintedFields {
        pairs
            .iter()
            .map(|(credential, fields)| {
                (
                    (*credential).to_string(),
                    fields
                        .iter()
                        .map(|(k, v)| ((*k).to_string(), Zeroizing::new((*v).to_string())))
                        .collect(),
                )
            })
            .collect()
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn an_empty_allowlist_permits_anything() {
        let p = profile("name: dev\n");
        assert_eq!(check_command(&p, "rm", &args(&["-rf", "/"])), Ok(()));
    }

    #[test]
    fn argv0_matches_a_bare_name_by_its_basename() {
        let p = profile("name: dev\nexec:\n  allow_argv0: [psql]\n");
        assert_eq!(check_command(&p, "psql", &[]), Ok(()));
        assert_eq!(check_command(&p, "/opt/homebrew/bin/psql", &[]), Ok(()));
    }

    #[test]
    fn an_absolute_entry_pins_that_exact_path() {
        let p = profile("name: dev\nexec:\n  allow_argv0: ['/usr/local/bin/psql']\n");
        assert_eq!(check_command(&p, "/usr/local/bin/psql", &[]), Ok(()));
        // The basename rule is one-directional on purpose: pinning a path is
        // how an operator says "that binary, not whatever is on PATH".
        let err = check_command(&p, "psql", &[]).unwrap_err();
        assert!(matches!(err, CommandDenied::Argv0 { .. }), "{err}");
    }

    #[test]
    fn a_denied_argv0_names_itself_and_what_was_permitted() {
        let p = profile("name: dev\nexec:\n  allow_argv0: [psql, pg_dump]\n");
        let err = check_command(&p, "bash", &[]).unwrap_err();
        let text = err.to_string();
        assert!(text.contains('`'), "{text}");
        assert!(text.contains("bash"), "{text}");
        assert!(text.contains("psql, pg_dump"), "{text}");
        assert!(text.contains("dev"), "{text}");
    }

    #[test]
    fn every_argument_must_match_at_least_one_pattern() {
        let p = profile("name: dev\nexec:\n  allow_args: ['^-c$', '^SELECT ']\n");
        assert_eq!(
            check_command(&p, "psql", &args(&["-c", "SELECT 1"])),
            Ok(())
        );

        let err = check_command(&p, "psql", &args(&["-c", "DROP TABLE t"])).unwrap_err();
        match err {
            CommandDenied::Arg { arg, count, .. } => {
                assert_eq!(arg, "DROP TABLE t");
                assert_eq!(count, 2);
            }
            other => panic!("expected an argument denial, got {other}"),
        }
    }

    #[test]
    fn the_denial_names_the_offending_argument_verbatim() {
        let p = profile("name: dev\nexec:\n  allow_args: ['^-c$']\n");
        let err = check_command(&p, "psql", &args(&["--dangerous"])).unwrap_err();
        assert!(err.to_string().contains("--dangerous"), "{err}");
    }

    #[test]
    fn an_empty_arg_allowlist_permits_arguments_even_when_argv0_is_pinned() {
        let p = profile("name: dev\nexec:\n  allow_argv0: [psql]\n");
        assert_eq!(
            check_command(&p, "psql", &args(&["anything", "-x"])),
            Ok(())
        );
    }

    #[test]
    fn a_command_with_no_arguments_passes_a_non_empty_arg_allowlist() {
        // "every argument matches one of these" is vacuously true with none,
        // and the alternative would make `allow_args` also ban bare commands.
        let p = profile("name: dev\nexec:\n  allow_args: ['^-c$']\n");
        assert_eq!(check_command(&p, "psql", &[]), Ok(()));
    }

    #[test]
    fn the_trust_environment_is_the_base_of_every_composed_environment() {
        let p = profile("name: dev\n");
        let trust = BTreeMap::from([("SSL_CERT_FILE".to_string(), "/tmp/ca.pem".to_string())]);
        let env = compose_env(&p, &trust, &MintedFields::new(), &BTreeMap::new()).unwrap();
        assert_eq!(env["SSL_CERT_FILE"].as_str(), "/tmp/ca.pem");
        assert_eq!(env.len(), 1);
    }

    #[test]
    fn minted_fields_are_substituted_into_templates() {
        let p = profile(
            "\
name: dev
credentials:
  - name: db
    kind: postgres-dynamic
env:
  PGUSER: ${minted.db.PGUSER}
  PGAPPNAME: briefcred-${minted.db.PGUSER}-shell
",
        );
        let env = compose_env(
            &p,
            &BTreeMap::new(),
            &minted(&[("db", &[("PGUSER", "briefcred_t_0123456789ab")])]),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(env["PGUSER"].as_str(), "briefcred_t_0123456789ab");
        assert_eq!(
            env["PGAPPNAME"].as_str(),
            "briefcred-briefcred_t_0123456789ab-shell"
        );
    }

    #[test]
    fn the_profile_env_wins_over_the_trust_environment() {
        // A profile that deliberately points a runtime at its own bundle must
        // not be silently overwritten by the default trust environment.
        let p = profile("name: dev\nenv:\n  SSL_CERT_FILE: /etc/ssl/cert.pem\n");
        let trust = BTreeMap::from([("SSL_CERT_FILE".to_string(), "/tmp/ca.pem".to_string())]);
        let env = compose_env(&p, &trust, &MintedFields::new(), &BTreeMap::new()).unwrap();
        assert_eq!(env["SSL_CERT_FILE"].as_str(), "/etc/ssl/cert.pem");
    }

    #[test]
    fn a_credential_this_run_did_not_mint_is_a_named_error() {
        let p = profile(
            "\
name: dev
credentials:
  - name: db
    kind: postgres-dynamic
env:
  PGUSER: ${minted.db.PGUSER}
",
        );
        let err =
            compose_env(&p, &BTreeMap::new(), &MintedFields::new(), &BTreeMap::new()).unwrap_err();
        assert_eq!(
            err,
            EnvError::MissingCredential {
                key: "PGUSER".into(),
                credential: "db".into()
            }
        );
        assert!(err.to_string().contains("--cred"), "{err}");
    }

    #[test]
    fn a_field_the_minter_does_not_produce_lists_the_ones_it_does() {
        let p = profile(
            "\
name: dev
credentials:
  - name: db
    kind: postgres-dynamic
env:
  X: ${minted.db.PGTOKEN}
",
        );
        let err = compose_env(
            &p,
            &BTreeMap::new(),
            &minted(&[("db", &[("PGUSER", "u"), ("PGPASSWORD", "p")])]),
            &BTreeMap::new(),
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("PGTOKEN"), "{text}");
        assert!(text.contains("PGPASSWORD, PGUSER"), "{text}");
    }

    #[test]
    fn a_config_reference_resolves_from_the_supplied_table() {
        let p = profile("name: dev\nenv:\n  PGHOST: ${config.db_host}\n");
        let config = BTreeMap::from([("db_host".to_string(), "10.0.0.1".to_string())]);
        let env = compose_env(&p, &BTreeMap::new(), &MintedFields::new(), &config).unwrap();
        assert_eq!(env["PGHOST"].as_str(), "10.0.0.1");

        let err =
            compose_env(&p, &BTreeMap::new(), &MintedFields::new(), &BTreeMap::new()).unwrap_err();
        assert!(err.to_string().contains("db_host"), "{err}");
    }

    #[test]
    fn the_passthrough_list_is_the_defaults_plus_the_profile_sorted_and_unique() {
        let p = profile("name: dev\nenv_passthrough: [PGSSLMODE, PATH, AWS_REGION]\n");
        assert_eq!(
            passthrough_names(&p),
            vec![
                "AWS_REGION",
                "HOME",
                "LANG",
                "PATH",
                "PGSSLMODE",
                "TERM",
                "TMPDIR"
            ]
        );
    }

    #[test]
    fn a_profile_that_names_nothing_still_gets_the_defaults() {
        let mut expected = DEFAULT_PASSTHROUGH.map(String::from).to_vec();
        expected.sort();
        assert_eq!(passthrough_names(&profile("name: dev\n")), expected);
    }

    #[test]
    fn a_minted_field_no_template_names_never_reaches_the_environment() {
        // The environment is the profile's `env` block, not a dump of
        // everything that was minted: a credential the profile does not put in
        // `env` must not reach the child by accident.
        let p = profile("name: dev\ncredentials:\n  - name: db\n    kind: postgres-dynamic\n");
        let env = compose_env(
            &p,
            &BTreeMap::new(),
            &minted(&[("db", &[("PGPASSWORD", "t0p-s3cret")])]),
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(env.is_empty(), "{:?}", env.keys().collect::<Vec<_>>());
    }
}
