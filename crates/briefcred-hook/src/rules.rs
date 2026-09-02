//! `hook-rules.yaml`: which commands briefcred has an opinion about.
//!
//! The hook sees every Bash tool call an agent makes, and almost all of them
//! are none of briefcred's business. The rule file is how an operator says
//! which ones are: a regex over the command line, the profile that governs it,
//! and what to do.
//!
//! Rules are tried in order and the first match wins, so a specific rule goes
//! above a general one. A command that matches nothing is not mentioned in the
//! output at all, which is how the hook stays out of the way.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The file the rules are read from, inside the config directory.
pub const RULES_FILE: &str = "hook-rules.yaml";

/// What the hook tells the agent to do about a matched command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Let it run. With `rewrite`, run it under briefcred.
    Allow,
    /// Refuse it.
    Deny,
    /// Put it to the user.
    Ask,
}

impl Decision {
    /// The spelling Claude Code's `permissionDecision` field uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Ask => "ask",
        }
    }
}

/// One rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// A regex matched against the whole command line.
    #[serde(rename = "match")]
    pub pattern: String,
    /// The profile whose `exec` policy governs commands this rule matches.
    pub profile: String,
    /// What to do when it matches.
    pub decision: Decision,
    /// Whether to rewrite the command to run under `briefcred exec`.
    #[serde(default)]
    pub rewrite: bool,
}

/// The whole rule file.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    /// In order. The first match wins.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Rules {
    /// Parse a rule document, compiling every pattern.
    ///
    /// Compiling here rather than at match time means a typo in a regex is an
    /// error the operator sees when the hook first runs, rather than a rule
    /// that silently never matches.
    pub fn from_yaml_str(yaml: &str) -> Result<Rules, String> {
        let rules: Rules = serde_yaml_ng::from_str(yaml).map_err(|e| e.to_string())?;
        for rule in &rules.rules {
            regex::Regex::new(&rule.pattern)
                .map_err(|e| format!("`match: {}` is not a valid regex: {e}", rule.pattern))?;
        }
        Ok(rules)
    }

    /// Read the rule file, treating an absent one as "no rules".
    ///
    /// A missing file is the normal state for somebody who has installed
    /// briefcred and not yet wired the hook up, and it must not make every
    /// tool call fail.
    pub fn load(dir: &Path) -> Result<Rules, String> {
        let path = dir.join(RULES_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => Rules::from_yaml_str(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Rules::default()),
            Err(err) => Err(format!("cannot read {}: {err}", path.display())),
        }
    }

    /// The first rule matching `command`, if any.
    pub fn matching(&self, command: &str) -> Option<&Rule> {
        self.rules
            .iter()
            .find(|rule| regex::Regex::new(&rule.pattern).is_ok_and(|re| re.is_match(command)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
rules:
  - match: '^psql .*DROP'
    profile: db-ro
    decision: deny
  - match: '^psql '
    profile: db-ro
    decision: allow
    rewrite: true
";

    #[test]
    fn the_first_matching_rule_wins() {
        let rules = Rules::from_yaml_str(SAMPLE).unwrap();
        let denied = rules.matching("psql -c 'DROP TABLE t'").unwrap();
        assert_eq!(denied.decision, Decision::Deny);
        assert!(!denied.rewrite);

        let allowed = rules.matching("psql -c 'SELECT 1'").unwrap();
        assert_eq!(allowed.decision, Decision::Allow);
        assert!(allowed.rewrite);
    }

    #[test]
    fn a_command_no_rule_mentions_matches_nothing() {
        let rules = Rules::from_yaml_str(SAMPLE).unwrap();
        assert!(rules.matching("ls -la").is_none());
        assert!(rules.matching("echo psql").is_none());
    }

    #[test]
    fn an_uncompilable_pattern_is_an_error_at_load_rather_than_a_dead_rule() {
        let err = Rules::from_yaml_str(
            "rules:\n  - match: '[unclosed'\n    profile: p\n    decision: allow\n",
        )
        .unwrap_err();
        assert!(err.contains("not a valid regex"), "{err}");
    }

    #[test]
    fn an_unknown_key_or_decision_is_rejected() {
        assert!(Rules::from_yaml_str(
            "rules:\n  - match: x\n    profile: p\n    decision: allow\n    rewite: true\n"
        )
        .is_err());
        assert!(Rules::from_yaml_str(
            "rules:\n  - match: x\n    profile: p\n    decision: maybe\n"
        )
        .is_err());
    }

    #[test]
    fn a_missing_rule_file_is_no_rules_rather_than_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let rules = Rules::load(dir.path()).unwrap();
        assert!(rules.rules.is_empty());
        assert!(rules.matching("anything").is_none());
    }

    #[test]
    fn a_broken_rule_file_names_itself() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(RULES_FILE), "rules: [ {match: '['} ]\n").unwrap();
        let err = Rules::load(dir.path()).unwrap_err();
        assert!(err.contains(RULES_FILE), "{err}");
    }

    #[test]
    fn every_decision_spells_itself_the_way_the_agent_expects() {
        assert_eq!(Decision::Allow.as_str(), "allow");
        assert_eq!(Decision::Deny.as_str(), "deny");
        assert_eq!(Decision::Ask.as_str(), "ask");
    }
}
