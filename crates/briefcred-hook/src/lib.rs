//! The `briefcred-hook` shim: briefcred's answer to an agent's `PreToolUse`.
//!
//! An agent asks, before it runs a shell command, whether it may. This binary
//! reads that question on stdin as JSON, decides, and writes the answer on
//! stdout as JSON. It is a filter: no state, no daemon of its own, one process
//! per tool call.
//!
//! # The two halves of a decision
//!
//! 1. **The rule file** says whether briefcred has an opinion about this
//!    command at all, and what that opinion is. It is a regex over the command
//!    line, which is a blunt instrument and is meant to be — its job is to
//!    route, not to enforce.
//! 2. **The daemon** says whether the profile's `exec` policy would actually
//!    permit the command. That is the enforcement, and it is the same check
//!    `briefcred exec` runs, so the hook cannot promise something exec would
//!    refuse.
//!
//! A rule that says `allow` for a command the profile forbids becomes a deny,
//! never the other way round. The hook can only ever be more restrictive than
//! the rule file, because the rule file is the easier of the two to get wrong.
//!
//! # Failing open
//!
//! When the daemon is not running, the hook says nothing rather than denying.
//! A credential broker that stops an agent from running `ls` because a
//! background service is down is a broker nobody keeps installed. Nothing is
//! *granted* by failing open: without the daemon there is no credential to
//! grant, so the worst case is the agent running the command with whatever it
//! already had, which is what it would have done without briefcred at all.

#![deny(unsafe_code)]

pub mod rules;

use serde::{Deserialize, Serialize};

use crate::rules::{Decision, Rules};

/// The slice of Claude Code's `PreToolUse` payload this hook reads.
///
/// Deliberately not `deny_unknown_fields`: the agent's payload is not
/// briefcred's schema, and a new field appearing in it must not break every
/// tool call.
#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    /// The tool being invoked, for example `Bash`.
    #[serde(default)]
    pub tool_name: String,
    /// The tool's own input.
    #[serde(default)]
    pub tool_input: ToolInput,
}

/// The part of `tool_input` a shell tool carries.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ToolInput {
    /// The command line the agent wants to run.
    #[serde(default)]
    pub command: String,
}

/// What the hook writes on stdout.
#[derive(Debug, Clone, Serialize)]
pub struct HookOutput {
    /// The single key the agent reads.
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
}

/// The decision, in the agent's own shape.
#[derive(Debug, Clone, Serialize)]
pub struct HookSpecificOutput {
    /// Always `PreToolUse`.
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    /// `allow`, `deny`, or `ask`.
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    /// Why, in words the user will read.
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
    /// A replacement for the tool's input, when the rule rewrites.
    #[serde(rename = "updatedInput", skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<UpdatedInput>,
}

/// The rewritten tool input.
#[derive(Debug, Clone, Serialize)]
pub struct UpdatedInput {
    /// The command the agent should run instead.
    pub command: String,
}

impl HookOutput {
    /// Build an answer.
    pub fn new(
        decision: Decision,
        reason: impl Into<String>,
        updated_input: Option<UpdatedInput>,
    ) -> HookOutput {
        HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: decision.as_str().to_string(),
                permission_decision_reason: reason.into(),
                updated_input,
            },
        }
    }
}

/// What the daemon said about a command, or that it was not asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAnswer {
    /// The profile's `exec` policy permits it.
    Allowed,
    /// It does not, and this is why.
    Denied(String),
    /// The daemon could not be asked, and this is why.
    Unknown(String),
}

/// Decide, given a rule file and whatever the daemon said.
///
/// Pure, so the whole decision matrix is testable without a daemon, a socket,
/// or an agent. `command` is the agent's command line.
pub fn decide(
    rules: &Rules,
    command: &str,
    ask_daemon: impl Fn(&str) -> PolicyAnswer,
) -> Option<HookOutput> {
    let rule = rules.matching(command)?;

    // The daemon is only consulted for a rule that would let the command run.
    // A `deny` rule needs no second opinion, and asking for one would mean the
    // daemon being down could turn a deny into something else.
    if rule.decision == Decision::Deny {
        return Some(HookOutput::new(
            Decision::Deny,
            format!("briefcred: profile `{}` denies this command", rule.profile),
            None,
        ));
    }

    match ask_daemon(&rule.profile) {
        PolicyAnswer::Denied(why) => Some(HookOutput::new(
            Decision::Deny,
            format!("briefcred: {why}"),
            None,
        )),
        // The daemon is down. Say so, and put it to the user rather than
        // pretending briefcred vouched for a command it never checked.
        PolicyAnswer::Unknown(why) => Some(HookOutput::new(
            Decision::Ask,
            format!("briefcred could not check this command: {why}"),
            None,
        )),
        PolicyAnswer::Allowed if rule.rewrite && is_compound(command) => {
            // The daemon was asked about the command's *words*, because
            // `split_command` is not a shell. For a plain command those words
            // are the command. For `psql … | tee /etc/passwd` they are not: the
            // rewrite hands the whole line back to a shell, which then runs a
            // second program the daemon never saw and which briefcred would be
            // vouching for. So the answer is `ask` — never `allow`.
            Some(HookOutput::new(
                Decision::Ask,
                format!(
                    "briefcred: profile `{}` permits the first command, but this line has a \
                     shell operator in it and briefcred cannot vouch for what the rest of it \
                     runs",
                    rule.profile
                ),
                None,
            ))
        }
        PolicyAnswer::Allowed => {
            let updated_input = rule.rewrite.then(|| UpdatedInput {
                command: rewrite(&rule.profile, command),
            });
            let reason = if rule.rewrite {
                format!(
                    "briefcred: running under profile `{}` with short-lived credentials",
                    rule.profile
                )
            } else {
                format!("briefcred: profile `{}` permits this command", rule.profile)
            };
            Some(HookOutput::new(rule.decision, reason, updated_input))
        }
    }
}

/// The shell metacharacters that make a command line more than one command.
///
/// Not an exhaustive shell grammar and not trying to be. Each of these can
/// introduce a second program on a line the daemon only judged the first of,
/// and the cost of listing one that turns out to be harmless is a prompt.
const SHELL_OPERATORS: [&str; 8] = ["|", ";", "&&", "||", ">", "<", "$(", "`"];

/// Whether `command` runs, or could run, more than the one program the daemon
/// was asked about.
///
/// Deliberately naive: a `|` inside a quoted argument counts. Treating a quoted
/// pipe as safe would mean re-implementing the quoting rules of whatever shell
/// eventually runs the line, and being wrong there turns an `ask` into an
/// `allow` for a command briefcred never checked. Being wrong the other way
/// turns it into a prompt.
pub fn is_compound(command: &str) -> bool {
    SHELL_OPERATORS
        .iter()
        .any(|operator| command.contains(operator))
}

/// The command line that runs `command` under briefcred.
///
/// `--` before the command, so anything in it that looks like a briefcred flag
/// stays part of the child's argv.
pub fn rewrite(profile: &str, command: &str) -> String {
    format!("briefcred exec --profile={profile} -- {command}")
}

/// Split a command line into `argv0` and its arguments.
///
/// Handles single and double quotes and backslash escaping, which covers what
/// an agent actually emits. It is deliberately not a shell: a command with a
/// pipe, a redirect, or a substitution in it is returned as its words, and the
/// daemon's allowlist then sees those words. That is the conservative reading —
/// `psql | tee /etc/passwd` presents `|` and `tee` as arguments, which an
/// `allow_args` list will refuse.
pub fn split_command(command: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for ch in command.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match (quote, ch) {
            (None, '\\') => {
                escaped = true;
                started = true;
            }
            (None, '\'') | (None, '"') => {
                quote = Some(ch);
                started = true;
            }
            (Some(open), c) if c == open => quote = None,
            (Some(_), c) => current.push(c),
            (None, c) if c.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (None, c) => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        words.push(current);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = "\
rules:
  - match: '^psql .*DROP'
    profile: db-ro
    decision: deny
  - match: '^psql '
    profile: db-ro
    decision: allow
    rewrite: true
  - match: '^pg_dump '
    profile: db-ro
    decision: ask
";

    fn rules() -> Rules {
        Rules::from_yaml_str(RULES).unwrap()
    }

    fn allows(_profile: &str) -> PolicyAnswer {
        PolicyAnswer::Allowed
    }

    fn decision_of(output: &HookOutput) -> &str {
        &output.hook_specific_output.permission_decision
    }

    #[test]
    fn a_command_no_rule_matches_produces_no_output_at_all() {
        assert!(decide(&rules(), "ls -la", allows).is_none());
    }

    #[test]
    fn an_allow_rule_with_rewrite_returns_the_wrapped_command() {
        let output = decide(&rules(), "psql -c 'SELECT 1'", allows).unwrap();
        assert_eq!(decision_of(&output), "allow");
        assert_eq!(
            output
                .hook_specific_output
                .updated_input
                .as_ref()
                .map(|u| u.command.as_str()),
            Some("briefcred exec --profile=db-ro -- psql -c 'SELECT 1'")
        );
    }

    #[test]
    fn an_allow_and_rewrite_rule_only_asks_when_the_line_is_more_than_one_command() {
        // Every one of these matches the `^psql ` allow-and-rewrite rule, and
        // every one of them puts a second program on the line. Rewriting it
        // would hand the whole thing to a shell with briefcred's blessing on a
        // command the daemon judged only the first word of.
        for command in [
            "psql -c 'SELECT 1' | tee /etc/passwd",
            "psql -c 'SELECT 1'; rm -rf /",
            "psql -c 'SELECT 1' && curl evil.example",
            "psql -c 'SELECT 1' || curl evil.example",
            "psql -c 'SELECT 1' > /etc/passwd",
            "psql -f - < /etc/passwd",
            "psql -c $(cat /etc/passwd)",
            "psql -c `cat /etc/passwd`",
        ] {
            let output = decide(&rules(), command, allows).unwrap();
            assert_eq!(decision_of(&output), "ask", "{command}");
            assert!(
                output.hook_specific_output.updated_input.is_none(),
                "{command} must not be rewritten"
            );
        }

        // And a plain one still runs, or the rule would be useless.
        for command in ["psql -c 'SELECT 1'", "psql --dbname app -c \"SELECT 2\""] {
            let output = decide(&rules(), command, allows).unwrap();
            assert_eq!(decision_of(&output), "allow", "{command}");
            assert!(
                output.hook_specific_output.updated_input.is_some(),
                "{command} must still be rewritten"
            );
        }
    }

    #[test]
    fn a_deny_rule_still_denies_a_compound_command_rather_than_asking() {
        // The escalation only ever goes towards a prompt. A line that a `deny`
        // rule matches is refused whatever else is on it.
        let output = decide(&rules(), "psql -c 'DROP TABLE t' | tee out", |_| {
            panic!("a deny rule must not need the daemon")
        })
        .unwrap();
        assert_eq!(decision_of(&output), "deny");
    }

    #[test]
    fn an_ask_rule_asks_and_rewrites_nothing() {
        let output = decide(&rules(), "pg_dump app", allows).unwrap();
        assert_eq!(decision_of(&output), "ask");
        assert!(output.hook_specific_output.updated_input.is_none());
    }

    #[test]
    fn a_deny_rule_denies_without_consulting_the_daemon() {
        let output = decide(&rules(), "psql -c 'DROP TABLE t'", |_| {
            panic!("a deny rule must not need the daemon")
        })
        .unwrap();
        assert_eq!(decision_of(&output), "deny");
        assert!(output.hook_specific_output.updated_input.is_none());
    }

    #[test]
    fn the_daemon_can_turn_an_allow_rule_into_a_deny_but_not_the_reverse() {
        let output = decide(&rules(), "psql -c 'SELECT 1'", |_| {
            PolicyAnswer::Denied("`psql` is not permitted by profile `db-ro`".into())
        })
        .unwrap();
        assert_eq!(decision_of(&output), "deny");
        assert!(output
            .hook_specific_output
            .permission_decision_reason
            .contains("not permitted"));

        // And the other direction: a deny rule stays a deny however
        // enthusiastically the daemon would have permitted it.
        let output = decide(&rules(), "psql -c 'DROP TABLE t'", allows).unwrap();
        assert_eq!(decision_of(&output), "deny");
    }

    #[test]
    fn a_daemon_that_cannot_be_asked_becomes_an_ask_rather_than_an_allow() {
        let output = decide(&rules(), "psql -c 'SELECT 1'", |_| {
            PolicyAnswer::Unknown("daemon is not running".into())
        })
        .unwrap();
        assert_eq!(decision_of(&output), "ask");
        assert!(output
            .hook_specific_output
            .permission_decision_reason
            .contains("not running"));
        assert!(
            output.hook_specific_output.updated_input.is_none(),
            "a command briefcred could not check must not be rewritten to run under briefcred"
        );
    }

    #[test]
    fn the_rewrite_puts_the_separator_before_the_command() {
        // Without `--`, an agent's `psql --profile x` would be read as
        // briefcred's own flag.
        assert_eq!(
            rewrite("db-ro", "psql --profile x"),
            "briefcred exec --profile=db-ro -- psql --profile x"
        );
    }

    #[test]
    fn a_command_line_splits_the_way_a_shell_would_for_the_easy_cases() {
        assert_eq!(
            split_command("psql -c 'SELECT 1'"),
            vec!["psql", "-c", "SELECT 1"]
        );
        assert_eq!(
            split_command("psql -c \"SELECT 1\""),
            vec!["psql", "-c", "SELECT 1"]
        );
        assert_eq!(split_command("  psql   -l  "), vec!["psql", "-l"]);
        assert_eq!(split_command(""), Vec::<String>::new());
        assert_eq!(split_command("echo a\\ b"), vec!["echo", "a b"]);
    }

    #[test]
    fn an_empty_quoted_argument_survives_the_split() {
        assert_eq!(split_command("psql -c ''"), vec!["psql", "-c", ""]);
    }

    #[test]
    fn shell_metacharacters_come_through_as_words_for_the_allowlist_to_refuse() {
        assert_eq!(
            split_command("psql | tee /etc/passwd"),
            vec!["psql", "|", "tee", "/etc/passwd"]
        );
    }

    #[test]
    fn the_output_shape_is_the_one_the_agent_reads() {
        let output = decide(&rules(), "psql -l", allows).unwrap();
        let json = serde_json::to_value(&output).unwrap();
        let inner = &json["hookSpecificOutput"];
        assert_eq!(inner["hookEventName"], "PreToolUse");
        assert_eq!(inner["permissionDecision"], "allow");
        assert!(inner["permissionDecisionReason"].is_string());
        assert_eq!(
            inner["updatedInput"]["command"],
            "briefcred exec --profile=db-ro -- psql -l"
        );
    }

    #[test]
    fn an_answer_without_a_rewrite_omits_updated_input_entirely() {
        // Not `null`: an agent that sees the key at all may treat it as a
        // replacement, and replacing a command with nothing is not the answer.
        let output = decide(&rules(), "pg_dump app", allows).unwrap();
        let json = serde_json::to_value(&output).unwrap();
        assert!(json["hookSpecificOutput"].get("updatedInput").is_none());
    }

    #[test]
    fn a_payload_with_fields_this_binary_does_not_know_still_parses() {
        let input: HookInput = serde_json::from_str(
            r#"{"tool_name":"Bash","tool_input":{"command":"psql -l","timeout":5},
                "session_id":"abc","cwd":"/tmp"}"#,
        )
        .unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.tool_input.command, "psql -l");
    }
}
