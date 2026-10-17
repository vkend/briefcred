//! Reading and writing YAML, with one set of parser options for every caller.
//!
//! Through `serde-saphyr`, a parser written in safe Rust. Its predecessor here,
//! `serde_yaml_ng`, sat on `unsafe-libyaml`, a machine translation of libyaml's
//! C into unsafe Rust that is archived and will not be fixed
//! ([RUSTSEC-2024-0449](https://rustsec.org/advisories/RUSTSEC-2024-0449)).
//! Profiles are the most attacker-reachable input the daemon parses, since a
//! registry can hand it one, so the parser is the last place for that code.
//!
//! The options are kept here rather than at each call site so that a profile,
//! a hook rule file and a test fixture can never disagree about what a
//! document means.

use serde::de::DeserializeOwned;
use serde::Serialize;

/// A document that does not parse, as one line naming the line and column.
///
/// Rendered without the parser's source snippet: a profile error lands in the
/// daemon log and the audit trail as well as on a terminal, and eight lines
/// of excerpt in a log row is worse than a position the reader can jump to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<serde_saphyr::Error> for Error {
    fn from(err: serde_saphyr::Error) -> Self {
        let mut render = serde_saphyr::RenderOptions::new(&serde_saphyr::UserMessageFormatter);
        render.snippets = serde_saphyr::SnippetMode::Off;
        Error(err.render_with_options(render))
    }
}

/// A value that does not serialise.
pub use serde_saphyr::SerializeError;

/// The parser options every briefcred document is read with.
///
/// `strict_booleans` keeps YAML 1.2's reading of `yes`, `no`, `on` and `off`
/// as strings, which is what the previous parser did and what a profile
/// author writing `region: no` means. Duplicate keys stay an error, the
/// parser's default: a profile naming `master` twice is a mistake, not an
/// instruction to take the last one.
fn options() -> serde_saphyr::Options {
    serde_saphyr::options! { strict_booleans: true }
}

/// Parse one YAML document into `T`.
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    serde_saphyr::from_str_with_options(text, options()).map_err(Error::from)
}

/// Write `value` as a YAML document.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, SerializeError> {
    // `&value`, a sized reference, so a caller can pass a `str`.
    serde_saphyr::to_string(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_1_1_booleans_stay_strings() {
        let value: serde_json::Value = from_str("a: yes\nb: off\nc: true\n").unwrap();
        assert_eq!(
            value,
            serde_json::json!({"a": "yes", "b": "off", "c": true})
        );
    }

    #[test]
    fn a_duplicate_key_is_an_error() {
        let err = from_str::<serde_json::Value>("a: 1\na: 2\n").unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn an_error_is_one_line_that_names_the_position() {
        let err = from_str::<serde_json::Value>("a: [\n")
            .unwrap_err()
            .to_string();
        assert!(!err.contains('\n'), "{err}");
        assert!(err.contains("line 1"), "{err}");
    }

    #[test]
    fn what_is_written_reads_back_as_the_same_value() {
        let value = serde_json::json!({"description": "yes", "db": "0123", "arn": "a: b"});
        let text = to_string(&value).unwrap();
        assert_eq!(from_str::<serde_json::Value>(&text).unwrap(), value);
    }
}
