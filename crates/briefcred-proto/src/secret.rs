//! The one string type in briefcred that is deliberately serialisable.
//!
//! Everywhere else a secret is [`zeroize::Zeroizing<String>`] and is not
//! `Serialize`, because the only ways a secret can leave a process by accident
//! are a log line and a serialiser. The helper protocol is the exception that
//! proves the rule: a helper runs the minter in its own address space, so the
//! master credential has to reach it somehow, and the only channel is the
//! anonymous pipe the daemon holds the other end of.
//!
//! [`SecretString`] therefore serialises as a plain JSON string and does three
//! things to make that safe to have in the codebase:
//!
//! - `Debug` prints `<redacted>`, so a `{:?}` of a whole request cannot leak it.
//! - The value is held in `Zeroizing<String>`, so dropping the request wipes it.
//! - It is only ever used on the helper wire, never on the client socket and
//!   never in an audit row. Both of those are asserted in tests.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// A secret that crosses the daemon-to-helper pipe and nothing else.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wrap a secret for the helper wire.
    pub fn new(value: impl Into<String>) -> SecretString {
        SecretString(Zeroizing::new(value.into()))
    }

    /// The secret itself. Callers must not log or store what they get back.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The secret as the zeroising string every minter API expects.
    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }
}

impl From<Zeroizing<String>> for SecretString {
    fn from(value: Zeroizing<String>) -> SecretString {
        SecretString(value)
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<SecretString, D::Error> {
        Ok(SecretString(Zeroizing::new(String::deserialize(
            deserializer,
        )?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_never_debug_prints_itself() {
        let secret = SecretString::new("hunter2");
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert!(!format!("{secret:#?}").contains("hunter2"));
    }

    #[test]
    fn a_secret_round_trips_as_a_plain_json_string() {
        let secret = SecretString::new("hunter2");
        let json = serde_json::to_string(&secret).unwrap();
        assert_eq!(json, "\"hunter2\"");
        let back: SecretString = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), "hunter2");
    }
}
