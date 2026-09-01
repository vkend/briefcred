//! The minter registry: `kind` strings to minter constructors.
//!
//! A minter registers itself with [`inventory::submit!`] next to its own
//! implementation, so adding one is a single file rather than an edit to a
//! central `match`. [`Registry::discover`] collects everything the linker kept
//! and is what the daemon validates profiles against.
//!
//! The registry deliberately holds constructors rather than instances: a
//! minter is built only for the kinds a loaded profile actually names, and it
//! is built from that credential's `config` block so a misconfigured minter
//! fails at profile load rather than at mint time.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::traits::Minter;

/// One registered minter kind and the function that builds it.
///
/// Submitted with [`inventory::submit!`]; see `CONTRIBUTING.md`, "Adding a
/// minter", for the contract a `build` function must honour.
pub struct MinterFactory {
    /// The `kind` string a profile's credential spec selects this minter with.
    pub kind: &'static str,
    /// Build a minter from a credential spec's `config` block.
    ///
    /// Must validate the config and return [`Error::MinterConfig`] rather than
    /// panicking or deferring the failure to the first mint.
    pub build: fn(&serde_yaml::Value) -> Result<Arc<dyn Minter>>,
}

inventory::collect!(MinterFactory);

/// Every minter kind this binary was linked with.
#[derive(Clone, Default)]
pub struct Registry {
    factories: BTreeMap<&'static str, &'static MinterFactory>,
}

impl Registry {
    /// Collect every [`MinterFactory`] submitted anywhere in the binary.
    pub fn discover() -> Registry {
        let mut factories = BTreeMap::new();
        for factory in inventory::iter::<MinterFactory> {
            factories.insert(factory.kind, factory);
        }
        Registry { factories }
    }

    /// An empty registry, for tests that assert on the unknown-kind path.
    pub fn empty() -> Registry {
        Registry::default()
    }

    /// Every registered kind, sorted, for error messages and `ListProfiles`.
    pub fn kinds(&self) -> Vec<&'static str> {
        self.factories.keys().copied().collect()
    }

    /// Whether `kind` is registered.
    pub fn contains(&self, kind: &str) -> bool {
        self.factories.contains_key(kind)
    }

    /// Build the minter for `kind` from `config`.
    pub fn build(&self, kind: &str, config: &serde_yaml::Value) -> Result<Arc<dyn Minter>> {
        let factory = self
            .factories
            .get(kind)
            .ok_or_else(|| Error::profile(self.unknown_kind(kind)))?;
        (factory.build)(config)
    }

    /// The exact wording used whenever a profile names a kind nobody registered.
    ///
    /// Centralised because it is asserted on in tests and quoted in the docs:
    /// the list of registered kinds is the whole value of the message.
    pub fn unknown_kind(&self, kind: &str) -> String {
        format!(
            "unknown minter kind \"{kind}\" (registered: {})",
            self.kinds().join(", ")
        )
    }
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("kinds", &self.kinds())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_postgres_minter_registers_itself() {
        let registry = Registry::discover();
        assert!(
            registry.contains(crate::minters::postgres::KIND),
            "{registry:?}"
        );
    }

    #[test]
    fn kinds_come_back_sorted_so_the_error_text_is_stable() {
        let registry = Registry::discover();
        let mut sorted = registry.kinds();
        sorted.sort_unstable();
        assert_eq!(registry.kinds(), sorted);
    }

    #[test]
    fn an_unknown_kind_names_itself_and_everything_registered() {
        let registry = Registry::discover();
        let message = registry.unknown_kind("postgres-dynamik");
        assert_eq!(
            message,
            format!(
                "unknown minter kind \"postgres-dynamik\" (registered: {})",
                registry.kinds().join(", ")
            )
        );
        assert!(message.contains("postgres-dynamic"), "{message}");
    }

    #[test]
    fn an_empty_registry_still_produces_a_well_formed_message() {
        assert_eq!(
            Registry::empty().unknown_kind("anything"),
            "unknown minter kind \"anything\" (registered: )"
        );
    }

    #[test]
    fn building_an_unregistered_kind_is_a_profile_error() {
        let err = Registry::empty()
            .build("nope", &serde_yaml::Value::Null)
            .unwrap_err();
        assert!(err.to_string().contains("unknown minter kind"), "{err}");
    }

    #[test]
    fn building_a_registered_kind_returns_a_minter_of_that_kind() {
        let config: serde_yaml::Value = serde_yaml::from_str(
            "host: 127.0.0.1\ndbname: app\nuser: master\nsslmode: disable\nrole_template: {}\n",
        )
        .unwrap();
        let minter = Registry::discover()
            .build(crate::minters::postgres::KIND, &config)
            .unwrap();
        assert_eq!(minter.kind(), crate::minters::postgres::KIND);
    }

    #[test]
    fn building_a_registered_kind_with_a_bad_config_fails_at_build_time() {
        let config: serde_yaml::Value = serde_yaml::from_str("host: 127.0.0.1\n").unwrap();
        let err = Registry::discover()
            .build(crate::minters::postgres::KIND, &config)
            .unwrap_err();
        assert!(
            matches!(err, Error::MinterConfig { .. }),
            "expected a config error, got {err}"
        );
    }
}
