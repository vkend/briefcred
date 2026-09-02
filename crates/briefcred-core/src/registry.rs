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

/// Where the daemon runs a minter.
///
/// The default is [`Hosting::Helper`], and it is the default because it is the
/// safe answer: a minter that opens a connection with a master credential gets
/// an address space of its own, so a bug in its parser costs one backend
/// rather than every master the daemon holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Hosting {
    /// The daemon spawns `briefcred-helper-<kind>` and speaks to it over
    /// stdio. The master credential crosses that pipe and never enters the
    /// daemon's own memory for longer than it takes to write it.
    Helper,
    /// The daemon runs the minter in its own process.
    ///
    /// Only correct for a minter that talks to no backend, because the master
    /// is then resident in the daemon. `ssh-cert` is the one that qualifies:
    /// it signs a certificate and writes two files, and a helper would buy
    /// nothing but the cost of a process.
    Daemon,
}

/// One registered minter kind and the function that builds it.
///
/// Submitted with [`inventory::submit!`]; see `CONTRIBUTING.md`, "Adding a
/// minter", for the contract a `build` function must honour.
pub struct MinterFactory {
    /// The `kind` string a profile's credential spec selects this minter with.
    pub kind: &'static str,
    /// Where the daemon runs this minter. Almost always [`Hosting::Helper`].
    pub hosting: Hosting,
    /// Check a credential spec's `config` block.
    ///
    /// Called from [`crate::Profile::validate`] whenever the daemon loads its
    /// profile directory, so it must return [`Error::MinterConfig`] rather
    /// than panicking or deferring the failure to the first mint.
    pub validate: fn(&serde_yaml::Value) -> Result<()>,
    /// Construct the minter, where this binary is the one that runs it.
    ///
    /// `None` says "the implementation is not linked here". A minter whose
    /// code lives in its own helper crate — because it drags in a vendor SDK
    /// nothing else needs — registers its *schema* in `briefcred-core`, so the
    /// daemon can validate a profile that names it, and leaves this `None`.
    /// The helper binary constructs the minter directly.
    ///
    /// [`Hosting::Daemon`] and `None` are a contradiction, and
    /// [`Registry::build`] reports it as one.
    pub construct: Option<fn() -> Arc<dyn Minter>>,
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

    /// Where the daemon must run `kind`, or `None` if nothing registered it.
    pub fn hosting(&self, kind: &str) -> Option<Hosting> {
        self.factories.get(kind).map(|factory| factory.hosting)
    }

    /// Check `config` against the schema `kind` expects.
    ///
    /// This is what profile loading runs, and it is deliberately separate from
    /// [`Registry::build`]: every binary that reads profiles must be able to
    /// reject a bad one, but only the binary that actually mints needs the
    /// minter itself.
    pub fn validate(&self, kind: &str, config: &serde_yaml::Value) -> Result<()> {
        (self.factory(kind)?.validate)(config)
    }

    /// Build the minter for `kind` from `config`, after validating it.
    pub fn build(&self, kind: &str, config: &serde_yaml::Value) -> Result<Arc<dyn Minter>> {
        let factory = self.factory(kind)?;
        (factory.validate)(config)?;
        let construct = factory.construct.ok_or_else(|| Error::MinterConfig {
            kind: factory.kind,
            message: format!(
                "`{kind}` is minted by `briefcred-helper-{kind}`; this binary has its \
                 configuration schema but not its implementation"
            ),
        })?;
        Ok(construct())
    }

    fn factory(&self, kind: &str) -> Result<&'static MinterFactory> {
        self.factories
            .get(kind)
            .copied()
            .ok_or_else(|| Error::profile(self.unknown_kind(kind)))
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
