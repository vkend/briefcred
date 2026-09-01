//! Minter implementations.
//!
//! Each minter is selected by the `kind` string in a profile's credential
//! spec. Phase 0 ships one; the registry that resolves `kind` at profile load
//! arrives with the daemon in Phase 3.

pub mod postgres;

pub use postgres::PostgresDynamicMinter;
