//! The `briefcred` command-line interface.
//!
//! The CLI owns setup and lifecycle. It talks to the daemon over the Unix
//! socket, and it talks to launchd or systemd to start and stop it, but it
//! never starts the daemon itself: the service manager is the only thing that
//! owns that process.

#![deny(unsafe_code)]

#[macro_use]
pub mod output;

pub mod audit;
pub mod bootstrap;
pub mod ca;
pub mod cli;
pub mod client;
pub mod error;
pub mod exec;
pub mod install;
pub mod lifecycle;
pub mod mcp;
pub mod service;
pub mod session_key;
pub mod signing;
pub mod trust;

pub use cli::{Cli, Command, DaemonAction, ProfileAction};
pub use error::{Error, Result};
