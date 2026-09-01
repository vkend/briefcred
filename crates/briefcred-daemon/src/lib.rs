//! The briefcred per-user daemon: IPC, lifecycle, audit, and metrics.

#![forbid(unsafe_code)]

pub mod audit;
pub mod config;
pub mod error;

pub use config::Config;
pub use error::{Error, Result};
