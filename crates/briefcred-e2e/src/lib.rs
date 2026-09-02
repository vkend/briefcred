//! End-to-end test support for briefcred.
//!
//! The crate ships no product code. It exists so integration tests have two
//! shared, reusable fixtures: [`pg_harness`] brings up a throwaway PostgreSQL
//! cluster on a free loopback port, and [`daemon_harness`] runs the real
//! `briefcred-daemon` binary under a temporary `BRIEFCRED_HOME`. Both tear
//! everything down when they are dropped.

pub mod daemon_harness;
pub mod pg_harness;
