//! End-to-end test support for briefcred.
//!
//! The crate ships no product code. It exists so integration tests have a
//! shared, reusable fixture: [`pg_harness`] brings up a throwaway PostgreSQL
//! cluster on a free loopback port and tears it down again.

pub mod pg_harness;
