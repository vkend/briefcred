//! Minter implementations.
//!
//! Each minter is selected by the `kind` string in a profile's credential
//! spec and registers itself with [`crate::registry`], so adding one is a new
//! file rather than an edit to a central table.
//!
//! [`postgres`] runs in a helper process, which is where a minter that opens a
//! network connection with a master credential belongs. [`ssh_cert`] runs
//! inside the daemon, because it talks to nothing; its module documentation
//! says what that costs. [`http`] and [`postgres_proxy`] run nowhere at all:
//! their credentials are served by one of the daemon's two proxies, and they
//! register only their schema.

pub mod aws_sts;
pub mod http;
pub mod postgres;
pub mod postgres_proxy;
pub mod ssh_cert;

pub use aws_sts::AwsStsConfig;
pub use http::HttpKind;
pub use postgres::PostgresDynamicMinter;
pub use postgres_proxy::PgProxyConfig;
pub use ssh_cert::SshCertMinter;
