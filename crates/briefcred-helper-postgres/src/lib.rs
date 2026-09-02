//! The PostgreSQL minting helper.
//!
//! One process per `(profile, postgres-dynamic)` pair, spawned by the daemon
//! and spoken to over stdio with [`briefcred_proto::helper`]. It exists so
//! that `tokio-postgres`, `rustls`, and the master database password live in
//! an address space the daemon does not share: a panic here costs one helper,
//! and a memory disclosure here exposes one backend's master rather than
//! every backend's.
//!
//! The helper is a thin shell around [`PostgresDynamicMinter`], which keeps
//! its master connection open across calls and reopens it when it drops. All
//! the SQL, and all the reasoning about revoke ordering, stays in
//! `briefcred-core` where it is unit-tested without a cluster, and the
//! protocol conversion stays in [`briefcred_core::MinterAdapter`], which every
//! helper and the daemon share.

#![deny(unsafe_code)]

use std::sync::Arc;

use briefcred_core::minters::postgres::PostgresDynamicMinter;
use briefcred_core::MinterAdapter;
use briefcred_proto::helper::{HelperError, HelperParams, HelperResult, StdioHandler};

/// The helper, holding the one minter it serves.
#[derive(Debug)]
pub struct PostgresHelper {
    adapter: MinterAdapter,
}

impl Default for PostgresHelper {
    fn default() -> PostgresHelper {
        PostgresHelper::new()
    }
}

impl PostgresHelper {
    /// A helper with no connection open yet.
    pub fn new() -> PostgresHelper {
        PostgresHelper {
            adapter: MinterAdapter::new(Arc::new(PostgresDynamicMinter::new())),
        }
    }
}

impl StdioHandler for PostgresHelper {
    async fn handle(&self, params: HelperParams) -> Result<HelperResult, HelperError> {
        self.adapter.dispatch(params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use briefcred_proto::helper::{
        encode_line, HelperRequest, HelperResponse, MintParams, ShutdownParams, CODE_INVALID_PARAMS,
    };
    use briefcred_proto::SecretString;

    #[tokio::test]
    async fn the_helper_stops_when_it_is_told_to() {
        let mut output: Vec<u8> = Vec::new();
        let line = encode_line(&HelperRequest::new(
            1,
            HelperParams::Shutdown(ShutdownParams {}),
        ))
        .unwrap();
        briefcred_proto::helper::serve_stdio(
            &PostgresHelper::new(),
            tokio::io::BufReader::new(line.as_bytes()),
            &mut output,
        )
        .await
        .unwrap();

        let reply: HelperResponse =
            serde_json::from_str(String::from_utf8(output).unwrap().trim_end()).unwrap();
        assert!(reply.error.is_none(), "{reply:?}");
    }

    #[tokio::test]
    async fn a_malformed_mint_id_is_refused_before_a_connection_is_attempted() {
        // Reaching the backend would need a cluster; being refused first is
        // both the correct behaviour and what makes this testable.
        let err = PostgresHelper::new()
            .handle(HelperParams::Mint(MintParams {
                mint_id: "not-a-mint-id".into(),
                profile: "dev".into(),
                credential: "db".into(),
                config: serde_json::json!({}),
                master: SecretString::new("m"),
                ttl_secs: 900,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code, CODE_INVALID_PARAMS);
        assert!(err.message.contains("not-a-mint-id"), "{err}");
    }
}
