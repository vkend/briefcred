//! End-to-end tests for [`PostgresDynamicMinter`] against a real cluster.
//!
//! Each test brings up its own ephemeral PostgreSQL instance so a failure in
//! one cannot leave state behind for another.

use std::time::Duration;

use briefcred_core::minters::PostgresDynamicMinter;
use briefcred_core::{MintCtx, MintId, Minter, RevokeCtx, RevokeOutcome};
use briefcred_e2e::pg_harness::{cluster_or_skip, PgCluster, LIMITED_USER, MASTER_USER};
use zeroize::Zeroizing;

fn mint_ctx(
    cluster: &PgCluster,
    user: &str,
    master: Zeroizing<String>,
    grants: &str,
) -> (MintId, MintCtx) {
    let mint_id = MintId::generate();
    let ctx = MintCtx {
        mint_id: mint_id.clone(),
        profile: "e2e".into(),
        credential: "db".into(),
        config: cluster.minter_config(user, grants),
        master,
        ttl: Duration::from_secs(300),
    };
    (mint_id, ctx)
}

async fn role_exists(cluster: &PgCluster, mint_id: &MintId) -> bool {
    let client = cluster.connect_master().await;
    client
        .query_opt(
            "SELECT 1 FROM pg_roles WHERE rolname = $1",
            &[&mint_id.as_str()],
        )
        .await
        .expect("query pg_roles")
        .is_some()
}

/// Mint, use the credential for real work, revoke, and confirm the role is gone.
#[tokio::test]
async fn mint_connect_and_revoke_removes_the_role() {
    let Some(cluster) = cluster_or_skip("mint_connect_and_revoke_removes_the_role").await else {
        return;
    };

    let master = cluster.connect_master().await;
    master
        .batch_execute("CREATE TABLE probe (id int); INSERT INTO probe VALUES (1), (2)")
        .await
        .expect("create probe table");

    let grants = "    - privileges: [USAGE]\n      on: SCHEMA public\n    - privileges: [SELECT]\n      on: TABLE probe\n";
    let (mint_id, ctx) = mint_ctx(&cluster, MASTER_USER, cluster.master_password(), grants);
    let config = ctx.config.clone();

    let minter = PostgresDynamicMinter::new();
    let minted = minter.mint(ctx).await.expect("mint");

    assert_eq!(minted.mint_id, mint_id);
    assert_eq!(
        minted.fields["PGUSER"].as_str(),
        mint_id.as_str(),
        "the minted role name is the mint id"
    );
    assert_eq!(minted.fields["PGPORT"].as_str(), cluster.port().to_string());
    assert!(minted.fields["DATABASE_URL"].contains(mint_id.as_str()));
    assert!(minted.expires_at > time::OffsetDateTime::now_utc());

    // The minted password must actually authenticate: the cluster uses
    // scram-sha-256 for host connections.
    let as_minted = cluster
        .connect_as(mint_id.as_str(), &minted.fields["PGPASSWORD"])
        .await
        .expect("connect as the minted role");
    let one: i32 = as_minted
        .query_one("SELECT 1", &[])
        .await
        .expect("SELECT 1")
        .get(0);
    assert_eq!(one, 1);
    let rows: i64 = as_minted
        .query_one("SELECT count(*) FROM probe", &[])
        .await
        .expect("the granted SELECT privilege works")
        .get(0);
    assert_eq!(rows, 2);
    drop(as_minted);

    let outcome = minter
        .revoke(RevokeCtx {
            mint_id: mint_id.clone(),
            config,
            master: cluster.master_password(),
            revoke_token: minted.revoke_token.clone(),
        })
        .await;
    assert_eq!(outcome, RevokeOutcome::Revoked);
    assert!(
        !role_exists(&cluster, &mint_id).await,
        "role should be gone"
    );
    assert_eq!(cluster.leaked_role_count().await, 0);

    // Revoking again is not an error; the role is simply already absent.
    let outcome = minter
        .revoke(RevokeCtx {
            mint_id,
            config: cluster.minter_config(MASTER_USER, grants),
            master: cluster.master_password(),
            revoke_token: minted.revoke_token,
        })
        .await;
    assert_eq!(outcome, RevokeOutcome::AlreadyGone);
}

/// Five cycles under a master that does not own schema `public`, where each
/// minted role creates a table, so `DROP OWNED BY` is load-bearing.
#[tokio::test]
async fn repeated_cycles_under_a_non_owning_master_leave_no_roles() {
    let Some(cluster) =
        cluster_or_skip("repeated_cycles_under_a_non_owning_master_leave_no_roles").await
    else {
        return;
    };

    let owner: String = cluster
        .connect_master()
        .await
        .query_one(
            "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public'",
            &[],
        )
        .await
        .expect("read the owner of schema public")
        .get(0);
    assert_ne!(
        owner, LIMITED_USER,
        "the fixture is pointless unless the master does not own schema public"
    );

    let grants = "    - privileges: [USAGE, CREATE]\n      on: SCHEMA public\n";
    let minter = PostgresDynamicMinter::new();

    for cycle in 0..5 {
        let (mint_id, ctx) = mint_ctx(&cluster, LIMITED_USER, cluster.limited_password(), grants);
        let config = ctx.config.clone();
        let minted = minter.mint(ctx).await.expect("mint");

        let as_minted = cluster
            .connect_as(mint_id.as_str(), &minted.fields["PGPASSWORD"])
            .await
            .expect("connect as the minted role");
        as_minted
            .batch_execute(&format!("CREATE TABLE owned_by_mint_{cycle} (id int)"))
            .await
            .expect("the minted role can create a table it then owns");
        drop(as_minted);

        let outcome = minter
            .revoke(RevokeCtx {
                mint_id: mint_id.clone(),
                config,
                master: cluster.limited_password(),
                revoke_token: minted.revoke_token,
            })
            .await;
        assert_eq!(outcome, RevokeOutcome::Revoked, "cycle {cycle}");
        assert!(!role_exists(&cluster, &mint_id).await, "cycle {cycle}");
    }

    assert_eq!(
        cluster.leaked_role_count().await,
        0,
        "no briefcred_t_% roles may survive"
    );

    let orphan_tables: i64 = cluster
        .connect_master()
        .await
        .query_one(
            "SELECT count(*) FROM pg_tables WHERE tablename LIKE 'owned_by_mint_%'",
            &[],
        )
        .await
        .expect("count leftover tables")
        .get(0);
    assert_eq!(
        orphan_tables, 0,
        "DROP OWNED BY must clear the role's tables"
    );
}

/// A revoke that cannot complete reports `Failed` with a usable detail.
#[tokio::test]
async fn a_failed_revoke_reports_a_non_empty_detail() {
    let Some(cluster) = cluster_or_skip("a_failed_revoke_reports_a_non_empty_detail").await else {
        return;
    };

    let grants = "    - privileges: [USAGE]\n      on: SCHEMA public\n";
    let (mint_id, ctx) = mint_ctx(&cluster, LIMITED_USER, cluster.limited_password(), grants);
    let config = ctx.config.clone();

    let minter = PostgresDynamicMinter::new();
    let minted = minter.mint(ctx).await.expect("mint");

    // Take the master's ability to drop roles away between mint and revoke.
    cluster
        .connect_master()
        .await
        .batch_execute(&format!("ALTER ROLE {LIMITED_USER} NOCREATEROLE"))
        .await
        .expect("drop CREATEROLE from the master");

    let outcome = minter
        .revoke(RevokeCtx {
            mint_id: mint_id.clone(),
            config,
            master: cluster.limited_password(),
            revoke_token: minted.revoke_token,
        })
        .await;

    match &outcome {
        RevokeOutcome::Failed { detail } => {
            assert!(!detail.trim().is_empty(), "detail must not be empty");
            assert!(detail.contains("DROP ROLE"), "{detail}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(outcome.label(), "failed");
    assert!(
        role_exists(&cluster, &mint_id).await,
        "the role survives a failed revoke, which is what reconciliation is for"
    );

    // Restoring the privilege lets the same revoke succeed, so the failure was
    // the missing privilege and not a defect in the statements.
    cluster
        .connect_master()
        .await
        .batch_execute(&format!("ALTER ROLE {LIMITED_USER} CREATEROLE"))
        .await
        .expect("restore CREATEROLE");
    let outcome = minter
        .revoke(RevokeCtx {
            mint_id,
            config: cluster.minter_config(LIMITED_USER, grants),
            master: cluster.limited_password(),
            revoke_token: String::new(),
        })
        .await;
    assert_eq!(outcome, RevokeOutcome::Revoked);
    assert_eq!(cluster.leaked_role_count().await, 0);
}
