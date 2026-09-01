//! Dynamic PostgreSQL role minting.
//!
//! Mint creates a `LOGIN` role named after the [`MintId`], with a random
//! password and a `VALID UNTIL` matching the requested TTL, then applies the
//! profile's grant template — all in one transaction, so a failed grant leaves
//! no role behind.
//!
//! Revoke is deliberately not "just `DROP OWNED BY`". On managed PostgreSQL
//! the master role does not own schema `public`, and `DROP OWNED BY` then
//! fails to remove privileges it cannot see. So revoke replays the grant
//! template as a symmetric `REVOKE` loop first, then attempts `DROP OWNED BY`
//! to clear objects the role created, and only then `DROP ROLE`.

use std::collections::BTreeMap;

use async_trait::async_trait;
use base64::Engine as _;
use postgres_protocol::escape::{escape_identifier, escape_literal};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio_postgres::NoTls;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::traits::Minter;
use crate::types::{MintCtx, MintId, MintedCredential, RevokeCtx, RevokeOutcome};

/// The `kind` string profiles use to select this minter.
pub const KIND: &str = "postgres-dynamic";

/// Bytes of entropy in a minted role password, before base64.
const PASSWORD_BYTES: usize = 32;

/// How a connection to the master database is protected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SslMode {
    /// Never use TLS. Only appropriate for a loopback cluster.
    Disable,
    /// Use TLS when the server offers it.
    Prefer,
    /// Refuse to connect without TLS. The default.
    #[default]
    Require,
}

impl From<SslMode> for tokio_postgres::config::SslMode {
    fn from(mode: SslMode) -> Self {
        match mode {
            SslMode::Disable => tokio_postgres::config::SslMode::Disable,
            SslMode::Prefer => tokio_postgres::config::SslMode::Prefer,
            SslMode::Require => tokio_postgres::config::SslMode::Require,
        }
    }
}

impl SslMode {
    fn as_str(self) -> &'static str {
        match self {
            SslMode::Disable => "disable",
            SslMode::Prefer => "prefer",
            SslMode::Require => "require",
        }
    }
}

/// One entry of a role template: privileges and the object they apply to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// SQL privilege keywords, for example `["SELECT", "INSERT"]`.
    pub privileges: Vec<String>,
    /// The object clause, for example `ALL TABLES IN SCHEMA public` or
    /// `TABLE orders`.
    pub on: String,
}

impl Grant {
    /// Reject anything that could change the shape of the generated statement.
    ///
    /// Grants come from an operator-authored profile rather than from an
    /// agent, but they are still the only free-form text that reaches SQL, so
    /// they are restricted to keywords, dotted identifiers, and spaces.
    pub fn validate(&self) -> Result<()> {
        if self.privileges.is_empty() {
            return Err(Error::MinterConfig {
                kind: KIND,
                message: format!("grant on `{}` lists no privileges", self.on),
            });
        }
        for privilege in &self.privileges {
            if !is_keyword_phrase(privilege) {
                return Err(Error::MinterConfig {
                    kind: KIND,
                    message: format!(
                        "privilege `{privilege}` must be SQL keywords separated by single spaces"
                    ),
                });
            }
        }
        if !is_object_clause(&self.on) {
            return Err(Error::MinterConfig {
                kind: KIND,
                message: format!(
                    "`on: {}` must be keywords and dotted identifiers only",
                    self.on
                ),
            });
        }
        Ok(())
    }

    fn privileges_sql(&self) -> String {
        self.privileges.join(", ")
    }
}

fn is_keyword_phrase(value: &str) -> bool {
    !value.is_empty()
        && value
            .split(' ')
            .all(|word| !word.is_empty() && word.chars().all(|c| c.is_ascii_alphabetic()))
}

fn is_object_clause(value: &str) -> bool {
    !value.trim().is_empty()
        && value.split(' ').all(|word| {
            !word.is_empty()
                && word
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        })
}

/// The set of grants a minted role received, so revoke can be symmetric.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleTemplate {
    /// Applied in order at mint, replayed as `REVOKE` at revoke.
    #[serde(default)]
    pub grants: Vec<Grant>,
}

/// The `config` block of a `postgres-dynamic` credential spec.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresConfig {
    /// Server hostname.
    pub host: String,
    /// Server port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Database to connect to and to mint roles in.
    pub dbname: String,
    /// The master role. Its password comes from a [`crate::MasterSource`],
    /// never from this file.
    pub user: String,
    /// TLS policy. Defaults to [`SslMode::Require`].
    #[serde(default)]
    pub sslmode: SslMode,
    /// Privileges every minted role receives.
    pub role_template: RoleTemplate,
}

fn default_port() -> u16 {
    5432
}

impl PostgresConfig {
    /// Interpret a credential spec's `config` block.
    pub fn from_value(value: &serde_yaml::Value) -> Result<PostgresConfig> {
        let config: PostgresConfig =
            serde_yaml::from_value(value.clone()).map_err(|e| Error::MinterConfig {
                kind: KIND,
                message: e.to_string(),
            })?;
        for grant in &config.role_template.grants {
            grant.validate()?;
        }
        Ok(config)
    }
}

/// Mints short-lived PostgreSQL login roles.
#[derive(Debug, Default, Clone, Copy)]
pub struct PostgresDynamicMinter;

impl PostgresDynamicMinter {
    /// Construct the minter. It holds no state; Phase 3 adds a helper process
    /// that keeps the master connection open across mints.
    pub fn new() -> PostgresDynamicMinter {
        PostgresDynamicMinter
    }
}

#[async_trait]
impl Minter for PostgresDynamicMinter {
    fn kind(&self) -> &'static str {
        KIND
    }

    async fn mint(&self, ctx: MintCtx) -> Result<MintedCredential> {
        let config = PostgresConfig::from_value(&ctx.config)?;
        let password = random_password();
        let expires_at = OffsetDateTime::now_utc() + ctx.ttl;
        let valid_until = expires_at
            .format(&Rfc3339)
            .map_err(|e| Error::Postgres(format!("cannot format VALID UNTIL: {e}")))?;

        let mut client = connect(&config, &ctx.master).await?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Postgres(describe(&e)))?;

        tx.batch_execute(&create_role_sql(&ctx.mint_id, &password, &valid_until))
            .await
            .map_err(|e| Error::Postgres(describe(&e)))?;
        tx.batch_execute(&grant_membership_sql(&ctx.mint_id))
            .await
            .map_err(|e| Error::Postgres(describe(&e)))?;
        for grant in &config.role_template.grants {
            tx.batch_execute(&grant_sql(grant, &ctx.mint_id))
                .await
                .map_err(|e| Error::Postgres(describe(&e)))?;
        }
        tx.commit()
            .await
            .map_err(|e| Error::Postgres(describe(&e)))?;

        let revoke_token = serde_json::to_string(&config.role_template)
            .map_err(|e| Error::Postgres(format!("cannot encode revoke token: {e}")))?;

        let mut fields: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
        fields.insert(
            "PGUSER".into(),
            Zeroizing::new(ctx.mint_id.as_str().to_string()),
        );
        fields.insert("PGPASSWORD".into(), password.clone());
        fields.insert("PGHOST".into(), Zeroizing::new(config.host.clone()));
        fields.insert("PGPORT".into(), Zeroizing::new(config.port.to_string()));
        fields.insert("PGDATABASE".into(), Zeroizing::new(config.dbname.clone()));
        fields.insert(
            "DATABASE_URL".into(),
            database_url(&config, &ctx.mint_id, &password),
        );

        Ok(MintedCredential {
            mint_id: ctx.mint_id,
            fields,
            expires_at,
            revoke_token,
        })
    }

    async fn revoke(&self, ctx: RevokeCtx) -> RevokeOutcome {
        let config = match PostgresConfig::from_value(&ctx.config) {
            Ok(config) => config,
            Err(e) => return RevokeOutcome::failed(e.to_string()),
        };
        let template = match grants_from_token(&ctx.revoke_token) {
            Some(template) => template,
            None => config.role_template.clone(),
        };

        let client = match connect(&config, &ctx.master).await {
            Ok(client) => client,
            Err(e) => return RevokeOutcome::failed(e.to_string()),
        };

        match client
            .query_opt(
                "SELECT 1 FROM pg_roles WHERE rolname = $1",
                &[&ctx.mint_id.as_str()],
            )
            .await
        {
            Ok(None) => return RevokeOutcome::AlreadyGone,
            Ok(Some(_)) => {}
            Err(e) => return RevokeOutcome::failed(describe(&e)),
        }

        // Symmetric REVOKE loop first: on a managed cluster the master cannot
        // see, and therefore cannot drop, privileges through DROP OWNED BY.
        for grant in &template.grants {
            if let Err(e) = client.batch_execute(&revoke_sql(grant, &ctx.mint_id)).await {
                return RevokeOutcome::failed(describe(&e));
            }
        }

        // Best effort: clears objects the role created so DROP ROLE can
        // succeed. If it fails but DROP ROLE then succeeds, the role owned
        // nothing and the error was not load-bearing.
        let owned_error = client
            .batch_execute(&drop_owned_sql(&ctx.mint_id))
            .await
            .err()
            .map(|e| describe(&e));

        if let Err(e) = client.batch_execute(&drop_role_sql(&ctx.mint_id)).await {
            let detail = match owned_error {
                Some(owned) => format!(
                    "DROP ROLE failed: {}; DROP OWNED BY failed: {owned}",
                    describe(&e)
                ),
                None => format!("DROP ROLE failed: {}", describe(&e)),
            };
            return RevokeOutcome::failed(detail);
        }

        RevokeOutcome::Revoked
    }
}

/// `CREATE ROLE ... LOGIN PASSWORD ... VALID UNTIL ...`.
fn create_role_sql(mint_id: &MintId, password: &str, valid_until: &str) -> String {
    format!(
        "CREATE ROLE {} LOGIN PASSWORD {} VALID UNTIL {}",
        escape_identifier(mint_id.as_str()),
        escape_literal(password),
        escape_literal(valid_until),
    )
}

/// Make the master a member of the minted role.
///
/// PostgreSQL 14 does not give a `CREATEROLE` master implicit membership in
/// the roles it creates, and `DROP OWNED BY` requires membership. Without this
/// a non-superuser master can create roles it can never fully clean up.
fn grant_membership_sql(mint_id: &MintId) -> String {
    format!(
        "GRANT {} TO CURRENT_USER",
        escape_identifier(mint_id.as_str())
    )
}

fn grant_sql(grant: &Grant, mint_id: &MintId) -> String {
    format!(
        "GRANT {} ON {} TO {}",
        grant.privileges_sql(),
        grant.on,
        escape_identifier(mint_id.as_str()),
    )
}

fn revoke_sql(grant: &Grant, mint_id: &MintId) -> String {
    format!(
        "REVOKE {} ON {} FROM {}",
        grant.privileges_sql(),
        grant.on,
        escape_identifier(mint_id.as_str()),
    )
}

fn drop_owned_sql(mint_id: &MintId) -> String {
    format!("DROP OWNED BY {}", escape_identifier(mint_id.as_str()))
}

fn drop_role_sql(mint_id: &MintId) -> String {
    format!("DROP ROLE {}", escape_identifier(mint_id.as_str()))
}

fn grants_from_token(token: &str) -> Option<RoleTemplate> {
    serde_json::from_str(token).ok()
}

fn random_password() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; PASSWORD_BYTES]);
    getrandom::fill(bytes.as_mut()).expect("OS CSPRNG unavailable");
    Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(bytes.as_ref()))
}

/// A `postgresql://` URL for tooling that wants one string.
fn database_url(config: &PostgresConfig, mint_id: &MintId, password: &str) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "postgresql://{}:{}@{}:{}/{}?sslmode={}",
        percent_encode(mint_id.as_str()),
        percent_encode(password),
        percent_encode(&config.host),
        config.port,
        percent_encode(&config.dbname),
        config.sslmode.as_str(),
    ))
}

/// Percent-encode everything outside the RFC 3986 unreserved set.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn describe(error: &tokio_postgres::Error) -> String {
    match error.as_db_error() {
        Some(db) => format!("{}: {}", db.code().code(), db.message()),
        None => error.to_string(),
    }
}

async fn connect(
    config: &PostgresConfig,
    master: &Zeroizing<String>,
) -> Result<tokio_postgres::Client> {
    let mut pg = tokio_postgres::Config::new();
    pg.host(&config.host)
        .port(config.port)
        .dbname(&config.dbname)
        .user(&config.user)
        .password(master.as_bytes())
        .application_name("briefcred")
        .ssl_mode(config.sslmode.into());

    match config.sslmode {
        SslMode::Disable => {
            let (client, connection) = pg
                .connect(NoTls)
                .await
                .map_err(|e| Error::Postgres(describe(&e)))?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(client)
        }
        SslMode::Prefer | SslMode::Require => {
            let (client, connection) = pg
                .connect(make_tls()?)
                .await
                .map_err(|e| Error::Postgres(describe(&e)))?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(client)
        }
    }
}

fn make_tls() -> Result<tokio_postgres_rustls::MakeRustlsConnect> {
    let mut roots = rustls::RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    for cert in loaded.certs {
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Err(Error::Tls(
            "no platform root certificates available; cannot verify the database server".into(),
        ));
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_postgres_rustls::MakeRustlsConnect::new(client_config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint_id() -> MintId {
        "briefcred_t_0123456789ab".parse().unwrap()
    }

    fn grant() -> Grant {
        Grant {
            privileges: vec!["SELECT".into(), "INSERT".into()],
            on: "ALL TABLES IN SCHEMA public".into(),
        }
    }

    #[test]
    fn config_parses_with_documented_defaults() {
        let yaml = "\
host: db.internal
dbname: app
user: briefcred_master
role_template:
  grants:
    - privileges: [SELECT]
      on: ALL TABLES IN SCHEMA public
";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let config = PostgresConfig::from_value(&value).unwrap();
        assert_eq!(config.port, 5432);
        assert_eq!(config.sslmode, SslMode::Require);
        assert_eq!(config.role_template.grants.len(), 1);
    }

    #[test]
    fn config_rejects_an_unknown_key() {
        let value: serde_yaml::Value = serde_yaml::from_str(
            "host: h\ndbname: d\nuser: u\npassword: oops\nrole_template: {grants: []}\n",
        )
        .unwrap();
        let err = PostgresConfig::from_value(&value).unwrap_err();
        assert!(err.to_string().contains("password"), "{err}");
    }

    #[test]
    fn config_rejects_a_grant_that_could_alter_the_statement() {
        for bad in [
            "public; DROP DATABASE app",
            "TABLE \"orders\"",
            "TABLE orders--",
        ] {
            let grant = Grant {
                privileges: vec!["SELECT".into()],
                on: bad.into(),
            };
            assert!(grant.validate().is_err(), "`{bad}` should be rejected");
        }
        let grant = Grant {
            privileges: vec!["SELECT, ALL PRIVILEGES ON pg_authid".into()],
            on: "TABLE orders".into(),
        };
        assert!(grant.validate().is_err());
    }

    #[test]
    fn config_rejects_a_grant_with_no_privileges() {
        let grant = Grant {
            privileges: vec![],
            on: "TABLE orders".into(),
        };
        let err = grant.validate().unwrap_err();
        assert!(err.to_string().contains("no privileges"), "{err}");
    }

    #[test]
    fn create_role_quotes_the_identifier_and_escapes_the_password() {
        let sql = create_role_sql(&mint_id(), "pw'; DROP ROLE x --", "2026-01-01T00:00:00Z");
        assert!(
            sql.starts_with("CREATE ROLE \"briefcred_t_0123456789ab\" LOGIN PASSWORD "),
            "{sql}"
        );
        assert!(!sql.contains("PASSWORD 'pw'; DROP"), "{sql}");
        assert!(sql.ends_with("VALID UNTIL '2026-01-01T00:00:00Z'"), "{sql}");
    }

    #[test]
    fn grant_and_revoke_are_symmetric() {
        let g = grant();
        assert_eq!(
            grant_sql(&g, &mint_id()),
            "GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO \"briefcred_t_0123456789ab\""
        );
        assert_eq!(
            revoke_sql(&g, &mint_id()),
            "REVOKE SELECT, INSERT ON ALL TABLES IN SCHEMA public FROM \"briefcred_t_0123456789ab\""
        );
    }

    #[test]
    fn cleanup_statements_quote_the_identifier() {
        assert_eq!(
            drop_owned_sql(&mint_id()),
            "DROP OWNED BY \"briefcred_t_0123456789ab\""
        );
        assert_eq!(
            drop_role_sql(&mint_id()),
            "DROP ROLE \"briefcred_t_0123456789ab\""
        );
        assert_eq!(
            grant_membership_sql(&mint_id()),
            "GRANT \"briefcred_t_0123456789ab\" TO CURRENT_USER"
        );
    }

    #[test]
    fn the_revoke_token_round_trips_the_grant_template() {
        let template = RoleTemplate {
            grants: vec![grant()],
        };
        let token = serde_json::to_string(&template).unwrap();
        assert_eq!(grants_from_token(&token), Some(template));
        assert_eq!(grants_from_token("not json"), None);
    }

    #[test]
    fn the_database_url_encodes_password_punctuation() {
        let config = PostgresConfig {
            host: "db.internal".into(),
            port: 6543,
            dbname: "app".into(),
            user: "master".into(),
            sslmode: SslMode::Require,
            role_template: RoleTemplate { grants: vec![] },
        };
        let url = database_url(&config, &mint_id(), "a+b/c=d");
        assert_eq!(
            url.as_str(),
            "postgresql://briefcred_t_0123456789ab:a%2Bb%2Fc%3Dd@db.internal:6543/app?sslmode=require"
        );
    }

    #[test]
    fn generated_passwords_are_fresh_and_long() {
        let a = random_password();
        let b = random_password();
        assert_ne!(a.as_str(), b.as_str());
        assert!(a.len() >= 43, "{}", a.len());
    }

    #[test]
    fn the_minter_reports_its_kind() {
        assert_eq!(PostgresDynamicMinter::new().kind(), "postgres-dynamic");
    }
}
