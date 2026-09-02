//! The `postgres-proxy` credential kind: a database the agent never has the
//! password for.
//!
//! This is the connection-authentication counterpart to [`crate::minters::http`],
//! and it exists for the same reason: some credentials cannot be minted. A
//! managed PostgreSQL where the master role has no `CREATEROLE`, a database
//! owned by another team, a cluster whose role churn would be noticed — for all
//! of those, [`postgres-dynamic`] has nothing to create, and the only thing that
//! will ever authenticate is the master password itself.
//!
//! [`postgres-dynamic`]: crate::minters::postgres
//!
//! So the "mint" is a **synthetic token**, exactly as it is for the HTTP kinds:
//! a signed statement naming the session and the credential, handed to the
//! subprocess as a password for a database that is not the real one. The
//! subprocess connects to `127.0.0.1:<pg_proxy_port>` believing it is the
//! database; the daemon's Postgres proxy recognises the token, opens its own
//! connection to the real server with the real master, and forwards bytes
//! between the two. The master password exists only in the daemon.
//!
//! # What the profile writes, and what the subprocess gets
//!
//! ```yaml
//! credentials:
//!   - name: warehouse
//!     kind: postgres-proxy
//!     ttl_secs: 3600
//!     config:
//!       host: db.internal
//!       port: 5432
//!       dbname: analytics
//!       user: reporting
//! ```
//!
//! The `user` here is the **real** role the daemon authenticates as upstream,
//! and the master filed under the credential's `source_key` is that role's
//! password and nothing else — not `user:password`, because the role is already
//! named in the config and having it in two places is a way for them to
//! disagree.
//!
//! The fields published back are the six a PostgreSQL client reads:
//! [`DATABASE_URL_FIELD`] for anything that takes a connection string, and
//! `PGHOST` / `PGPORT` / `PGDATABASE` / `PGUSER` / `PGPASSWORD` for `psql` and
//! everything else that reads libpq's environment. All of them point at
//! loopback, and the only password in any of them is the synthetic token.
//!
//! Registered with [`Hosting::Proxy`] so a profile naming this kind validates at
//! load and so every mint and revoke path already knows not to look for a
//! helper binary.
//!
//! [`Hosting::Proxy`]: crate::registry::Hosting::Proxy

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The `kind` string profiles use to select the Postgres proxy.
pub const KIND: &str = "postgres-proxy";

/// The default upstream port, when the credential's `config` omits one.
pub const DEFAULT_PORT: u16 = 5432;

/// The field carrying a whole connection string.
pub const DATABASE_URL_FIELD: &str = "DATABASE_URL";

/// The field carrying the host a client should connect to. Always loopback.
pub const PGHOST_FIELD: &str = "PGHOST";

/// The field carrying the port the daemon's Postgres proxy listens on.
pub const PGPORT_FIELD: &str = "PGPORT";

/// The field carrying the database name, which is the real one.
pub const PGDATABASE_FIELD: &str = "PGDATABASE";

/// The field carrying the user a client authenticates to the proxy as.
///
/// The **session** identifier, not the upstream role: the proxy needs to know
/// which session is connecting before it has looked at a password, and the
/// startup packet's `user` is the only field available that early.
pub const PGUSER_FIELD: &str = "PGUSER";

/// The field carrying the synthetic token, as a password.
pub const PGPASSWORD_FIELD: &str = "PGPASSWORD";

/// Every field a `postgres-proxy` mint publishes, in the order it publishes
/// them. For documentation and for the tests that assert the set is complete.
pub const FIELDS: [&str; 6] = [
    DATABASE_URL_FIELD,
    PGHOST_FIELD,
    PGPORT_FIELD,
    PGDATABASE_FIELD,
    PGUSER_FIELD,
    PGPASSWORD_FIELD,
];

/// The `config` block of a [`KIND`] credential.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PgProxyConfig {
    /// The real server's hostname.
    pub host: String,
    /// The real server's port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// The database the proxy will connect the client to.
    ///
    /// A client that asks for a different database is refused rather than
    /// quietly redirected: the profile named one database, and a connection to
    /// another is outside what was authorised.
    pub dbname: String,
    /// The real role the daemon authenticates as upstream.
    ///
    /// Its password is the master filed under the credential's `source_key`.
    pub user: String,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

impl PgProxyConfig {
    /// Resolve a credential's `kind` string and `config` block.
    ///
    /// `None` for any other kind, which is how a caller asks "is this the
    /// Postgres proxy's business" in one step.
    pub fn parse(kind: &str, config: &serde_yaml::Value) -> Option<Result<PgProxyConfig>> {
        (kind == KIND).then(|| PgProxyConfig::from_yaml(config))
    }

    fn from_yaml(config: &serde_yaml::Value) -> Result<PgProxyConfig> {
        let parsed: PgProxyConfig =
            serde_yaml::from_value(config.clone()).map_err(|e| Error::MinterConfig {
                kind: KIND,
                message: e.to_string(),
            })?;
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("host", &self.host),
            ("dbname", &self.dbname),
            ("user", &self.user),
        ] {
            if value.trim().is_empty() {
                return Err(config_error(format!("`{field}` must not be empty")));
            }
            // These three are written into a startup packet as NUL-terminated
            // strings. An embedded NUL would truncate the value rather than be
            // rejected by the server, so a `dbname: "app\0other"` would connect
            // to `app` and nobody would ever be told.
            if value.contains('\0') {
                return Err(config_error(format!("`{field}` must not contain a NUL")));
            }
        }
        if self.port == 0 {
            return Err(config_error("`port` must not be 0"));
        }
        Ok(())
    }

    /// The `host:port` the daemon will open its upstream connection to.
    pub fn upstream(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn config_error(message: impl Into<String>) -> Error {
    Error::MinterConfig {
        kind: KIND,
        message: message.into(),
    }
}

inventory::submit! {
    crate::registry::MinterFactory {
        kind: KIND,
        hosting: crate::registry::Hosting::Proxy,
        validate: |config| PgProxyConfig::from_yaml(config).map(|_| ()),
        construct: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{Hosting, Registry};

    fn yaml(text: &str) -> serde_yaml::Value {
        serde_yaml::from_str(text).unwrap()
    }

    const FULL: &str = "host: db.internal\nport: 6432\ndbname: analytics\nuser: reporting\n";

    #[test]
    fn the_kind_registers_itself_as_the_proxys_business() {
        let registry = Registry::discover();
        assert_eq!(registry.hosting(KIND), Some(Hosting::Proxy));
        assert!(registry.is_proxy(KIND));
    }

    #[test]
    fn a_proxy_kind_cannot_be_built_as_a_minter() {
        let err = Registry::discover().build(KIND, &yaml(FULL)).unwrap_err();
        assert!(
            !err.to_string().contains("briefcred-helper"),
            "a proxy kind must not send anyone looking for a helper: {err}"
        );
    }

    #[test]
    fn a_full_config_resolves_every_field() {
        let config = PgProxyConfig::parse(KIND, &yaml(FULL)).unwrap().unwrap();
        assert_eq!(
            config,
            PgProxyConfig {
                host: "db.internal".into(),
                port: 6432,
                dbname: "analytics".into(),
                user: "reporting".into(),
            }
        );
        assert_eq!(config.upstream(), "db.internal:6432");
    }

    #[test]
    fn the_port_defaults_to_the_postgres_one() {
        let config = PgProxyConfig::parse(KIND, &yaml("host: h\ndbname: d\nuser: u\n"))
            .unwrap()
            .unwrap();
        assert_eq!(config.port, DEFAULT_PORT);
        assert_eq!(config.upstream(), "h:5432");
    }

    #[test]
    fn another_kind_parses_as_none() {
        assert!(PgProxyConfig::parse("postgres-dynamic", &yaml(FULL)).is_none());
        assert!(PgProxyConfig::parse("http-bearer", &serde_yaml::Value::Null).is_none());
    }

    #[test]
    fn a_missing_required_field_is_refused_at_load() {
        for partial in [
            "port: 5432\ndbname: d\nuser: u\n",
            "host: h\nuser: u\n",
            "host: h\ndbname: d\n",
        ] {
            assert!(
                PgProxyConfig::parse(KIND, &yaml(partial)).unwrap().is_err(),
                "{partial}"
            );
        }
        assert!(PgProxyConfig::parse(KIND, &serde_yaml::Value::Null)
            .unwrap()
            .is_err());
    }

    #[test]
    fn an_empty_required_field_is_refused_by_name() {
        for (field, document) in [
            ("host", "host: ''\ndbname: d\nuser: u\n"),
            ("dbname", "host: h\ndbname: '  '\nuser: u\n"),
            ("user", "host: h\ndbname: d\nuser: ''\n"),
        ] {
            let err = PgProxyConfig::parse(KIND, &yaml(document))
                .unwrap()
                .unwrap_err();
            assert!(err.to_string().contains(field), "{field}: {err}");
        }
    }

    #[test]
    fn a_value_with_a_nul_in_it_is_refused_rather_than_silently_truncated() {
        // The startup packet writes these NUL-terminated. A `dbname` with an
        // embedded NUL would connect to the prefix and nobody would be told.
        let mut config = serde_yaml::Mapping::new();
        config.insert("host".into(), "h".into());
        config.insert("dbname".into(), "app\0other".into());
        config.insert("user".into(), "u".into());
        let err = PgProxyConfig::parse(KIND, &serde_yaml::Value::Mapping(config))
            .unwrap()
            .unwrap_err();
        assert!(err.to_string().contains("NUL"), "{err}");
    }

    #[test]
    fn a_port_of_zero_is_refused_because_nothing_listens_there() {
        let err = PgProxyConfig::parse(KIND, &yaml("host: h\nport: 0\ndbname: d\nuser: u\n"))
            .unwrap()
            .unwrap_err();
        assert!(err.to_string().contains("port"), "{err}");
    }

    #[test]
    fn an_unknown_key_is_refused_so_a_typo_cannot_be_ignored() {
        let err = PgProxyConfig::parse(
            KIND,
            &yaml("host: h\ndbname: d\nuser: u\nsslmode: require\n"),
        )
        .unwrap()
        .unwrap_err();
        assert!(err.to_string().contains("sslmode"), "{err}");
    }

    #[test]
    fn the_published_field_names_are_the_ones_a_postgres_client_reads() {
        assert_eq!(
            FIELDS,
            [
                "DATABASE_URL",
                "PGHOST",
                "PGPORT",
                "PGDATABASE",
                "PGUSER",
                "PGPASSWORD"
            ]
        );
    }
}
