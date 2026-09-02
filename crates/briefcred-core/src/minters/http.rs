//! The three HTTP credential kinds the proxy serves.
//!
//! These are not minters. A `postgres-dynamic` credential is minted because
//! there is a real principal to create at a real backend; an `http-bearer`
//! credential has no such thing. The API key the profile holds is the only
//! credential the vendor will ever accept, and briefcred's job is to make sure
//! the subprocess never sees it.
//!
//! So the "mint" is a **synthetic token**: a signed statement naming the
//! session and the credential, handed to the subprocess in place of the real
//! key. The subprocess sends it; the daemon's proxy recognises it, checks the
//! profile's policy, swaps the real value in, and forwards the request. The
//! real key exists only in the daemon's session map.
//!
//! What each kind changes is how the real value is rendered into the outgoing
//! request:
//!
//! | kind | master | outgoing header |
//! | --- | --- | --- |
//! | `http-bearer` | the token | `Authorization: Bearer <master>` |
//! | `http-header` | the value | `<config.name>: <master>` |
//! | `http-basic` | `user:pass` | `Authorization: Basic <base64(master)>` |
//!
//! Registered here with [`Hosting::Proxy`] so a profile naming one validates
//! at load, and so every other path in the daemon can ask the registry "is this
//! the proxy's business" rather than special-casing three strings.
//!
//! [`Hosting::Proxy`]: crate::registry::Hosting::Proxy

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// A credential whose master is sent as `Authorization: Bearer <master>`.
pub const BEARER_KIND: &str = "http-bearer";

/// A credential whose master is sent as a named header, verbatim.
pub const HEADER_KIND: &str = "http-header";

/// A credential whose master is `user:pass` and is sent as HTTP basic auth.
pub const BASIC_KIND: &str = "http-basic";

/// Every kind the proxy serves, for error messages and documentation.
pub const KINDS: [&str; 3] = [BEARER_KIND, HEADER_KIND, BASIC_KIND];

/// The field name the synthetic token is published under.
///
/// One field, so a profile's `env` block reads `${minted.openai.TOKEN}` for
/// every HTTP kind rather than a different name per kind.
pub const TOKEN_FIELD: &str = "TOKEN";

/// The field naming the proxy the token has to be sent through.
///
/// Published alongside the token so a profile can point a runtime that does not
/// read `HTTPS_PROXY` at the proxy explicitly.
pub const PROXY_URL_FIELD: &str = "PROXY_URL";

/// The `config` block of an [`HEADER_KIND`] credential.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderConfig {
    /// The header name the real value is sent under, for example `X-Api-Key`.
    pub name: String,
}

/// One HTTP credential kind, with whatever configuration it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpKind {
    /// `Authorization: Bearer <master>`.
    Bearer,
    /// `<name>: <master>`.
    Header {
        /// The header name, as written in the credential's `config`.
        name: String,
    },
    /// `Authorization: Basic <base64(master)>`, master being `user:pass`.
    Basic,
}

impl HttpKind {
    /// Resolve a credential's `kind` string and `config` block.
    ///
    /// `None` for a kind that is not one of the HTTP kinds, which is how every
    /// caller asks "is this credential the proxy's business" in one step.
    pub fn parse(kind: &str, config: &serde_yaml::Value) -> Option<Result<HttpKind>> {
        match kind {
            BEARER_KIND => Some(no_config(BEARER_KIND, config).map(|()| HttpKind::Bearer)),
            BASIC_KIND => Some(no_config(BASIC_KIND, config).map(|()| HttpKind::Basic)),
            HEADER_KIND => Some(header_config(config).map(|c| HttpKind::Header { name: c.name })),
            _ => None,
        }
    }

    /// The `kind` string this variant is written as in a profile.
    pub fn kind(&self) -> &'static str {
        match self {
            HttpKind::Bearer => BEARER_KIND,
            HttpKind::Header { .. } => HEADER_KIND,
            HttpKind::Basic => BASIC_KIND,
        }
    }

    /// The header this credential's real value belongs in.
    pub fn header_name(&self) -> &str {
        match self {
            HttpKind::Bearer | HttpKind::Basic => "authorization",
            HttpKind::Header { name } => name,
        }
    }

    /// Render `master` as the header value the upstream expects.
    ///
    /// [`Zeroizing`] because the result *is* the master, differently spelled:
    /// a `String` here would be a copy of a credential with no owner obliged to
    /// wipe it.
    pub fn header_value(&self, master: &str) -> Zeroizing<String> {
        match self {
            HttpKind::Bearer => Zeroizing::new(format!("Bearer {master}")),
            HttpKind::Header { .. } => Zeroizing::new(master.to_string()),
            HttpKind::Basic => Zeroizing::new(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(master)
            )),
        }
    }
}

/// A kind that takes no configuration, rejecting one that was given some.
///
/// Silently ignoring a `config` block would let a profile that meant
/// `http-header` write `http-bearer` with a `name:` and never find out.
fn no_config(kind: &'static str, config: &serde_yaml::Value) -> Result<()> {
    if config.is_null() {
        return Ok(());
    }
    if let Some(map) = config.as_mapping() {
        if map.is_empty() {
            return Ok(());
        }
    }
    Err(Error::MinterConfig {
        kind,
        message: format!("`{kind}` takes no `config` block"),
    })
}

fn header_config(config: &serde_yaml::Value) -> Result<HeaderConfig> {
    let parsed: HeaderConfig =
        serde_yaml::from_value(config.clone()).map_err(|e| Error::MinterConfig {
            kind: HEADER_KIND,
            message: e.to_string(),
        })?;
    if parsed.name.trim().is_empty() {
        return Err(Error::MinterConfig {
            kind: HEADER_KIND,
            message: "`name` must not be empty".to_string(),
        });
    }
    // A header name with a colon, a space, or a newline in it would either be
    // rejected by the HTTP writer or, worse, split into two headers.
    if !parsed
        .name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::MinterConfig {
            kind: HEADER_KIND,
            message: format!(
                "`name: {}` is not a header name; use letters, digits, `-` and `_`",
                parsed.name
            ),
        });
    }
    Ok(parsed)
}

/// Validate one HTTP credential's `config` block, for the registry.
fn validate(kind: &'static str) -> impl Fn(&serde_yaml::Value) -> Result<()> {
    move |config| match HttpKind::parse(kind, config) {
        Some(result) => result.map(|_| ()),
        None => unreachable!("`{kind}` is registered by this module"),
    }
}

inventory::submit! {
    crate::registry::MinterFactory {
        kind: BEARER_KIND,
        hosting: crate::registry::Hosting::Proxy,
        validate: |config| validate(BEARER_KIND)(config),
        construct: None,
    }
}

inventory::submit! {
    crate::registry::MinterFactory {
        kind: HEADER_KIND,
        hosting: crate::registry::Hosting::Proxy,
        validate: |config| validate(HEADER_KIND)(config),
        construct: None,
    }
}

inventory::submit! {
    crate::registry::MinterFactory {
        kind: BASIC_KIND,
        hosting: crate::registry::Hosting::Proxy,
        validate: |config| validate(BASIC_KIND)(config),
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

    #[test]
    fn all_three_kinds_register_themselves_as_the_proxys_business() {
        let registry = Registry::discover();
        for kind in KINDS {
            assert_eq!(registry.hosting(kind), Some(Hosting::Proxy), "{kind}");
            assert!(registry.is_proxy(kind), "{kind}");
        }
        assert!(!registry.is_proxy("postgres-dynamic"));
    }

    #[test]
    fn a_proxy_kind_cannot_be_built_as_a_minter() {
        let err = Registry::discover()
            .build(BEARER_KIND, &serde_yaml::Value::Null)
            .unwrap_err();
        assert!(err.to_string().contains("HTTP proxy"), "{err}");
        assert!(
            !err.to_string().contains("briefcred-helper"),
            "a proxy kind must not send anyone looking for a helper: {err}"
        );
    }

    #[test]
    fn a_kind_that_is_not_one_of_ours_parses_as_none() {
        assert!(HttpKind::parse("postgres-dynamic", &serde_yaml::Value::Null).is_none());
    }

    #[test]
    fn bearer_and_basic_take_no_configuration() {
        assert_eq!(
            HttpKind::parse(BEARER_KIND, &serde_yaml::Value::Null)
                .unwrap()
                .unwrap(),
            HttpKind::Bearer
        );
        assert_eq!(
            HttpKind::parse(BASIC_KIND, &yaml("{}")).unwrap().unwrap(),
            HttpKind::Basic
        );
        let err = HttpKind::parse(BEARER_KIND, &yaml("name: X-Api-Key\n"))
            .unwrap()
            .unwrap_err();
        assert!(err.to_string().contains("takes no `config`"), "{err}");
    }

    #[test]
    fn a_header_credential_names_its_header() {
        let kind = HttpKind::parse(HEADER_KIND, &yaml("name: X-Api-Key\n"))
            .unwrap()
            .unwrap();
        assert_eq!(
            kind,
            HttpKind::Header {
                name: "X-Api-Key".to_string()
            }
        );
        assert_eq!(kind.header_name(), "X-Api-Key");
        assert_eq!(kind.kind(), HEADER_KIND);
    }

    #[test]
    fn a_header_credential_without_a_name_is_rejected() {
        assert!(HttpKind::parse(HEADER_KIND, &serde_yaml::Value::Null)
            .unwrap()
            .is_err());
        assert!(HttpKind::parse(HEADER_KIND, &yaml("name: ''\n"))
            .unwrap()
            .is_err());
    }

    #[test]
    fn a_header_name_that_could_split_the_request_is_rejected() {
        for bad in ["X-Api-Key: evil", "X Api Key", "X-Api-Key\r\nHost", "X:"] {
            let err = HttpKind::parse(HEADER_KIND, &yaml(&format!("name: {bad:?}\n")))
                .unwrap()
                .unwrap_err();
            assert!(err.to_string().contains("header name"), "{bad}: {err}");
        }
    }

    #[test]
    fn an_unknown_key_in_a_header_config_is_rejected() {
        assert!(
            HttpKind::parse(HEADER_KIND, &yaml("name: X-Api-Key\nnmae: y\n"))
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn each_kind_renders_its_masters_own_header_value() {
        assert_eq!(&*HttpKind::Bearer.header_value("sk-real"), "Bearer sk-real");
        assert_eq!(
            &*HttpKind::Header {
                name: "X-Api-Key".into()
            }
            .header_value("sk-real"),
            "sk-real"
        );
        // `user:pass` base64-encoded is the whole of HTTP basic auth.
        assert_eq!(
            &*HttpKind::Basic.header_value("aladdin:opensesame"),
            "Basic YWxhZGRpbjpvcGVuc2VzYW1l"
        );
    }

    #[test]
    fn bearer_and_basic_both_land_in_the_authorization_header() {
        assert_eq!(HttpKind::Bearer.header_name(), "authorization");
        assert_eq!(HttpKind::Basic.header_name(), "authorization");
    }
}
