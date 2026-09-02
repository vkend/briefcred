//! The HTTP proxy: where a synthetic token becomes a real credential.
//!
//! A subprocess started by `briefcred exec` gets three things it did not ask
//! for: a CA it trusts, a proxy to send through, and a synthetic token where
//! its API key would be. Together they mean the request it makes arrives here
//! instead of at the vendor, and briefcred decides what happens next.
//!
//! The modules split along the four questions one forwarded request asks:
//!
//! | module | question |
//! | --- | --- |
//! | [`token`] | who sent this, and is the token still good |
//! | [`issuer`] | and has the grant it names been revoked |
//! | [`policy`] | is this session allowed to make this request |
//! | [`swap`] | what does the outgoing request carry instead |
//!
//! [`tls`] terminates the subprocess's TLS and re-encrypts upstream, and
//! [`listener`] is the loop that puts all of it in order.

use std::collections::BTreeMap;

pub mod issuer;
pub mod listener;
pub mod policy;
pub mod revocation;
pub mod swap;
pub mod tls;
pub mod token;

/// The environment variables that point a runtime at briefcred's proxy.
///
/// Three spellings of one setting, because there is no agreement on which one a
/// runtime reads: `curl` and most Unix tooling take the lowercase or uppercase
/// pair, Go and Python take `HTTP_PROXY`/`HTTPS_PROXY`, and a good deal of
/// software only understands `ALL_PROXY`.
pub const PROXY_ENV_VARS: [&str; 3] = ["ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY"];

/// Every proxy variable, all pointing at `url`.
pub fn proxy_env(url: &str) -> BTreeMap<String, String> {
    PROXY_ENV_VARS
        .iter()
        .map(|name| ((*name).to_string(), url.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_proxy_variable_points_at_the_same_address() {
        let env = proxy_env("http://127.0.0.1:9318");
        assert_eq!(env.len(), PROXY_ENV_VARS.len());
        for name in PROXY_ENV_VARS {
            assert_eq!(
                env.get(name).map(String::as_str),
                Some("http://127.0.0.1:9318")
            );
        }
    }

    #[test]
    fn the_documented_three_variables_are_the_ones_shipped() {
        let mut sorted = PROXY_ENV_VARS;
        sorted.sort_unstable();
        assert_eq!(sorted, PROXY_ENV_VARS, "keep the list sorted");
        for name in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"] {
            assert!(PROXY_ENV_VARS.contains(&name), "{name}");
        }
    }
}
