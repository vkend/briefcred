//! The two TLS halves of the proxy: terminating, and re-encrypting.
//!
//! A `CONNECT` tunnel means the proxy sits between two TLS peers that both
//! think they are talking to each other. It has to be **both** ends:
//!
//! - **Server side**, to the subprocess: a leaf from briefcred's own CA for the
//!   host the subprocess asked for, which it trusts because `briefcred exec`
//!   put the CA in its trust environment.
//! - **Client side**, to the upstream: an ordinary TLS client with the system
//!   trust store, because the upstream is a real vendor and its certificate has
//!   to verify for real.
//!
//! The second half is the one worth stating loudly: briefcred terminates the
//! subprocess's TLS, so it must not weaken the connection it makes on the
//! subprocess's behalf. There is no "accept any certificate" path in this
//! module, and the only way to add a root is a `daemon.toml` key that exists
//! for the test suite and says so.

use std::path::Path;
use std::sync::Arc;

use briefcred_core::ca::CertificateAuthority;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::CertificateDer;

use crate::error::{Error, Result};

/// A `ServerConfig` presenting a fresh leaf for `hostname`.
///
/// Built per connection rather than cached alongside the leaf: a `ServerConfig`
/// is cheap next to the key generation the CA's own cache already avoids, and
/// caching it here would be a second cache to keep coherent with the first.
pub fn server_config(ca: &CertificateAuthority, hostname: &str) -> Result<Arc<ServerConfig>> {
    let leaf = ca
        .issue_leaf(std::slice::from_ref(&hostname.to_string()))
        .map_err(|e| Error::Proxy(format!("cannot issue a leaf for `{hostname}`: {e}")))?;

    let chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut leaf.cert_pem().as_bytes())
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| Error::Proxy(format!("the issued leaf is not valid PEM: {e}")))?;
    let key = rustls_pemfile::private_key(&mut leaf.key_pem().as_bytes())
        .map_err(|e| Error::Proxy(format!("the issued leaf key is not valid PEM: {e}")))?
        .ok_or_else(|| Error::Proxy("the issued leaf carries no private key".to_string()))?;

    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Proxy(format!("cannot build a TLS server config: {e}")))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| Error::Proxy(format!("cannot serve TLS for `{hostname}`: {e}")))?;
    Ok(Arc::new(config))
}

/// A `ClientConfig` that verifies upstreams against the system trust store.
///
/// `extra_roots`, when given, is a PEM bundle added to the store. It exists so
/// the test suite can point the proxy at an in-process upstream signed by a
/// throwaway CA, and it is **test-only**: `daemon.toml` documents it as such,
/// and adding a root here is adding a certificate authority the proxy will
/// believe for every host.
pub fn client_config(extra_roots: Option<&Path>) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();

    match rustls_native_certs::load_native_certs() {
        loaded if !loaded.certs.is_empty() => {
            let (added, _ignored) = roots.add_parsable_certificates(loaded.certs);
            if added == 0 {
                return Err(Error::Proxy(
                    "the system trust store has no usable certificates".to_string(),
                ));
            }
        }
        // A platform whose trust store cannot be read is not a platform where
        // the proxy should give up: the bundled Mozilla roots verify every
        // public upstream anybody is likely to call. Said once, at startup, so
        // an operator can see which set is in force.
        _ => {
            eprintln!(
                "briefcred-daemon: cannot read the system trust store; \
                 falling back to the bundled Mozilla roots"
            );
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
    }

    if let Some(path) = extra_roots {
        let pem = std::fs::read(path).map_err(|e| Error::io("read", path, e))?;
        let extra: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut pem.as_slice())
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| Error::Proxy(format!("{} is not valid PEM: {e}", path.display())))?;
        if extra.is_empty() {
            return Err(Error::Proxy(format!(
                "{} contains no certificate",
                path.display()
            )));
        }
        eprintln!(
            "briefcred-daemon: trusting {} extra upstream root(s) from {} \
             (`upstream_roots` is for tests; remove it in production)",
            extra.len(),
            path.display()
        );
        for certificate in extra {
            roots
                .add(certificate)
                .map_err(|e| Error::Proxy(format!("{} is not a usable CA: {e}", path.display())))?;
        }
    }

    Ok(Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Proxy(format!("cannot build a TLS client config: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// The cryptographic provider both halves use.
///
/// Named rather than left to rustls's feature detection: the detection is
/// process-global, it fails outright when more than one provider is linked
/// anywhere in the workspace, and a proxy that cannot build a TLS config is a
/// proxy that fails at the first request rather than at startup.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_config_carries_a_leaf_for_the_host_that_was_asked_for() {
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        // Succeeding at all proves the leaf and its key were parsed and matched
        // each other; rustls refuses a mismatched pair.
        assert!(server_config(&ca, "api.openai.com").is_ok());
    }

    #[test]
    fn two_hosts_are_served_different_certificates() {
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        let first = ca.issue_leaf(&["api.openai.com".to_string()]).unwrap();
        let second = ca.issue_leaf(&["api.stripe.com".to_string()]).unwrap();
        assert_ne!(first.cert_pem(), second.cert_pem());
        assert!(server_config(&ca, "api.stripe.com").is_ok());
    }

    #[test]
    fn the_client_verifies_against_real_roots_by_default() {
        assert!(client_config(None).is_ok());
    }

    #[test]
    fn an_extra_root_bundle_is_added_when_one_is_configured() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CertificateAuthority::generate("test-upstream").unwrap();
        let path = dir.path().join("roots.pem");
        std::fs::write(&path, ca.cert_pem()).unwrap();
        assert!(client_config(Some(&path)).is_ok());
    }

    #[test]
    fn a_root_bundle_with_nothing_in_it_is_an_error_rather_than_a_silent_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.pem");
        std::fs::write(&path, "not a certificate\n").unwrap();
        let err = client_config(Some(&path)).unwrap_err();
        assert!(err.to_string().contains("no certificate"), "{err}");

        let missing = dir.path().join("absent.pem");
        assert!(client_config(Some(&missing)).is_err());
    }
}
