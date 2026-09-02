//! TLS for the upstream half of the Postgres proxy.
//!
//! The client half needs none: a subprocess reaches the proxy over loopback
//! and presents a token that is worthless anywhere else. The upstream half is
//! the opposite — it carries the master password, over whatever network sits
//! between this machine and the real database, and it is the one connection in
//! briefcred whose plaintext would hand an eavesdropper the credential the
//! whole design exists to withhold.
//!
//! PostgreSQL's TLS is not `STARTTLS` and not a separate port. The client
//! sends an `SSLRequest` — eight bytes, no message tag — and the server
//! answers with a single byte: `S` to say the next byte is a TLS record, `N`
//! to say it will not. [`crate::pgproxy::forward`] performs that exchange;
//! this module supplies the connector it hands the socket to afterwards.
//!
//! # The two verifying modes
//!
//! [`SslMode::Require`] and [`SslMode::VerifyFull`] both encrypt. Only the
//! second one checks who is on the other end, and the distinction is libpq's
//! rather than an invention here: `require` defends against a listener on the
//! path, `verify-full` additionally against a server that is not the one named
//! in `host`. A profile pointing at a database with a private or self-signed
//! certificate can have the first without a trust-store entry; a profile that
//! wants the second needs the issuing CA in the system store.

use std::sync::Arc;

use briefcred_core::minters::postgres_proxy::SslMode;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::TlsConnector;

/// Build the connector for one upstream connection.
///
/// `None` for [`SslMode::Disable`], which is how a caller asks "is there a
/// handshake to do here" in one step.
pub fn connector(mode: SslMode) -> Result<Option<TlsConnector>, String> {
    let config = match mode {
        SslMode::Disable => return Ok(None),
        SslMode::VerifyFull => verifying_config()?,
        SslMode::Require => encrypting_config()?,
    };
    Ok(Some(TlsConnector::from(Arc::new(config))))
}

/// The `verify-full` configuration: the system trust store, and a hostname
/// check that `rustls` performs against the `ServerName` the caller passes.
fn verifying_config() -> Result<ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        // Same fallback the HTTP proxy makes, for the same reason: a platform
        // whose store cannot be read still verifies every public CA.
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    } else {
        let (added, _ignored) = roots.add_parsable_certificates(loaded.certs);
        if added == 0 {
            return Err("the system trust store has no usable certificates".to_string());
        }
    }
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("cannot build a TLS client config: {e}"))
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

/// The `require` configuration: encryption without identity.
///
/// The verifier below accepts any certificate, which is exactly what libpq's
/// `require` does and exactly why `require` is not `verify-full`. It is
/// reachable only from a profile whose `sslmode` says so.
fn encrypting_config() -> Result<ClientConfig, String> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("cannot build a TLS client config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
        .with_no_client_auth();
    // Nothing downstream inspects the session cache, and a proxy that opens one
    // connection per subprocess gets nothing from resumption but a cache.
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

/// The cryptographic provider, named rather than detected.
///
/// `rustls`'s process-global detection fails outright when more than one
/// provider is linked anywhere in the workspace, and a connection that cannot
/// build a config should fail for a reason an operator can act on.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The `require` verifier: encrypts, and asserts nothing about the peer.
#[derive(Debug)]
struct AcceptAnyServer;

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_asks_for_no_handshake_and_the_other_two_do() {
        assert!(connector(SslMode::Disable).unwrap().is_none());
        assert!(connector(SslMode::Require).unwrap().is_some());
        assert!(connector(SslMode::VerifyFull).unwrap().is_some());
    }

    #[test]
    fn the_require_verifier_offers_the_providers_own_schemes() {
        // An empty set would make every handshake fail with a confusing
        // "no supported signature scheme" rather than connect.
        assert!(!AcceptAnyServer.supported_verify_schemes().is_empty());
    }
}
