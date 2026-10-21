//! The roots briefcred trusts for its own outbound TLS.
//!
//! Every connection that carries a real credential to a real server — the HTTP
//! proxy's upstream half, the Postgres proxy in `verify-full`, the Postgres
//! minter, the registry fetch — verifies against [`upstream_roots`], so the
//! answer to "which CAs would briefcred believe" lives in one place.
//!
//! The answer is the system trust store, minus [`DISTRUSTED_ROOTS`]. The store
//! is the platform's, but `rustls` reads only its anchors: it does not see the
//! blocks a platform layers on top (Apple's revocation service, Mozilla's
//! OneCRL), and it does no revocation checking of its own. When a root program
//! withdraws a root in a hurry, the copy on disk can trail it by an OS update,
//! and this list is how briefcred stops believing it in the meantime.
//!
//! Compromised *intermediates* are a separate list, and not this module's:
//! `rustls-webpki` rejects any path through a public key it distrusts,
//! including the same key under a different cross-sign. The test at the
//! bottom of this file pins that it still does.

use rustls::RootCertStore;
use rustls_pki_types::TrustAnchor;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// A root briefcred refuses to trust even when the system store carries it.
pub struct DistrustedRoot {
    /// The certificate's subject, for the message an operator reads.
    pub name: &'static str,
    /// SHA-256 of the DER `SubjectPublicKeyInfo`, as
    /// `openssl x509 -pubkey | openssl pkey -pubin -outform DER | sha256sum`
    /// prints it. Matched on the key rather than the certificate, so a
    /// re-issued or cross-signed copy of the same root is caught too.
    pub spki_sha256: &'static str,
}

/// Roots withdrawn by the root programs faster than every system store has.
pub const DISTRUSTED_ROOTS: &[DistrustedRoot] = &[
    // The October 2026 eMudhra incident: eight intermediates whose private
    // keys were generated as integers below 256, recoverable by anyone.
    // Mozilla and Chrome withdrew the root on 20 October as a precaution
    // beyond the intermediates themselves (Mozilla bug 2083449, comment 18).
    // macOS 26.3 still ships it.
    DistrustedRoot {
        name: "emSign ECC Root CA - G3",
        spki_sha256: "8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782",
    },
];

/// The system trust store with [`DISTRUSTED_ROOTS`] taken out.
///
/// A platform whose store cannot be read falls back to the Mozilla roots
/// bundled in `webpki-roots`, which verify every public upstream anybody is
/// likely to call, and says so once on stderr so an operator can see which
/// set is in force.
pub fn upstream_roots() -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        eprintln!(
            "briefcred: cannot read the system trust store; \
             falling back to the bundled Mozilla roots"
        );
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    } else {
        let (added, _ignored) = roots.add_parsable_certificates(loaded.certs);
        if added == 0 {
            return Err(Error::Tls(
                "the system trust store has no usable certificates".to_string(),
            ));
        }
    }
    remove_distrusted(&mut roots);
    Ok(roots)
}

/// Drop every anchor whose key is in [`DISTRUSTED_ROOTS`]; return how many.
fn remove_distrusted(roots: &mut RootCertStore) -> usize {
    let before = roots.roots.len();
    roots.roots.retain(|anchor| distrusted(anchor).is_none());
    before - roots.roots.len()
}

fn distrusted(anchor: &TrustAnchor<'_>) -> Option<&'static DistrustedRoot> {
    let digest = hex::encode(Sha256::digest(spki_der(anchor)));
    DISTRUSTED_ROOTS
        .iter()
        .find(|root| root.spki_sha256 == digest)
}

/// The anchor's `SubjectPublicKeyInfo` with its outer `SEQUENCE` put back.
///
/// `webpki` keeps only the contents, and a hash of those matches nothing an
/// operator can produce with `openssl`.
fn spki_der(anchor: &TrustAnchor<'_>) -> Vec<u8> {
    let contents = anchor.subject_public_key_info.as_ref();
    let mut der = vec![0x30];
    match contents.len() {
        len @ 0..=0x7f => der.push(len as u8),
        len => {
            let bytes: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|byte| *byte == 0)
                .collect();
            der.push(0x80 | bytes.len() as u8);
            der.extend(bytes);
        }
    }
    der.extend_from_slice(contents);
    der
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue, IsCa, Issuer,
        KeyPair,
    };
    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::{CertificateError, Error as TlsError, OtherError};
    use rustls_pki_types::pem::PemObject as _;
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    /// emSign ECC Root CA - G3, as macOS 26.3 ships it. SHA-256
    /// 86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B.
    const EMSIGN_ECC_ROOT_G3: &str = "-----BEGIN CERTIFICATE-----
MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG
EwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNo
bm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g
RzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJ
TjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9s
b2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0
WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xyS
fvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuB
zhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWB
CUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD
+JbNR6iC8hZVdyR+EhCVBCyj
-----END CERTIFICATE-----";

    /// EM DV TLS CA - G3B as Sectigo cross-signed it under AAA Certificate
    /// Services, a root macOS still trusts. One of the eight compromised keys
    /// (CCADB A012347, SHA-256 45A883F3…66FCDDBE), and the copy that reaches
    /// a trusted root even once the emSign roots are gone.
    const EM_DV_TLS_CA_G3B_SECTIGO: &str = "-----BEGIN CERTIFICATE-----
MIIDzjCCAragAwIBAgIRAKAk/fS6Zlx4XOSgIEg4WLcwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJW
MRswGQYDVQQDDBJFTSBEViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAATnntnASpdzxHNeUREdqFrCvV5kqzdLgOEsvCA47B5PDjuBL8mFnh5nr7BO
L4vJf3SFumWqkR7opORbYtXMA9Vr5nizw4y03JN8okYOI4RTyJKTXSnUT5HhVga2
PM7atGijggE1MIIBMTAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAd
BgNVHQ4EFgQU4h4v5xwZOQ5VS2LBICRXNSSKJRQwDgYDVR0PAQH/BAQDAgEGMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MDEGA1UdIAQqMCgwCAYGZ4EMAQIBMA0GCysGAQQBg44hAQABMA0GCysGAQQBg44h
AQJkMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FB
QUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEF
BQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBCwUAA4IB
AQBzQ1IoqpdotM6gFrR4Q3YrKifOLeaj5XXunldpVE/vZn2TxC2y0s8oYiLR5ICE
wqVXSB7N6BM1Mp+Nif7Jbhb2IswAfSR4Iik8+B0iRmi7lYoNlycCgHjmsjOmZaxM
QkPmjXAJbG5f4V41OsvJZmS7lI3r0IuvEDVX3GAZ13on6IImSs9ybNpHQ7NCqkMQ
7wH4uAO1dtpFycgJSdHaCOhHjrox2BTYGLdpUrYwY3EOAjlZ8UGgsxs7mG+xquMl
bN1LFURwfnkVMP3T/DBIZ/ys2+lNFyxK3FlArrV4/000uTnVB1lO8oGORYdXoT5V
GUyRCEIDhF5TBUuKF4E3kf1h
-----END CERTIFICATE-----";

    fn der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
    }

    #[test]
    fn the_emsign_g3_root_is_taken_out_of_a_store_that_carries_it() {
        let mut roots = RootCertStore::empty();
        roots.add(der(EMSIGN_ECC_ROOT_G3)).unwrap();
        let other = crate::CertificateAuthority::generate("unrelated").unwrap();
        roots.add(der(other.cert_pem())).unwrap();

        assert_eq!(remove_distrusted(&mut roots), 1);
        assert_eq!(roots.roots.len(), 1, "only the emSign root goes");
    }

    #[test]
    fn the_spki_hash_is_the_one_openssl_prints() {
        // `spki_der` rebuilds the outer SEQUENCE webpki strips; a wrong length
        // encoding would match nothing and quietly distrust nothing.
        let mut roots = RootCertStore::empty();
        roots.add(der(EMSIGN_ECC_ROOT_G3)).unwrap();
        let found = distrusted(&roots.roots[0]).map(|root| root.name);
        assert_eq!(found, Some("emSign ECC Root CA - G3"));
    }

    #[test]
    fn a_long_spki_is_rewrapped_with_a_long_form_length() {
        // RSA keys run past 127 bytes, which takes the long-form branch.
        let rsa = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .find(|anchor| anchor.subject_public_key_info.len() > 0xff)
            .unwrap();
        let wrapped = spki_der(rsa);
        assert_eq!(&wrapped[..2], &[0x30, 0x82]);
        let len = u16::from_be_bytes([wrapped[2], wrapped[3]]) as usize;
        assert_eq!(len, rsa.subject_public_key_info.len());
    }

    #[test]
    fn the_roots_briefcred_verifies_against_exclude_the_emsign_g3_root() {
        let roots = upstream_roots().unwrap();
        assert!(roots
            .roots
            .iter()
            .all(|anchor| distrusted(anchor).is_none()));
    }

    /// A leaf issued under one of the compromised intermediates is refused.
    ///
    /// Built without the intermediate's private key: the leaf is signed by a
    /// throwaway key under the intermediate's name, and the real Sectigo
    /// cross-sign is sent alongside it, the way an attacker's server would.
    /// Path building matches the names and reaches AAA Certificate Services
    /// wherever the store has it. Before `rustls-webpki` 0.103.16 the only
    /// thing that then failed was the leaf's signature — which a holder of
    /// the recovered key would pass. The assertion is on the specific error:
    /// `BadSignature` here means the distrust list is gone.
    #[test]
    fn a_chain_through_a_compromised_emudhra_intermediate_is_distrusted() {
        let intermediate = der(EM_DV_TLS_CA_G3B_SECTIGO);

        let mut issuer = CertificateParams::default();
        issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        issuer.distinguished_name = {
            // Byte-for-byte the cross-sign's subject: PrintableString country,
            // UTF8String organisation and common name, in that order.
            let mut name = DistinguishedName::new();
            name.push(
                DnType::CountryName,
                DnValue::PrintableString("NL".try_into().unwrap()),
            );
            name.push(DnType::OrganizationName, "eMudhra BV");
            name.push(DnType::CommonName, "EM DV TLS CA - G3B");
            name
        };
        // Never self-signed or trusted: it exists only to sign the leaf.
        let issuer = Issuer::new(issuer, KeyPair::generate().unwrap());

        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["api.openai.com".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();

        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(upstream_roots().unwrap()),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let err = verifier
            .verify_server_cert(
                leaf.der(),
                &[intermediate],
                &ServerName::try_from("api.openai.com").unwrap(),
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        let TlsError::InvalidCertificate(CertificateError::Other(OtherError(inner))) = &err else {
            panic!("expected the path to be distrusted, got {err:?}");
        };
        // `rustls` wraps the `webpki` error opaquely; its `Debug` is the
        // variant name, which is what this test exists to pin.
        assert_eq!(format!("{inner:?}"), "CertDistrusted", "{err:?}");
    }
}
