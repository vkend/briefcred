//! The per-machine root CA, and the leaf certificates it issues.
//!
//! briefcred terminates TLS locally, so it needs a certificate authority the
//! machine trusts. That CA is generated once at install time, never leaves
//! the machine, and signs nothing but short-lived leaves for the hostnames a
//! wrapped subprocess is talking to.
//!
//! Three deliberate limits keep the blast radius small:
//!
//! - `pathlen:0`, so the CA can sign leaves and nothing else. A stolen key
//!   cannot mint an intermediate and delegate onward.
//! - Leaves live [`LEAF_VALIDITY`], long enough for a work session and short
//!   enough that a leaked one expires before it is useful.
//! - The private key lives in a [`KeyStore`], never in a field anything
//!   prints. `ca.pem` on disk is the public half only.

use std::collections::BTreeMap;
use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use time::{Duration as TimeDuration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keystore::{KeyStore, KeystoreKind, CA_KEY_ITEM};
use crate::paths::Paths;
use crate::profile::Profile;

/// How long the root CA is valid for.
pub const CA_VALIDITY_YEARS: i64 = 10;

/// How long an issued leaf is valid for.
pub const LEAF_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);

/// The environment variables that point a runtime at briefcred's CA bundle.
///
/// One per ecosystem that ignores the system trust store. A profile may cut
/// this list down but may not add to it: an unknown name here would be a
/// variable briefcred does not know the semantics of.
pub const TRUST_ENV_VARS: [&str; 6] = [
    "AWS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
];

/// The `[ca]` table of `daemon.toml`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct CaConfig {
    /// Where the CA private key is kept. Absent means the platform default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keystore: Option<KeystoreKind>,
}

/// Just enough of `daemon.toml` to find the `[ca]` table.
///
/// Deliberately tolerant of the keys it does not know: the daemon owns the
/// rest of that file and rejects typos there, and the CLI must not need a
/// second copy of the whole schema to find out where the CA key lives.
#[derive(Debug, Default, Deserialize)]
struct DaemonTomlCaSection {
    #[serde(default)]
    ca: CaConfig,
}

impl CaConfig {
    /// Read the `[ca]` table from `paths.daemon_toml()`.
    ///
    /// An absent file is the default configuration, the same rule the daemon
    /// applies to the rest of that file.
    pub fn load(paths: &Paths) -> Result<CaConfig> {
        let path = paths.daemon_toml();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CaConfig::default())
            }
            Err(source) => return Err(Error::Io { path, source }),
        };
        let parsed: DaemonTomlCaSection = toml::from_str(&text)
            .map_err(|e| Error::Ca(format!("{}: {}", path.display(), e.message())))?;
        Ok(parsed.ca)
    }

    /// The keystore backend this configuration asks for on this platform.
    pub fn keystore(&self, paths: &Paths) -> KeystoreKind {
        self.keystore
            .unwrap_or_else(|| KeystoreKind::platform_default(paths.platform()))
    }

    /// Open that backend. The one place the CA's keystore is chosen.
    pub fn open_keystore(&self, paths: &Paths) -> Result<Box<dyn KeyStore>> {
        crate::keystore::open(self.keystore(paths), paths)
    }
}

/// The common name of the CA for `hostname`.
pub fn common_name(hostname: &str) -> String {
    format!("briefcred local CA {hostname}")
}

/// This machine's hostname, or `localhost` if it cannot be determined.
///
/// Only ever used to label the CA, so a fallback is better than a failure:
/// a certificate named `localhost` is confusing, but no certificate at all
/// stops the install.
pub fn machine_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

/// One issued leaf certificate and the key that goes with it.
///
/// `Clone` because the cache hands out copies; the key half is
/// [`Zeroizing`], so every copy wipes itself.
#[derive(Clone)]
pub struct Leaf {
    cert_pem: String,
    key_pem: Zeroizing<String>,
    hostnames: Vec<String>,
    expires_at: OffsetDateTime,
}

impl Leaf {
    /// The leaf certificate, PEM-encoded. Public material.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The leaf's private key, PEM-encoded PKCS#8.
    pub fn key_pem(&self) -> &Zeroizing<String> {
        &self.key_pem
    }

    /// When this leaf stops being valid.
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

impl fmt::Debug for Leaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Leaf")
            .field("hostnames", &self.hostnames)
            .field("expires_at", &self.expires_at)
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// What `briefcred ca show` reports about the CA on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaInfo {
    /// The CA's subject common name.
    pub common_name: String,
    /// When the CA became valid.
    pub not_before: OffsetDateTime,
    /// When the CA stops being valid.
    pub not_after: OffsetDateTime,
    /// Lowercase, colon-free SHA-256 of the DER encoding.
    pub fingerprint_sha256: String,
}

/// The root CA: its certificate, its signing key, and its leaf cache.
pub struct CertificateAuthority {
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    key_pem: Zeroizing<String>,
    leaves: Mutex<BTreeMap<String, Leaf>>,
}

impl fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("cert_pem_bytes", &self.cert_pem.len())
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

impl CertificateAuthority {
    /// Generate a fresh root CA labelled for `hostname`.
    pub fn generate(hostname: &str) -> Result<CertificateAuthority> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| Error::Ca(format!("cannot generate a CA key: {e}")))?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name(hostname));
        dn.push(DnType::OrganizationName, "briefcred");

        let now = seconds_precision(OffsetDateTime::now_utc());
        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        // `Constrained(0)` is the whole point: this CA signs leaves and can
        // never issue an intermediate that signs on its behalf.
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = now;
        params.not_after = now + ca_validity();

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| Error::Ca(format!("cannot sign the CA certificate: {e}")))?;
        let cert_pem = cert.pem();
        let cert_der = cert.der().clone();
        let key_pem = Zeroizing::new(key_pair.serialize_pem());

        Ok(CertificateAuthority {
            cert_pem,
            cert_der,
            issuer: Issuer::new(params, key_pair),
            key_pem,
            leaves: Mutex::new(BTreeMap::new()),
        })
    }

    /// Rebuild a CA from its certificate and its private key.
    pub fn from_pem(cert_pem: &str, key_pem: &Zeroizing<String>) -> Result<CertificateAuthority> {
        let key_pair = KeyPair::from_pem(key_pem)
            .map_err(|e| Error::Ca(format!("the stored CA private key is unusable: {e}")))?;
        let cert_der = first_certificate(cert_pem)?;
        let issuer = Issuer::from_ca_cert_der(&cert_der, key_pair)
            .map_err(|e| Error::Ca(format!("ca.pem is not a usable CA certificate: {e}")))?;

        Ok(CertificateAuthority {
            cert_pem: cert_pem.to_string(),
            cert_der,
            issuer,
            key_pem: key_pem.clone(),
            leaves: Mutex::new(BTreeMap::new()),
        })
    }

    /// The CA certificate, PEM-encoded. This is what gets trusted.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA certificate in DER, for building a rustls root store.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// The CA's private key, PEM-encoded PKCS#8.
    ///
    /// Only [`CertificateAuthority::save`] and the tests should need this.
    pub fn key_pem(&self) -> &Zeroizing<String> {
        &self.key_pem
    }

    /// Write `ca.pem` and hand the private key to `store`.
    ///
    /// The key goes first. If the certificate write then fails there is an
    /// orphan key, which [`CertificateAuthority::ensure`] overwrites on the
    /// next run; the reverse order would leave a trusted certificate whose
    /// key is gone, which nothing can recover from.
    pub fn save(&self, paths: &Paths, store: &dyn KeyStore) -> Result<()> {
        crate::paths::ensure_private_dir(&paths.ca_dir())?;
        store.put(CA_KEY_ITEM, &self.key_pem)?;
        let cert = paths.ca_cert();
        std::fs::write(&cert, &self.cert_pem).map_err(|source| Error::Io {
            path: cert.clone(),
            source,
        })?;
        // World-readable on purpose: `curl --cacert`, Node, and Python all
        // read it as the user running them, and it is public material.
        std::fs::set_permissions(&cert, std::fs::Permissions::from_mode(0o644))
            .map_err(|source| Error::Io { path: cert, source })
    }

    /// Load the CA from `ca.pem` and `store`, or `None` if it is not set up.
    ///
    /// A certificate without its key, or a key without its certificate, is an
    /// error rather than a `None`: half a CA means something went wrong, and
    /// silently regenerating over it would invalidate every trusted copy.
    pub fn load(paths: &Paths, store: &dyn KeyStore) -> Result<Option<CertificateAuthority>> {
        let cert_path = paths.ca_cert();
        let cert_pem = match std::fs::read_to_string(&cert_path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(Error::Io {
                    path: cert_path,
                    source,
                })
            }
        };

        let key_pem = store.get(CA_KEY_ITEM)?.ok_or_else(|| {
            Error::Ca(format!(
                "{} exists but its private key is missing from {}; \
                 run `briefcred ca regenerate` and re-trust the new CA",
                cert_path.display(),
                store.location()
            ))
        })?;

        CertificateAuthority::from_pem(&cert_pem, &key_pem).map(Some)
    }

    /// Load the CA, generating and saving one if there is none.
    ///
    /// Returns whether it had to generate, so `install` can say which it did.
    pub fn ensure(
        paths: &Paths,
        store: &dyn KeyStore,
        hostname: &str,
    ) -> Result<(CertificateAuthority, bool)> {
        if let Some(existing) = CertificateAuthority::load(paths, store)? {
            return Ok((existing, false));
        }
        let ca = CertificateAuthority::generate(hostname)?;
        ca.save(paths, store)?;
        Ok((ca, true))
    }

    /// Delete `ca.pem` and the stored private key. Idempotent.
    pub fn remove(paths: &Paths, store: &dyn KeyStore) -> Result<()> {
        let cert = paths.ca_cert();
        match std::fs::remove_file(&cert) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(Error::Io { path: cert, source }),
        }
        store.delete(CA_KEY_ITEM)
    }

    /// Issue a leaf valid for `hostnames`, reusing a cached one if it holds.
    ///
    /// The cache is keyed on the whole hostname list, so a leaf issued for
    /// `api.example.com` is not handed out for `db.example.com`.
    pub fn issue_leaf(&self, hostnames: &[String]) -> Result<Leaf> {
        if hostnames.is_empty() {
            return Err(Error::Ca(
                "a leaf needs at least one hostname to be valid for".to_string(),
            ));
        }
        let key = hostnames.join(",");
        let now = seconds_precision(OffsetDateTime::now_utc());

        let mut cache = self
            .leaves
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Reissue a little before expiry rather than at it, so a leaf handed
        // out now is still valid when the handshake it is for happens.
        if let Some(leaf) = cache.get(&key) {
            if leaf.expires_at > now + TimeDuration::minutes(5) {
                return Ok(leaf.clone());
            }
        }

        let mut params = CertificateParams::new(hostnames.to_vec())
            .map_err(|e| Error::Ca(format!("{hostnames:?} are not valid hostnames: {e}")))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostnames[0].clone());
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        // Backdated a few minutes so a client whose clock runs slow does not
        // reject a certificate issued a second ago as not yet valid.
        params.not_before = now - TimeDuration::minutes(5);
        params.not_after = now + leaf_validity();

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| Error::Ca(format!("cannot generate a leaf key: {e}")))?;
        let cert = params
            .signed_by(&key_pair, &self.issuer)
            .map_err(|e| Error::Ca(format!("cannot sign a leaf for {hostnames:?}: {e}")))?;

        let leaf = Leaf {
            cert_pem: cert.pem(),
            key_pem: Zeroizing::new(key_pair.serialize_pem()),
            hostnames: hostnames.to_vec(),
            expires_at: params.not_after,
        };
        cache.insert(key, leaf.clone());
        Ok(leaf)
    }

    /// Parse the CA's own certificate for `briefcred ca show`.
    pub fn info(&self) -> Result<CaInfo> {
        let (_, parsed) = x509_parser::parse_x509_certificate(&self.cert_der)
            .map_err(|e| Error::Ca(format!("cannot parse the CA certificate: {e}")))?;
        let common_name = parsed
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or_default()
            .to_string();

        Ok(CaInfo {
            common_name,
            not_before: parsed.validity().not_before.to_datetime(),
            not_after: parsed.validity().not_after.to_datetime(),
            fingerprint_sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&self.cert_der)),
        })
    }
}

/// How long the CA is valid for, as a duration.
///
/// Ten Julian years, so the arithmetic needs no calendar and cannot land on a
/// day that does not exist.
fn ca_validity() -> TimeDuration {
    TimeDuration::days(CA_VALIDITY_YEARS * 365 + CA_VALIDITY_YEARS / 4)
}

fn leaf_validity() -> TimeDuration {
    TimeDuration::try_from(LEAF_VALIDITY).expect("LEAF_VALIDITY is a day")
}

/// Drop sub-second precision, which X.509 cannot represent anyway.
///
/// Without this a certificate read back from disk has a validity window a
/// fraction shorter than the one that was asked for.
fn seconds_precision(at: OffsetDateTime) -> OffsetDateTime {
    at.replace_nanosecond(0).unwrap_or(at)
}

/// The first certificate in a PEM bundle, as DER.
fn first_certificate(pem: &str) -> Result<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .ok_or_else(|| Error::Ca("ca.pem contains no certificate".to_string()))?
        .map_err(|e| Error::Ca(format!("ca.pem is not valid PEM: {e}")))
}

/// The trust environment a profile's subprocess should run with.
///
/// Every name in [`TRUST_ENV_VARS`] pointing at `ca.pem`, minus anything the
/// profile's `trust_env` list leaves out. An absent list means all six; an
/// empty list means none, which is how a profile opts out entirely.
pub fn trust_env(paths: &Paths, profile: &Profile) -> BTreeMap<String, String> {
    let bundle = paths.ca_cert().display().to_string();
    TRUST_ENV_VARS
        .iter()
        .filter(|name| match &profile.trust_env {
            Some(allowed) => allowed.iter().any(|a| a == *name),
            None => true,
        })
        .map(|name| ((*name).to_string(), bundle.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::FileKeyStore;
    use crate::paths::{Paths, Platform};
    use std::ffi::OsString;
    use std::sync::Arc;

    use rustls::client::verify_server_cert_signed_by_trust_anchor;
    use rustls::server::ParsedCertificate;
    use rustls::RootCertStore;
    use rustls_pki_types::UnixTime;

    fn temp_paths() -> (tempfile::TempDir, Paths) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_str().unwrap().to_string();
        let paths = Paths::resolve(Platform::MacOs, &|key| {
            (key == crate::paths::HOME_ENV).then(|| OsString::from(root.clone()))
        })
        .unwrap();
        paths.ensure_layout().unwrap();
        (temp, paths)
    }

    fn pem_to_der(pem: &str) -> CertificateDer<'static> {
        rustls_pemfile::certs(&mut pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
    }

    /// Verify `leaf` chains to `ca` for `server_name`, exactly as a TLS
    /// client would.
    fn verify_chain(ca: &CertificateDer<'static>, leaf: &str, server_name: &str) -> bool {
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        let end_entity = pem_to_der(leaf);
        let parsed = ParsedCertificate::try_from(&end_entity).unwrap();
        let name = rustls_pki_types::ServerName::try_from(server_name.to_string()).unwrap();
        verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &roots,
            &[],
            UnixTime::now(),
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .all,
        )
        .is_ok()
            && rustls::client::verify_server_name(&parsed, &name).is_ok()
    }

    #[test]
    fn an_absent_daemon_toml_leaves_the_ca_on_its_platform_default() {
        let (_temp, paths) = temp_paths();
        let config = CaConfig::load(&paths).unwrap();
        assert_eq!(config.keystore, None);
        assert_eq!(config.keystore(&paths), KeystoreKind::Keychain);
    }

    #[test]
    fn the_ca_table_overrides_the_platform_default() {
        let (_temp, paths) = temp_paths();
        std::fs::write(paths.daemon_toml(), "[ca]\nkeystore = \"file\"\n").unwrap();
        let config = CaConfig::load(&paths).unwrap();
        assert_eq!(config.keystore(&paths), KeystoreKind::File);
    }

    #[test]
    fn the_daemons_own_keys_do_not_disturb_the_ca_table() {
        let (_temp, paths) = temp_paths();
        std::fs::write(
            paths.daemon_toml(),
            "retention_days = 7\nmetrics_enabled = false\n[ca]\nkeystore = \"keychain\"\n",
        )
        .unwrap();
        assert_eq!(
            CaConfig::load(&paths).unwrap().keystore(&paths),
            KeystoreKind::Keychain
        );
    }

    #[test]
    fn an_unknown_keystore_name_is_rejected_rather_than_defaulted() {
        let (_temp, paths) = temp_paths();
        std::fs::write(paths.daemon_toml(), "[ca]\nkeystore = \"gnome\"\n").unwrap();
        assert!(CaConfig::load(&paths).is_err());
    }

    #[test]
    fn an_unknown_key_in_the_ca_table_names_itself() {
        let (_temp, paths) = temp_paths();
        std::fs::write(paths.daemon_toml(), "[ca]\nkeystoer = \"file\"\n").unwrap();
        let err = CaConfig::load(&paths).unwrap_err();
        assert!(err.to_string().contains("keystoer"), "{err}");
    }

    #[test]
    fn the_common_name_names_the_machine_it_belongs_to() {
        assert_eq!(common_name("mac.local"), "briefcred local CA mac.local");
    }

    #[test]
    fn a_generated_ca_is_a_ten_year_path_length_zero_root() {
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        let info = ca.info().unwrap();
        assert_eq!(info.common_name, "briefcred local CA mac.local");
        let years = (info.not_after - info.not_before).whole_days() / 365;
        assert_eq!(years, CA_VALIDITY_YEARS, "{info:?}");

        let der = ca.cert_der().clone();
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        let constraints = parsed.basic_constraints().unwrap().unwrap();
        assert!(constraints.value.ca, "the CA must be a CA");
        assert_eq!(constraints.value.path_len_constraint, Some(0));
        assert!(constraints.critical, "basicConstraints must be critical");
    }

    #[test]
    fn a_generated_ca_signs_with_ecdsa_p256() {
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        let der = ca.cert_der().clone();
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        // 1.2.840.10045.4.3.2 is ecdsa-with-SHA256.
        assert_eq!(
            parsed.signature_algorithm.algorithm.to_id_string(),
            "1.2.840.10045.4.3.2"
        );
    }

    #[test]
    fn an_issued_leaf_chains_to_the_ca_for_its_hostname() {
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        let leaf = ca.issue_leaf(&["localhost".to_string()]).unwrap();
        assert!(verify_chain(ca.cert_der(), leaf.cert_pem(), "localhost"));
    }

    #[test]
    fn a_leaf_is_not_accepted_for_a_hostname_it_does_not_carry() {
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        let leaf = ca.issue_leaf(&["localhost".to_string()]).unwrap();
        assert!(!verify_chain(ca.cert_der(), leaf.cert_pem(), "example.com"));
    }

    #[test]
    fn a_leaf_from_one_ca_does_not_chain_to_another() {
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        let other = CertificateAuthority::generate("mac.local").unwrap();
        let leaf = ca.issue_leaf(&["localhost".to_string()]).unwrap();
        assert!(!verify_chain(
            other.cert_der(),
            leaf.cert_pem(),
            "localhost"
        ));
    }

    #[test]
    fn a_leaf_is_valid_for_a_day_and_is_a_server_certificate() {
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        let leaf = ca.issue_leaf(&["localhost".to_string()]).unwrap();
        let remaining = leaf.expires_at() - OffsetDateTime::now_utc();
        assert!(
            remaining <= TimeDuration::hours(24) && remaining > TimeDuration::hours(23),
            "{remaining:?}"
        );

        let der = pem_to_der(leaf.cert_pem());
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        let eku = parsed.extended_key_usage().unwrap().unwrap();
        assert!(eku.value.server_auth, "a leaf must be a server certificate");
        assert!(!parsed.basic_constraints().unwrap().unwrap().value.ca);
    }

    #[test]
    fn the_same_hostnames_get_the_same_cached_leaf() {
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        let names = vec!["a.test".to_string(), "b.test".to_string()];
        let first = ca.issue_leaf(&names).unwrap();
        let second = ca.issue_leaf(&names).unwrap();
        assert_eq!(first.cert_pem(), second.cert_pem());
    }

    #[test]
    fn different_hostnames_get_different_leaves() {
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        let first = ca.issue_leaf(&["a.test".to_string()]).unwrap();
        let second = ca.issue_leaf(&["b.test".to_string()]).unwrap();
        assert_ne!(first.cert_pem(), second.cert_pem());
    }

    #[test]
    fn issuing_for_no_hostnames_is_rejected_rather_than_silently_useless() {
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        assert!(ca.issue_leaf(&[]).is_err());
    }

    #[test]
    fn a_saved_ca_comes_back_able_to_issue_the_same_chain() {
        let (_temp, paths) = temp_paths();
        let store = FileKeyStore::new(paths.ca_dir());
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        ca.save(&paths, &store).unwrap();

        let loaded = CertificateAuthority::load(&paths, &store).unwrap().unwrap();
        assert_eq!(loaded.cert_pem(), ca.cert_pem());
        let leaf = loaded.issue_leaf(&["localhost".to_string()]).unwrap();
        assert!(verify_chain(ca.cert_der(), leaf.cert_pem(), "localhost"));
    }

    #[test]
    fn saving_writes_only_the_public_half_to_disk() {
        let (_temp, paths) = temp_paths();
        let store = FileKeyStore::new(paths.ca_dir());
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        ca.save(&paths, &store).unwrap();

        let on_disk = std::fs::read_to_string(paths.ca_cert()).unwrap();
        assert!(on_disk.contains("BEGIN CERTIFICATE"));
        assert!(
            !on_disk.contains("PRIVATE KEY"),
            "ca.pem holds a private key"
        );
    }

    #[test]
    fn an_absent_ca_loads_as_none() {
        let (_temp, paths) = temp_paths();
        let store = FileKeyStore::new(paths.ca_dir());
        assert!(CertificateAuthority::load(&paths, &store)
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_certificate_without_its_key_is_an_error_not_a_regeneration() {
        let (_temp, paths) = temp_paths();
        let store = FileKeyStore::new(paths.ca_dir());
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        ca.save(&paths, &store).unwrap();
        store.delete(CA_KEY_ITEM).unwrap();

        let err = CertificateAuthority::load(&paths, &store).unwrap_err();
        assert!(err.to_string().contains("private key"), "{err}");
    }

    #[test]
    fn ensure_generates_once_and_then_reuses() {
        let (_temp, paths) = temp_paths();
        let store = FileKeyStore::new(paths.ca_dir());
        let (first, generated) = CertificateAuthority::ensure(&paths, &store, "mac.local").unwrap();
        assert!(generated);
        let (second, generated) =
            CertificateAuthority::ensure(&paths, &store, "mac.local").unwrap();
        assert!(!generated);
        assert_eq!(first.cert_pem(), second.cert_pem());
    }

    #[test]
    fn removing_takes_both_halves_and_is_idempotent() {
        let (_temp, paths) = temp_paths();
        let store = FileKeyStore::new(paths.ca_dir());
        CertificateAuthority::ensure(&paths, &store, "mac.local").unwrap();
        CertificateAuthority::remove(&paths, &store).unwrap();
        CertificateAuthority::remove(&paths, &store).unwrap();
        assert!(!paths.ca_cert().exists());
        assert!(store.get(CA_KEY_ITEM).unwrap().is_none());
    }

    #[test]
    fn the_fingerprint_is_the_sha256_of_the_der() {
        use sha2::{Digest, Sha256};
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        let expected = hex::encode(Sha256::digest(ca.cert_der()));
        assert_eq!(ca.info().unwrap().fingerprint_sha256, expected);
    }

    #[test]
    fn neither_the_ca_nor_a_leaf_prints_its_private_key() {
        let ca = CertificateAuthority::generate("mac.local").unwrap();
        let leaf = ca.issue_leaf(&["localhost".to_string()]).unwrap();
        for rendered in [format!("{ca:?}"), format!("{leaf:?}")] {
            assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
        }
    }

    fn profile_with(trust_env: Option<&[&str]>) -> Profile {
        let mut profile = Profile::from_yaml_str("name: dev\n").unwrap();
        profile.trust_env = trust_env.map(|names| names.iter().map(|s| s.to_string()).collect());
        profile
    }

    #[test]
    fn a_profile_without_an_override_gets_all_six_variables() {
        let (_temp, paths) = temp_paths();
        let env = trust_env(&paths, &profile_with(None));
        assert_eq!(env.len(), TRUST_ENV_VARS.len());
        let expected = paths.ca_cert().display().to_string();
        for name in TRUST_ENV_VARS {
            assert_eq!(env.get(name), Some(&expected), "{name}");
        }
    }

    #[test]
    fn a_profile_override_narrows_the_list_to_what_it_names() {
        let (_temp, paths) = temp_paths();
        let env = trust_env(
            &paths,
            &profile_with(Some(&["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"])),
        );
        assert_eq!(
            env.keys().collect::<Vec<_>>(),
            vec!["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"]
        );
    }

    #[test]
    fn an_empty_override_opts_the_profile_out_entirely() {
        let (_temp, paths) = temp_paths();
        assert!(trust_env(&paths, &profile_with(Some(&[]))).is_empty());
    }

    #[test]
    fn an_override_naming_something_briefcred_does_not_set_is_rejected_at_load() {
        let yaml = "name: dev\ntrust_env:\n  - NODE_EXTRA_CA_CERTS\n  - MADE_UP_BUNDLE\n";
        let err = Profile::from_yaml_str(yaml).unwrap_err();
        assert!(err.to_string().contains("MADE_UP_BUNDLE"), "{err}");
    }

    #[test]
    fn the_documented_six_variables_are_the_ones_shipped() {
        let mut sorted = TRUST_ENV_VARS;
        sorted.sort_unstable();
        assert_eq!(sorted, TRUST_ENV_VARS, "keep the list sorted");
        for name in [
            "NODE_EXTRA_CA_CERTS",
            "REQUESTS_CA_BUNDLE",
            "SSL_CERT_FILE",
            "GIT_SSL_CAINFO",
            "AWS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
        ] {
            assert!(TRUST_ENV_VARS.contains(&name), "{name}");
        }
    }

    #[test]
    fn a_ca_is_usable_from_several_threads_at_once() {
        let ca = Arc::new(CertificateAuthority::generate("mac.local").unwrap());
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let ca = Arc::clone(&ca);
                std::thread::spawn(move || ca.issue_leaf(&[format!("host{}.test", i % 2)]).unwrap())
            })
            .collect();
        let leaves: Vec<Leaf> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let distinct: std::collections::BTreeSet<&str> =
            leaves.iter().map(|l| l.cert_pem()).collect();
        assert_eq!(distinct.len(), 2, "one cached leaf per hostname");
    }
}
