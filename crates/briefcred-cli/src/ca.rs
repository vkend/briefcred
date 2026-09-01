//! `briefcred ca show`, `regenerate`, and `untrust`.
//!
//! Everything here is local: it reads and writes `ca.pem` and the key store,
//! and it never runs a command that needs administrator rights. The system
//! trust store is [`crate::trust`]'s job, and [`crate::cli`] sequences the
//! two. That split is what lets the tests below run the real code without
//! prompting the developer for a password.

use std::path::PathBuf;

use briefcred_core::ca::{CaInfo, CertificateAuthority};
use briefcred_core::keystore::KeyStore;
use briefcred_core::paths::Paths;

use crate::error::{Error, Result};

/// What `briefcred ca show` has to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// Where the certificate lives.
    pub cert: PathBuf,
    /// Its subject, validity, and fingerprint.
    pub info: CaInfo,
    /// Where the private key is kept, as the backend describes itself.
    pub key_location: String,
    /// Which key store backend that is.
    pub keystore: String,
    /// Whether the machine trusts it, when that can be determined.
    pub trusted: Option<bool>,
}

/// Describe the CA on disk.
///
/// `trusted` is passed in rather than looked up so this stays a pure
/// function of the layout and the key store.
pub fn describe(paths: &Paths, store: &dyn KeyStore, trusted: Option<bool>) -> Result<Status> {
    let ca = CertificateAuthority::load(paths, store)?.ok_or(Error::NoCa)?;
    Ok(Status {
        cert: paths.ca_cert(),
        info: ca.info()?,
        key_location: store.location(),
        keystore: store.kind().to_string(),
        trusted,
    })
}

/// What a regeneration replaced, and with what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Regenerated {
    /// The fingerprint of the CA that was replaced, if there was one.
    pub previous_fingerprint: Option<String>,
    /// The new CA.
    pub info: CaInfo,
    /// Where the certificate now is.
    pub cert: PathBuf,
}

/// Replace the CA with a freshly generated one.
///
/// The caller is responsible for having untrusted the old certificate first:
/// once this returns, the file that the system trust store's entry refers to
/// is gone, and only the entry is left.
pub fn regenerate(paths: &Paths, store: &dyn KeyStore, hostname: &str) -> Result<Regenerated> {
    let previous = CertificateAuthority::load(paths, store)
        .ok()
        .flatten()
        .and_then(|ca| ca.info().ok())
        .map(|info| info.fingerprint_sha256);

    CertificateAuthority::remove(paths, store)?;
    let (ca, _) = CertificateAuthority::ensure(paths, store, hostname)?;
    Ok(Regenerated {
        previous_fingerprint: previous,
        info: ca.info()?,
        cert: paths.ca_cert(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use briefcred_core::keystore::{FileKeyStore, CA_KEY_ITEM};
    use briefcred_core::paths::Platform;
    use std::ffi::OsString;

    fn fixture() -> (tempfile::TempDir, Paths, FileKeyStore) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_str().unwrap().to_string();
        let paths = Paths::resolve(Platform::MacOs, &|key| {
            (key == briefcred_core::paths::HOME_ENV).then(|| OsString::from(root.clone()))
        })
        .unwrap();
        paths.ensure_layout().unwrap();
        let store = FileKeyStore::new(paths.ca_dir());
        (temp, paths, store)
    }

    #[test]
    fn showing_a_ca_that_was_never_created_says_so() {
        let (_temp, paths, store) = fixture();
        let err = describe(&paths, &store, None).unwrap_err();
        assert!(matches!(err, Error::NoCa), "{err}");
        assert!(err.to_string().contains("briefcred install"), "{err}");
    }

    #[test]
    fn showing_reports_the_subject_the_key_location_and_the_trust_state() {
        let (_temp, paths, store) = fixture();
        CertificateAuthority::ensure(&paths, &store, "mac.local").unwrap();

        let status = describe(&paths, &store, Some(true)).unwrap();
        assert_eq!(status.cert, paths.ca_cert());
        assert_eq!(status.info.common_name, "briefcred local CA mac.local");
        assert_eq!(status.keystore, "file");
        assert_eq!(status.key_location, paths.ca_dir().display().to_string());
        assert_eq!(status.trusted, Some(true));
        assert_eq!(status.info.fingerprint_sha256.len(), 64);
    }

    #[test]
    fn showing_never_reveals_the_private_key() {
        let (_temp, paths, store) = fixture();
        CertificateAuthority::ensure(&paths, &store, "mac.local").unwrap();
        let key = store.get(CA_KEY_ITEM).unwrap().unwrap();
        let status = describe(&paths, &store, None).unwrap();
        let rendered = format!("{status:?}");
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
        assert!(!rendered.contains(key.trim()), "{rendered}");
    }

    #[test]
    fn regenerating_replaces_both_halves_and_reports_the_old_fingerprint() {
        let (_temp, paths, store) = fixture();
        let (before, _) = CertificateAuthority::ensure(&paths, &store, "mac.local").unwrap();
        let old_fingerprint = before.info().unwrap().fingerprint_sha256;
        let old_key = store.get(CA_KEY_ITEM).unwrap().unwrap();

        let result = regenerate(&paths, &store, "mac.local").unwrap();
        assert_eq!(result.previous_fingerprint, Some(old_fingerprint.clone()));
        assert_ne!(result.info.fingerprint_sha256, old_fingerprint);
        assert_ne!(store.get(CA_KEY_ITEM).unwrap().unwrap(), old_key);

        // The replacement must be a working CA, not just different bytes.
        let reloaded = CertificateAuthority::load(&paths, &store).unwrap().unwrap();
        assert_eq!(
            reloaded.info().unwrap().fingerprint_sha256,
            result.info.fingerprint_sha256
        );
        reloaded.issue_leaf(&["localhost".to_string()]).unwrap();
    }

    #[test]
    fn regenerating_when_there_is_no_ca_yet_simply_creates_one() {
        let (_temp, paths, store) = fixture();
        let result = regenerate(&paths, &store, "mac.local").unwrap();
        assert_eq!(result.previous_fingerprint, None);
        assert!(paths.ca_cert().exists());
    }
}
