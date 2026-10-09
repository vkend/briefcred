//! Where the CA's private key rests when briefcred is not using it.
//!
//! Two backends implement [`KeyStore`]: the macOS login keychain, and a
//! `0600` file under [`crate::paths::Paths::ca_dir`]. The choice is made in
//! exactly one place, [`crate::ca::CaConfig::open_keystore`], so no caller
//! has to know which platform it is on, and `daemon.toml` can override it.
//!
//! A stored secret is a PEM-encoded PKCS#8 private key. It is handled only as
//! [`Zeroizing<String>`], so it is wiped when the last copy is dropped, and
//! neither backend ever writes it to a log or a `Debug` output.

use std::fmt;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::paths::{ensure_private_dir, Paths, Platform};

/// The keychain service name every briefcred CA item is filed under.
pub const KEYCHAIN_SERVICE: &str = "io.github.vkend.briefcred.ca";

/// The item the root CA's private key is stored under.
///
/// The file backend renders it as `ca.key` in the CA directory; the keychain
/// backend files it as the account of a generic password under
/// [`KEYCHAIN_SERVICE`].
pub const CA_KEY_ITEM: &str = "ca";

/// The item the proxy's synthetic-token signing key is stored under.
///
/// Per machine, not per session: a token has to stay verifiable for its whole
/// lifetime, and a key that changed with every daemon restart would invalidate
/// every token in flight. It is an Ed25519 private key, hex-encoded, and it
/// never leaves the daemon — the proxy is the only thing that signs with it and
/// the only thing that verifies against it.
pub const TOKEN_SIGNER_ITEM: &str = "token-signer";

/// `errSecItemNotFound`: the keychain has no such item.
#[cfg(target_os = "macos")]
const ITEM_NOT_FOUND: i32 = -25300;

fn io_error(action: &str, path: &Path, source: std::io::Error) -> Error {
    Error::Keystore(format!("cannot {action} {}: {source}", path.display()))
}

/// A place a private key can be kept between runs.
///
/// Implementations must be usable from several threads because the daemon
/// holds one for the lifetime of the process.
pub trait KeyStore: Send + Sync {
    /// Store `secret` under `item`, replacing any previous value.
    fn put(&self, item: &str, secret: &Zeroizing<String>) -> Result<()>;

    /// Read the secret stored under `item`, or `None` if there is none.
    fn get(&self, item: &str) -> Result<Option<Zeroizing<String>>>;

    /// Remove `item`. Removing something absent is not an error.
    fn delete(&self, item: &str) -> Result<()>;

    /// Where this backend keeps things, for `briefcred ca show`.
    ///
    /// Must never name the secret itself, only its location.
    fn location(&self) -> String;

    /// Which backend this is.
    fn kind(&self) -> KeystoreKind;
}

impl fmt::Debug for dyn KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyStore")
            .field("kind", &self.kind())
            .field("location", &self.location())
            .finish()
    }
}

/// Which [`KeyStore`] implementation to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeystoreKind {
    /// A `0600` file under the CA directory. Available everywhere.
    File,
    /// The macOS login keychain, as a generic password item.
    Keychain,
}

impl KeystoreKind {
    /// The backend used when `daemon.toml` does not name one.
    ///
    /// The keychain on macOS, where it is gated by the user's login session;
    /// a file elsewhere, because there is no equivalent everyone has.
    pub fn platform_default(platform: Platform) -> KeystoreKind {
        match platform {
            Platform::MacOs => KeystoreKind::Keychain,
            Platform::Linux => KeystoreKind::File,
        }
    }

    /// The name used for this backend in `daemon.toml` and in CLI output.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeystoreKind::File => "file",
            KeystoreKind::Keychain => "keychain",
        }
    }
}

impl fmt::Display for KeystoreKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Open the backend named by `kind` for this layout.
///
/// Asking for the keychain on a platform that has none is an error rather
/// than a silent downgrade to a file: a configuration that says "keychain"
/// must not quietly write the key to disk instead.
pub fn open(kind: KeystoreKind, paths: &Paths) -> Result<Box<dyn KeyStore>> {
    match kind {
        KeystoreKind::File => Ok(Box::new(FileKeyStore::new(paths.ca_dir()))),
        KeystoreKind::Keychain => {
            #[cfg(target_os = "macos")]
            {
                Ok(Box::new(KeychainKeyStore::new(KEYCHAIN_SERVICE)))
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = paths;
                Err(Error::Keystore(
                    "the keychain backend needs macOS; set `[ca] keystore = \"file\"` in daemon.toml"
                        .to_string(),
                ))
            }
        }
    }
}

/// A key kept in a `0600` file inside a `0700` directory.
///
/// The fallback everywhere, and what the tests use: it needs no user session,
/// prompts nobody, and leaves nothing behind on the developer's machine.
pub struct FileKeyStore {
    dir: PathBuf,
}

impl FileKeyStore {
    /// A store that keeps its files in `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> FileKeyStore {
        FileKeyStore { dir: dir.into() }
    }

    /// The file `item` is stored in.
    pub fn path(&self, item: &str) -> PathBuf {
        self.dir.join(format!("{item}.key"))
    }
}

impl KeyStore for FileKeyStore {
    fn put(&self, item: &str, secret: &Zeroizing<String>) -> Result<()> {
        let path = self.path(item);
        ensure_private_dir(&self.dir)?;
        // Created 0600 from the start rather than written and then chmodded:
        // between those two steps the key would be world-readable.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| io_error("open", &path, e))?;
        file.write_all(secret.as_bytes())
            .map_err(|e| io_error("write", &path, e))?;
        // The CA key is the one thing a crash must not lose: without it the
        // certificate on disk, and every machine trusting it, is dead weight.
        file.sync_all().map_err(|e| io_error("sync", &path, e))?;
        // An existing file keeps its old mode through `truncate`, so set it.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| io_error("set the mode of", &path, e))
    }

    fn get(&self, item: &str) -> Result<Option<Zeroizing<String>>> {
        let path = self.path(item);
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(Some(Zeroizing::new(text))),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(io_error("read", &path, err)),
        }
    }

    fn delete(&self, item: &str) -> Result<()> {
        let path = self.path(item);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(io_error("remove", &path, err)),
        }
    }

    fn location(&self) -> String {
        self.dir.display().to_string()
    }

    fn kind(&self) -> KeystoreKind {
        KeystoreKind::File
    }
}

/// A key kept in the macOS login keychain as a generic password item.
#[cfg(target_os = "macos")]
pub struct KeychainKeyStore {
    service: String,
}

#[cfg(target_os = "macos")]
impl KeychainKeyStore {
    /// A store filing its items under the keychain service name `service`.
    pub fn new(service: impl Into<String>) -> KeychainKeyStore {
        KeychainKeyStore {
            service: service.into(),
        }
    }
}

#[cfg(target_os = "macos")]
impl KeyStore for KeychainKeyStore {
    fn put(&self, item: &str, secret: &Zeroizing<String>) -> Result<()> {
        // `set_generic_password` replaces an existing item, so there is no
        // delete-then-add window where the key is briefly absent.
        security_framework::passwords::set_generic_password(&self.service, item, secret.as_bytes())
            .map_err(|e| Error::Keystore(format!("cannot store `{item}`: {e}")))
    }

    fn get(&self, item: &str) -> Result<Option<Zeroizing<String>>> {
        match security_framework::passwords::get_generic_password(&self.service, item) {
            Ok(bytes) => {
                let mut bytes = Zeroizing::new(bytes);
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| Error::Keystore(format!("`{item}` is not valid UTF-8")))?
                    .to_string();
                bytes.zeroize();
                Ok(Some(Zeroizing::new(text)))
            }
            Err(err) if err.code() == ITEM_NOT_FOUND => Ok(None),
            Err(err) => Err(Error::Keystore(format!("cannot read `{item}`: {err}"))),
        }
    }

    fn delete(&self, item: &str) -> Result<()> {
        match security_framework::passwords::delete_generic_password(&self.service, item) {
            Ok(()) => Ok(()),
            Err(err) if err.code() == ITEM_NOT_FOUND => Ok(()),
            Err(err) => Err(Error::Keystore(format!("cannot remove `{item}`: {err}"))),
        }
    }

    fn location(&self) -> String {
        format!("login keychain, service {}", self.service)
    }

    fn kind(&self) -> KeystoreKind {
        KeystoreKind::Keychain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, FileKeyStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path());
        (dir, store)
    }

    #[test]
    fn a_stored_secret_comes_back_unchanged() {
        let (_dir, store) = temp_store();
        let secret = Zeroizing::new("-----BEGIN PRIVATE KEY-----\nabc\n".to_string());
        store.put(CA_KEY_ITEM, &secret).unwrap();
        assert_eq!(store.get(CA_KEY_ITEM).unwrap().as_deref(), Some(&*secret));
    }

    #[test]
    fn an_absent_item_reads_as_none_rather_than_an_error() {
        let (_dir, store) = temp_store();
        assert!(store.get(CA_KEY_ITEM).unwrap().is_none());
    }

    #[test]
    fn storing_twice_replaces_rather_than_appends() {
        let (_dir, store) = temp_store();
        store
            .put(CA_KEY_ITEM, &Zeroizing::new("first".into()))
            .unwrap();
        store
            .put(CA_KEY_ITEM, &Zeroizing::new("second".into()))
            .unwrap();
        assert_eq!(
            store
                .get(CA_KEY_ITEM)
                .unwrap()
                .as_deref()
                .map(|s| s.as_str()),
            Some("second")
        );
    }

    #[test]
    fn deleting_is_idempotent_and_leaves_nothing_readable() {
        let (_dir, store) = temp_store();
        store.put(CA_KEY_ITEM, &Zeroizing::new("k".into())).unwrap();
        store.delete(CA_KEY_ITEM).unwrap();
        store.delete(CA_KEY_ITEM).unwrap();
        assert!(store.get(CA_KEY_ITEM).unwrap().is_none());
    }

    #[test]
    fn the_key_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store) = temp_store();
        store.put(CA_KEY_ITEM, &Zeroizing::new("k".into())).unwrap();
        let mode = std::fs::metadata(store.path(CA_KEY_ITEM))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "key file is {mode:o}");
    }

    #[test]
    fn the_default_backend_is_the_keychain_on_macos_and_a_file_elsewhere() {
        assert_eq!(
            KeystoreKind::platform_default(Platform::MacOs),
            KeystoreKind::Keychain
        );
        assert_eq!(
            KeystoreKind::platform_default(Platform::Linux),
            KeystoreKind::File
        );
    }

    #[test]
    fn a_backend_never_prints_the_secret_it_holds() {
        let (_dir, store) = temp_store();
        store
            .put(CA_KEY_ITEM, &Zeroizing::new("super-secret-material".into()))
            .unwrap();
        let store: Box<dyn KeyStore> = Box::new(store);
        let rendered = format!("{store:?} {}", store.location());
        assert!(!rendered.contains("super-secret-material"), "{rendered}");
    }

    /// Ignored because it writes a real item into the developer's login
    /// keychain and, on a locked keychain, blocks on a GUI unlock prompt.
    /// Run it deliberately with `cargo test -p briefcred-core keychain --
    /// --ignored`.
    #[test]
    #[ignore]
    #[cfg(target_os = "macos")]
    fn the_keychain_backend_round_trips() {
        let store = KeychainKeyStore::new("io.github.vkend.briefcred.ca.test");
        let item = "round-trip";
        let secret = Zeroizing::new("keychain-value".to_string());
        store.put(item, &secret).unwrap();
        assert_eq!(store.get(item).unwrap().as_deref(), Some(&*secret));
        store.delete(item).unwrap();
        assert!(store.get(item).unwrap().is_none());
    }
}
