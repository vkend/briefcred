//! Where master credentials come from.
//!
//! A master credential is the long-lived secret a minter authenticates with:
//! the PostgreSQL superuser password, the AWS access key, and so on. It is the
//! most valuable thing briefcred touches, so it is only ever held as
//! [`Zeroizing<String>`], is never logged, and is fetched fresh for the
//! session that needs it rather than cached in the daemon.
//!
//! Three backends implement [`MasterSource`]:
//!
//! | backend            | where it looks                                | intended use |
//! |--------------------|-----------------------------------------------|--------------|
//! | [`KeychainSource`] | macOS login keychain, service `dev.briefcred.master` | the real one |
//! | [`FileSource`]     | `0600` files under [`Paths::secrets_dir`]      | Linux, and dev |
//! | [`EnvSource`]      | `BRIEFCRED_MASTER_<KEY>`                       | dev only |
//!
//! [`Paths::secrets_dir`]: crate::paths::Paths::secrets_dir

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Once;

use async_trait::async_trait;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::traits::MasterSource;

/// The keychain service name every briefcred master credential is filed under.
///
/// Distinct from [`crate::keystore::KEYCHAIN_SERVICE`]: the CA's private key
/// and the masters are different classes of secret and must not share a
/// namespace, or a `key` could name the CA key by accident.
pub const KEYCHAIN_SERVICE: &str = "dev.briefcred.master";

/// Prefix [`EnvSource`] looks a key up under.
pub const ENV_PREFIX: &str = "BRIEFCRED_MASTER_";

/// `errSecItemNotFound`: the keychain has no such item.
#[cfg(target_os = "macos")]
const ITEM_NOT_FOUND: i32 = -25300;

/// Which [`MasterSource`] implementation a deployment uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    /// The macOS login keychain.
    Keychain,
    /// `0600` files under the secrets directory.
    File,
    /// Process environment. Development only.
    Env,
}

impl SourceKind {
    /// The backend used when nothing names one: the keychain on macOS, files
    /// elsewhere. Never [`SourceKind::Env`], which must be opted into.
    pub fn platform_default(platform: crate::paths::Platform) -> SourceKind {
        match platform {
            crate::paths::Platform::MacOs => SourceKind::Keychain,
            crate::paths::Platform::Linux => SourceKind::File,
        }
    }

    /// The name used in `daemon.toml` and in CLI output.
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceKind::Keychain => "keychain",
            SourceKind::File => "file",
            SourceKind::Env => "env",
        }
    }
}

impl std::fmt::Display for SourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Open the backend named by `kind` for this layout.
///
/// Asking for the keychain off macOS is an error rather than a silent
/// downgrade, exactly as it is for the CA key store.
pub fn open(kind: SourceKind, paths: &crate::paths::Paths) -> Result<Box<dyn MasterSource>> {
    match kind {
        SourceKind::File => Ok(Box::new(FileSource::new(paths.secrets_dir()))),
        SourceKind::Env => Ok(Box::new(EnvSource::new())),
        SourceKind::Keychain => {
            #[cfg(target_os = "macos")]
            {
                Ok(Box::new(KeychainSource::new(KEYCHAIN_SERVICE)))
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err(Error::Master(
                    "the keychain master source needs macOS; set `master_source = \"file\"` in daemon.toml"
                        .to_string(),
                ))
            }
        }
    }
}

/// Reject a key that could escape the namespace it is looked up in.
///
/// The same rule for every backend, so a key that works against the keychain
/// cannot become a path traversal when the deployment moves to files.
fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(Error::Master("a master key must not be empty".to_string()));
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(Error::Master(format!(
            "master key `{key}` must use only letters, digits, `-`, `_`, and `.`"
        )));
    }
    if key.starts_with('.') {
        return Err(Error::Master(format!(
            "master key `{key}` must not start with `.`"
        )));
    }
    Ok(())
}

/// A master credential kept in the macOS login keychain.
///
/// The account of a generic password item under [`KEYCHAIN_SERVICE`] is the
/// key; the password is the master itself.
#[cfg(target_os = "macos")]
pub struct KeychainSource {
    service: String,
}

#[cfg(target_os = "macos")]
impl KeychainSource {
    /// A source reading items filed under the keychain service `service`.
    pub fn new(service: impl Into<String>) -> KeychainSource {
        KeychainSource {
            service: service.into(),
        }
    }

    /// Store `secret` under `key`, replacing any previous value.
    ///
    /// Used by `briefcred master set`; the daemon only ever reads.
    pub fn put(&self, key: &str, secret: &Zeroizing<String>) -> Result<()> {
        validate_key(key)?;
        security_framework::passwords::set_generic_password(&self.service, key, secret.as_bytes())
            .map_err(|e| Error::Master(format!("cannot store master `{key}`: {e}")))
    }

    /// Remove `key`. Removing something absent is not an error.
    pub fn delete(&self, key: &str) -> Result<()> {
        validate_key(key)?;
        match security_framework::passwords::delete_generic_password(&self.service, key) {
            Ok(()) => Ok(()),
            Err(err) if err.code() == ITEM_NOT_FOUND => Ok(()),
            Err(err) => Err(Error::Master(format!(
                "cannot remove master `{key}`: {err}"
            ))),
        }
    }
}

#[cfg(target_os = "macos")]
#[async_trait]
impl MasterSource for KeychainSource {
    async fn fetch(&self, key: &str) -> Result<Zeroizing<String>> {
        validate_key(key)?;
        match security_framework::passwords::get_generic_password(&self.service, key) {
            Ok(bytes) => {
                let mut bytes = Zeroizing::new(bytes);
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| Error::Master(format!("master `{key}` is not valid UTF-8")))?
                    .to_string();
                bytes.zeroize();
                Ok(Zeroizing::new(text))
            }
            Err(err) if err.code() == ITEM_NOT_FOUND => Err(Error::MasterNotFound {
                key: key.to_string(),
                location: self.location(),
            }),
            Err(err) => Err(Error::Master(format!("cannot read master `{key}`: {err}"))),
        }
    }

    fn location(&self) -> String {
        format!("login keychain, service {}", self.service)
    }
}

/// A master credential kept in a `0600` file inside a `0700` directory.
///
/// The Linux backend, and what the tests use: it needs no user session and
/// prompts nobody. A trailing newline is stripped, because every editor adds
/// one and nobody means it to be part of the password.
pub struct FileSource {
    dir: PathBuf,
}

impl FileSource {
    /// A source reading files from `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> FileSource {
        FileSource { dir: dir.into() }
    }

    /// The file `key` is stored in.
    pub fn path(&self, key: &str) -> PathBuf {
        self.dir.join(key)
    }

    /// Write `secret` to `key`'s file, creating it `0600`.
    ///
    /// Used by `briefcred master set`; the daemon only ever reads.
    pub fn put(&self, key: &str, secret: &Zeroizing<String>) -> Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        validate_key(key)?;
        crate::paths::ensure_private_dir(&self.dir)?;
        let path = self.path(key);
        // Created `0600` from the start rather than written and then chmodded:
        // between those two steps the master would be world-readable.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| Error::Master(format!("cannot open {}: {e}", path.display())))?;
        file.write_all(secret.as_bytes())
            .map_err(|e| Error::Master(format!("cannot write {}: {e}", path.display())))?;
        // An existing file keeps its old mode through `truncate`, so set it.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Master(format!("cannot set the mode of {}: {e}", path.display())))
    }
}

#[async_trait]
impl MasterSource for FileSource {
    async fn fetch(&self, key: &str) -> Result<Zeroizing<String>> {
        use std::os::unix::fs::PermissionsExt as _;

        validate_key(key)?;
        let path = self.path(key);
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::MasterNotFound {
                    key: key.to_string(),
                    location: self.location(),
                })
            }
            Err(err) => {
                return Err(Error::Master(format!(
                    "cannot stat {}: {err}",
                    path.display()
                )))
            }
        };
        // A master anyone on the machine can read is not a master. Refusing is
        // the only response that does not quietly normalise the mistake.
        let mode = metadata.permissions().mode() & 0o077;
        if mode != 0 {
            return Err(Error::Master(format!(
                "{} is readable by group or other (mode {:o}); run `chmod 600` on it",
                path.display(),
                metadata.permissions().mode() & 0o777
            )));
        }

        let text = std::fs::read_to_string(&path)
            .map_err(|e| Error::Master(format!("cannot read {}: {e}", path.display())))?;
        let mut text = Zeroizing::new(text);
        let trimmed = Zeroizing::new(text.trim_end_matches(['\n', '\r']).to_string());
        text.zeroize();
        if trimmed.is_empty() {
            return Err(Error::Master(format!("{} is empty", path.display())));
        }
        Ok(trimmed)
    }

    fn location(&self) -> String {
        self.dir.display().to_string()
    }
}

/// A master credential read from the process environment.
///
/// Development only. It is the one backend whose secrets are visible to every
/// child process and to anything that dumps the daemon's environment, so it
/// warns the first time it is used and the warning names the key.
pub struct EnvSource {
    vars: Option<BTreeMap<String, String>>,
    warned: Once,
}

impl Default for EnvSource {
    fn default() -> EnvSource {
        EnvSource::new()
    }
}

impl EnvSource {
    /// A source reading the real process environment.
    pub fn new() -> EnvSource {
        EnvSource {
            vars: None,
            warned: Once::new(),
        }
    }

    /// A source reading a fixed map instead, so tests never mutate the
    /// process environment and can run in parallel.
    pub fn with_vars(vars: BTreeMap<String, String>) -> EnvSource {
        EnvSource {
            vars: Some(vars),
            warned: Once::new(),
        }
    }

    /// The variable `key` is read from.
    pub fn var_name(key: &str) -> String {
        format!("{ENV_PREFIX}{}", key.to_ascii_uppercase().replace('-', "_"))
    }

    fn lookup(&self, name: &str) -> Option<String> {
        match &self.vars {
            Some(vars) => vars.get(name).cloned(),
            None => std::env::var(name).ok(),
        }
    }
}

#[async_trait]
impl MasterSource for EnvSource {
    async fn fetch(&self, key: &str) -> Result<Zeroizing<String>> {
        validate_key(key)?;
        let name = EnvSource::var_name(key);
        // Once per source, not once per fetch: the daemon holds one, and a
        // warning on every fetch would bury the log it is trying to warn in.
        self.warned.call_once(|| {
            eprintln!(
                "briefcred: reading master credentials from the environment ({ENV_PREFIX}*). \
                 This is for development only: every child process inherits them."
            );
        });
        let value = self.lookup(&name).ok_or_else(|| Error::MasterNotFound {
            key: key.to_string(),
            location: self.location(),
        })?;
        let value = Zeroizing::new(value);
        if value.is_empty() {
            return Err(Error::Master(format!("{name} is set but empty")));
        }
        Ok(value)
    }

    fn location(&self) -> String {
        format!("environment, {ENV_PREFIX}*")
    }
}

impl std::fmt::Debug for dyn MasterSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterSource")
            .field("location", &self.location())
            .finish()
    }
}

/// A source backed by an in-memory map.
///
/// Test scaffolding, not a backend: it is compiled only under `cfg(test)` or
/// the `test-util` feature, so it cannot reach a production binary. It still
/// holds its masters in [`Zeroizing<String>`] and redacts its own `Debug`,
/// because a type that models a master source has to obey the same rules as
/// one — a test helper that leaks in a panic message leaks just as loudly.
#[cfg(any(test, feature = "test-util"))]
#[derive(Default, Clone)]
pub struct MemorySource {
    entries: BTreeMap<String, Zeroizing<String>>,
}

#[cfg(any(test, feature = "test-util"))]
impl std::fmt::Debug for MemorySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemorySource")
            .field("keys", &self.entries.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl MemorySource {
    /// A source holding exactly `entries`.
    pub fn new(entries: impl IntoIterator<Item = (String, String)>) -> MemorySource {
        MemorySource {
            entries: entries
                .into_iter()
                .map(|(k, v)| (k, Zeroizing::new(v)))
                .collect(),
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
#[async_trait]
impl MasterSource for MemorySource {
    async fn fetch(&self, key: &str) -> Result<Zeroizing<String>> {
        validate_key(key)?;
        self.entries
            .get(key)
            .cloned()
            .ok_or_else(|| Error::MasterNotFound {
                key: key.to_string(),
                location: self.location(),
            })
    }

    fn location(&self) -> String {
        "in-memory test source".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn temp_source() -> (tempfile::TempDir, FileSource) {
        let dir = tempfile::tempdir().unwrap();
        let source = FileSource::new(dir.path());
        (dir, source)
    }

    #[tokio::test]
    async fn a_file_master_comes_back_unchanged() {
        let (_dir, source) = temp_source();
        source
            .put("app-db", &Zeroizing::new("hunter2".into()))
            .unwrap();
        assert_eq!(&*source.fetch("app-db").await.unwrap(), "hunter2");
    }

    #[tokio::test]
    async fn a_file_master_loses_only_its_trailing_newline() {
        let (dir, source) = temp_source();
        std::fs::write(dir.path().join("k"), "s3cret\n").unwrap();
        std::fs::set_permissions(dir.path().join("k"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert_eq!(&*source.fetch("k").await.unwrap(), "s3cret");
    }

    #[tokio::test]
    async fn a_missing_file_master_names_the_key_and_the_directory() {
        let (dir, source) = temp_source();
        let err = source.fetch("absent").await.unwrap_err();
        assert!(matches!(err, Error::MasterNotFound { .. }), "{err}");
        let text = err.to_string();
        assert!(text.contains("absent"), "{text}");
        assert!(text.contains(&dir.path().display().to_string()), "{text}");
    }

    #[tokio::test]
    async fn a_group_readable_file_master_is_refused() {
        let (dir, source) = temp_source();
        let path = dir.path().join("loose");
        std::fs::write(&path, "s3cret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let err = source.fetch("loose").await.unwrap_err();
        assert!(
            err.to_string().contains("readable by group or other"),
            "{err}"
        );
        assert!(!err.to_string().contains("s3cret"), "{err}");
    }

    #[tokio::test]
    async fn an_empty_file_master_is_refused_rather_than_returned() {
        let (dir, source) = temp_source();
        let path = dir.path().join("blank");
        std::fs::write(&path, "\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(source
            .fetch("blank")
            .await
            .unwrap_err()
            .to_string()
            .contains("empty"));
    }

    #[test]
    fn a_written_file_master_is_readable_only_by_its_owner() {
        let (_dir, source) = temp_source();
        source.put("k", &Zeroizing::new("v".into())).unwrap();
        let mode = std::fs::metadata(source.path("k"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "master file is {mode:o}");
    }

    #[tokio::test]
    async fn a_key_that_could_escape_the_directory_is_refused() {
        let (_dir, source) = temp_source();
        for bad in ["../ca/ca.key", "a/b", "", ".hidden", "k$", "k\0"] {
            assert!(
                source.fetch(bad).await.is_err(),
                "`{bad}` must not be a usable master key"
            );
        }
    }

    #[tokio::test]
    async fn the_env_source_reads_the_prefixed_upper_case_variable() {
        assert_eq!(EnvSource::var_name("app-db"), "BRIEFCRED_MASTER_APP_DB");
        let source = EnvSource::with_vars(BTreeMap::from([(
            "BRIEFCRED_MASTER_APP_DB".to_string(),
            "s3cret".to_string(),
        )]));
        assert_eq!(&*source.fetch("app-db").await.unwrap(), "s3cret");
    }

    #[tokio::test]
    async fn a_missing_env_master_names_the_key() {
        let source = EnvSource::with_vars(BTreeMap::new());
        let err = source.fetch("app-db").await.unwrap_err();
        assert!(matches!(err, Error::MasterNotFound { .. }), "{err}");
    }

    #[tokio::test]
    async fn an_empty_env_master_is_refused() {
        let source = EnvSource::with_vars(BTreeMap::from([(
            "BRIEFCRED_MASTER_K".to_string(),
            String::new(),
        )]));
        assert!(source
            .fetch("k")
            .await
            .unwrap_err()
            .to_string()
            .contains("empty"));
    }

    #[tokio::test]
    async fn a_source_never_prints_the_master_it_holds() {
        let (_dir, file) = temp_source();
        file.put("k", &Zeroizing::new("super-secret-master".into()))
            .unwrap();
        let memory = MemorySource::new([("k".to_string(), "super-secret-master".to_string())]);
        // `MemorySource` is checked through its own `Debug` as well as through
        // the trait object's, because it is the one that holds the value.
        let direct = format!("{memory:?}");
        assert!(!direct.contains("super-secret-master"), "{direct}");
        assert!(direct.contains("\"k\""), "{direct}");

        let sources: Vec<Box<dyn MasterSource>> = vec![
            Box::new(FileSource::new(file.path("").parent().unwrap())),
            Box::new(EnvSource::with_vars(BTreeMap::from([(
                "BRIEFCRED_MASTER_K".to_string(),
                "super-secret-master".to_string(),
            )]))),
            Box::new(memory),
        ];
        for source in &sources {
            let rendered = format!("{source:?} {}", source.location());
            assert!(!rendered.contains("super-secret-master"), "{rendered}");
        }
    }

    #[test]
    fn the_platform_default_is_the_keychain_on_macos_and_a_file_elsewhere() {
        use crate::paths::Platform;
        assert_eq!(
            SourceKind::platform_default(Platform::MacOs),
            SourceKind::Keychain
        );
        assert_eq!(
            SourceKind::platform_default(Platform::Linux),
            SourceKind::File
        );
        assert_eq!(SourceKind::Env.as_str(), "env");
    }

    /// Ignored because it writes a real item into the developer's login
    /// keychain and, on a locked keychain, blocks on a GUI unlock prompt.
    /// Run it deliberately with
    /// `cargo test -p briefcred-core keychain_master -- --ignored`.
    #[tokio::test]
    #[ignore]
    #[cfg(target_os = "macos")]
    async fn the_keychain_master_source_round_trips() {
        let source = KeychainSource::new("dev.briefcred.master.test");
        let secret = Zeroizing::new("keychain-master".to_string());
        source.put("round-trip", &secret).unwrap();
        assert_eq!(&*source.fetch("round-trip").await.unwrap(), &*secret);
        source.delete("round-trip").unwrap();
        assert!(matches!(
            source.fetch("round-trip").await.unwrap_err(),
            Error::MasterNotFound { .. }
        ));
    }
}
