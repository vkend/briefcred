//! Profile distribution: registries, trust roots, and where a profile came from.
//!
//! A profile written by hand in `profiles/` is the user's own and needs no
//! vouching. A profile that arrived from somewhere else does: it names hosts a
//! subprocess may reach and credentials briefcred will mint, so an unsigned one
//! is an instruction from whoever last had write access to a web server.
//!
//! So the two live in different places and are held to different standards.
//! Local profiles are `profiles/*.yaml`. Fetched ones are
//! `profiles/registry/<registry name>/*.yaml`, each beside its `.minisig`, and
//! each is dropped unless its signature verifies against one of the trust roots
//! in `daemon.toml`. A local profile with the same name as a fetched one wins,
//! which is what makes a registry usable: you take the set somebody publishes
//! and override the one profile you need to change.
//!
//! [`ProfilesConfig::dev_mode`] suspends that. It exists because a registry is
//! unusable while you are writing it, and it is loud about what it costs: every
//! unverified file is warned about at load, marked in `briefcred profiles`, and
//! written to the audit log.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::error::{Error, Result};
use crate::minisign::{self, PublicKey};
use crate::profile::Profile;
use crate::registry::Registry;

/// The subdirectory of `profiles/` that fetched registries live under.
pub const REGISTRY_DIR: &str = "registry";

/// How long a registry fetch may take before it is given up on.
///
/// Ten seconds per request. `briefcred profile sync` is something a person
/// runs and waits for, and a registry that cannot answer in ten seconds is
/// one to report rather than one to keep waiting for.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The subdirectory of the clone's temporary directory that `git` writes into.
const CLONE_SUBDIR: &str = "repo";

/// How many same-host redirects a registry fetch will follow.
const MAX_REDIRECTS: usize = 5;

/// The index a plain-HTTPS registry publishes at `<base>/index.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryIndex {
    /// One entry per profile the registry offers.
    pub profiles: Vec<IndexEntry>,
}

/// One profile in a [`RegistryIndex`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexEntry {
    /// The profile's name, for the operator reading the index.
    pub name: String,
    /// Where the YAML sits, relative to the registry's base URL.
    ///
    /// Its `.minisig` is the same path with `.minisig` appended.
    pub path: String,
    /// Lowercase hex SHA-256 of the YAML.
    ///
    /// Checked before the signature, so a mirror that has served the wrong
    /// bytes is named as such rather than as a signature failure.
    pub sha256: String,
}

/// The `[profiles]` table of `daemon.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProfilesConfig {
    /// Minisign public keys whose signatures briefcred will believe.
    ///
    /// Each entry is the single base64 line out of a `.pub` file, without the
    /// comment. An empty list means no registry profile can ever load, which
    /// is the right default: "nothing is trusted" must never quietly become
    /// "everything is".
    pub trust_roots: Vec<String>,
    /// The registries `briefcred profile sync` fetches from.
    pub registries: Vec<RegistrySpec>,
    /// Load registry profiles that are unsigned or fail verification.
    ///
    /// For writing a registry, never for using one. Every file it lets
    /// through is warned about on the daemon's stderr, marked `dev_mode` in
    /// `briefcred profiles`, and recorded in the audit log.
    pub dev_mode: bool,
}

/// One registry in `daemon.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySpec {
    /// The directory under `profiles/registry/` this registry is fetched into.
    pub name: String,
    /// Where to fetch it from. See [`RegistrySource`] for the schemes.
    pub url: String,
}

impl ProfilesConfig {
    /// Parse every trust root, so a typo in `daemon.toml` is a startup error.
    pub fn trust_keys(&self) -> Result<Vec<PublicKey>> {
        self.trust_roots
            .iter()
            .enumerate()
            .map(|(i, line)| {
                PublicKey::parse_line(line).map_err(|e| {
                    Error::Signature(format!("`profiles.trust_roots` entry {}: {e}", i + 1))
                })
            })
            .collect()
    }

    /// The trust decision this config describes.
    pub fn trust(&self) -> Result<Trust> {
        Ok(Trust {
            roots: self.trust_keys()?,
            dev_mode: self.dev_mode,
        })
    }

    /// Read only the `[profiles]` table out of a `daemon.toml`.
    ///
    /// The CLI needs the registries and the trust roots without knowing the
    /// daemon's whole schema, so that a `daemon.toml` carrying a key this
    /// binary is too old to understand does not stop a sync.
    pub fn from_daemon_toml(path: &Path) -> Result<ProfilesConfig> {
        #[derive(Deserialize)]
        struct JustTheProfiles {
            #[serde(default)]
            profiles: ProfilesConfig,
        }
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ProfilesConfig::default())
            }
            Err(source) => {
                return Err(Error::Io {
                    path: path.to_path_buf(),
                    source,
                })
            }
        };
        let parsed: JustTheProfiles = toml::from_str(&text).map_err(|e| Error::Config {
            path: path.to_path_buf(),
            message: e.message().to_string(),
        })?;
        // Fail here rather than at the first fetch: a malformed trust root is
        // a configuration error, and finding it out after a sync has already
        // replaced a directory is finding it out too late.
        parsed.profiles.trust_keys()?;
        Ok(parsed.profiles)
    }
}

/// What briefcred will believe about a registry profile.
#[derive(Debug, Clone, Default)]
pub struct Trust {
    /// The keys whose signatures count.
    pub roots: Vec<PublicKey>,
    /// Whether an unverified file is loaded anyway, loudly.
    pub dev_mode: bool,
}

impl Trust {
    /// A trust decision that accepts nothing: the default for a daemon whose
    /// `daemon.toml` has no `[profiles]` table.
    pub fn none() -> Trust {
        Trust::default()
    }
}

/// Where a registry's files come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrySource {
    /// `file://<absolute path>`: a directory of `*.yaml` and `*.minisig`.
    ///
    /// The form the tests use, and the one an operator uses for a registry
    /// that lives on a shared volume rather than on the web.
    Directory(PathBuf),
    /// `https://<base>`: an `index.json` and the files it names.
    Https(String),
    /// `git+https://<repo>`: a shallow clone, then read as a directory.
    Git(String),
}

impl RegistrySource {
    /// Interpret a registry's `url`.
    ///
    /// Three schemes and no others. Anything else — `http://`, `ssh://`, a
    /// bare path — is refused by name rather than guessed at, because every
    /// guess here is a guess about where a profile came from.
    pub fn parse(url: &str) -> Result<RegistrySource> {
        if let Some(path) = url.strip_prefix("file://") {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(Error::Signature(format!(
                    "`file://` registry url `{url}` must name an absolute path"
                )));
            }
            return Ok(RegistrySource::Directory(path));
        }
        if let Some(repo) = url.strip_prefix("git+") {
            // `git+file://` is accepted only in test builds, so the clone path
            // can be exercised against a local bare repository without a
            // network. A shipping binary takes `git+https://` and nothing
            // else: a `file://` remote in a real `daemon.toml` would be a
            // registry whose "transport" is whatever wrote that path.
            let local_ok = cfg!(test) && repo.starts_with("file://");
            if !repo.starts_with("https://") && !local_ok {
                return Err(Error::Signature(format!(
                    "git registry url `{url}` must be `git+https://`"
                )));
            }
            return Ok(RegistrySource::Git(repo.to_string()));
        }
        if url.starts_with("https://") {
            return Ok(RegistrySource::Https(url.trim_end_matches('/').to_string()));
        }
        Err(Error::Signature(format!(
            "registry url `{url}` must start with `file://`, `https://`, or `git+https://`"
        )))
    }
}

/// What one `briefcred profile sync` of one registry did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// The registry's name.
    pub name: String,
    /// Where its files were written.
    pub dir: PathBuf,
    /// How many profiles a trust root vouched for.
    pub accepted: usize,
    /// How many were written unverified because `dev_mode` is on.
    pub unverified: usize,
    /// One line per file that was not, saying which and why.
    pub skipped: Vec<String>,
}

/// Fetch one registry into `profiles_dir/registry/<name>/`, verifying as it goes.
///
/// The fetch lands in a temporary directory and is moved into place at the
/// end, so a sync that fails halfway leaves the previous contents intact
/// rather than a directory holding half of two registries.
pub async fn sync_registry(
    spec: &RegistrySpec,
    profiles_dir: &Path,
    trust: &Trust,
) -> Result<SyncOutcome> {
    if spec.name.is_empty() || spec.name.contains(['/', '\\']) || spec.name.starts_with('.') {
        return Err(Error::Registry {
            name: spec.name.clone(),
            message: "a registry name must be a single path segment and must not start with `.`"
                .to_string(),
        });
    }
    let source = RegistrySource::parse(&spec.url).map_err(|e| Error::Registry {
        name: spec.name.clone(),
        message: e.to_string(),
    })?;

    let registry_root = profiles_dir.join(REGISTRY_DIR);
    let staging = tempdir_beside(&registry_root, &spec.name)?;
    let staged_counts = match stage(spec, &source, staging.path(), trust).await {
        Ok(counts) => counts,
        Err(err) => {
            let _ = std::fs::remove_dir_all(staging.path());
            return Err(err);
        }
    };
    let Staged {
        accepted,
        unverified,
        skipped,
    } = staged_counts;

    let target = registry_root.join(&spec.name);
    // A fetch that produced nothing, over a registry that currently has
    // something, is a fetch that went wrong: a bad URL, a moved branch, a
    // clone that landed somewhere unexpected. Replacing a working profile set
    // with an empty directory on that evidence is the worst available answer,
    // so the swap is refused and the previous set stays.
    if accepted + unverified == 0 && count_profiles(&target) > 0 {
        let _ = std::fs::remove_dir_all(staging.path());
        return Err(Error::Registry {
            name: spec.name.clone(),
            message: format!(
                "fetched no profiles, but {} already has some; keeping what is there",
                target.display()
            ),
        });
    }

    // Hand the staged directory over to this function: from here on it is
    // moved into place rather than cleaned up.
    let staged = staging.keep();
    // Not a single atomic operation: a directory rename onto a non-empty
    // directory is not portable. The window is between the remove and the
    // rename, and what it costs is a daemon reload that briefly sees no
    // profiles from this registry — never a mixed set, because the staged
    // directory is complete before either step runs.
    if target.exists() {
        std::fs::remove_dir_all(&target).map_err(|source| Error::Io {
            path: target.clone(),
            source,
        })?;
    }
    std::fs::rename(&staged, &target).map_err(|source| Error::Io {
        path: target.clone(),
        source,
    })?;

    Ok(SyncOutcome {
        name: spec.name.clone(),
        dir: target,
        accepted,
        unverified,
        skipped,
    })
}

/// Fetch into `staging`, returning what the pass accepted and refused.
async fn stage(
    spec: &RegistrySpec,
    source: &RegistrySource,
    staging: &Path,
    trust: &Trust,
) -> Result<Staged> {
    let named = |message: String| Error::Registry {
        name: spec.name.clone(),
        message,
    };
    let files: Vec<FetchedFile> = match source {
        RegistrySource::Directory(dir) => read_directory(dir).map_err(|e| named(e.to_string()))?,
        RegistrySource::Git(repo) => {
            let clone = clone_shallow(repo).map_err(|e| named(e.to_string()))?;
            read_directory(&clone.path().join(CLONE_SUBDIR)).map_err(|e| named(e.to_string()))?
        }
        RegistrySource::Https(base) => fetch_https(base).await.map_err(|e| named(e.to_string()))?,
    };

    let mut accepted = 0usize;
    let mut unverified = 0usize;
    let mut skipped = Vec::new();
    for file in &files {
        match check(file, trust) {
            Ok(_) => accepted += 1,
            Err(why) => {
                if !trust.dev_mode {
                    skipped.push(format!("{}: {why}", file.name));
                    continue;
                }
                // Written, but not counted as accepted: `accepted` is how many
                // profiles a trust root vouched for, and under `dev_mode` that
                // is exactly the number this file is not one of.
                unverified += 1;
                skipped.push(format!("{}: {why} (loaded anyway: dev_mode)", file.name));
            }
        }
        std::fs::write(staging.join(&file.name), &file.yaml).map_err(|source| Error::Io {
            path: staging.join(&file.name),
            source,
        })?;
        if let Some(signature) = &file.signature {
            let path = staging.join(format!("{}.minisig", file.name));
            std::fs::write(&path, signature).map_err(|source| Error::Io { path, source })?;
        }
    }
    Ok(Staged {
        accepted,
        unverified,
        skipped,
    })
}

/// What one staging pass produced.
struct Staged {
    /// Files a trust root vouched for.
    accepted: usize,
    /// Files written only because `dev_mode` is on.
    unverified: usize,
    /// One line per file that did not verify, whether or not it was written.
    skipped: Vec<String>,
}

/// How many `*.yaml` files a registry directory currently holds.
fn count_profiles(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            let path = entry.path();
            path.extension().is_some_and(|ext| ext == "yaml") && path.is_file()
        })
        .count()
}

/// One profile file and its signature, as fetched.
struct FetchedFile {
    /// The file name it will be written under, always ending in `.yaml`.
    name: String,
    yaml: Vec<u8>,
    signature: Option<String>,
}

/// Whether this file would load, and which key vouched for it.
fn check(file: &FetchedFile, trust: &Trust) -> std::result::Result<PublicKey, String> {
    let Some(signature) = &file.signature else {
        return Err("no .minisig alongside it".to_string());
    };
    minisign::verify_with_any(&file.yaml, signature, &trust.roots).map_err(|e| e.to_string())
}

/// Read every `*.yaml` in `dir`, pairing each with its `.minisig`.
fn read_directory(dir: &Path) -> Result<Vec<FetchedFile>> {
    let entries = std::fs::read_dir(dir).map_err(|source| Error::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| Error::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "yaml") && path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                names.push(name.to_string());
            }
        }
    }
    names.sort();

    names
        .into_iter()
        .map(|name| {
            let yaml = std::fs::read(dir.join(&name)).map_err(|source| Error::Io {
                path: dir.join(&name),
                source,
            })?;
            let signature = std::fs::read_to_string(dir.join(format!("{name}.minisig"))).ok();
            Ok(FetchedFile {
                name,
                yaml,
                signature,
            })
        })
        .collect()
}

/// `git clone --depth 1` into a temporary directory.
///
/// The system `git` rather than a library: a registry in a git repository is
/// almost always one behind an authenticating remote, and `git` is the thing
/// that already knows about the user's credential helper, their SSH agent,
/// and their proxy settings.
fn clone_shallow(repo: &str) -> Result<tempfile::TempDir> {
    let dir = tempfile::TempDir::new().map_err(|source| Error::Io {
        path: PathBuf::from("a temporary directory"),
        source,
    })?;
    // The clone goes in a subdirectory, so the `TempDir` guard owns the parent
    // and still removes everything when it drops. Callers read
    // `dir.path().join(CLONE_SUBDIR)`, never `dir.path()` — which holds only
    // the subdirectory and would read as a registry with no profiles in it.
    let output = std::process::Command::new("git")
        .args(["clone", "--depth", "1", "--quiet", repo])
        .arg(dir.path().join(CLONE_SUBDIR))
        .output()
        .map_err(|e| Error::Signature(format!("cannot run git: {e}")))?;
    if !output.status.success() {
        return Err(Error::Signature(format!(
            "git clone failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(dir)
}

/// Fetch `index.json` and every file it names.
async fn fetch_https(base: &str) -> Result<Vec<FetchedFile>> {
    let client = https_client(base)?;
    let index_url = format!("{base}/index.json");
    let index: RegistryIndex = serde_json::from_slice(&get(&client, &index_url).await?)
        .map_err(|e| Error::Signature(format!("{index_url} is not a valid index.json: {e}")))?;

    let mut out = Vec::with_capacity(index.profiles.len());
    for entry in &index.profiles {
        let name = safe_file_name(&entry.path)?;
        let yaml = get(&client, &format!("{base}/{}", entry.path)).await?;
        let digest = hex::encode(Sha256::digest(&yaml));
        // Checked before the signature so a mirror serving stale or swapped
        // bytes is reported as that, rather than as "the signature is bad".
        if !digest.eq_ignore_ascii_case(&entry.sha256) {
            return Err(Error::Signature(format!(
                "{} does not match the sha256 in index.json",
                entry.path
            )));
        }
        let signature = get(&client, &format!("{base}/{}.minisig", entry.path))
            .await
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok());
        out.push(FetchedFile {
            name,
            yaml,
            signature,
        });
    }
    Ok(out)
}

/// A client that times out and will not be redirected off the registry's host.
///
/// A redirect to another host is how a registry that has been tampered with
/// points briefcred at somebody else's files. The signature would still have
/// to check out, so this is defence in depth rather than the only control, but
/// it also stops the sha256 in a trusted index vouching for a stranger's bytes.
fn https_client(base: &str) -> Result<reqwest::Client> {
    let host = reqwest::Url::parse(base)
        .map_err(|e| Error::Signature(format!("registry url `{base}` is not a url: {e}")))?
        .host_str()
        .map(str::to_string)
        .ok_or_else(|| Error::Signature(format!("registry url `{base}` has no host")))?;
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        match attempt.url().host_str() {
            Some(next) if next == host => attempt.follow(),
            _ => attempt.stop(),
        }
    });
    reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .redirect(policy)
        .build()
        .map_err(|e| Error::Signature(format!("cannot build an HTTPS client: {e}")))
}

async fn get(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::Signature(format!("cannot fetch {url}: {e}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(Error::Signature(format!("{url} returned HTTP {status}")));
    }
    Ok(response
        .bytes()
        .await
        .map_err(|e| Error::Signature(format!("cannot read {url}: {e}")))?
        .to_vec())
}

/// The file name a registry-supplied path may be written under.
///
/// A registry names its own files, so the name is untrusted input that ends up
/// as a path: `../../daemon.toml` in an `index.json` must not become a write
/// outside the registry's directory.
fn safe_file_name(path: &str) -> Result<String> {
    let name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::Signature(format!("index.json path `{path}` has no file name")))?;
    if path.contains("..") || path.starts_with('/') {
        return Err(Error::Signature(format!(
            "index.json path `{path}` must be a relative path without `..`"
        )));
    }
    if !name.ends_with(".yaml") {
        return Err(Error::Signature(format!(
            "index.json path `{path}` must name a `.yaml` file"
        )));
    }
    Ok(name.to_string())
}

/// A staging directory inside `registry/`, so the final move is a rename
/// within one filesystem rather than a copy across two.
fn tempdir_beside(registry_root: &Path, name: &str) -> Result<tempfile::TempDir> {
    crate::paths::ensure_private_dir(registry_root)?;
    tempfile::Builder::new()
        .prefix(&format!(".{name}.sync."))
        .tempdir_in(registry_root)
        .map_err(|source| Error::Io {
            path: registry_root.to_path_buf(),
            source,
        })
}

/// Where a loaded profile came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileSource {
    /// `profiles/<file>.yaml`, written by the user.
    Local,
    /// `profiles/registry/<name>/<file>.yaml`, fetched from that registry.
    Registry(String),
}

impl std::fmt::Display for ProfileSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileSource::Local => f.write_str("local"),
            ProfileSource::Registry(name) => write!(f, "registry({name})"),
        }
    }
}

/// What briefcred was able to say about a profile file's signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// A `.minisig` beside it verified against a trust root.
    Verified,
    /// There is no `.minisig` beside it.
    Unsigned,
    /// There is one, and it does not verify against any trust root.
    Invalid,
    /// It is unsigned or invalid and was loaded anyway because `dev_mode` is on.
    DevMode,
}

impl std::fmt::Display for SignatureStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SignatureStatus::Verified => "verified",
            SignatureStatus::Unsigned => "unsigned",
            SignatureStatus::Invalid => "invalid",
            SignatureStatus::DevMode => "dev_mode",
        })
    }
}

/// One profile, with everything known about where it came from.
#[derive(Debug, Clone)]
pub struct LoadedProfile {
    /// The profile itself.
    pub profile: Profile,
    /// The file it was read from.
    pub path: PathBuf,
    /// Local, or the registry that published it.
    pub source: ProfileSource,
    /// What its signature was worth.
    pub signature: SignatureStatus,
    /// The key that vouched for it, when one did.
    pub signer_key_id: Option<String>,
    /// The registry whose profile of the same name this one shadows.
    pub overrides: Option<String>,
}

/// What briefcred did about a profile file it would not simply load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAction {
    /// It did not verify and was left out of the set.
    Dropped,
    /// It did not verify and was loaded anyway because `dev_mode` is on.
    LoadedDevMode,
    /// It verified, but another registry already publishes that profile name.
    ///
    /// Not a trust failure, and deliberately a different value: an operator
    /// reading the audit log must not find a name collision filed as a
    /// signature problem.
    Ignored,
}

impl TrustAction {
    /// The value this action is recorded under in the audit log.
    pub fn as_str(self) -> &'static str {
        match self {
            TrustAction::Dropped => "dropped",
            TrustAction::LoadedDevMode => "loaded_dev_mode",
            TrustAction::Ignored => "ignored",
        }
    }

    /// Whether this is a signature failure rather than a collision.
    pub fn is_trust_failure(self) -> bool {
        matches!(self, TrustAction::Dropped | TrustAction::LoadedDevMode)
    }
}

/// One complaint about one file, in the form the daemon audits it.
///
/// Structured rather than a sentence: the daemon has to file each of these as
/// an audit row with the path and the action in their own fields, and
/// recovering them by looking for a substring in a message would be a parser
/// for text this crate is also the only writer of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustWarning {
    /// The file this is about.
    pub path: PathBuf,
    /// What was done about it.
    pub action: TrustAction,
    /// Why, in a form fit for an operator. Never file contents.
    pub reason: String,
}

impl std::fmt::Display for TrustWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.action {
            TrustAction::Dropped => "dropped",
            TrustAction::LoadedDevMode => "loaded unverified because dev_mode is on",
            TrustAction::Ignored => "ignored",
        };
        write!(f, "{}: {what}: {}", self.path.display(), self.reason)
    }
}

/// Every profile briefcred will honour, and every complaint made getting there.
#[derive(Debug, Clone, Default)]
pub struct ProfileSet {
    /// The profiles, by name, after precedence has been applied.
    pub profiles: BTreeMap<String, LoadedProfile>,
    /// The files that were dropped, distrusted, or shadowed.
    ///
    /// Each is audited and printed. A set can be perfectly usable and still
    /// carry warnings: one bad file in a registry does not stop the rest.
    pub warnings: Vec<TrustWarning>,
}

impl ProfileSet {
    /// Whether any loaded profile is only there because `dev_mode` is on.
    pub fn has_dev_mode_profiles(&self) -> bool {
        self.profiles
            .values()
            .any(|p| p.signature == SignatureStatus::DevMode)
    }

    /// Load `profiles_dir`, applying trust to the registry subtree and letting
    /// local profiles override registry ones of the same name.
    ///
    /// A file that does not parse or does not validate is an error, and the
    /// caller keeps its previous set. A file that fails *verification* is not:
    /// it is dropped from the set and warned about, because keeping the last
    /// good copy of a profile whose signature has just stopped verifying is
    /// exactly the wrong response to that news.
    pub fn load(profiles_dir: &Path, registry: &Registry, trust: &Trust) -> Result<ProfileSet> {
        let mut set = ProfileSet::default();

        for (name, loaded) in load_registries(profiles_dir, registry, trust, &mut set.warnings)? {
            set.profiles.insert(name, loaded);
        }

        for (name, profile) in Profile::load_dir(profiles_dir, registry)? {
            let path = profiles_dir.join(format!("{name}.yaml"));
            let overrides = match set.profiles.get(&name).map(|p| &p.source) {
                Some(ProfileSource::Registry(registry_name)) => Some(registry_name.clone()),
                _ => None,
            };
            set.profiles.insert(
                name,
                LoadedProfile {
                    profile,
                    // `load_dir` keys by the profile's `name`, which need not
                    // match its file name, so the path is only right when it
                    // does. Recovered below from the directory listing.
                    path,
                    source: ProfileSource::Local,
                    signature: SignatureStatus::Unsigned,
                    signer_key_id: None,
                    overrides,
                },
            );
        }
        repair_local_paths(profiles_dir, &mut set.profiles);

        Ok(set)
    }
}

/// Load every registry subdirectory, dropping what does not verify.
fn load_registries(
    profiles_dir: &Path,
    registry: &Registry,
    trust: &Trust,
    warnings: &mut Vec<TrustWarning>,
) -> Result<BTreeMap<String, LoadedProfile>> {
    let root = profiles_dir.join(REGISTRY_DIR);
    let mut names: Vec<String> = Vec::new();
    match std::fs::read_dir(&root) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|source| Error::Io {
                    path: root.clone(),
                    source,
                })?;
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                // A `.`-prefixed directory is a sync that was interrupted
                // partway. Skipped rather than loaded: it is by definition an
                // incomplete copy of a registry.
                if path.is_dir() && !name.starts_with('.') {
                    names.push(name.to_string());
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(source) => return Err(Error::Io { path: root, source }),
    }
    names.sort();

    let mut out: BTreeMap<String, LoadedProfile> = BTreeMap::new();
    for registry_name in names {
        let dir = root.join(&registry_name);
        for file in read_directory(&dir)? {
            let path = dir.join(&file.name);
            let (status, key_id) = match check(&file, trust) {
                Ok(key) => (SignatureStatus::Verified, Some(key.key_id().to_string())),
                Err(why) => {
                    let status = if file.signature.is_none() {
                        SignatureStatus::Unsigned
                    } else {
                        SignatureStatus::Invalid
                    };
                    if !trust.dev_mode {
                        warnings.push(TrustWarning {
                            path: path.clone(),
                            action: TrustAction::Dropped,
                            reason: format!("{status}: {why}"),
                        });
                        continue;
                    }
                    warnings.push(TrustWarning {
                        path: path.clone(),
                        action: TrustAction::LoadedDevMode,
                        reason: format!("{status}: {why}"),
                    });
                    (SignatureStatus::DevMode, None)
                }
            };

            let text = String::from_utf8(file.yaml).map_err(|_| Error::Profile {
                path: Some(path.clone()),
                message: "not valid UTF-8".to_string(),
            })?;
            let profile = Profile::from_yaml_str(&text).map_err(|e| e.at_path(&path))?;
            profile.validate(registry).map_err(|e| e.at_path(&path))?;

            if let Some(previous) = out.get(&profile.name) {
                // Two registries publishing the same name: the first in
                // alphabetical order wins, and the collision is reported. The
                // alternative — last one wins — makes which profile you get
                // depend on a directory listing.
                warnings.push(TrustWarning {
                    path: path.clone(),
                    action: TrustAction::Ignored,
                    reason: format!(
                        "`{}` is already published by {}",
                        profile.name, previous.source
                    ),
                });
                continue;
            }
            out.insert(
                profile.name.clone(),
                LoadedProfile {
                    profile,
                    path,
                    source: ProfileSource::Registry(registry_name.clone()),
                    signature: status,
                    signer_key_id: key_id,
                    overrides: None,
                },
            );
        }
    }
    Ok(out)
}

/// Point each local profile at the file it actually came from.
///
/// [`Profile::load_dir`] keys by the profile's `name`, which is usually but not
/// always its file name. Rather than duplicate the loader to keep the paths,
/// the directory is re-read and any profile whose guessed path is wrong is
/// matched by content.
fn repair_local_paths(profiles_dir: &Path, profiles: &mut BTreeMap<String, LoadedProfile>) {
    let wrong: Vec<String> = profiles
        .iter()
        .filter(|(_, p)| p.source == ProfileSource::Local && !p.path.is_file())
        .map(|(name, _)| name.clone())
        .collect();
    if wrong.is_empty() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(profiles_dir) else {
        return;
    };
    let mut by_name: BTreeMap<String, PathBuf> = BTreeMap::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "yaml") || !path.is_file() {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(profile) = Profile::from_yaml_str(&text) {
                by_name.insert(profile.name, path);
            }
        }
    }
    for name in wrong {
        if let Some(path) = by_name.remove(&name) {
            if let Some(loaded) = profiles.get_mut(&name) {
                loaded.path = path;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::minisign::SecretKey;

    fn registry() -> Registry {
        Registry::discover()
    }

    /// A home with a profiles directory and one registry inside it.
    struct Home {
        dir: tempfile::TempDir,
    }

    impl Home {
        fn new() -> Home {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("profiles")).unwrap();
            Home { dir }
        }

        fn profiles(&self) -> PathBuf {
            self.dir.path().join("profiles")
        }

        fn local(&self, file: &str, yaml: &str) {
            std::fs::write(self.profiles().join(file), yaml).unwrap();
        }

        fn registry_dir(&self, name: &str) -> PathBuf {
            let dir = self.profiles().join(REGISTRY_DIR).join(name);
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        /// Write a registry file, signed with `key` when one is given.
        fn published(&self, registry: &str, file: &str, yaml: &str, key: Option<&SecretKey>) {
            let dir = self.registry_dir(registry);
            std::fs::write(dir.join(file), yaml).unwrap();
            if let Some(key) = key {
                let signature = key.sign(yaml.as_bytes(), file).unwrap();
                std::fs::write(dir.join(format!("{file}.minisig")), signature).unwrap();
            }
        }
    }

    fn trust_of(key: &SecretKey) -> Trust {
        Trust {
            roots: vec![key.public()],
            dev_mode: false,
        }
    }

    #[test]
    fn a_signed_registry_profile_loads_and_names_its_signer() {
        let home = Home::new();
        let (key, public) = SecretKey::generate().unwrap();
        home.published("acme", "alpha.yaml", "name: alpha\n", Some(&key));

        let set = ProfileSet::load(&home.profiles(), &registry(), &trust_of(&key)).unwrap();

        let loaded = set.profiles.get("alpha").expect("alpha must load");
        assert_eq!(loaded.signature, SignatureStatus::Verified);
        assert_eq!(loaded.source, ProfileSource::Registry("acme".to_string()));
        assert_eq!(
            loaded.signer_key_id.as_deref(),
            Some(public.key_id().to_string().as_str())
        );
        assert_eq!(loaded.overrides, None);
        assert!(set.warnings.is_empty(), "{:?}", set.warnings);
    }

    #[test]
    fn an_unsigned_registry_profile_is_dropped_and_named() {
        let home = Home::new();
        let (key, _) = SecretKey::generate().unwrap();
        home.published("acme", "alpha.yaml", "name: alpha\n", None);

        let set = ProfileSet::load(&home.profiles(), &registry(), &trust_of(&key)).unwrap();

        assert!(set.profiles.is_empty(), "an unsigned profile must not load");
        assert_eq!(set.warnings.len(), 1);
        assert_eq!(set.warnings[0].action, TrustAction::Dropped);
        assert!(
            set.warnings[0].path.ends_with("alpha.yaml"),
            "{:?}",
            set.warnings
        );
        assert!(
            set.warnings[0].reason.contains("unsigned"),
            "{:?}",
            set.warnings
        );
    }

    #[test]
    fn a_tampered_registry_profile_is_dropped_even_though_its_signature_parses() {
        let home = Home::new();
        let (key, _) = SecretKey::generate().unwrap();
        home.published("acme", "alpha.yaml", "name: alpha\n", Some(&key));
        // Edit the file after signing, which is exactly what a compromised
        // mirror does.
        std::fs::write(
            home.registry_dir("acme").join("alpha.yaml"),
            "name: alpha\ndescription: pwned\n",
        )
        .unwrap();

        let set = ProfileSet::load(&home.profiles(), &registry(), &trust_of(&key)).unwrap();

        assert!(set.profiles.is_empty());
        assert_eq!(set.warnings[0].action, TrustAction::Dropped);
        assert!(
            set.warnings[0].reason.contains("invalid"),
            "{:?}",
            set.warnings
        );
    }

    #[test]
    fn a_profile_signed_by_a_key_that_is_not_a_trust_root_is_dropped() {
        let home = Home::new();
        let (stranger, _) = SecretKey::generate().unwrap();
        let (ours, _) = SecretKey::generate().unwrap();
        home.published("acme", "alpha.yaml", "name: alpha\n", Some(&stranger));

        let set = ProfileSet::load(&home.profiles(), &registry(), &trust_of(&ours)).unwrap();

        assert!(set.profiles.is_empty());
        assert_eq!(set.warnings[0].action, TrustAction::Dropped);
        assert!(
            set.warnings[0].reason.contains("not a trust root"),
            "{:?}",
            set.warnings
        );
    }

    #[test]
    fn dev_mode_loads_an_unsigned_profile_and_says_so_every_time() {
        let home = Home::new();
        home.published("acme", "alpha.yaml", "name: alpha\n", None);
        let trust = Trust {
            roots: Vec::new(),
            dev_mode: true,
        };

        let set = ProfileSet::load(&home.profiles(), &registry(), &trust).unwrap();

        let loaded = set.profiles.get("alpha").expect("dev_mode must load it");
        assert_eq!(loaded.signature, SignatureStatus::DevMode);
        assert_eq!(loaded.signer_key_id, None);
        assert!(set.has_dev_mode_profiles());
        assert_eq!(set.warnings[0].action, TrustAction::LoadedDevMode);
        assert_eq!(set.warnings[0].action.as_str(), "loaded_dev_mode");
        assert!(
            set.warnings[0].to_string().contains("dev_mode"),
            "{:?}",
            set.warnings
        );
    }

    #[test]
    fn a_local_profile_overrides_a_registry_one_of_the_same_name() {
        let home = Home::new();
        let (key, _) = SecretKey::generate().unwrap();
        home.published(
            "acme",
            "alpha.yaml",
            "name: alpha\ndescription: published\n",
            Some(&key),
        );
        home.local("alpha.yaml", "name: alpha\ndescription: mine\n");

        let set = ProfileSet::load(&home.profiles(), &registry(), &trust_of(&key)).unwrap();

        let loaded = set.profiles.get("alpha").unwrap();
        assert_eq!(loaded.source, ProfileSource::Local);
        assert_eq!(loaded.overrides.as_deref(), Some("acme"));
        assert_eq!(loaded.profile.description.as_deref(), Some("mine"));
        assert_eq!(loaded.path, home.profiles().join("alpha.yaml"));
    }

    #[test]
    fn a_local_profile_that_shadows_nothing_reports_no_override() {
        let home = Home::new();
        home.local("solo.yaml", "name: solo\n");
        let set = ProfileSet::load(&home.profiles(), &registry(), &Trust::none()).unwrap();
        let loaded = set.profiles.get("solo").unwrap();
        assert_eq!(loaded.source, ProfileSource::Local);
        assert_eq!(loaded.overrides, None);
        assert_eq!(loaded.signature, SignatureStatus::Unsigned);
    }

    #[test]
    fn a_local_profile_whose_file_name_is_not_its_profile_name_still_knows_its_path() {
        let home = Home::new();
        home.local("00-first.yaml", "name: alpha\n");
        let set = ProfileSet::load(&home.profiles(), &registry(), &Trust::none()).unwrap();
        assert_eq!(
            set.profiles.get("alpha").unwrap().path,
            home.profiles().join("00-first.yaml")
        );
    }

    #[test]
    fn two_registries_publishing_one_name_resolve_in_a_stated_order() {
        let home = Home::new();
        let (key, _) = SecretKey::generate().unwrap();
        home.published(
            "aaa",
            "alpha.yaml",
            "name: alpha\ndescription: a\n",
            Some(&key),
        );
        home.published(
            "zzz",
            "alpha.yaml",
            "name: alpha\ndescription: z\n",
            Some(&key),
        );

        let set = ProfileSet::load(&home.profiles(), &registry(), &trust_of(&key)).unwrap();

        assert_eq!(
            set.profiles.get("alpha").unwrap().source,
            ProfileSource::Registry("aaa".to_string())
        );
        assert_eq!(
            set.warnings[0].action,
            TrustAction::Ignored,
            "a name collision is not a signature failure"
        );
        assert!(!set.warnings[0].action.is_trust_failure());
        assert!(
            set.warnings[0].reason.contains("already published"),
            "{:?}",
            set.warnings
        );
    }

    #[test]
    fn a_registry_profile_that_does_not_parse_fails_the_whole_load() {
        let home = Home::new();
        let (key, _) = SecretKey::generate().unwrap();
        home.published("acme", "alpha.yaml", "name: alpha\nbogus: 1\n", Some(&key));

        let err = ProfileSet::load(&home.profiles(), &registry(), &trust_of(&key)).unwrap_err();

        assert!(err.to_string().contains("bogus"), "{err}");
        assert!(err.to_string().contains("alpha.yaml"), "{err}");
    }

    #[test]
    fn a_partial_sync_directory_is_ignored_rather_than_half_loaded() {
        let home = Home::new();
        let (key, _) = SecretKey::generate().unwrap();
        home.published(".acme.sync.tmp", "alpha.yaml", "name: alpha\n", Some(&key));

        let set = ProfileSet::load(&home.profiles(), &registry(), &trust_of(&key)).unwrap();
        assert!(set.profiles.is_empty());
    }

    #[test]
    fn a_missing_profiles_directory_loads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let set =
            ProfileSet::load(&dir.path().join("profiles"), &registry(), &Trust::none()).unwrap();
        assert!(set.profiles.is_empty());
        assert!(set.warnings.is_empty());
    }

    #[tokio::test]
    async fn syncing_a_file_registry_copies_the_signed_files_and_skips_the_rest() {
        let home = Home::new();
        let source = tempfile::tempdir().unwrap();
        let (key, _) = SecretKey::generate().unwrap();
        std::fs::write(source.path().join("alpha.yaml"), "name: alpha\n").unwrap();
        std::fs::write(
            source.path().join("alpha.yaml.minisig"),
            key.sign(b"name: alpha\n", "alpha").unwrap(),
        )
        .unwrap();
        std::fs::write(source.path().join("beta.yaml"), "name: beta\n").unwrap();

        let spec = RegistrySpec {
            name: "acme".to_string(),
            url: format!("file://{}", source.path().display()),
        };
        let outcome = sync_registry(&spec, &home.profiles(), &trust_of(&key))
            .await
            .unwrap();

        assert_eq!(outcome.accepted, 1);
        assert_eq!(outcome.skipped.len(), 1);
        assert!(
            outcome.skipped[0].contains("beta.yaml"),
            "{:?}",
            outcome.skipped
        );
        assert!(outcome.dir.join("alpha.yaml").is_file());
        assert!(outcome.dir.join("alpha.yaml.minisig").is_file());
        assert!(
            !outcome.dir.join("beta.yaml").exists(),
            "beta must not be written"
        );

        // And what was written loads.
        let set = ProfileSet::load(&home.profiles(), &registry(), &trust_of(&key)).unwrap();
        assert_eq!(set.profiles.len(), 1);
    }

    #[tokio::test]
    async fn a_second_sync_replaces_the_previous_contents_rather_than_merging() {
        let home = Home::new();
        let source = tempfile::tempdir().unwrap();
        let (key, _) = SecretKey::generate().unwrap();
        let write = |name: &str, yaml: &str| {
            std::fs::write(source.path().join(name), yaml).unwrap();
            std::fs::write(
                source.path().join(format!("{name}.minisig")),
                key.sign(yaml.as_bytes(), name).unwrap(),
            )
            .unwrap();
        };
        write("alpha.yaml", "name: alpha\n");
        let spec = RegistrySpec {
            name: "acme".to_string(),
            url: format!("file://{}", source.path().display()),
        };
        sync_registry(&spec, &home.profiles(), &trust_of(&key))
            .await
            .unwrap();

        std::fs::remove_file(source.path().join("alpha.yaml")).unwrap();
        std::fs::remove_file(source.path().join("alpha.yaml.minisig")).unwrap();
        write("beta.yaml", "name: beta\n");
        let outcome = sync_registry(&spec, &home.profiles(), &trust_of(&key))
            .await
            .unwrap();

        assert!(outcome.dir.join("beta.yaml").is_file());
        assert!(
            !outcome.dir.join("alpha.yaml").exists(),
            "a withdrawn profile must not survive a sync"
        );
        // No staging directory is left behind.
        let leftovers: Vec<PathBuf> = std::fs::read_dir(home.profiles().join(REGISTRY_DIR))
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            })
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// A bare git repository holding `files`, as a `git+file://` URL.
    fn bare_repo(dir: &Path, files: &[(&str, String)]) -> String {
        let work = dir.join("work");
        let bare = dir.join("registry.git");
        std::fs::create_dir_all(&work).unwrap();
        let git = |args: &[&str], cwd: &Path| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.com")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.com")
                .output()
                .expect("run git");
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        git(&["init", "--quiet", "--initial-branch=main"], &work);
        for (name, body) in files {
            std::fs::write(work.join(name), body).unwrap();
        }
        // A repository with no files still needs a commit to be cloneable.
        std::fs::write(work.join(".keep"), "").unwrap();
        git(&["add", "-A"], &work);
        git(&["commit", "--quiet", "-m", "profiles"], &work);
        git(
            &[
                "clone",
                "--quiet",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            dir,
        );
        format!("git+file://{}", bare.display())
    }

    #[tokio::test]
    async fn syncing_a_git_registry_reads_the_files_in_the_clone() {
        let home = Home::new();
        let repo = tempfile::tempdir().unwrap();
        let (key, _) = SecretKey::generate().unwrap();
        let yaml = "name: alpha\n".to_string();
        let signature = key.sign(yaml.as_bytes(), "alpha.yaml").unwrap();
        let url = bare_repo(
            repo.path(),
            &[
                ("alpha.yaml", yaml),
                ("alpha.yaml.minisig", signature),
                ("beta.yaml", "name: beta\n".to_string()),
            ],
        );

        let spec = RegistrySpec {
            name: "acme".to_string(),
            url,
        };
        let outcome = sync_registry(&spec, &home.profiles(), &trust_of(&key))
            .await
            .expect("a git registry must sync");

        // The bug this test exists for: the clone was read one directory too
        // high, so every git registry fetched zero files and reported success.
        assert_eq!(outcome.accepted, 1, "the signed profile must be read");
        assert_eq!(outcome.skipped.len(), 1, "{:?}", outcome.skipped);
        assert!(outcome.dir.join("alpha.yaml").is_file());
        assert!(outcome.dir.join("alpha.yaml.minisig").is_file());
        assert!(!outcome.dir.join("beta.yaml").exists());

        let set = ProfileSet::load(&home.profiles(), &registry(), &trust_of(&key)).unwrap();
        assert!(set.profiles.contains_key("alpha"));
    }

    #[tokio::test]
    async fn a_registry_that_fetches_nothing_does_not_wipe_the_one_already_there() {
        let home = Home::new();
        let (key, _) = SecretKey::generate().unwrap();

        // First sync: a good registry with one signed profile.
        let full = tempfile::tempdir().unwrap();
        let yaml = "name: alpha\n".to_string();
        let signature = key.sign(yaml.as_bytes(), "alpha.yaml").unwrap();
        let spec = RegistrySpec {
            name: "acme".to_string(),
            url: bare_repo(
                full.path(),
                &[("alpha.yaml", yaml), ("alpha.yaml.minisig", signature)],
            ),
        };
        sync_registry(&spec, &home.profiles(), &trust_of(&key))
            .await
            .unwrap();
        let target = home.profiles().join(REGISTRY_DIR).join("acme");
        assert!(target.join("alpha.yaml").is_file());

        // Second sync, from a repository holding no profiles at all — a moved
        // branch, a bad URL, a clone that landed somewhere unexpected. It must
        // be an error, and the working set must survive it.
        let empty = tempfile::tempdir().unwrap();
        let empty_spec = RegistrySpec {
            name: "acme".to_string(),
            url: bare_repo(empty.path(), &[]),
        };
        let err = sync_registry(&empty_spec, &home.profiles(), &trust_of(&key))
            .await
            .expect_err("an empty fetch over a populated registry must be refused");
        assert!(err.to_string().contains("keeping what is there"), "{err}");
        assert!(
            target.join("alpha.yaml").is_file(),
            "the previous profile set must survive an empty fetch"
        );

        // And no staging directory is left behind by the refusal.
        let leftovers: Vec<PathBuf> = std::fs::read_dir(home.profiles().join(REGISTRY_DIR))
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            })
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[tokio::test]
    async fn an_empty_fetch_into_an_empty_registry_is_allowed() {
        // The guard is about not destroying something, so a first sync of a
        // genuinely empty registry must still succeed.
        let home = Home::new();
        let (key, _) = SecretKey::generate().unwrap();
        let source = tempfile::tempdir().unwrap();
        let spec = RegistrySpec {
            name: "acme".to_string(),
            url: format!("file://{}", source.path().display()),
        };
        let outcome = sync_registry(&spec, &home.profiles(), &trust_of(&key))
            .await
            .unwrap();
        assert_eq!(outcome.accepted, 0);
    }

    #[tokio::test]
    async fn under_dev_mode_an_unverified_file_is_written_but_not_counted_as_accepted() {
        let home = Home::new();
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("alpha.yaml"), "name: alpha\n").unwrap();
        let spec = RegistrySpec {
            name: "acme".to_string(),
            url: format!("file://{}", source.path().display()),
        };
        let trust = Trust {
            roots: Vec::new(),
            dev_mode: true,
        };

        let outcome = sync_registry(&spec, &home.profiles(), &trust)
            .await
            .unwrap();

        assert_eq!(outcome.accepted, 0, "nothing vouched for it");
        assert_eq!(outcome.unverified, 1);
        assert_eq!(outcome.skipped.len(), 1);
        assert!(
            outcome.dir.join("alpha.yaml").is_file(),
            "it is still written"
        );
    }

    #[tokio::test]
    async fn a_registry_name_that_is_a_path_is_refused() {
        let home = Home::new();
        let spec = RegistrySpec {
            name: "../escape".to_string(),
            url: "file:///tmp".to_string(),
        };
        let err = sync_registry(&spec, &home.profiles(), &Trust::none())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("single path segment"), "{err}");
    }

    #[test]
    fn the_registry_url_schemes_are_the_three_documented_ones() {
        assert_eq!(
            RegistrySource::parse("file:///srv/profiles").unwrap(),
            RegistrySource::Directory(PathBuf::from("/srv/profiles"))
        );
        assert_eq!(
            RegistrySource::parse("https://example.com/profiles/").unwrap(),
            RegistrySource::Https("https://example.com/profiles".to_string())
        );
        assert_eq!(
            RegistrySource::parse("git+https://example.com/p.git").unwrap(),
            RegistrySource::Git("https://example.com/p.git".to_string())
        );
        for bad in [
            "http://example.com",
            "ssh://example.com/p.git",
            "git+ssh://example.com/p.git",
            "/srv/profiles",
            "file://relative",
        ] {
            assert!(RegistrySource::parse(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn an_index_entry_may_not_escape_the_registry_directory() {
        assert_eq!(safe_file_name("profiles/alpha.yaml").unwrap(), "alpha.yaml");
        for bad in [
            "../../daemon.toml",
            "/etc/passwd",
            "../alpha.yaml",
            "alpha.txt",
        ] {
            assert!(safe_file_name(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn the_profiles_table_parses_out_of_a_daemon_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.toml");
        let (_, public) = SecretKey::generate().unwrap();
        std::fs::write(
            &path,
            format!(
                "retention_days = 7\n\
                 [profiles]\n\
                 trust_roots = [\"{}\"]\n\
                 dev_mode = true\n\
                 registries = [{{ name = \"acme\", url = \"https://example.com/p\" }}]\n",
                public.to_line()
            ),
        )
        .unwrap();

        let config = ProfilesConfig::from_daemon_toml(&path).unwrap();
        assert!(config.dev_mode);
        assert_eq!(config.registries.len(), 1);
        assert_eq!(config.registries[0].name, "acme");
        assert_eq!(config.trust_keys().unwrap()[0].key_id(), public.key_id());
    }

    #[test]
    fn a_missing_daemon_toml_is_an_empty_profiles_table_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let config = ProfilesConfig::from_daemon_toml(&dir.path().join("daemon.toml")).unwrap();
        assert_eq!(config, ProfilesConfig::default());
        assert!(!config.dev_mode, "dev_mode must be off unless asked for");
    }

    #[test]
    fn a_malformed_trust_root_is_an_error_at_configuration_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.toml");
        std::fs::write(&path, "[profiles]\ntrust_roots = [\"not a key\"]\n").unwrap();
        let err = ProfilesConfig::from_daemon_toml(&path).unwrap_err();
        assert!(err.to_string().contains("trust_roots"), "{err}");
    }
}
