//! `briefcred profile keygen`, `sign`, `verify`, and `sync`.
//!
//! The three key commands are deliberately thin: they are minisign, and the
//! files they read and write are files `minisign` itself can read and write.
//! Somebody publishing profiles can sign with whichever of the two tools they
//! have, and an operator can list a briefcred key as a trust root for their
//! existing release tooling.
//!
//! `sync` is the one that matters for safety. It fetches each registry named
//! in `daemon.toml` into `profiles/registry/<name>/` and refuses to write a
//! file that no trust root vouches for, so the daemon's own check at load time
//! is the second of two rather than the only one.

use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use briefcred_core::distribution::{self, ProfilesConfig, RegistrySpec};
use briefcred_core::minisign::{PublicKey, SecretKey};
use briefcred_core::paths::Paths;

use crate::error::{Error, Result};

/// The secret half of a signing key, inside the directory `keygen` was given.
pub const SECRET_KEY_FILE: &str = "briefcred.key";

/// The public half.
pub const PUBLIC_KEY_FILE: &str = "briefcred.pub";

/// Generate a signing key pair into `out`.
///
/// The secret key is written `0600` and **without a password**. briefcred's
/// signing happens in release pipelines, where there is nobody to prompt; the
/// protection on the file is the filesystem's, and the command says so rather
/// than leaving the user to discover it.
pub fn keygen(out: &Path) -> Result<()> {
    std::fs::create_dir_all(out).map_err(|source| Error::Io {
        action: "create",
        path: out.to_path_buf(),
        source,
    })?;
    let secret_path = out.join(SECRET_KEY_FILE);
    let public_path = out.join(PUBLIC_KEY_FILE);
    // Refused rather than overwritten: a key file replaced by accident
    // invalidates every signature ever made with it, and there is no undo.
    for path in [&secret_path, &public_path] {
        if path.exists() {
            return Err(Error::Refused(format!(
                "{} already exists; move it aside first",
                path.display()
            )));
        }
    }

    let (secret, public) = SecretKey::generate()?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&secret_path)
        .map_err(|source| Error::Io {
            action: "create",
            path: secret_path.clone(),
            source,
        })?;
    use std::io::Write as _;
    file.write_all(secret.to_file().as_bytes())
        .map_err(|source| Error::Io {
            action: "write",
            path: secret_path.clone(),
            source,
        })?;
    std::fs::write(&public_path, public.to_file()).map_err(|source| Error::Io {
        action: "write",
        path: public_path.clone(),
        source,
    })?;

    println!("briefcred profile keygen");
    println!(
        "  secret     {} (mode 0600, no password)",
        secret_path.display()
    );
    println!("  public     {}", public_path.display());
    println!("  key id     {}", public.key_id());
    println!();
    println!("add this line to `trust_roots` in daemon.toml:");
    println!("  {}", public.to_line());
    Ok(())
}

/// Sign `file`, writing `<file>.minisig` beside it.
pub fn sign(file: &Path, key_path: &Path) -> Result<()> {
    let secret = SecretKey::parse_file(&read_to_string(key_path)?)?;
    let content = std::fs::read(file).map_err(|source| Error::Io {
        action: "read",
        path: file.to_path_buf(),
        source,
    })?;

    // minisign's own trusted-comment convention: the time it was signed and
    // the name of what was signed. Both are covered by the global signature,
    // so a signature moved onto another file names the file it was made for.
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let signature = secret.sign(&content, &format!("timestamp:{now}\tfile:{name}"))?;

    let out = signature_path(file);
    std::fs::write(&out, signature).map_err(|source| Error::Io {
        action: "write",
        path: out.clone(),
        source,
    })?;
    println!("signed {} with key {}", file.display(), secret.key_id());
    println!("  wrote {}", out.display());
    Ok(())
}

/// Verify `file` against `<file>.minisig` and the public key at `key_path`.
pub fn verify(file: &Path, key_path: &Path) -> Result<()> {
    let public = PublicKey::parse_file(&read_to_string(key_path)?)?;
    let content = std::fs::read(file).map_err(|source| Error::Io {
        action: "read",
        path: file.to_path_buf(),
        source,
    })?;
    let signature_path = signature_path(file);
    let signature = read_to_string(&signature_path)?;

    let parsed = briefcred_core::minisign::Signature::parse(&signature)?;
    parsed.verify(&content, &public)?;
    println!("{}: signature is valid", file.display());
    println!("  key id     {}", public.key_id());
    println!("  comment    {}", parsed.trusted_comment());
    Ok(())
}

/// Fetch every registry in `daemon.toml` and report what was accepted.
///
/// Returns the process exit code: non-zero when any registry failed outright
/// or any file was skipped, so a pipeline that syncs a registry notices that
/// half of it did not arrive.
pub async fn sync(paths: &Paths) -> Result<u8> {
    let config = ProfilesConfig::from_daemon_toml(&paths.daemon_toml())?;
    if config.registries.is_empty() {
        println!("no registries configured; add `[profiles] registries` to daemon.toml");
        return Ok(0);
    }
    let trust = config.trust()?;
    if trust.roots.is_empty() && !trust.dev_mode {
        return Err(Error::Refused(
            "no `profiles.trust_roots` in daemon.toml, so nothing a registry serves could be \
             trusted; add a trust root (`briefcred profile keygen` prints one)"
                .to_string(),
        ));
    }
    if trust.dev_mode {
        println!("!! dev_mode is on: unverified profiles will be accepted");
    }

    println!("briefcred profile sync");
    let mut problems = 0u8;
    for spec in &config.registries {
        problems = problems.saturating_add(sync_one(spec, paths, &trust).await);
    }
    println!();
    println!("the daemon reloads profiles by itself; 'briefcred profiles' will show them");
    Ok(u8::from(problems > 0))
}

/// Sync one registry, printing its result. Returns 1 if anything went wrong.
async fn sync_one(
    spec: &RegistrySpec,
    paths: &Paths,
    trust: &briefcred_core::distribution::Trust,
) -> u8 {
    match distribution::sync_registry(spec, &paths.profiles_dir(), trust).await {
        Ok(outcome) => {
            println!(
                "  {:<16} {} profile(s) into {}",
                outcome.name,
                outcome.accepted,
                outcome.dir.display()
            );
            for skipped in &outcome.skipped {
                println!("    ! {skipped}");
            }
            u8::from(!outcome.skipped.is_empty())
        }
        Err(err) => {
            // One unreachable registry must not stop the others: a laptop off
            // the network still wants the registry on its own disk.
            println!("  {:<16} failed: {err}", spec.name);
            1
        }
    }
}

/// `<file>.minisig`, which is minisign's own naming.
fn signature_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_os_string();
    name.push(".minisig");
    PathBuf::from(name)
}

fn read_to_string(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|source| Error::Io {
        action: "read",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use briefcred_core::paths::Platform;

    /// A `Paths` rooted at a temporary home, the way every test does it.
    fn paths_for(home: &Path) -> Paths {
        let home = home.to_path_buf();
        Paths::resolve(Platform::MacOs, &move |key| {
            (key == briefcred_core::paths::HOME_ENV)
                .then(|| std::ffi::OsString::from(home.as_os_str()))
        })
        .unwrap()
    }

    #[test]
    fn keygen_writes_a_private_secret_key_and_a_usable_public_one() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        keygen(dir.path()).unwrap();

        let secret_path = dir.path().join(SECRET_KEY_FILE);
        let mode = std::fs::metadata(&secret_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the signing key must not be readable");

        let secret =
            SecretKey::parse_file(&std::fs::read_to_string(&secret_path).unwrap()).unwrap();
        let public = PublicKey::parse_file(
            &std::fs::read_to_string(dir.path().join(PUBLIC_KEY_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(secret.key_id(), public.key_id());
    }

    #[test]
    fn keygen_refuses_to_overwrite_an_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        keygen(dir.path()).unwrap();
        let err = keygen(dir.path()).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }

    #[test]
    fn sign_then_verify_round_trips_through_the_files_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        keygen(dir.path()).unwrap();
        let profile = dir.path().join("alpha.yaml");
        std::fs::write(&profile, "name: alpha\n").unwrap();

        sign(&profile, &dir.path().join(SECRET_KEY_FILE)).unwrap();
        assert!(dir.path().join("alpha.yaml.minisig").is_file());
        verify(&profile, &dir.path().join(PUBLIC_KEY_FILE)).unwrap();
    }

    #[test]
    fn verify_fails_once_the_file_has_been_edited() {
        let dir = tempfile::tempdir().unwrap();
        keygen(dir.path()).unwrap();
        let profile = dir.path().join("alpha.yaml");
        std::fs::write(&profile, "name: alpha\n").unwrap();
        sign(&profile, &dir.path().join(SECRET_KEY_FILE)).unwrap();

        std::fs::write(&profile, "name: alpha\ndescription: pwned\n").unwrap();
        let err = verify(&profile, &dir.path().join(PUBLIC_KEY_FILE)).unwrap_err();
        assert!(err.to_string().contains("does not match the file"), "{err}");
    }

    #[test]
    fn verify_fails_against_a_different_key() {
        let dir = tempfile::tempdir().unwrap();
        let ours = dir.path().join("ours");
        let theirs = dir.path().join("theirs");
        keygen(&ours).unwrap();
        keygen(&theirs).unwrap();
        let profile = dir.path().join("alpha.yaml");
        std::fs::write(&profile, "name: alpha\n").unwrap();
        sign(&profile, &ours.join(SECRET_KEY_FILE)).unwrap();

        let err = verify(&profile, &theirs.join(PUBLIC_KEY_FILE)).unwrap_err();
        assert!(err.to_string().contains("checked against key"), "{err}");
    }

    #[test]
    fn the_trusted_comment_names_the_file_that_was_signed() {
        let dir = tempfile::tempdir().unwrap();
        keygen(dir.path()).unwrap();
        let profile = dir.path().join("alpha.yaml");
        std::fs::write(&profile, "name: alpha\n").unwrap();
        sign(&profile, &dir.path().join(SECRET_KEY_FILE)).unwrap();

        let text = std::fs::read_to_string(dir.path().join("alpha.yaml.minisig")).unwrap();
        let signature = briefcred_core::minisign::Signature::parse(&text).unwrap();
        assert!(
            signature.trusted_comment().contains("file:alpha.yaml"),
            "{}",
            signature.trusted_comment()
        );
    }

    #[test]
    fn the_signature_path_is_the_file_plus_minisig() {
        assert_eq!(
            signature_path(Path::new("/tmp/a.yaml")),
            PathBuf::from("/tmp/a.yaml.minisig")
        );
    }

    #[tokio::test]
    async fn sync_without_a_trust_root_refuses_rather_than_fetching() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join("daemon.toml"),
            "[profiles]\nregistries = [{ name = \"acme\", url = \"file:///nowhere\" }]\n",
        )
        .unwrap();
        let paths = paths_for(home.path());
        let err = sync(&paths).await.unwrap_err();
        assert!(err.to_string().contains("trust_roots"), "{err}");
    }

    #[tokio::test]
    async fn sync_with_no_registries_says_so_and_succeeds() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_for(home.path());
        assert_eq!(sync(&paths).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn sync_fetches_a_file_registry_and_reports_a_skipped_file() {
        let home = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        keygen(keys.path()).unwrap();
        let public = PublicKey::parse_file(
            &std::fs::read_to_string(keys.path().join(PUBLIC_KEY_FILE)).unwrap(),
        )
        .unwrap();

        let signed = source.path().join("alpha.yaml");
        std::fs::write(&signed, "name: alpha\n").unwrap();
        sign(&signed, &keys.path().join(SECRET_KEY_FILE)).unwrap();
        std::fs::write(source.path().join("beta.yaml"), "name: beta\n").unwrap();

        std::fs::write(
            home.path().join("daemon.toml"),
            format!(
                "[profiles]\ntrust_roots = [\"{}\"]\n\
                 registries = [{{ name = \"acme\", url = \"file://{}\" }}]\n",
                public.to_line(),
                source.path().display()
            ),
        )
        .unwrap();

        let paths = paths_for(home.path());
        // Non-zero: one file was skipped, and a pipeline has to notice.
        assert_eq!(sync(&paths).await.unwrap(), 1);

        let fetched = paths.profiles_dir().join("registry").join("acme");
        assert!(fetched.join("alpha.yaml").is_file());
        assert!(fetched.join("alpha.yaml.minisig").is_file());
        assert!(!fetched.join("beta.yaml").exists());
    }
}
