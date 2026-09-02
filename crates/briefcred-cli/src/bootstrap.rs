//! `briefcred profile bootstrap`: write a profile, then store its master.
//!
//! # Why the master does not cross the socket
//!
//! It would be easy to add a `StoreMaster { key, value }` request and have the
//! daemon write the keychain item. briefcred does not, for one reason: the
//! daemon's whole job is to hold master credentials for the *shortest* time
//! that lets the work happen, and a write path would mean a master arriving in
//! the daemon's address space for a task the daemon has no part in. The
//! keychain is reachable by the same user from either process, so routing the
//! write through the daemon buys nothing and costs a copy of the secret in the
//! most valuable process on the machine.
//!
//! So the CLI writes it directly to the platform [`MasterSource`], and asks the
//! daemon only for the thing the daemon *is* the authority on: whether the user
//! has proved presence for this profile. That is `Request::Unlock`, which
//! fetches nothing and retains nothing.
//!
//! [`MasterSource`]: briefcred_core::MasterSource

use std::path::{Path, PathBuf};

use briefcred_core::paths::Paths;
use briefcred_core::{Registry, SourceKind};
use briefcred_proto::{Request, Response};
use dialoguer::{Confirm, Input, Password, Select};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// What the interview produced.
pub struct Bootstrapped {
    /// The profile file that was written.
    pub path: PathBuf,
    /// The master-source key the master was stored under.
    pub source_key: String,
    /// Where that source keeps it, for the closing message.
    pub location: String,
}

/// Run the interview and write everything it collected.
pub async fn run(paths: &Paths, sock: &Path, source_kind: SourceKind) -> Result<Bootstrapped> {
    let registry = Registry::discover();
    let kinds = registry.kinds();
    if kinds.is_empty() {
        return Err(Error::Refused(
            "this build has no minters registered, so there is nothing to bootstrap".to_string(),
        ));
    }

    let name: String = Input::new()
        .with_prompt("Profile name")
        .validate_with(|input: &String| validate_name(input))
        .interact_text()
        .map_err(prompt_failed)?;

    let path = paths.profiles_dir().join(format!("{name}.yaml"));
    if path.exists()
        && !Confirm::new()
            .with_prompt(format!("{} exists. Overwrite it?", path.display()))
            .default(false)
            .interact()
            .map_err(prompt_failed)?
    {
        return Err(Error::Refused("nothing was written".to_string()));
    }

    let kind = kinds[Select::new()
        .with_prompt("Minter kind")
        .items(&kinds)
        .default(0)
        .interact()
        .map_err(prompt_failed)?];

    let description: String = Input::new()
        .with_prompt("Description (optional)")
        .allow_empty(true)
        .interact_text()
        .map_err(prompt_failed)?;

    let config = ask_config(kind)?;
    let yaml = render_profile(&name, &description, kind, &config);

    // Parsed and validated before it is written, so a bootstrap can never
    // leave behind a file the daemon will refuse to load.
    let profile = briefcred_core::Profile::from_yaml_str(&yaml)?;
    profile.validate(&registry)?;
    let source_key = profile.credentials[0].source_key().to_string();

    // The gate before the secret is asked for, so a cancelled prompt means the
    // master was never typed rather than typed and then thrown away.
    unlock(sock, &name).await?;

    let master = Zeroizing::new(
        Password::new()
            .with_prompt(format!("Master credential for `{source_key}`"))
            .with_confirmation("Confirm", "They did not match")
            .interact()
            .map_err(prompt_failed)?,
    );
    if master.is_empty() {
        return Err(Error::Refused(
            "an empty master credential is not usable; nothing was written".to_string(),
        ));
    }

    briefcred_core::paths::ensure_private_dir(&paths.profiles_dir())?;
    std::fs::write(&path, &yaml).map_err(|e| Error::io("write", &path, e))?;

    let location = store_master(paths, source_kind, &source_key, &master)?;
    Ok(Bootstrapped {
        path,
        source_key,
        location,
    })
}

/// Ask the daemon to run the profile's unlock gate, and nothing else.
///
/// A profile that has just been described does not exist to the daemon yet, so
/// a `no such profile` answer here is expected on a first bootstrap and is not
/// a reason to refuse: the presence check is best effort for a profile the
/// daemon has never seen.
async fn unlock(sock: &Path, profile: &str) -> Result<()> {
    let request = Request::Unlock {
        profile: profile.to_string(),
        client_headless: briefcred_core::session_env::is_headless(),
    };
    match crate::client::request(sock, request).await {
        Ok(Response::Unlocked { .. }) | Ok(Response::Error { .. }) => Ok(()),
        Ok(Response::Locked { reason, message }) => Err(Error::Locked { reason, message }),
        Ok(other) => Err(Error::Unexpected(format!("{other:?}"))),
        // The daemon being down does not stop somebody setting a profile up;
        // it stops them using it, which they will find out at the first exec.
        Err(Error::NotRunning) => {
            eprintln!("briefcred: the daemon is not running, so presence was not checked");
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Write the master to the platform's own store.
fn store_master(
    paths: &Paths,
    kind: SourceKind,
    key: &str,
    master: &Zeroizing<String>,
) -> Result<String> {
    match kind {
        SourceKind::File => {
            let source = briefcred_core::source::FileSource::new(paths.secrets_dir());
            source.put(key, master)?;
            Ok(source.path(key).display().to_string())
        }
        #[cfg(target_os = "macos")]
        SourceKind::Keychain => {
            let source = briefcred_core::source::KeychainSource::new(
                briefcred_core::source::KEYCHAIN_SERVICE,
            );
            source.put(key, master)?;
            Ok(format!(
                "login keychain, service {}",
                briefcred_core::source::KEYCHAIN_SERVICE
            ))
        }
        #[cfg(not(target_os = "macos"))]
        SourceKind::Keychain => Err(Error::Refused(
            "the keychain master source needs macOS; set `master_source = \"file\"` in daemon.toml"
                .to_string(),
        )),
        // Refusing rather than writing: an environment variable is not
        // somewhere a value can be *put*, and pretending otherwise would leave
        // the user believing the master had been stored.
        SourceKind::Env => Err(Error::Refused(
            "the environment master source is read-only; set the variable yourself, or switch \
             `master_source` in daemon.toml"
                .to_string(),
        )),
    }
}

/// The kind-specific questions.
///
/// A `match` on the kind rather than something the registry drives: a minter's
/// config schema is a Rust type, and asking it to describe itself for a prompt
/// would be a serialisation framework nobody has asked for yet. A kind with no
/// interview gets an empty config and the user edits the file, which is stated
/// rather than silent.
fn ask_config(kind: &str) -> Result<Vec<(String, String)>> {
    if kind != briefcred_core::minters::postgres::KIND {
        println!(
            "`{kind}` has no guided setup yet; the profile will be written with an empty \
             `config:` block for you to fill in."
        );
        return Ok(Vec::new());
    }

    let host: String = Input::new()
        .with_prompt("Database host")
        .default("127.0.0.1".to_string())
        .interact_text()
        .map_err(prompt_failed)?;
    let port: u16 = Input::new()
        .with_prompt("Port")
        .default(5432u16)
        .interact_text()
        .map_err(prompt_failed)?;
    let dbname: String = Input::new()
        .with_prompt("Database name")
        .interact_text()
        .map_err(prompt_failed)?;
    let user: String = Input::new()
        .with_prompt("Master role")
        .interact_text()
        .map_err(prompt_failed)?;
    let sslmodes = ["require", "prefer", "disable"];
    let sslmode = sslmodes[Select::new()
        .with_prompt("TLS")
        .items(&sslmodes)
        .default(0)
        .interact()
        .map_err(prompt_failed)?];

    Ok(vec![
        ("host".into(), host),
        ("port".into(), port.to_string()),
        ("dbname".into(), dbname),
        ("user".into(), user),
        ("sslmode".into(), sslmode.to_string()),
    ])
}

/// Build the profile document.
///
/// Emitted as text rather than through `serde_yaml` so the file a user opens
/// afterwards has the comments that tell them what to change. A generated
/// config with no comments is one nobody edits.
pub fn render_profile(
    name: &str,
    description: &str,
    kind: &str,
    config: &[(String, String)],
) -> String {
    let mut yaml = format!("name: {name}\n");
    if !description.trim().is_empty() {
        yaml.push_str(&format!("description: {}\n", description.trim()));
    }
    yaml.push_str("unlock:\n  policy: biometric\n");
    yaml.push_str("credentials:\n");
    yaml.push_str(&format!("  - name: db\n    kind: {kind}\n"));
    yaml.push_str("    ttl_secs: 900\n");
    yaml.push_str("    config:\n");
    for (key, value) in config {
        yaml.push_str(&format!("      {key}: {value}\n"));
    }
    if config.is_empty() {
        yaml.push_str("      # fill this in for the `");
        yaml.push_str(kind);
        yaml.push_str("` minter\n");
    }
    if kind == briefcred_core::minters::postgres::KIND {
        yaml.push_str("      role_template:\n        grants:\n");
        yaml.push_str("          - privileges: [SELECT]\n");
        yaml.push_str("            on: ALL TABLES IN SCHEMA public\n");
    }
    yaml.push_str("# Every argument the subprocess is given must match one of these\n");
    yaml.push_str("# patterns, and argv[0] must be one of these names. Both empty means\n");
    yaml.push_str("# `any`, which is worth narrowing before an agent uses this profile.\n");
    yaml.push_str("exec:\n  allow_argv0: []\n  allow_args: []\n");
    yaml.push_str("env:\n");
    if kind == briefcred_core::minters::postgres::KIND {
        for field in ["PGUSER", "PGPASSWORD", "PGHOST", "PGPORT", "PGDATABASE"] {
            yaml.push_str(&format!("  {field}: ${{minted.db.{field}}}\n"));
        }
    }
    yaml
}

/// A profile name has to be a usable filename and a usable master key.
fn validate_name(name: &str) -> std::result::Result<(), String> {
    if name.trim().is_empty() {
        return Err("a profile needs a name".to_string());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("use letters, digits, `-`, and `_` only".to_string());
    }
    Ok(())
}

fn prompt_failed(err: dialoguer::Error) -> Error {
    Error::Refused(format!("nothing was written: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_postgres_profile_loads_and_validates() {
        let yaml = render_profile(
            "db-ro",
            "read-only analytics",
            briefcred_core::minters::postgres::KIND,
            &[
                ("host".into(), "127.0.0.1".into()),
                ("port".into(), "5432".into()),
                ("dbname".into(), "app".into()),
                ("user".into(), "briefcred_master".into()),
                ("sslmode".into(), "require".into()),
            ],
        );
        let profile = briefcred_core::Profile::from_yaml_str(&yaml).unwrap();
        profile.validate(&Registry::discover()).unwrap();

        assert_eq!(profile.name, "db-ro");
        assert_eq!(profile.description.as_deref(), Some("read-only analytics"));
        assert_eq!(profile.credentials.len(), 1);
        assert_eq!(profile.env.len(), 5);
        assert_eq!(
            profile.env.get("PGPASSWORD").map(String::as_str),
            Some("${minted.db.PGPASSWORD}")
        );
    }

    #[test]
    fn a_generated_profile_never_contains_a_secret() {
        // The interview asks for the master last and hands it to the key store
        // rather than to the file. This asserts the shape that makes that true.
        let yaml = render_profile(
            "db-ro",
            "",
            briefcred_core::minters::postgres::KIND,
            &[
                ("host".into(), "db.internal".into()),
                ("port".into(), "5432".into()),
                ("dbname".into(), "app".into()),
                ("user".into(), "briefcred_master".into()),
                ("sslmode".into(), "require".into()),
            ],
        );
        assert!(!yaml.contains("password"), "{yaml}");
        assert!(!yaml.to_lowercase().contains("secret"), "{yaml}");
    }

    #[test]
    fn a_kind_with_no_interview_still_produces_a_loadable_skeleton() {
        let yaml = render_profile("thing", "", "postgres-dynamic", &[]);
        assert!(yaml.contains("# fill this in"), "{yaml}");
        // It parses as a schema even though the minter would reject the empty
        // config, so the user is editing a real file rather than a fragment.
        assert!(briefcred_core::Profile::from_yaml_str(&yaml).is_ok());
    }

    #[test]
    fn a_profile_name_has_to_be_a_usable_filename() {
        assert!(validate_name("db-ro").is_ok());
        assert!(validate_name("db_ro2").is_ok());
        for bad in ["", "  ", "../etc/passwd", "db ro", "db/ro", "db.yaml"] {
            assert!(validate_name(bad).is_err(), "`{bad}` should be refused");
        }
    }

    #[test]
    fn the_environment_source_is_refused_rather_than_silently_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let paths =
            briefcred_core::paths::Paths::resolve(briefcred_core::paths::Platform::Linux, &|key| {
                (key == briefcred_core::paths::HOME_ENV)
                    .then(|| dir.path().as_os_str().to_os_string())
            })
            .unwrap();
        let err = store_master(
            &paths,
            SourceKind::Env,
            "db",
            &Zeroizing::new("s3cret".into()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("read-only"), "{err}");
    }

    #[test]
    fn a_file_master_is_written_where_the_layout_says() {
        let dir = tempfile::tempdir().unwrap();
        let paths =
            briefcred_core::paths::Paths::resolve(briefcred_core::paths::Platform::Linux, &|key| {
                (key == briefcred_core::paths::HOME_ENV)
                    .then(|| dir.path().as_os_str().to_os_string())
            })
            .unwrap();
        let location = store_master(
            &paths,
            SourceKind::File,
            "db",
            &Zeroizing::new("s3cret".into()),
        )
        .unwrap();
        assert!(location.starts_with(&paths.secrets_dir().display().to_string()));
        assert_eq!(
            std::fs::read_to_string(paths.secrets_dir().join("db")).unwrap(),
            "s3cret"
        );
    }
}
