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
//! # Why the profile is written before the gate runs
//!
//! The gate is the profile's own `unlock.policy`, and the daemon cannot apply a
//! policy for a profile it has never seen. So the order is: write the YAML,
//! wait for the daemon's watcher to report it through `ShowProfile`, run the
//! gate, and only then ask for the master.
//!
//! That ordering means a bootstrap can fail with a file already on disk, so the
//! write is wrapped in a guard that puts the directory back exactly as it found
//! it: a new profile is removed, and a *re-bootstrap* restores the previous
//! contents byte for byte. Both halves matter. A profile whose master was never
//! stored fails at the first `briefcred exec`, a week later, complaining about a
//! missing master — and deleting somebody's working profile because they
//! cancelled the password prompt would be worse still.
//!
//! [`MasterSource`]: briefcred_core::MasterSource

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use briefcred_core::paths::Paths;
use briefcred_core::{Registry, SourceKind};
use briefcred_proto::{Request, Response};
use dialoguer::{Confirm, Input, Password, Select};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// What the interview produced.
///
/// `Debug` is derived and safe to derive: every field is a path or a key name.
/// The master itself is never held here — it goes straight from the prompt to
/// the key store and is dropped.
#[derive(Debug)]
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

    finish(
        paths,
        sock,
        source_kind,
        &registry,
        &name,
        &path,
        &yaml,
        &|key| {
            Password::new()
                .with_prompt(format!("Master credential for `{key}`"))
                .with_confirmation("Confirm", "They did not match")
                .interact()
                .map(Zeroizing::new)
                .map_err(prompt_failed)
        },
    )
    .await
}

/// Everything after the interview: write, gate, collect the master, store it.
///
/// Split from [`run`] so it can be driven by a test. The interview above is
/// `dialoguer` talking to a terminal and cannot be driven without a pty; this
/// half is where every decision that can damage something lives, so this is the
/// half that has to be tested. `ask_master` is injected for the same reason.
#[allow(clippy::too_many_arguments)]
async fn finish(
    paths: &Paths,
    sock: &Path,
    source_kind: SourceKind,
    registry: &Registry,
    name: &str,
    path: &Path,
    yaml: &str,
    ask_master: &dyn Fn(&str) -> Result<Zeroizing<String>>,
) -> Result<Bootstrapped> {
    // Parsed and validated before it is written, so a bootstrap can never
    // leave behind a file the daemon will refuse to load.
    let profile = briefcred_core::Profile::from_yaml_str(yaml)?;
    profile.validate(registry)?;
    let source_key = profile.credentials[0].source_key().to_string();

    // The profile is written *before* the gate, because the gate is the
    // profile's own `unlock.policy` and the daemon cannot apply a policy for a
    // profile it has never seen. Writing first, waiting for the hot reload, and
    // then asking is what makes the check real rather than decorative.
    //
    // Every `?` from here to `commit` puts the profiles directory back exactly
    // as it was. That is the guard's whole job, and it is a guard rather than
    // an unwind at each exit because the first version of this function did the
    // unwinding by hand — and deleted the user's existing profile when a
    // re-bootstrap was abandoned.
    briefcred_core::paths::ensure_private_dir(&paths.profiles_dir())?;
    let written = ProfileFile::write(path, yaml)?;

    gate(sock, name).await?;

    let master = ask_master(&source_key)?;
    if master.is_empty() {
        return Err(Error::Refused(
            "an empty master credential is not usable; nothing was written".to_string(),
        ));
    }

    let location = store_master(paths, source_kind, &source_key, &master)?;

    written.commit();
    Ok(Bootstrapped {
        path: path.to_path_buf(),
        source_key,
        location,
    })
}

/// A profile file that undoes itself unless it is committed.
///
/// A bootstrap has to write the profile before it can ask the daemon about it,
/// and can then fail for half a dozen reasons: a cancelled Touch ID prompt, a
/// mistyped confirmation, an empty master, a key store that refused, a daemon
/// that never loaded the file. Each of those has to leave the profiles
/// directory exactly as it found it — which for a *new* profile means removing
/// the file, and for a **re-bootstrap of an existing one means putting the old
/// contents back**. Deleting a user's working profile because they changed
/// their mind at the password prompt is the worst thing this command could do.
struct ProfileFile {
    path: PathBuf,
    /// What was there before, or `None` if the file is new.
    previous: Option<Vec<u8>>,
    committed: bool,
}

impl ProfileFile {
    /// Write `yaml` to `path`, remembering whatever was there.
    fn write(path: &Path, yaml: &str) -> Result<ProfileFile> {
        let previous = match std::fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(Error::io("read", path, err)),
        };
        std::fs::write(path, yaml).map_err(|e| Error::io("write", path, e))?;
        Ok(ProfileFile {
            path: path.to_path_buf(),
            previous,
            committed: false,
        })
    }

    /// Keep the new contents.
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for ProfileFile {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let restored = match &self.previous {
            Some(bytes) => std::fs::write(&self.path, bytes),
            None => match std::fs::remove_file(&self.path) {
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                other => other,
            },
        };
        if let Err(err) = restored {
            // Nothing useful to return to from a `Drop`, and this is the one
            // case where the user has to be told loudly: their profile may be
            // in a state neither they nor briefcred chose.
            eprintln!(
                "briefcred: could not restore {} after an abandoned bootstrap: {err}",
                self.path.display()
            );
        }
    }
}

/// How long to wait for the daemon's profile watcher to pick the file up.
///
/// The watcher debounces for 250 ms, so this is an order of magnitude more
/// than the happy path needs and still short enough that a user does not
/// wonder whether it has hung.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(3);

/// Wait for the daemon to see the new profile, then run its unlock gate.
///
/// Both halves have to succeed. A profile the daemon never loaded cannot have
/// its policy applied, and a gate that was not satisfied means the master must
/// not be collected — those are the two ways this check could quietly become a
/// no-op, which is exactly what it did in the first version of this command.
async fn gate(sock: &Path, profile: &str) -> Result<()> {
    let mut connection = match crate::client::Connection::open(sock).await {
        Ok(connection) => connection,
        // The daemon being down does not stop somebody setting a profile up;
        // it stops them using it, which they find out at the first exec. This
        // is the one case where the gate is skipped, and it says so out loud.
        Err(Error::NotRunning) => {
            eprintln!(
                "briefcred: the daemon is not running, so presence was not checked; \
                 the profile's unlock policy will apply from the first `briefcred exec`"
            );
            return Ok(());
        }
        Err(err) => return Err(err),
    };

    wait_for_profile(&mut connection, profile).await?;

    match connection
        .send(Request::Unlock {
            profile: profile.to_string(),
            client_headless: briefcred_core::session_env::is_headless(),
        })
        .await?
    {
        Response::Unlocked { .. } => Ok(()),
        Response::Locked { reason, message } => Err(Error::Locked { reason, message }),
        Response::Error { message } => Err(Error::Refused(message)),
        other => Err(Error::Unexpected(format!("{other:?}"))),
    }
}

/// Poll `ShowProfile` until the daemon has loaded the file that was just written.
async fn wait_for_profile(connection: &mut crate::client::Connection, profile: &str) -> Result<()> {
    let deadline = Instant::now() + RELOAD_TIMEOUT;
    let mut last;
    loop {
        match connection
            .send(Request::ShowProfile {
                name: profile.to_string(),
            })
            .await?
        {
            Response::Profile { .. } => return Ok(()),
            // The expected answer while the watcher's debounce is still
            // running; kept so the timeout can quote the daemon's own words.
            Response::Error { message } => last = message,
            other => return Err(Error::Unexpected(format!("{other:?}"))),
        }
        if Instant::now() >= deadline {
            return Err(Error::Refused(format!(
                "the daemon did not load the new profile within {}s ({last}); \
                 nothing was written",
                RELOAD_TIMEOUT.as_secs()
            )));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
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
        .items(sslmodes)
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
    use briefcred_proto::{read_frame, write_frame};

    /// A stub daemon on a real socket, answering each request from a script.
    ///
    /// The gate's whole contract is "what did the daemon say, and what did the
    /// CLI do about it", so the tests drive it with a daemon that says exactly
    /// what the case under test needs.
    async fn stub_daemon(
        sock: std::path::PathBuf,
        replies: Vec<Response>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            for reply in replies {
                match read_frame::<_, Request>(&mut stream).await {
                    Ok(Some(_)) => {}
                    _ => return,
                }
                if write_frame(&mut stream, &reply).await.is_err() {
                    return;
                }
            }
        })
    }

    /// A layout rooted at `dir`, so a test never touches real directories.
    fn test_paths(dir: &Path) -> Paths {
        Paths::resolve(briefcred_core::paths::Platform::Linux, &|key| {
            (key == briefcred_core::paths::HOME_ENV).then(|| dir.as_os_str().to_os_string())
        })
        .unwrap()
    }

    /// A valid `postgres-dynamic` profile document.
    fn valid_yaml(name: &str) -> String {
        render_profile(
            name,
            "",
            briefcred_core::minters::postgres::KIND,
            &[
                ("host".into(), "127.0.0.1".into()),
                ("port".into(), "5432".into()),
                ("dbname".into(), "app".into()),
                ("user".into(), "briefcred_master".into()),
                ("sslmode".into(), "require".into()),
            ],
        )
    }

    /// A daemon that reports the profile as loaded and then refuses the unlock,
    /// which is the cancelled-Touch-ID path.
    async fn refusing_daemon(sock: &Path) -> tokio::task::JoinHandle<()> {
        stub_daemon(
            sock.to_path_buf(),
            vec![
                Response::Profile {
                    profile: briefcred_proto::ProfileSummary {
                        name: "db-ro".into(),
                        description: None,
                        unlock_policy: "biometric".into(),
                        unlock_cache_secs: 300,
                        credentials: Vec::new(),
                    },
                },
                Response::Locked {
                    reason: "cancelled".into(),
                    message: "the unlock prompt was cancelled".into(),
                },
            ],
        )
        .await
    }

    /// The master prompt, for a test that should never reach it.
    fn never_asked(_key: &str) -> Result<Zeroizing<String>> {
        panic!("the master must not be asked for after the gate refused")
    }

    #[tokio::test]
    async fn an_aborted_bootstrap_of_a_new_profile_leaves_no_file_behind() {
        let home = tempfile::tempdir().unwrap();
        let paths = test_paths(home.path());
        briefcred_core::paths::ensure_private_dir(&paths.profiles_dir()).unwrap();
        let sock = home.path().join("sock");
        let path = paths.profiles_dir().join("db-ro.yaml");

        let daemon = refusing_daemon(&sock).await;
        let err = finish(
            &paths,
            &sock,
            SourceKind::File,
            &Registry::discover(),
            "db-ro",
            &path,
            &valid_yaml("db-ro"),
            &never_asked,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, Error::Locked { .. }), "{err}");
        assert!(
            !path.exists(),
            "a bootstrap that did not finish must not leave a profile behind"
        );
        daemon.abort();
    }

    #[tokio::test]
    async fn an_aborted_re_bootstrap_restores_the_existing_profile_byte_for_byte() {
        // The regression this test exists for: the first version of `finish`
        // removed the file on any failure, so abandoning a *re*-bootstrap —
        // cancelling the Touch ID prompt, mistyping the confirmation — deleted
        // the user's working profile while reporting "nothing was written".
        let home = tempfile::tempdir().unwrap();
        let paths = test_paths(home.path());
        briefcred_core::paths::ensure_private_dir(&paths.profiles_dir()).unwrap();
        let sock = home.path().join("sock");
        let path = paths.profiles_dir().join("db-ro.yaml");

        let original = "name: db-ro\ndescription: the one that already worked\n";
        std::fs::write(&path, original).unwrap();

        let daemon = refusing_daemon(&sock).await;
        let err = finish(
            &paths,
            &sock,
            SourceKind::File,
            &Registry::discover(),
            "db-ro",
            &path,
            &valid_yaml("db-ro"),
            &never_asked,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, Error::Locked { .. }), "{err}");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            original,
            "an abandoned re-bootstrap must leave the previous profile exactly as it was"
        );
        daemon.abort();
    }

    #[tokio::test]
    async fn every_later_failure_also_restores_the_previous_profile() {
        // The gate is not the only way out. An empty master and a key store
        // that refuses both happen after the write, and both used to delete.
        let original = "name: db-ro\ndescription: the one that already worked\n";

        for (label, source_kind, master) in [
            ("an empty master", SourceKind::File, ""),
            // `env` is read-only, so `store_master` refuses: the last failure
            // point before the commit.
            ("a refusing key store", SourceKind::Env, "s3cret"),
        ] {
            let home = tempfile::tempdir().unwrap();
            let paths = test_paths(home.path());
            briefcred_core::paths::ensure_private_dir(&paths.profiles_dir()).unwrap();
            let sock = home.path().join("sock");
            let path = paths.profiles_dir().join("db-ro.yaml");
            std::fs::write(&path, original).unwrap();

            let daemon = stub_daemon(
                sock.clone(),
                vec![
                    Response::Profile {
                        profile: briefcred_proto::ProfileSummary {
                            name: "db-ro".into(),
                            description: None,
                            unlock_policy: "none".into(),
                            unlock_cache_secs: 0,
                            credentials: Vec::new(),
                        },
                    },
                    Response::Unlocked {
                        profile: "db-ro".into(),
                    },
                ],
            )
            .await;

            let err = finish(
                &paths,
                &sock,
                source_kind,
                &Registry::discover(),
                "db-ro",
                &path,
                &valid_yaml("db-ro"),
                &|_| Ok(Zeroizing::new(master.to_string())),
            )
            .await
            .unwrap_err();

            assert!(err.to_string().len() > 1, "{label}: {err}");
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                original,
                "{label} must leave the previous profile exactly as it was"
            );
            daemon.abort();
        }
    }

    #[tokio::test]
    async fn a_bootstrap_that_finishes_keeps_the_new_profile_and_stores_the_master() {
        let home = tempfile::tempdir().unwrap();
        let paths = test_paths(home.path());
        briefcred_core::paths::ensure_private_dir(&paths.profiles_dir()).unwrap();
        let sock = home.path().join("sock");
        let path = paths.profiles_dir().join("db-ro.yaml");
        std::fs::write(&path, "name: db-ro\n").unwrap();

        let daemon = stub_daemon(
            sock.clone(),
            vec![
                Response::Profile {
                    profile: briefcred_proto::ProfileSummary {
                        name: "db-ro".into(),
                        description: None,
                        unlock_policy: "none".into(),
                        unlock_cache_secs: 0,
                        credentials: Vec::new(),
                    },
                },
                Response::Unlocked {
                    profile: "db-ro".into(),
                },
            ],
        )
        .await;

        let yaml = valid_yaml("db-ro");
        let done = finish(
            &paths,
            &sock,
            SourceKind::File,
            &Registry::discover(),
            "db-ro",
            &path,
            &yaml,
            &|_| Ok(Zeroizing::new("s3cret".to_string())),
        )
        .await
        .unwrap();

        assert_eq!(done.source_key, "db");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            yaml,
            "a committed bootstrap keeps the new profile"
        );
        assert_eq!(
            std::fs::read_to_string(paths.secrets_dir().join("db")).unwrap(),
            "s3cret"
        );
        daemon.abort();
    }

    #[test]
    fn the_guard_restores_on_drop_and_keeps_on_commit() {
        let dir = tempfile::tempdir().unwrap();

        // New file, dropped: removed.
        let fresh = dir.path().join("fresh.yaml");
        drop(ProfileFile::write(&fresh, "name: fresh\n").unwrap());
        assert!(!fresh.exists());

        // Existing file, dropped: restored.
        let existing = dir.path().join("existing.yaml");
        std::fs::write(&existing, "name: before\n").unwrap();
        drop(ProfileFile::write(&existing, "name: after\n").unwrap());
        assert_eq!(
            std::fs::read_to_string(&existing).unwrap(),
            "name: before\n"
        );

        // Committed: kept.
        ProfileFile::write(&existing, "name: after\n")
            .unwrap()
            .commit();
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "name: after\n");
    }

    #[tokio::test]
    async fn a_profile_the_daemon_never_loads_aborts_rather_than_asking_for_the_master() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sock");
        // Every `ShowProfile` answers "no such profile", so the poll times out.
        let daemon = stub_daemon(
            sock.clone(),
            (0..64)
                .map(|_| Response::Error {
                    message: "no profile `db-ro`".to_string(),
                })
                .collect(),
        )
        .await;

        let err = gate(&sock, "db-ro").await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("did not load the new profile"), "{text}");
        assert!(
            text.contains("no profile `db-ro`"),
            "the daemon's own words: {text}"
        );
        assert!(text.contains("nothing was written"), "{text}");
        daemon.abort();
    }

    #[tokio::test]
    async fn a_loaded_profile_and_a_satisfied_gate_is_the_only_way_through() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sock");
        let daemon = stub_daemon(
            sock.clone(),
            vec![
                Response::Profile {
                    profile: briefcred_proto::ProfileSummary {
                        name: "db-ro".into(),
                        description: None,
                        unlock_policy: "none".into(),
                        unlock_cache_secs: 0,
                        credentials: Vec::new(),
                    },
                },
                Response::Unlocked {
                    profile: "db-ro".into(),
                },
            ],
        )
        .await;

        gate(&sock, "db-ro").await.unwrap();
        daemon.abort();
    }

    #[tokio::test]
    async fn a_daemon_that_is_not_running_skips_the_gate_and_says_so() {
        // The one documented case where the check is skipped: setting a profile
        // up must not require the daemon to be running.
        gate(Path::new("/nonexistent/sock"), "db-ro").await.unwrap();
    }

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
