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
//! # Why the questions and the file are separate
//!
//! The interview produces an [`Answers`], and [`render_profile`] turns that
//! into YAML. Nothing in between talks to a terminal. `dialoguer` cannot be
//! driven without a pty, so a renderer reachable only through it would be a
//! renderer nobody tests — and the renderer is where a profile that loads but
//! does nothing (an HTTP credential with no policy, a token no variable
//! exposes) would come from.
//!
//! The interview validates each answer by asking the minter's own validator
//! rather than restating its rules, so "what is a role ARN" has one answer: the
//! one the daemon enforces when it loads the file.
//!
//! [`MasterSource`]: briefcred_core::MasterSource

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use briefcred_core::minters::aws_sts::{self, AwsStsConfig, CallerSource};
use briefcred_core::minters::http::{self, HeaderConfig};
use briefcred_core::minters::postgres::{self, Grant, PostgresConfig, RoleTemplate};
use briefcred_core::minters::postgres_proxy::{self, PgProxyConfig};
use briefcred_core::minters::ssh_cert::{self, SshCertConfig};
use briefcred_core::paths::Paths;
use briefcred_core::policy::METHODS;
use briefcred_core::profile::{UnlockPolicy, DEFAULT_TTL_SECS, DEFAULT_UNLOCK_CACHE_SECS};
use briefcred_core::{Registry, SourceKind};
use briefcred_proto::{Request, Response};
use dialoguer::{Confirm, Input, Password, Select};
use serde::Serialize;
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
    /// The master-source key the master was stored under, or is reused from.
    pub source_key: String,
    /// Where that source keeps it, for the closing message.
    pub location: String,
}

/// Every kind the interview knows how to set up.
///
/// A test asserts this covers [`Registry::discover`], so a new minter cannot be
/// registered without somebody deciding what its questions are.
pub const GUIDED_KINDS: [&str; 7] = [
    http::BEARER_KIND,
    http::HEADER_KIND,
    http::BASIC_KIND,
    postgres::KIND,
    postgres_proxy::KIND,
    aws_sts::KIND,
    ssh_cert::KIND,
];

/// Run the interview and write everything it collected.
pub async fn run(paths: &Paths, sock: &Path, source_kind: SourceKind) -> Result<Bootstrapped> {
    let registry = Registry::discover();
    let (kinds, unguided): (Vec<&'static str>, Vec<&'static str>) = registry
        .kinds()
        .into_iter()
        .partition(|kind| GUIDED_KINDS.contains(kind));
    for kind in &unguided {
        println!(
            "`{kind}` has no guided setup; write its profile by hand (docs/profile-schema.md)."
        );
    }
    if kinds.is_empty() {
        return Err(Error::Refused(
            "this build has no minters the interview can set up, so there is nothing to bootstrap"
                .to_string(),
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

    let answers = interview(&name, kind, paths, source_kind)?;
    let yaml = render_profile(&answers);

    let hint = master_hint(&answers.setup);
    let ask = |key: &str| ask_master(kind, hint, key);
    let master = match answers.master {
        MasterChoice::New => MasterStep::Ask(&ask),
        MasterChoice::Reuse(_) => MasterStep::Reuse,
    };
    finish(
        paths,
        sock,
        source_kind,
        &registry,
        &name,
        &path,
        &yaml,
        master,
    )
    .await
}

/// What [`finish`] does about the master once the gate has passed.
pub enum MasterStep<'a> {
    /// Ask for a new master and store it under the credential's source key.
    ///
    /// Injected rather than called directly so a test can stand in for the
    /// prompt.
    Ask(&'a dyn Fn(&str) -> Result<Zeroizing<String>>),
    /// The profile names a master that is already stored: ask for nothing and
    /// store nothing.
    ///
    /// The gate still runs. It is about whether the *user* is present, not
    /// about the master, and a re-bootstrap that skipped it would be a way to
    /// rewrite a profile without ever proving presence for it.
    Reuse,
}

/// Everything after the interview: write, gate, collect the master, store it.
///
/// Split from [`run`] so it can be driven by a test. The interview above is
/// `dialoguer` talking to a terminal and cannot be driven without a pty; this
/// half is where every decision that can damage something lives, so this is the
/// half that has to be tested. The master prompt is injected for the same
/// reason.
#[allow(clippy::too_many_arguments)]
async fn finish(
    paths: &Paths,
    sock: &Path,
    source_kind: SourceKind,
    registry: &Registry,
    name: &str,
    path: &Path,
    yaml: &str,
    master: MasterStep<'_>,
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

    let location = match master {
        MasterStep::Reuse => format!(
            "{}, reused rather than stored",
            master_location(paths, source_kind, &source_key)
        ),
        MasterStep::Ask(ask_master) => {
            let master = ask_master(&source_key)?;
            if master.is_empty() {
                return Err(Error::Refused(
                    "an empty master credential is not usable; nothing was written".to_string(),
                ));
            }
            store_master(paths, source_kind, &source_key, &master)?
        }
    };

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

/// Where a master filed under `key` lives, for messages.
///
/// Worked out from the layout rather than by opening the source, because
/// nothing here needs the source itself — only the words for where it is.
fn master_location(paths: &Paths, kind: SourceKind, key: &str) -> String {
    match kind {
        SourceKind::File => briefcred_core::source::FileSource::new(paths.secrets_dir())
            .path(key)
            .display()
            .to_string(),
        SourceKind::Keychain => format!(
            "login keychain, service {}",
            briefcred_core::source::KEYCHAIN_SERVICE
        ),
        SourceKind::Env => format!(
            "environment, {}",
            briefcred_core::source::EnvSource::var_name(key)
        ),
    }
}

/// Whether a master is already filed under `key`, where that can be told
/// without reading it.
///
/// `Err` carries why it could not be told. Only the file source can answer:
/// a `stat` says whether the file is there and never opens it. The keychain
/// source exposes one way in, which reads the secret (and may raise an
/// access prompt for it), and reading a master to see whether it exists is
/// exactly what this check must not do. The environment source reads the
/// *daemon's* environment, which this process cannot see.
fn master_exists(
    paths: &Paths,
    kind: SourceKind,
    key: &str,
) -> std::result::Result<bool, &'static str> {
    match kind {
        SourceKind::File => briefcred_core::source::FileSource::new(paths.secrets_dir())
            .path(key)
            .try_exists()
            .map_err(|_| "the secrets directory could not be inspected"),
        SourceKind::Keychain => Err("the keychain can only be asked by reading the master itself"),
        SourceKind::Env => Err("the variable is read from the daemon's environment, not this one"),
    }
}

/// Everything the interview collected, and nothing else.
///
/// Holds no secret, which is what makes it safe to derive `Debug` and to hand
/// to a renderer that writes a file: the master goes from its prompt to the
/// key store inside [`finish`] and never passes through here.
#[derive(Debug, Clone)]
pub struct Answers {
    /// The profile's name, which is also its file name.
    pub name: String,
    /// Free text; empty for none.
    pub description: String,
    /// The credential's name, as `${minted.<credential>.<field>}` names it.
    pub credential: String,
    /// The credential's lifetime.
    pub ttl_secs: u64,
    /// The kind and its `config` block.
    pub setup: Setup,
    /// What the proxy may forward. Empty for a kind the proxy does not serve.
    pub policy: Vec<PolicyRule>,
    /// Environment variable to minted field, in the order they are written.
    pub env: Vec<(String, &'static str)>,
    /// The presence check.
    pub unlock: UnlockPolicy,
    /// How long an unlock is honoured.
    pub cache_secs: u64,
    /// Permitted `argv[0]` values. Empty means any.
    pub allow_argv0: Vec<String>,
    /// Whether a master is collected, or an existing one pointed at.
    pub master: MasterChoice,
}

/// Where the credential's master comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MasterChoice {
    /// Ask for one after the gate and store it under the credential's name.
    New,
    /// Point the credential at a master already filed under this key.
    Reuse(String),
}

/// One credential kind, with its `config` block.
///
/// The configs are the minters' own types, so the YAML is produced by the same
/// serde definitions the daemon parses it with: a field renamed in a minter
/// cannot leave the interview writing the old name.
#[derive(Debug, Clone)]
pub enum Setup {
    /// `http-bearer`, which takes no config.
    HttpBearer,
    /// `http-header`, which names its header.
    HttpHeader(HeaderConfig),
    /// `http-basic`, which takes no config.
    HttpBasic,
    /// `postgres-dynamic`.
    PostgresDynamic(PostgresConfig),
    /// `postgres-proxy`.
    PostgresProxy(PgProxyConfig),
    /// `aws-sts`.
    AwsSts(AwsStsConfig),
    /// `ssh-cert`.
    SshCert(SshCertConfig),
}

impl Setup {
    /// The `kind` string this setup is written as.
    pub fn kind(&self) -> &'static str {
        match self {
            Setup::HttpBearer => http::BEARER_KIND,
            Setup::HttpHeader(_) => http::HEADER_KIND,
            Setup::HttpBasic => http::BASIC_KIND,
            Setup::PostgresDynamic(_) => postgres::KIND,
            Setup::PostgresProxy(_) => postgres_proxy::KIND,
            Setup::AwsSts(_) => aws_sts::KIND,
            Setup::SshCert(_) => ssh_cert::KIND,
        }
    }

    /// Whether the HTTP proxy serves this kind, and so whether it needs a policy.
    pub fn is_http(&self) -> bool {
        http::KINDS.contains(&self.kind())
    }

    /// The `config` block as YAML, or `None` for a kind that takes none.
    ///
    /// `None` rather than an empty mapping because `http-bearer` and
    /// `http-basic` refuse a `config` block outright, and the absence is what
    /// says so most plainly.
    fn config_yaml(&self) -> Option<String> {
        let text = match self {
            Setup::HttpBearer | Setup::HttpBasic => return None,
            Setup::HttpHeader(config) => serde_yaml_ng::to_string(config),
            Setup::PostgresDynamic(config) => serde_yaml_ng::to_string(config),
            Setup::PostgresProxy(config) => serde_yaml_ng::to_string(config),
            Setup::AwsSts(config) => serde_yaml_ng::to_string(config),
            Setup::SshCert(config) => serde_yaml_ng::to_string(config),
        };
        Some(text.expect("a minter config serialises"))
    }

    /// What a reader of the file needs to know about this kind's config and
    /// master, written above the `config:` block.
    fn notes(&self) -> &'static [&'static str] {
        match self {
            Setup::HttpBearer => &[
                "The master is the API token. The subprocess gets a synthetic token,",
                "and the proxy sends `Authorization: Bearer <master>` upstream only",
                "for a request the policy below permits.",
            ],
            Setup::HttpHeader(_) => &[
                "The master is the header's real value. The subprocess gets a",
                "synthetic token, and the proxy puts the real value in this header",
                "only for a request the policy below permits.",
            ],
            Setup::HttpBasic => &[
                "The master is `user:pass`. The subprocess gets a synthetic token,",
                "and the proxy sends HTTP basic auth upstream only for a request",
                "the policy below permits.",
            ],
            Setup::PostgresDynamic(_) => &[
                "Each session gets a fresh login role with the grants below, which is",
                "dropped when the session ends. `user` is the master role (it needs",
                "CREATEROLE); the master is what it logs in with.",
            ],
            Setup::PostgresProxy(_) => &[
                "The subprocess connects to briefcred's local Postgres proxy with a",
                "synthetic token; the daemon connects to `host` as `user` with the",
                "master. `sslmode` is the daemon's own link to the real server.",
            ],
            Setup::AwsSts(_) => &[
                "One AssumeRole session per briefcred session. With `source: static`",
                "the master is `ACCESS_KEY_ID:SECRET_ACCESS_KEY` of whoever assumes it.",
                "Add `session_policy:` (JSON) to narrow the session further.",
            ],
            Setup::SshCert(_) => &[
                "A fresh key and a certificate for these principals, signed by the CA",
                "whose OpenSSH private key is the master. Extensions default to",
                "permit-pty; add `critical_options` such as source-address to pin it.",
            ],
        }
    }
}

/// One request shape the HTTP proxy may forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    /// Upper-case methods from [`METHODS`]. Empty means every method.
    pub methods: Vec<String>,
    /// The upstream host, lower-case, without scheme or port.
    pub host: String,
    /// Which paths on that host.
    pub path: PathMatch,
}

/// The path half of a [`PolicyRule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathMatch {
    /// Every path on the host.
    Any,
    /// This path and no other.
    Exact(String),
    /// Every path starting with this.
    Prefix(String),
}

/// The fields `kind`'s minter publishes, for `${minted.<credential>.<field>}`.
///
/// From the minters' constants where they export them; `postgres-dynamic`,
/// `aws-sts` and `ssh-cert` insert theirs as literals at mint time, so those
/// lists are copied from the `fields.insert` calls and have to follow them.
pub fn published_fields(kind: &str) -> &'static [&'static str] {
    const HTTP: [&str; 2] = [http::TOKEN_FIELD, http::PROXY_URL_FIELD];
    match kind {
        http::BEARER_KIND | http::HEADER_KIND | http::BASIC_KIND => &HTTP,
        postgres::KIND => &[
            "PGUSER",
            "PGPASSWORD",
            "PGHOST",
            "PGPORT",
            "PGDATABASE",
            "DATABASE_URL",
        ],
        postgres_proxy::KIND => &postgres_proxy::FIELDS,
        aws_sts::KIND => &[
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_REGION",
        ],
        ssh_cert::KIND => &["SSH_IDENTITY_FILE", "SSH_CERT_FILE", "GIT_SSH_COMMAND"],
        _ => &[],
    }
}

/// The environment a credential is exposed through before anyone edits it.
///
/// Every published field under its own name, which is already the name the
/// tools read (`PGPASSWORD`, `AWS_SESSION_TOKEN`), except for HTTP: `TOKEN`
/// means nothing to an SDK, so it is offered as `<PROFILE>_API_KEY`, and
/// `PROXY_URL` is left out because `exec` sets `HTTPS_PROXY` and friends
/// itself.
pub fn default_env(kind: &str, profile: &str) -> Vec<(String, &'static str)> {
    if http::KINDS.contains(&kind) {
        return vec![(
            format!("{}_API_KEY", env_prefix(profile)),
            http::TOKEN_FIELD,
        )];
    }
    published_fields(kind)
        .iter()
        .map(|field| (field.to_string(), *field))
        .collect()
}

/// A credential name that says what it is, rather than `db` for everything.
pub fn default_credential_name(kind: &str) -> &'static str {
    match kind {
        postgres::KIND | postgres_proxy::KIND => "db",
        aws_sts::KIND => "aws",
        ssh_cert::KIND => "ssh",
        _ => "api",
    }
}

/// Every presence check, in the order offered. The safest is first because
/// the first is the default.
pub const UNLOCK_POLICIES: [UnlockPolicy; 3] = [
    UnlockPolicy::Biometric,
    UnlockPolicy::Passcode,
    UnlockPolicy::None,
];

/// What each presence check means, for the prompt and the file.
///
/// An exhaustive `match`, so a new [`UnlockPolicy`] variant does not compile
/// until somebody has written its line here — and, seeing it, adds it to
/// [`UNLOCK_POLICIES`].
fn unlock_blurb(policy: UnlockPolicy) -> &'static str {
    match policy {
        UnlockPolicy::Biometric => "Touch ID or Face ID, falling back to the device passcode.",
        UnlockPolicy::Passcode => "The device passcode only.",
        UnlockPolicy::None => "No presence check. For unattended use, and weaker for it.",
    }
}

/// The comment lines above `policy:`.
const POLICY_NOTES: &[&str] = &[
    "Cedar, and default deny: the proxy forwards with the real credential",
    "only what a `permit` below matches. `resource` carries host, path and",
    "scheme; docs/policy-cookbook.md has more shapes. To widen it safely, set",
    "`policy_mode: observe`, read the would_deny rows in the audit log, then",
    "go back to enforce.",
];

/// Build the profile document.
///
/// Emitted as text rather than through `serde_yaml_ng` so the file a user opens
/// afterwards has the comments that tell them what to change. A generated
/// config with no comments is one nobody edits. The `config` block is the one
/// part serialised, because its field names belong to the minter.
pub fn render_profile(answers: &Answers) -> String {
    let kind = answers.setup.kind();
    let mut yaml = format!("name: {}\n", scalar(&answers.name));
    if !answers.description.trim().is_empty() {
        yaml.push_str(&format!(
            "description: {}\n",
            scalar(answers.description.trim())
        ));
    }

    yaml.push_str("\nunlock:\n");
    comment(&mut yaml, 2, &[unlock_blurb(answers.unlock)]);
    yaml.push_str(&format!("  policy: {}\n", scalar(&answers.unlock)));
    comment(
        &mut yaml,
        2,
        &["How long one unlock is honoured, in seconds. 0 asks every session."],
    );
    yaml.push_str(&format!("  cache_secs: {}\n", answers.cache_secs));

    yaml.push_str("\ncredentials:\n");
    yaml.push_str(&format!("  - name: {}\n", scalar(&answers.credential)));
    yaml.push_str(&format!("    kind: {kind}\n"));
    yaml.push_str(&format!("    ttl_secs: {}\n", answers.ttl_secs));
    match &answers.master {
        MasterChoice::New => comment(
            &mut yaml,
            4,
            &["The master is filed under this credential's name."],
        ),
        MasterChoice::Reuse(key) => {
            comment(
                &mut yaml,
                4,
                &["Shares a master that was already stored; bootstrap stored none."],
            );
            yaml.push_str(&format!("    source_key: {}\n", scalar(key)));
        }
    }
    comment(&mut yaml, 4, answers.setup.notes());
    if let Some(config) = answers.setup.config_yaml() {
        yaml.push_str("    config:\n");
        for line in config.lines() {
            yaml.push_str(&format!("      {line}\n"));
        }
    }

    if !answers.policy.is_empty() {
        yaml.push('\n');
        comment(&mut yaml, 0, POLICY_NOTES);
        yaml.push_str("policy: |\n");
        for line in render_policy(&answers.policy).lines() {
            if line.is_empty() {
                yaml.push('\n');
            } else {
                yaml.push_str(&format!("  {line}\n"));
            }
        }
    }

    // The warning sits directly above the list it is about, and says the
    // dangerous thing only when the list is the dangerous one.
    yaml.push_str("\nexec:\n");
    if answers.allow_argv0.is_empty() {
        comment(
            &mut yaml,
            2,
            &[
                "argv[0] must be one of these names, matched literally. Empty means",
                "ANY program may run with these credentials: narrow it before an",
                "agent uses this profile.",
            ],
        );
        yaml.push_str("  allow_argv0: []\n");
    } else {
        comment(
            &mut yaml,
            2,
            &["argv[0] must be one of these names, matched literally."],
        );
        yaml.push_str("  allow_argv0:\n");
        for program in &answers.allow_argv0 {
            yaml.push_str(&format!("    - {}\n", scalar(program)));
        }
    }
    comment(
        &mut yaml,
        2,
        &[
            "Regexes every argument must match one of, unanchored: write `^...$`",
            "for a whole argument. Empty means any.",
        ],
    );
    yaml.push_str("  allow_args: []\n");

    yaml.push('\n');
    comment(
        &mut yaml,
        0,
        &[
            "What the subprocess sees. Each `${minted.<credential>.<field>}` is",
            "filled in per session, and none of them is the master.",
        ],
    );
    if answers.env.is_empty() {
        yaml.push_str("env: {}\n");
    } else {
        yaml.push_str("env:\n");
        for (var, field) in &answers.env {
            yaml.push_str(&format!(
                "  {}: ${{minted.{}.{field}}}\n",
                scalar(var),
                answers.credential
            ));
        }
    }
    let unused: Vec<String> = published_fields(kind)
        .iter()
        .filter(|field| !answers.env.iter().any(|(_, used)| used == *field))
        .map(|field| format!("${{minted.{}.{field}}}", answers.credential))
        .collect();
    if !unused.is_empty() {
        comment(
            &mut yaml,
            2,
            &[&format!("Also published: {}.", unused.join(", "))],
        );
    }
    yaml
}

/// The Cedar text for `rules`, one `permit` each.
///
/// Every rule also requires `https`, so the real credential is only ever put
/// into a request that leaves this machine encrypted. A plain-HTTP upstream
/// needs that clause removed by hand, which is the right amount of friction.
pub fn render_policy(rules: &[PolicyRule]) -> String {
    let permits: Vec<String> = rules
        .iter()
        .map(|rule| {
            let action = match rule.methods.as_slice() {
                [] => "action in [Action::\"http\"]".to_string(),
                [one] => format!("action == Action::\"{one}\""),
                many => format!(
                    "action in [{}]",
                    many.iter()
                        .map(|method| format!("Action::\"{method}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            let mut conditions = vec![
                "resource.scheme == \"https\"".to_string(),
                format!("resource.host == \"{}\"", rule.host),
            ];
            match &rule.path {
                PathMatch::Any => {}
                PathMatch::Exact(path) => conditions.push(format!("resource.path == \"{path}\"")),
                PathMatch::Prefix(path) => {
                    conditions.push(format!("resource.path like \"{path}*\""))
                }
            }
            format!(
                "permit(principal, {action}, resource)\nwhen {{\n  {}\n}};\n",
                conditions.join("\n    && ")
            )
        })
        .collect();
    permits.join("\n")
}

/// Append `lines` as YAML comments at `indent` spaces.
fn comment(yaml: &mut String, indent: usize, lines: &[&str]) {
    for line in lines {
        yaml.push_str(&format!("{:indent$}# {line}\n", ""));
    }
}

/// `value` as a YAML scalar, quoted exactly when YAML needs it to be.
///
/// Through `serde_yaml_ng` rather than by hand, because the cases are not
/// obvious: a description of `yes`, a database called `0123`, or a role ARN
/// with a `: ` in it would each load as something other than what was typed.
fn scalar<T: Serialize + ?Sized>(value: &T) -> String {
    serde_yaml_ng::to_string(value)
        .expect("a scalar serialises")
        .trim_end()
        .to_string()
}

/// Run `kind`'s own validator over a candidate config, for a prompt.
///
/// The interview checks each answer by building a config around it and asking
/// the minter, not by restating the minter's rules here. Two copies of "what
/// is a role ARN" would drift, and the one the daemon enforces is the one that
/// matters.
fn check<T: Serialize>(kind: &str, config: &T) -> std::result::Result<(), String> {
    let value = serde_yaml_ng::to_value(config).map_err(|e| e.to_string())?;
    Registry::discover()
        .validate(kind, &value)
        .map_err(|e| e.to_string())
}

/// Every question after the profile name and kind, in the order asked.
fn interview(
    name: &str,
    kind: &'static str,
    paths: &Paths,
    source_kind: SourceKind,
) -> Result<Answers> {
    let description: String = Input::new()
        .with_prompt("Description (optional)")
        .allow_empty(true)
        .interact_text()
        .map_err(prompt_failed)?;

    let credential: String = Input::new()
        .with_prompt("Credential name")
        .default(default_credential_name(kind).to_string())
        .validate_with(|input: &String| validate_identifier("credential", input))
        .interact_text()
        .map_err(prompt_failed)?;
    let ttl_secs: u64 = Input::new()
        .with_prompt("Credential lifetime, seconds")
        .default(DEFAULT_TTL_SECS)
        .validate_with(|ttl: &u64| match ttl {
            0 => Err("a credential needs a lifetime of at least one second"),
            _ => Ok(()),
        })
        .interact_text()
        .map_err(prompt_failed)?;

    let setup = ask_setup(kind)?;

    let (policy, env) = if setup.is_http() {
        (ask_policy()?, ask_http_env(name)?)
    } else {
        let env = default_env(kind, name);
        let names: Vec<&str> = env.iter().map(|(var, _)| var.as_str()).collect();
        println!("The subprocess will see {}.", names.join(", "));
        (Vec::new(), env)
    };

    let labels: Vec<String> = UNLOCK_POLICIES
        .iter()
        .map(|policy| format!("{}: {}", scalar(policy), unlock_blurb(*policy)))
        .collect();
    let unlock = UNLOCK_POLICIES[Select::new()
        .with_prompt("Unlock policy")
        .items(&labels)
        .default(0)
        .interact()
        .map_err(prompt_failed)?];
    let cache_secs: u64 = Input::new()
        .with_prompt("Honour an unlock for how many seconds (0 = ask every session)")
        .default(DEFAULT_UNLOCK_CACHE_SECS)
        .interact_text()
        .map_err(prompt_failed)?;

    let programs: String = Input::new()
        .with_prompt("Programs this profile may run, as argv[0] (comma-separated; empty = any)")
        .allow_empty(true)
        .interact_text()
        .map_err(prompt_failed)?;
    let allow_argv0 = split_list(&programs);
    if allow_argv0.is_empty() {
        println!("Any program may run with this profile; the file says so where it matters.");
    }

    let master = ask_master_choice(&credential, paths, source_kind)?;

    Ok(Answers {
        name: name.to_string(),
        description,
        credential,
        ttl_secs,
        setup,
        policy,
        env,
        unlock,
        cache_secs,
        allow_argv0,
        master,
    })
}

/// The kind-specific questions.
///
/// A `match` on the kind rather than something the registry drives: a minter's
/// config schema is a Rust type, and asking it to describe itself for a prompt
/// would be a serialisation framework nobody has asked for yet. Each answer is
/// still checked by the minter's own validator through [`check`].
fn ask_setup(kind: &str) -> Result<Setup> {
    match kind {
        http::BEARER_KIND => Ok(Setup::HttpBearer),
        http::BASIC_KIND => Ok(Setup::HttpBasic),
        http::HEADER_KIND => {
            let name: String = Input::new()
                .with_prompt("Header the real value is sent in")
                .default("X-Api-Key".to_string())
                .validate_with(|name: &String| {
                    check(http::HEADER_KIND, &HeaderConfig { name: name.clone() })
                })
                .interact_text()
                .map_err(prompt_failed)?;
            Ok(Setup::HttpHeader(HeaderConfig { name }))
        }
        postgres::KIND => {
            let (host, port, dbname, user) = ask_connection("Master role")?;
            let sslmode = choose(
                "TLS to the server",
                &[
                    postgres::SslMode::Require,
                    postgres::SslMode::Prefer,
                    postgres::SslMode::Disable,
                ],
            )?;
            let schema: String = Input::new()
                .with_prompt("Schema the minted role may use")
                .default("public".to_string())
                .validate_with(|schema: &String| {
                    grant(&["SELECT".to_string()], schema)
                        .validate()
                        .map_err(|e| e.to_string())
                })
                .interact_text()
                .map_err(prompt_failed)?;
            let privileges: String = Input::new()
                .with_prompt(format!(
                    "Privileges on all tables in `{schema}` (comma-separated)"
                ))
                .default("SELECT".to_string())
                .validate_with(|privileges: &String| {
                    grant(&upper_list(privileges), &schema)
                        .validate()
                        .map_err(|e| e.to_string())
                })
                .interact_text()
                .map_err(prompt_failed)?;
            Ok(Setup::PostgresDynamic(PostgresConfig {
                host,
                port,
                dbname,
                user,
                sslmode,
                role_template: RoleTemplate {
                    grants: vec![grant(&upper_list(&privileges), &schema)],
                },
            }))
        }
        postgres_proxy::KIND => {
            let (host, port, dbname, user) = ask_connection("Role the daemon connects as")?;
            let sslmode = choose(
                "The daemon's TLS to the real server",
                &[
                    postgres_proxy::SslMode::Require,
                    postgres_proxy::SslMode::VerifyFull,
                    postgres_proxy::SslMode::Disable,
                ],
            )?;
            Ok(Setup::PostgresProxy(PgProxyConfig {
                host,
                port,
                dbname,
                user,
                sslmode,
            }))
        }
        aws_sts::KIND => {
            let candidate = |role_arn: &str, region: &str, duration_secs: u64| AwsStsConfig {
                role_arn: role_arn.to_string(),
                region: region.to_string(),
                session_policy: None,
                source: CallerSource::Static,
                duration_secs,
            };
            let role_arn: String = Input::new()
                .with_prompt("Role ARN to assume")
                .validate_with(|arn: &String| {
                    check(
                        aws_sts::KIND,
                        &candidate(arn, "us-east-1", aws_sts::MIN_DURATION_SECS),
                    )
                })
                .interact_text()
                .map_err(prompt_failed)?;
            let region: String = Input::new()
                .with_prompt("Region")
                .default("us-east-1".to_string())
                .validate_with(|region: &String| {
                    check(
                        aws_sts::KIND,
                        &candidate(&role_arn, region, aws_sts::MIN_DURATION_SECS),
                    )
                })
                .interact_text()
                .map_err(prompt_failed)?;
            let source = choose(
                "Who calls AssumeRole (static = the stored master; ambient = the AWS default chain)",
                &[CallerSource::Static, CallerSource::Ambient],
            )?;
            let duration_secs: u64 = Input::new()
                .with_prompt("Session duration, seconds")
                .default(aws_sts::MIN_DURATION_SECS)
                .validate_with(|secs: &u64| {
                    check(aws_sts::KIND, &candidate(&role_arn, &region, *secs))
                })
                .interact_text()
                .map_err(prompt_failed)?;
            Ok(Setup::AwsSts(AwsStsConfig {
                source,
                ..candidate(&role_arn, &region, duration_secs)
            }))
        }
        ssh_cert::KIND => {
            let config = |principals: &str| SshCertConfig {
                principals: split_list(principals),
                extensions: None,
                critical_options: Default::default(),
            };
            let principals: String = Input::new()
                .with_prompt("Principals the certificate is valid for (comma-separated)")
                .validate_with(|principals: &String| check(ssh_cert::KIND, &config(principals)))
                .interact_text()
                .map_err(prompt_failed)?;
            Ok(Setup::SshCert(config(&principals)))
        }
        other => Err(Error::Refused(format!(
            "`{other}` has no guided setup; write its profile by hand (docs/profile-schema.md)"
        ))),
    }
}

/// Host, port, database and role, which both Postgres kinds ask the same way.
fn ask_connection(role_prompt: &str) -> Result<(String, u16, String, String)> {
    let host: String = Input::new()
        .with_prompt("Database host")
        .default("127.0.0.1".to_string())
        .interact_text()
        .map_err(prompt_failed)?;
    let port: u16 = Input::new()
        .with_prompt("Port")
        .default(postgres_proxy::DEFAULT_PORT)
        .validate_with(|port: &u16| match port {
            0 => Err("port 0 is not a port"),
            _ => Ok(()),
        })
        .interact_text()
        .map_err(prompt_failed)?;
    let dbname: String = Input::new()
        .with_prompt("Database name")
        .interact_text()
        .map_err(prompt_failed)?;
    let user: String = Input::new()
        .with_prompt(role_prompt)
        .interact_text()
        .map_err(prompt_failed)?;
    Ok((host, port, dbname, user))
}

/// One grant of `privileges` on every table in `schema`.
fn grant(privileges: &[String], schema: &str) -> Grant {
    Grant {
        privileges: privileges.to_vec(),
        on: format!("ALL TABLES IN SCHEMA {}", schema.trim()),
    }
}

/// Pick one of `options`, labelled by how each is spelled in a profile.
fn choose<T: Serialize + Copy>(prompt: &str, options: &[T]) -> Result<T> {
    let labels: Vec<String> = options.iter().map(scalar).collect();
    let index = Select::new()
        .with_prompt(prompt)
        .items(&labels)
        .default(0)
        .interact()
        .map_err(prompt_failed)?;
    Ok(options[index])
}

/// The requests an HTTP credential may be used for.
///
/// At least one, because the proxy denies by default: a profile with an HTTP
/// credential and no policy loads, mints, and forwards nothing, which is the
/// most confusing way a bootstrap could succeed.
fn ask_policy() -> Result<Vec<PolicyRule>> {
    println!(
        "The proxy forwards nothing a policy does not permit. Describe each request \
         this credential may be used for."
    );
    let mut rules: Vec<PolicyRule> = Vec::new();
    loop {
        let mut host = Input::<String>::new()
            .with_prompt("Upstream host, e.g. api.example.com")
            .validate_with(|host: &String| validate_host(host));
        if let Some(previous) = rules.last() {
            host = host.default(previous.host.clone());
        }
        let host = host.interact_text().map_err(prompt_failed)?;
        let methods: String = Input::new()
            .with_prompt(format!(
                "Methods, comma-separated from {} (* for all)",
                METHODS.join(" ")
            ))
            .default("GET".to_string())
            .validate_with(|methods: &String| parse_methods(methods).map(|_| ()))
            .interact_text()
            .map_err(prompt_failed)?;
        let path: String = Input::new()
            .with_prompt("Path: exact, or a prefix ending in * (e.g. /v1/chat/completions, /v1/*)")
            .validate_with(|path: &String| parse_path(path).map(|_| ()))
            .interact_text()
            .map_err(prompt_failed)?;
        rules.push(PolicyRule {
            methods: parse_methods(&methods).map_err(Error::Refused)?,
            host: host.trim().to_ascii_lowercase(),
            path: parse_path(&path).map_err(Error::Refused)?,
        });
        if !Confirm::new()
            .with_prompt("Permit another request?")
            .default(false)
            .interact()
            .map_err(prompt_failed)?
        {
            return Ok(rules);
        }
    }
}

/// Which variables an HTTP credential's token, and optionally its proxy URL,
/// are exposed as.
fn ask_http_env(profile: &str) -> Result<Vec<(String, &'static str)>> {
    let (default_var, _) = default_env(http::BEARER_KIND, profile).remove(0);
    let token: String = Input::new()
        .with_prompt("Environment variable for the token")
        .default(default_var)
        .validate_with(|var: &String| validate_env_var(var))
        .interact_text()
        .map_err(prompt_failed)?;
    let proxy_url: String = Input::new()
        .with_prompt(
            "Environment variable for the proxy URL (optional; exec already sets \
             HTTPS_PROXY, HTTP_PROXY and ALL_PROXY)",
        )
        .allow_empty(true)
        .validate_with(|var: &String| match var.as_str() {
            "" => Ok(()),
            same if same == token => Err("that is the token's variable".to_string()),
            other => validate_env_var(other),
        })
        .interact_text()
        .map_err(prompt_failed)?;
    let mut env = vec![(token, http::TOKEN_FIELD)];
    if !proxy_url.is_empty() {
        env.push((proxy_url, http::PROXY_URL_FIELD));
    }
    Ok(env)
}

/// Store a new master, or point at one that is already stored.
fn ask_master_choice(
    credential: &str,
    paths: &Paths,
    source_kind: SourceKind,
) -> Result<MasterChoice> {
    let choices = [
        format!("Store a new master under `{credential}`"),
        "Reuse a master that is already stored".to_string(),
    ];
    if Select::new()
        .with_prompt("Master")
        .items(&choices)
        .default(0)
        .interact()
        .map_err(prompt_failed)?
        == 0
    {
        return Ok(MasterChoice::New);
    }

    let key: String = Input::new()
        .with_prompt("Key the existing master is stored under")
        .default(credential.to_string())
        .validate_with(|key: &String| validate_master_key(key))
        .interact_text()
        .map_err(prompt_failed)?;
    let location = master_location(paths, source_kind, &key);
    match master_exists(paths, source_kind, &key) {
        Ok(true) => println!("Found `{key}` at {location}."),
        Ok(false) => {
            eprintln!("briefcred: there is no master `{key}` at {location}");
            if !Confirm::new()
                .with_prompt("Write the profile anyway? It cannot mint until that master exists")
                .default(false)
                .interact()
                .map_err(prompt_failed)?
            {
                return Err(Error::Refused("nothing was written".to_string()));
            }
        }
        Err(why) => println!("`{key}` was not checked: {why}."),
    }
    Ok(MasterChoice::Reuse(key))
}

/// What the master is for `setup`, so the prompt says what to paste.
fn master_hint(setup: &Setup) -> &'static str {
    match setup {
        Setup::HttpBearer => "the API token",
        Setup::HttpHeader(_) => "the header's real value",
        Setup::HttpBasic => "user:pass",
        Setup::PostgresDynamic(_) => "what the master role logs in with",
        Setup::PostgresProxy(_) => "what the upstream role logs in with",
        Setup::AwsSts(config) if config.source == CallerSource::Static => {
            "ACCESS_KEY_ID:SECRET_ACCESS_KEY"
        }
        Setup::AwsSts(_) => "unused with `source: ambient`; any placeholder",
        Setup::SshCert(_) => "the CA's OpenSSH private key",
    }
}

/// Collect a new master for `key`.
///
/// An SSH CA key is several lines and a password prompt takes one, so for
/// `ssh-cert` the master is read from a file the user names instead.
fn ask_master(kind: &str, hint: &str, key: &str) -> Result<Zeroizing<String>> {
    if kind == ssh_cert::KIND {
        let file: String = Input::new()
            .with_prompt(format!("File holding {hint}, to store as `{key}`"))
            .interact_text()
            .map_err(prompt_failed)?;
        let file = match (file.strip_prefix("~/"), std::env::var_os("HOME")) {
            (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
            _ => PathBuf::from(file),
        };
        let text = Zeroizing::new(
            std::fs::read_to_string(&file).map_err(|e| Error::io("read", &file, e))?,
        );
        if !text
            .trim_start()
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        {
            return Err(Error::Refused(format!(
                "{} is not an OpenSSH private key; nothing was written",
                file.display()
            )));
        }
        return Ok(text);
    }
    Password::new()
        .with_prompt(format!("Master for `{key}` ({hint})"))
        .with_confirmation("Confirm", "They did not match")
        .interact()
        .map(Zeroizing::new)
        .map_err(prompt_failed)
}

/// A comma-separated answer as a list, blanks dropped.
fn split_list(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// [`split_list`], upper-cased, for SQL keywords.
fn upper_list(input: &str) -> Vec<String> {
    split_list(input)
        .into_iter()
        .map(|item| item.to_ascii_uppercase())
        .collect()
}

/// `openai` to `OPENAI`, `my-api` to `MY_API`: a profile name as a variable
/// prefix.
fn env_prefix(profile: &str) -> String {
    profile
        .chars()
        .map(|c| match c {
            c if c.is_ascii_alphanumeric() => c.to_ascii_uppercase(),
            _ => '_',
        })
        .collect()
}

/// A methods answer: `*` for every method, else a list from [`METHODS`].
fn parse_methods(input: &str) -> std::result::Result<Vec<String>, String> {
    if input.trim() == "*" {
        return Ok(Vec::new());
    }
    let mut methods: Vec<String> = Vec::new();
    for method in upper_list(input) {
        if !METHODS.contains(&method.as_str()) {
            return Err(format!(
                "`{method}` is not one the proxy forwards; use {} or *",
                METHODS.join(", ")
            ));
        }
        if !methods.contains(&method) {
            methods.push(method);
        }
    }
    if methods.is_empty() {
        return Err("name at least one method, or * for all".to_string());
    }
    Ok(methods)
}

/// A path answer: `*` for any, `/x/*` for a prefix, `/x` for exactly `/x`.
///
/// Quotes and backslashes would end or escape the Cedar string, a `*` before
/// the end would be a wildcard nobody meant, and the proxy strips the query
/// and never sees a fragment, so a `?` or `#` could only ever fail to match.
fn parse_path(input: &str) -> std::result::Result<PathMatch, String> {
    let input = input.trim();
    if input == "*" {
        return Ok(PathMatch::Any);
    }
    if !input.starts_with('/') {
        return Err("a path starts with `/`, or is `*` for any".to_string());
    }
    let (body, prefix) = match input.strip_suffix('*') {
        Some(body) => (body, true),
        None => (input, false),
    };
    if let Some(bad) = body
        .chars()
        .find(|c| !c.is_ascii_graphic() || matches!(c, '"' | '\\' | '*' | '?' | '#'))
    {
        return Err(format!(
            "`{bad}` cannot appear in a path here; `*` only at the end"
        ));
    }
    Ok(match prefix {
        true => PathMatch::Prefix(body.to_string()),
        false => PathMatch::Exact(body.to_string()),
    })
}

/// A bare host name: no scheme, port, path, or anything Cedar would need
/// escaped.
fn validate_host(input: &str) -> std::result::Result<(), String> {
    let host = input.trim().to_ascii_lowercase();
    let well_formed = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && !host.contains("..");
    match well_formed {
        true => Ok(()),
        false => Err(format!(
            "`{input}` is not a host name; give the host only, without scheme, port or path"
        )),
    }
}

/// A name `exec` can set: a letter or `_`, then letters, digits and `_`.
fn validate_env_var(name: &str) -> std::result::Result<(), String> {
    let mut bytes = name.bytes();
    let valid = bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_');
    match valid {
        true => Ok(()),
        false => Err(format!(
            "`{name}` is not a variable name; use letters, digits and `_`, not starting with a digit"
        )),
    }
}

/// The master-source key rule, restated because the source's own check is
/// private to it: the same rule for every backend, so a key that works in the
/// keychain cannot become a path traversal in the file source.
fn validate_master_key(key: &str) -> std::result::Result<(), String> {
    if key.is_empty()
        || key.starts_with('.')
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(format!(
            "`{key}` is not a master key; use letters, digits, `-`, `_` and `.`, not starting with `.`"
        ));
    }
    Ok(())
}

/// A profile name has to be a usable filename and a usable master key.
fn validate_name(name: &str) -> std::result::Result<(), String> {
    validate_identifier("profile", name)
}

/// A name that is a usable filename, master key, and `${minted.<name>…}`
/// segment all at once: a `.` would split the template, a `/` the path.
fn validate_identifier(what: &str, name: &str) -> std::result::Result<(), String> {
    if name.trim().is_empty() {
        return Err(format!("a {what} needs a name"));
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
    use briefcred_core::policy::{HttpRequest, Outcome, PolicyMode};
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

    /// Representative answers for `kind`, as somebody taking every default
    /// and filling in the required fields would give them.
    fn sample(kind: &str, name: &str) -> Answers {
        let setup = match kind {
            http::BEARER_KIND => Setup::HttpBearer,
            http::HEADER_KIND => Setup::HttpHeader(HeaderConfig {
                name: "X-Api-Key".into(),
            }),
            http::BASIC_KIND => Setup::HttpBasic,
            postgres::KIND => Setup::PostgresDynamic(PostgresConfig {
                host: "127.0.0.1".into(),
                port: 5432,
                dbname: "app".into(),
                user: "briefcred_master".into(),
                sslmode: postgres::SslMode::Require,
                role_template: RoleTemplate {
                    grants: vec![grant(&["SELECT".to_string()], "public")],
                },
            }),
            postgres_proxy::KIND => Setup::PostgresProxy(PgProxyConfig {
                host: "db.internal".into(),
                port: 5432,
                dbname: "analytics".into(),
                user: "reporting".into(),
                sslmode: postgres_proxy::SslMode::VerifyFull,
            }),
            aws_sts::KIND => Setup::AwsSts(AwsStsConfig {
                role_arn: "arn:aws:iam::123456789012:role/reader".into(),
                region: "eu-west-1".into(),
                session_policy: None,
                source: CallerSource::Static,
                duration_secs: aws_sts::MIN_DURATION_SECS,
            }),
            ssh_cert::KIND => Setup::SshCert(SshCertConfig {
                principals: vec!["deploy".into()],
                extensions: None,
                critical_options: Default::default(),
            }),
            other => panic!("no sample for `{other}`; add one alongside its guided setup"),
        };
        let policy = match setup.is_http() {
            true => vec![PolicyRule {
                methods: vec!["POST".into()],
                host: "api.example.com".into(),
                path: PathMatch::Exact("/v1/x".into()),
            }],
            false => Vec::new(),
        };
        Answers {
            name: name.into(),
            description: String::new(),
            credential: default_credential_name(kind).into(),
            ttl_secs: DEFAULT_TTL_SECS,
            env: default_env(kind, name),
            setup,
            policy,
            unlock: UnlockPolicy::Biometric,
            cache_secs: DEFAULT_UNLOCK_CACHE_SECS,
            allow_argv0: Vec::new(),
            master: MasterChoice::New,
        }
    }

    /// A valid `postgres-dynamic` profile document.
    fn valid_yaml(name: &str) -> String {
        render_profile(&sample(postgres::KIND, name))
    }

    /// A daemon that has loaded the profile and whose gate lets it through.
    async fn unlocking_daemon(sock: &Path) -> tokio::task::JoinHandle<()> {
        stub_daemon(
            sock.to_path_buf(),
            vec![
                Response::Profile {
                    profile: briefcred_proto::ProfileSummary {
                        name: "shared".into(),
                        description: None,
                        unlock_policy: "biometric".into(),
                        unlock_cache_secs: 300,
                        source: "local".into(),
                        signature: "unsigned".into(),
                        signer_key_id: None,
                        overrides: None,
                        path: std::path::PathBuf::new(),
                        credentials: Vec::new(),
                    },
                },
                Response::Unlocked {
                    profile: "shared".into(),
                },
            ],
        )
        .await
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
                        source: "local".into(),
                        signature: "unsigned".into(),
                        signer_key_id: None,
                        overrides: None,
                        path: std::path::PathBuf::new(),
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
            MasterStep::Ask(&never_asked),
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
            MasterStep::Ask(&never_asked),
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
                            source: "local".into(),
                            signature: "unsigned".into(),
                            signer_key_id: None,
                            overrides: None,
                            path: std::path::PathBuf::new(),
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
                MasterStep::Ask(&|_| Ok(Zeroizing::new(master.to_string()))),
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
                        source: "local".into(),
                        signature: "unsigned".into(),
                        signer_key_id: None,
                        overrides: None,
                        path: std::path::PathBuf::new(),
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
            MasterStep::Ask(&|_| Ok(Zeroizing::new("s3cret".to_string()))),
        )
        .await
        .unwrap();

        assert_eq!(done.source_key, "db");
        assert!(
            !yaml.contains("s3cret"),
            "the master never reaches the profile"
        );
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
                        source: "local".into(),
                        signature: "unsigned".into(),
                        signer_key_id: None,
                        overrides: None,
                        path: std::path::PathBuf::new(),
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
        let mut answers = sample(postgres::KIND, "db-ro");
        answers.description = "read-only analytics".into();
        let yaml = render_profile(&answers);
        let profile = briefcred_core::Profile::from_yaml_str(&yaml).unwrap();
        profile.validate(&Registry::discover()).unwrap();

        assert_eq!(profile.name, "db-ro");
        assert_eq!(profile.description.as_deref(), Some("read-only analytics"));
        assert_eq!(profile.credentials.len(), 1);
        assert_eq!(profile.credentials[0].source_key, None);
        // PG* for psql, and DATABASE_URL because the minter publishes it too.
        assert_eq!(profile.env.len(), 6);
        assert_eq!(
            profile.env.get("PGPASSWORD").map(String::as_str),
            Some("${minted.db.PGPASSWORD}")
        );
        assert_eq!(
            profile.env.get("DATABASE_URL").map(String::as_str),
            Some("${minted.db.DATABASE_URL}")
        );
    }

    #[test]
    fn a_generated_profile_never_contains_a_secret() {
        // The interview asks for the master last and hands it to the key store
        // rather than to the file. This asserts the shape that makes that true.
        let mut answers = sample(postgres::KIND, "db-ro");
        if let Setup::PostgresDynamic(config) = &mut answers.setup {
            config.host = "db.internal".into();
        }
        let yaml = render_profile(&answers);
        assert!(!yaml.contains("password"), "{yaml}");
        assert!(!yaml.to_lowercase().contains("secret"), "{yaml}");
    }

    #[test]
    fn every_registered_kind_has_a_guided_setup() {
        for kind in Registry::discover().kinds() {
            assert!(
                GUIDED_KINDS.contains(&kind),
                "`{kind}` is registered but the bootstrap interview cannot set it up"
            );
            assert!(
                !published_fields(kind).is_empty(),
                "`{kind}` publishes no fields the interview knows of"
            );
        }
    }

    #[test]
    fn every_registered_kind_renders_a_profile_that_loads_and_validates() {
        let registry = Registry::discover();
        for kind in registry.kinds() {
            let answers = sample(kind, "sample");
            let yaml = render_profile(&answers);
            let profile = briefcred_core::Profile::from_yaml_str(&yaml)
                .unwrap_or_else(|e| panic!("`{kind}`: {e}\n{yaml}"));
            profile
                .validate(&registry)
                .unwrap_or_else(|e| panic!("`{kind}`: {e}\n{yaml}"));

            let credential = &profile.credentials[0];
            assert_eq!(credential.kind, kind);
            assert_eq!(credential.name, default_credential_name(kind), "{kind}");
            assert_eq!(credential.ttl_secs, DEFAULT_TTL_SECS, "{kind}");
            assert_eq!(profile.unlock.policy, UnlockPolicy::Biometric, "{kind}");
            assert_eq!(profile.unlock.cache_secs, DEFAULT_UNLOCK_CACHE_SECS);

            // Every variable names a field this kind actually publishes.
            assert!(!profile.env.is_empty(), "`{kind}` exposes nothing\n{yaml}");
            for (var, value) in &profile.env {
                let field = value
                    .strip_prefix(&format!("${{minted.{}.", credential.name))
                    .and_then(|rest| rest.strip_suffix('}'))
                    .unwrap_or_else(|| panic!("`{kind}`: {var}: {value}"));
                assert!(
                    published_fields(kind).contains(&field),
                    "`{kind}`: {var} reads `{field}`, which is not published"
                );
            }

            // An HTTP credential without a policy forwards nothing; any other
            // kind has no business with one.
            assert_eq!(profile.policy.is_some(), answers.setup.is_http(), "{kind}");
        }
    }

    /// A request through the proxy, for asking a compiled policy about it.
    fn request<'a>(method: &'a str, host: &'a str, path: &'a str) -> HttpRequest<'a> {
        HttpRequest {
            method,
            scheme: "https",
            host,
            path,
            context: Default::default(),
        }
    }

    #[test]
    fn an_http_profile_permits_what_was_asked_for_and_exposes_the_token() {
        for kind in http::KINDS {
            let yaml = render_profile(&sample(kind, "example"));
            let profile = briefcred_core::Profile::from_yaml_str(&yaml).unwrap();
            profile.validate(&Registry::discover()).unwrap();

            let policy = profile
                .compiled_policy()
                .unwrap()
                .unwrap_or_else(|| panic!("`{kind}` has no policy\n{yaml}"));
            let decide = |req: HttpRequest<'_>| policy.decide("sid", &req, PolicyMode::Enforce);
            assert_eq!(
                decide(request("POST", "api.example.com", "/v1/x")),
                Outcome::Allow,
                "{kind}"
            );
            for denied in [
                request("GET", "api.example.com", "/v1/x"),
                request("POST", "evil.example", "/v1/x"),
                request("POST", "api.example.com", "/v1/other"),
            ] {
                assert_eq!(decide(denied.clone()), Outcome::Deny, "{kind}: {denied:?}");
            }
            assert_eq!(
                decide(HttpRequest {
                    scheme: "http",
                    ..request("POST", "api.example.com", "/v1/x")
                }),
                Outcome::Deny,
                "{kind}: the real credential is only sent over https"
            );

            assert_eq!(
                profile.env.get("EXAMPLE_API_KEY").map(String::as_str),
                Some("${minted.api.TOKEN}"),
                "{kind}\n{yaml}"
            );
            assert!(yaml.contains("${minted.api.PROXY_URL}"), "{yaml}");
        }
    }

    #[test]
    fn every_policy_shape_compiles_and_means_what_it_says() {
        let mut answers = sample(http::BEARER_KIND, "example");
        answers.policy = vec![
            PolicyRule {
                methods: Vec::new(),
                host: "status.example.com".into(),
                path: PathMatch::Any,
            },
            PolicyRule {
                methods: vec!["GET".into(), "DELETE".into()],
                host: "api.example.com".into(),
                path: PathMatch::Prefix("/v1/files/".into()),
            },
        ];
        answers
            .env
            .push(("EXAMPLE_PROXY".into(), http::PROXY_URL_FIELD));
        let yaml = render_profile(&answers);
        let profile = briefcred_core::Profile::from_yaml_str(&yaml).unwrap();
        let policy = profile.compiled_policy().unwrap().unwrap();
        let decide = |req: HttpRequest<'_>| policy.decide("sid", &req, PolicyMode::Enforce);

        for method in METHODS {
            assert_eq!(
                decide(request(method, "status.example.com", "/anything/at/all")),
                Outcome::Allow,
                "{method}"
            );
        }
        assert_eq!(
            decide(request("DELETE", "api.example.com", "/v1/files/f-1")),
            Outcome::Allow
        );
        assert_eq!(
            decide(request("POST", "api.example.com", "/v1/files/f-1")),
            Outcome::Deny
        );
        assert_eq!(
            decide(request("GET", "api.example.com", "/v1/models")),
            Outcome::Deny
        );

        assert_eq!(
            profile.env.get("EXAMPLE_PROXY").map(String::as_str),
            Some("${minted.api.PROXY_URL}")
        );
        assert!(!yaml.contains("Also published"), "{yaml}");
    }

    #[test]
    fn reusing_a_master_names_it_in_the_profile() {
        let mut answers = sample(http::BEARER_KIND, "example");
        answers.master = MasterChoice::Reuse("openai".into());
        let profile = briefcred_core::Profile::from_yaml_str(&render_profile(&answers)).unwrap();
        assert_eq!(profile.credentials[0].source_key.as_deref(), Some("openai"));
        assert_eq!(profile.credentials[0].source_key(), "openai");
    }

    #[tokio::test]
    async fn a_reused_master_is_neither_asked_for_nor_stored_but_the_gate_still_runs() {
        let home = tempfile::tempdir().unwrap();
        let paths = test_paths(home.path());
        briefcred_core::paths::ensure_private_dir(&paths.profiles_dir()).unwrap();
        let sock = home.path().join("sock");
        let path = paths.profiles_dir().join("shared.yaml");

        let mut answers = sample(postgres::KIND, "shared");
        answers.master = MasterChoice::Reuse("warehouse-master".into());
        let yaml = render_profile(&answers);

        let daemon = unlocking_daemon(&sock).await;
        let done = finish(
            &paths,
            &sock,
            SourceKind::File,
            &Registry::discover(),
            "shared",
            &path,
            &yaml,
            MasterStep::Reuse,
        )
        .await
        .unwrap();
        daemon.await.unwrap();

        assert_eq!(done.source_key, "warehouse-master");
        assert!(done.location.contains("reused"), "{}", done.location);
        let written =
            briefcred_core::Profile::from_yaml_str(&std::fs::read_to_string(&path).unwrap())
                .unwrap();
        assert_eq!(
            written.credentials[0].source_key.as_deref(),
            Some("warehouse-master")
        );
        // Nothing was stored, under either name.
        assert!(!paths.secrets_dir().join("warehouse-master").exists());
        assert!(!paths.secrets_dir().join("db").exists());
    }

    #[tokio::test]
    async fn a_reused_master_still_restores_the_old_profile_when_the_gate_refuses() {
        let home = tempfile::tempdir().unwrap();
        let paths = test_paths(home.path());
        briefcred_core::paths::ensure_private_dir(&paths.profiles_dir()).unwrap();
        let sock = home.path().join("sock");
        let path = paths.profiles_dir().join("db-ro.yaml");
        let original = "name: db-ro\n";
        std::fs::write(&path, original).unwrap();

        let mut answers = sample(postgres::KIND, "db-ro");
        answers.master = MasterChoice::Reuse("db".into());
        let daemon = refusing_daemon(&sock).await;
        let err = finish(
            &paths,
            &sock,
            SourceKind::File,
            &Registry::discover(),
            "db-ro",
            &path,
            &render_profile(&answers),
            MasterStep::Reuse,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, Error::Locked { .. }), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        daemon.abort();
    }

    #[test]
    fn whether_a_master_exists_is_answered_only_where_it_can_be_without_reading_it() {
        let home = tempfile::tempdir().unwrap();
        let paths = test_paths(home.path());
        assert_eq!(master_exists(&paths, SourceKind::File, "db"), Ok(false));
        store_master(
            &paths,
            SourceKind::File,
            "db",
            &Zeroizing::new("s3cret".into()),
        )
        .unwrap();
        assert_eq!(master_exists(&paths, SourceKind::File, "db"), Ok(true));
        // Answered without touching either store: the keychain is never
        // opened, and the environment asked about is the daemon's.
        assert!(master_exists(&paths, SourceKind::Keychain, "db").is_err());
        assert!(master_exists(&paths, SourceKind::Env, "db").is_err());
    }

    #[test]
    fn every_unlock_policy_is_offered_and_round_trips() {
        for (unlock, cache_secs) in UNLOCK_POLICIES.into_iter().zip([0, 60, 43_200]) {
            let mut answers = sample(postgres::KIND, "db-ro");
            answers.unlock = unlock;
            answers.cache_secs = cache_secs;
            let profile =
                briefcred_core::Profile::from_yaml_str(&render_profile(&answers)).unwrap();
            assert_eq!(profile.unlock.policy, unlock);
            assert_eq!(profile.unlock.cache_secs, cache_secs);
        }
    }

    #[test]
    fn allow_argv0_is_a_list_and_the_any_warning_sits_on_the_empty_one() {
        let mut answers = sample(postgres::KIND, "db-ro");
        let open = render_profile(&answers);
        let line = open
            .lines()
            .position(|line| line == "  allow_argv0: []")
            .unwrap();
        assert!(
            open.lines()
                .nth(line - 1)
                .unwrap()
                .contains("agent uses this"),
            "the warning belongs directly above the empty list:\n{open}"
        );
        assert!(open.contains("ANY program"), "{open}");

        answers.allow_argv0 = vec!["psql".into(), "/usr/bin/env".into(), "yes".into()];
        let narrowed = render_profile(&answers);
        assert!(!narrowed.contains("ANY program"), "{narrowed}");
        let profile = briefcred_core::Profile::from_yaml_str(&narrowed).unwrap();
        assert_eq!(profile.exec.allow_argv0, ["psql", "/usr/bin/env", "yes"]);
    }

    #[test]
    fn free_text_answers_are_quoted_where_yaml_would_misread_them() {
        let mut answers = sample(postgres::KIND, "db-ro");
        answers.description = "read-only: analytics # not a comment".into();
        if let Setup::PostgresDynamic(config) = &mut answers.setup {
            config.dbname = "0123".into();
            config.user = "yes".into();
        }
        let profile = briefcred_core::Profile::from_yaml_str(&render_profile(&answers)).unwrap();
        profile.validate(&Registry::discover()).unwrap();
        assert_eq!(
            profile.description.as_deref(),
            Some("read-only: analytics # not a comment")
        );
        let config = postgres::PostgresConfig::from_value(&profile.credentials[0].config).unwrap();
        assert_eq!(config.dbname, "0123");
        assert_eq!(config.user, "yes");
    }

    #[test]
    fn the_answer_parsers_refuse_what_cedar_or_the_proxy_would_misread() {
        assert_eq!(parse_methods("*").unwrap(), Vec::<String>::new());
        assert_eq!(parse_methods("get, Post,GET").unwrap(), ["GET", "POST"]);
        for bad in ["", " , ", "TRACE", "GET,CONNECT"] {
            assert!(parse_methods(bad).is_err(), "`{bad}`");
        }

        assert_eq!(parse_path("*").unwrap(), PathMatch::Any);
        assert_eq!(
            parse_path("/v1/chat/completions").unwrap(),
            PathMatch::Exact("/v1/chat/completions".into())
        );
        assert_eq!(
            parse_path("/v1/*").unwrap(),
            PathMatch::Prefix("/v1/".into())
        );
        for bad in [
            "v1", "/v1/*/x", "/a\"b", "/a\\b", "/a b", "/a?b=1", "/a#b", "",
        ] {
            assert!(parse_path(bad).is_err(), "`{bad}`");
        }

        assert!(validate_host("api.example.com").is_ok());
        assert!(validate_host("API.Example.com").is_ok());
        for bad in [
            "",
            "https://api.example.com",
            "api.example.com:443",
            "api.example.com/v1",
            ".example.com",
            "a..b",
            "a\"b",
        ] {
            assert!(validate_host(bad).is_err(), "`{bad}`");
        }

        assert!(validate_env_var("OPENAI_API_KEY").is_ok());
        assert!(validate_env_var("_X1").is_ok());
        for bad in ["", "1PASSWORD", "MY-KEY", "A B", "A=B"] {
            assert!(validate_env_var(bad).is_err(), "`{bad}`");
        }

        assert!(validate_master_key("openai.prod-1").is_ok());
        for bad in ["", ".hidden", "../x", "a/b", "a b"] {
            assert!(validate_master_key(bad).is_err(), "`{bad}`");
        }

        assert!(validate_identifier("credential", "db").is_ok());
        for bad in ["", "@policy", "db.ro", "db ro"] {
            assert!(validate_identifier("credential", bad).is_err(), "`{bad}`");
        }

        assert_eq!(env_prefix("my-api"), "MY_API");
        assert_eq!(split_list(" psql, ,env "), ["psql", "env"]);
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
