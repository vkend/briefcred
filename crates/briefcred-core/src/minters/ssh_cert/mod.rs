//! Short-lived OpenSSH user certificates.
//!
//! Mint generates a fresh ed25519 keypair, signs a user certificate for it
//! with the profile's certificate authority, and writes both to a private
//! directory the subprocess is pointed at. Nothing is created at a server:
//! the certificate *is* the credential, and it stops working when its
//! `valid_before` passes.
//!
//! # Why this one runs in the daemon
//!
//! Every other minter talks to a backend over the network with a master
//! credential, so it is given its own process — a helper — and the daemon
//! never holds the master. This minter talks to nothing. Its whole job is
//! arithmetic on a signature, and giving it a process of its own would buy
//! only the cost of one. It is registered as
//! [`crate::registry::Hosting::Daemon`] and the daemon runs it in-process.
//!
//! The consequence is real and is recorded in `THREAT_MODEL.md`: the CA
//! private key is in the daemon's address space for the length of a mint,
//! where a Postgres master never is.
//!
//! # Revocation
//!
//! A signed certificate cannot be recalled. Revoking one means two things:
//! deleting the private key from this machine, so nothing here can use it
//! again, and adding its serial to the key revocation list in
//! [`crate::paths::Paths::state_dir`], so a server configured to read that
//! list refuses it. The second half only takes effect on servers an operator
//! has actually pointed at the file; `docs/ssh-krl.md` says how, and the
//! outcome is [`RevokeOutcome::Revoked`] because the half briefcred owns —
//! the key on this machine — is genuinely gone.

pub mod krl;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use ssh_key::certificate::{Builder, CertType};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, Certificate, LineEnding, PrivateKey};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::paths::{ensure_private_dir, Paths};
use crate::traits::Minter;
use crate::types::{
    MintCtx, MintId, MintedCredential, ReconcileCtx, ReconcileReport, RevokeCtx, RevokeOutcome,
};

/// The `kind` string profiles use to select this minter.
pub const KIND: &str = "ssh-cert";

/// The file name of the key revocation list, under the state directory.
pub const KRL_FILE: &str = "ssh-krl";

/// The private key's file name inside the mint's directory.
///
/// The certificate's name is this plus `-cert.pub`, which is the pairing
/// OpenSSH looks for on its own when it is given only the key.
pub const KEY_FILE: &str = "id_ed25519";

/// The certificate's file name inside the mint's directory.
pub const CERT_FILE: &str = "id_ed25519-cert.pub";

/// How far before now a certificate becomes valid.
///
/// A certificate stamped `valid_after = now` is refused by a server whose
/// clock is a second behind this machine's, which is a failure that looks like
/// a permissions problem and is diagnosed as one for an hour. A minute of
/// grace costs nothing: the certificate's *end* is what bounds its usefulness.
pub const CLOCK_SKEW_GRACE_SECS: u64 = 60;

/// The certificate extensions a profile gets when it names none.
///
/// Just a pty. An SSH certificate with no extensions at all cannot open an
/// interactive shell, which is a confusing thing to hand somebody; everything
/// beyond that — port forwarding, agent forwarding — is a capability a profile
/// should have to ask for. `examples/profiles/kubectl-bastion.yaml` is the
/// worked example of asking.
pub const DEFAULT_EXTENSIONS: &[&str] = &["permit-pty"];

/// The `config` block of an `ssh-cert` credential spec.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshCertConfig {
    /// The usernames the certificate is valid for, as `sshd` matches them.
    ///
    /// A certificate with no principals is valid for *every* user on every
    /// host that trusts the CA, so briefcred requires at least one.
    pub principals: Vec<String>,

    /// OpenSSH certificate extensions to grant, for example
    /// `permit-port-forwarding`. Defaults to [`DEFAULT_EXTENSIONS`]; an
    /// explicit empty list grants none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,

    /// OpenSSH critical options to impose, for example
    /// `source-address` or `force-command`.
    ///
    /// A server that does not understand a critical option refuses the
    /// certificate outright, which is what makes these the right place for a
    /// restriction that must not be silently dropped.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub critical_options: BTreeMap<String, String>,
}

impl SshCertConfig {
    /// Interpret a credential spec's `config` block.
    pub fn from_value(value: &serde_yaml::Value) -> Result<SshCertConfig> {
        let config: SshCertConfig =
            serde_yaml::from_value(value.clone()).map_err(|e| Error::MinterConfig {
                kind: KIND,
                message: e.to_string(),
            })?;
        config.validate()?;
        Ok(config)
    }

    /// The extensions this config asks for, applying the default.
    pub fn extensions(&self) -> Vec<String> {
        match &self.extensions {
            Some(explicit) => explicit.clone(),
            None => DEFAULT_EXTENSIONS.iter().map(|e| e.to_string()).collect(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.principals.is_empty() {
            return Err(config_error(
                "`principals` must name at least one user; a certificate with \
                 none is valid for every user on every host that trusts the CA",
            ));
        }
        for principal in &self.principals {
            if !is_principal(principal) {
                return Err(config_error(format!(
                    "principal `{principal}` must be a non-empty run of printable \
                     characters with no comma, quote, or whitespace"
                )));
            }
        }
        for extension in self.extensions() {
            if !is_option_name(&extension) {
                return Err(config_error(format!(
                    "extension `{extension}` must be an OpenSSH option name: \
                     lowercase letters, digits, `-`, `.`, and an optional `@domain`"
                )));
            }
        }
        for name in self.critical_options.keys() {
            if !is_option_name(name) {
                return Err(config_error(format!(
                    "critical option `{name}` must be an OpenSSH option name: \
                     lowercase letters, digits, `-`, `.`, and an optional `@domain`"
                )));
            }
        }
        Ok(())
    }
}

/// A principal is written into the certificate and compared byte for byte by
/// `sshd`, but it is also written into `authorized_principals` files and
/// `principals=` lists by hand, where a comma or a quote changes the meaning.
fn is_principal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .chars()
            .all(|c| c.is_ascii_graphic() && !matches!(c, ',' | '"' | '\'' | '\\'))
}

/// OpenSSH option names are keywords, optionally vendor-scoped with `@domain`.
fn is_option_name(value: &str) -> bool {
    let (name, domain) = match value.split_once('@') {
        Some((name, domain)) => (name, Some(domain)),
        None => (value, None),
    };
    let keyword = |part: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
    };
    keyword(name) && domain.is_none_or(keyword)
}

fn config_error(message: impl Into<String>) -> Error {
    Error::MinterConfig {
        kind: KIND,
        message: message.into(),
    }
}

/// The state a mint records so its revoke is exactly symmetric.
///
/// The serial cannot be recomputed — it is random — and the directory must not
/// be recomputed, because a profile edited between the mint and the revoke
/// would send the delete somewhere else.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RevokeToken {
    serial: u64,
    dir: PathBuf,
}

/// Mints short-lived OpenSSH user certificates.
#[derive(Debug, Default)]
pub struct SshCertMinter {
    /// Where mint directories are created. `None` means the system temporary
    /// directory, which is what everything but a test wants.
    temp_root: Option<PathBuf>,
    /// Where the key revocation list lives. `None` means
    /// [`Paths::state_dir`], resolved when it is needed.
    state_dir: Option<PathBuf>,
}

impl SshCertMinter {
    /// The minter as the daemon runs it, using the real filesystem layout.
    pub fn new() -> SshCertMinter {
        SshCertMinter::default()
    }

    /// A minter rooted at explicit directories, for tests.
    pub fn rooted(temp_root: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> SshCertMinter {
        SshCertMinter {
            temp_root: Some(temp_root.into()),
            state_dir: Some(state_dir.into()),
        }
    }

    fn temp_root(&self) -> PathBuf {
        self.temp_root.clone().unwrap_or_else(std::env::temp_dir)
    }

    fn krl_path(&self) -> Result<PathBuf> {
        let dir = match &self.state_dir {
            Some(dir) => dir.clone(),
            None => Paths::discover()?.state_dir(),
        };
        Ok(dir.join(KRL_FILE))
    }

    /// The directory one mint's key and certificate live in.
    pub fn mint_dir(&self, mint_id: &MintId) -> PathBuf {
        self.temp_root().join(format!("briefcred-{mint_id}"))
    }
}

// Registered next to the implementation, and marked as running inside the
// daemon rather than in a helper: see the module documentation for why this
// minter is the exception.
inventory::submit! {
    crate::registry::MinterFactory {
        kind: KIND,
        hosting: crate::registry::Hosting::Daemon,
        validate: |config| {
            SshCertConfig::from_value(config)?;
            Ok(())
        },
        construct: Some(|| std::sync::Arc::new(SshCertMinter::new())),
    }
}

#[async_trait]
impl Minter for SshCertMinter {
    fn kind(&self) -> &'static str {
        KIND
    }

    async fn mint(&self, ctx: MintCtx) -> Result<MintedCredential> {
        let config = SshCertConfig::from_value(&ctx.config)?;
        let ca = PrivateKey::from_openssh(ctx.master.as_bytes()).map_err(|e| {
            Error::Ssh(format!(
                "the master for this credential is not an OpenSSH private key: {e}"
            ))
        })?;
        if ca.is_encrypted() {
            return Err(Error::Ssh(
                "the CA private key is passphrase-encrypted; briefcred has no passphrase to \
                 give it. Store a key with no passphrase, protected by the platform key store."
                    .into(),
            ));
        }

        let now = OffsetDateTime::now_utc();
        let valid_after = now - std::time::Duration::from_secs(CLOCK_SKEW_GRACE_SECS);
        let expires_at = now + ctx.ttl;
        let serial = random_serial();

        let subject = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .map_err(|e| Error::Ssh(format!("cannot generate a key pair: {e}")))?;

        let mut builder = Builder::new_with_random_nonce(
            &mut OsRng,
            subject.public_key().key_data().clone(),
            unix_seconds(valid_after)?,
            unix_seconds(expires_at)?,
        )
        .map_err(|e| Error::Ssh(format!("cannot start a certificate: {e}")))?;
        builder
            .serial(serial)
            .and_then(|b| b.cert_type(CertType::User))
            .and_then(|b| b.key_id(ctx.mint_id.as_str()))
            .map_err(|e| Error::Ssh(format!("cannot set a certificate field: {e}")))?;
        for principal in &config.principals {
            builder
                .valid_principal(principal.clone())
                .map_err(|e| Error::Ssh(format!("cannot add principal `{principal}`: {e}")))?;
        }
        for extension in config.extensions() {
            builder
                .extension(extension.clone(), "")
                .map_err(|e| Error::Ssh(format!("cannot add extension `{extension}`: {e}")))?;
        }
        for (name, value) in &config.critical_options {
            builder
                .critical_option(name.clone(), value.clone())
                .map_err(|e| Error::Ssh(format!("cannot add critical option `{name}`: {e}")))?;
        }
        let certificate = builder
            .sign(&ca)
            .map_err(|e| Error::Ssh(format!("the CA could not sign the certificate: {e}")))?;

        let dir = self.mint_dir(&ctx.mint_id);
        let (key_path, cert_path) = write_identity(&dir, &subject, &certificate)?;

        let mut fields: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
        fields.insert(
            "SSH_IDENTITY_FILE".into(),
            Zeroizing::new(key_path.display().to_string()),
        );
        fields.insert(
            "SSH_CERT_FILE".into(),
            Zeroizing::new(cert_path.display().to_string()),
        );
        fields.insert(
            "GIT_SSH_COMMAND".into(),
            Zeroizing::new(format!(
                "ssh -i {} -o CertificateFile={}",
                key_path.display(),
                cert_path.display()
            )),
        );

        let revoke_token = serde_json::to_string(&RevokeToken {
            serial,
            dir: dir.clone(),
        })
        .map_err(|e| Error::Ssh(format!("cannot encode the revoke token: {e}")))?;

        Ok(MintedCredential {
            mint_id: ctx.mint_id,
            fields,
            expires_at,
            revoke_token,
        })
    }

    async fn revoke(&self, ctx: RevokeCtx) -> RevokeOutcome {
        // The token crossed a persistence boundary, so it is not trusted
        // input. Without one there is no serial to revoke and no directory
        // this revoke may delete, and guessing either would be worse than
        // saying so.
        let token: RevokeToken = match serde_json::from_str(&ctx.revoke_token) {
            Ok(token) => token,
            Err(e) => {
                return RevokeOutcome::failed(format!(
                    "the revoke token for `{}` is unreadable ({e}), so neither its key \
                     directory nor its serial is known",
                    ctx.mint_id
                ))
            }
        };
        // A token that names a directory somewhere else entirely is a token
        // that has been tampered with, and a revoke is not a licence to delete
        // an arbitrary path.
        if token.dir != self.mint_dir(&ctx.mint_id) {
            return RevokeOutcome::failed(format!(
                "the revoke token for `{}` names `{}`, which is not where that mint's \
                 key would have been written",
                ctx.mint_id,
                token.dir.display()
            ));
        }

        let existed = token.dir.exists();
        if let Err(e) = remove_dir(&token.dir) {
            return RevokeOutcome::failed(e.to_string());
        }

        let path = match self.krl_path() {
            Ok(path) => path,
            Err(e) => return RevokeOutcome::failed(e.to_string()),
        };
        if let Err(e) = krl::revoke_serial(&path, token.serial) {
            return RevokeOutcome::failed(format!(
                "the private key is deleted but serial {} could not be added to {}: {e}",
                token.serial,
                path.display()
            ));
        }

        // `AlreadyGone` is reserved for "there was nothing to remove". The
        // serial still had to reach the KRL, so it is recorded either way.
        if existed {
            RevokeOutcome::Revoked
        } else {
            RevokeOutcome::AlreadyGone
        }
    }

    /// Delete key directories left behind by a daemon that was killed.
    ///
    /// The revoke queue is the fast path. A `SIGKILL` mid-`exec` never runs
    /// it, and what survives is a directory holding a usable private key and
    /// the certificate that makes it usable — which is worse than a leaked
    /// database role, because nothing at a server expires it early.
    ///
    /// A directory is swept only when its name parses as a [`MintId`] *and*
    /// the certificate inside it has passed its `valid_before`. The expiry
    /// check is what keeps the sweep from deleting a key another live `exec`
    /// is in the middle of using. A directory whose certificate cannot be read
    /// is left alone: briefcred does not delete a path it cannot prove it
    /// created.
    async fn reconcile(&self, _ctx: ReconcileCtx) -> Result<ReconcileReport> {
        let root = self.temp_root();
        let mut report = ReconcileReport::default();
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(report),
            Err(source) => return Err(Error::Io { path: root, source }),
        };

        let now = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
        for entry in entries.flatten() {
            let Some(mint_id) = mint_id_of(&entry.file_name()) else {
                continue;
            };
            let dir = entry.path();
            let Ok(certificate) = std::fs::read_to_string(dir.join(CERT_FILE)) else {
                continue;
            };
            let Ok(certificate) = Certificate::from_openssh(certificate.trim()) else {
                continue;
            };
            if certificate.valid_before() > now {
                continue;
            }
            match remove_dir(&dir) {
                Ok(()) => report.revoked.push(mint_id),
                Err(e) => report.failed.push((mint_id, e.to_string())),
            }
        }
        report.revoked.sort();
        report.failed.sort();
        Ok(report)
    }
}

/// The [`MintId`] a mint directory is named for, if it is one.
fn mint_id_of(name: &std::ffi::OsStr) -> Option<MintId> {
    name.to_str()?.strip_prefix("briefcred-")?.parse().ok()
}

/// Write the key pair and its certificate into a fresh private directory.
///
/// The directory is `0700` and the private key `0600` before either has any
/// content: [`ensure_private_dir`] creates the directory with its mode, and
/// the key is written through a handle opened with `0600`, so there is no
/// instant at which a readable file holds a private key.
fn write_identity(
    dir: &Path,
    subject: &PrivateKey,
    certificate: &Certificate,
) -> Result<(PathBuf, PathBuf)> {
    ensure_private_dir(dir)?;
    let key_path = dir.join(KEY_FILE);
    let cert_path = dir.join(CERT_FILE);

    let pem = subject
        .to_openssh(LineEnding::LF)
        .map_err(|e| Error::Ssh(format!("cannot encode the private key: {e}")))?;
    write_mode(&key_path, pem.as_bytes(), 0o600)?;

    let mut openssh = certificate
        .to_openssh()
        .map_err(|e| Error::Ssh(format!("cannot encode the certificate: {e}")))?;
    openssh.push('\n');
    write_mode(&cert_path, openssh.as_bytes(), 0o644)?;

    Ok((key_path, cert_path))
}

/// Create `path` with exactly `mode` and write `bytes` to it.
fn write_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let io = |source| Error::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    // An existing file keeps its old mode, so it is set explicitly as well.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(io)
}

/// Remove a mint directory, treating an absent one as success.
fn remove_dir(dir: &Path) -> Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::Io {
            path: dir.to_path_buf(),
            source,
        }),
    }
}

/// A random, non-zero certificate serial.
///
/// Zero is what a certificate signed without a serial carries, so a zero
/// serial in a revocation list would be indistinguishable from "every
/// certificate nobody bothered to number".
fn random_serial() -> u64 {
    let mut bytes = [0u8; 8];
    loop {
        getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable");
        let serial = u64::from_be_bytes(bytes);
        if serial != 0 {
            return serial;
        }
    }
}

fn unix_seconds(at: OffsetDateTime) -> Result<u64> {
    u64::try_from(at.unix_timestamp())
        .map_err(|_| Error::Ssh(format!("{at} is before the Unix epoch")))
}

#[cfg(test)]
mod tests;
