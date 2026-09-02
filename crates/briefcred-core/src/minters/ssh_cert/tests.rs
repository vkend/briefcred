use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

use super::*;
use crate::registry::{Hosting, Registry};

/// A fresh CA private key in the OpenSSH PEM form a master source holds.
fn ca_key() -> Zeroizing<String> {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    Zeroizing::new(key.to_openssh(LineEnding::LF).unwrap().to_string())
}

fn config(yaml: &str) -> serde_yaml_ng::Value {
    serde_yaml_ng::from_str(yaml).unwrap()
}

const PRINCIPALS: &str = "principals: [ubuntu]\n";

/// A minter and the two directories it owns, kept alive by the returned dirs.
fn minter() -> (tempfile::TempDir, tempfile::TempDir, SshCertMinter) {
    let temp_root = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let minter = SshCertMinter::rooted(temp_root.path(), state.path());
    (temp_root, state, minter)
}

fn mint_ctx(config_yaml: &str, master: Zeroizing<String>) -> MintCtx {
    MintCtx {
        mint_id: MintId::generate(),
        profile: "dev".into(),
        credential: "bastion".into(),
        config: config(config_yaml),
        master,
        ttl: Duration::from_secs(900),
    }
}

#[test]
fn a_typo_in_the_config_is_refused_and_names_itself() {
    let err =
        SshCertConfig::from_value(&config("principals: [ubuntu]\nextentions: []\n")).unwrap_err();
    assert!(matches!(err, Error::MinterConfig { kind, .. } if kind == KIND));
    assert!(err.to_string().contains("extentions"), "{err}");
}

#[test]
fn a_certificate_with_no_principals_is_refused() {
    let err = SshCertConfig::from_value(&config("principals: []\n")).unwrap_err();
    assert!(err.to_string().contains("every user"), "{err}");
}

#[test]
fn a_principal_that_would_change_a_principals_file_is_refused() {
    for bad in ["", "ubuntu,root", "with space", "quote\"d"] {
        let yaml = format!("principals: [\"{}\"]\n", bad.replace('"', "\\\""));
        assert!(
            SshCertConfig::from_value(&config(&yaml)).is_err(),
            "`{bad}` must not be accepted as a principal"
        );
    }
}

#[test]
fn an_option_name_that_is_not_a_keyword_is_refused() {
    let err = SshCertConfig::from_value(&config(
        "principals: [ubuntu]\nextensions: [\"permit pty\"]\n",
    ))
    .unwrap_err();
    assert!(err.to_string().contains("option name"), "{err}");

    // Vendor-scoped names are how OpenSSH spells an extension nobody else
    // defines, and they are perfectly legal.
    SshCertConfig::from_value(&config(
        "principals: [ubuntu]\nextensions: [\"no-touch-required@openssh.com\"]\n",
    ))
    .unwrap();
}

#[test]
fn extensions_default_to_a_pty_and_an_empty_list_grants_none() {
    let defaulted = SshCertConfig::from_value(&config(PRINCIPALS)).unwrap();
    assert_eq!(defaulted.extensions(), vec!["permit-pty".to_string()]);

    let explicit =
        SshCertConfig::from_value(&config("principals: [ubuntu]\nextensions: []\n")).unwrap();
    assert!(explicit.extensions().is_empty());
}

#[test]
fn the_registry_resolves_the_kind_and_runs_it_in_the_daemon() {
    let registry = Registry::discover();
    assert!(registry.contains(KIND), "{registry:?}");
    assert_eq!(registry.hosting(KIND), Some(Hosting::Daemon));
    assert_eq!(
        registry.build(KIND, &config(PRINCIPALS)).unwrap().kind(),
        KIND
    );
}

#[test]
fn a_malformed_config_fails_at_build_rather_than_at_mint() {
    let err = Registry::discover()
        .build(KIND, &config("principals: []\n"))
        .unwrap_err();
    assert!(matches!(err, Error::MinterConfig { .. }), "{err}");
}

#[tokio::test]
async fn a_minted_certificate_validates_against_the_ca_that_signed_it() {
    let (_root, _state, minter) = minter();
    let master = ca_key();
    let ca = PrivateKey::from_openssh(master.as_bytes()).unwrap();

    let ctx = mint_ctx(
        "principals: [ubuntu, deploy]\nextensions: [permit-pty, permit-port-forwarding]\n",
        master.clone(),
    );
    let mint_id = ctx.mint_id.clone();
    let before = OffsetDateTime::now_utc();
    let minted = minter.mint(ctx).await.unwrap();

    let cert_path = minted.fields["SSH_CERT_FILE"].to_string();
    let certificate =
        Certificate::from_openssh(std::fs::read_to_string(&cert_path).unwrap().trim()).unwrap();

    let ca_fingerprint = ca.public_key().fingerprint(Default::default());
    certificate
        .validate_at(
            before.unix_timestamp() as u64,
            [&ca_fingerprint].into_iter(),
        )
        .expect("the certificate must validate against the CA that signed it");

    assert_eq!(certificate.key_id(), mint_id.as_str());
    assert_eq!(certificate.valid_principals(), ["ubuntu", "deploy"]);
    assert_ne!(certificate.serial(), 0, "a serial of 0 means `unnumbered`");
    // A range, not an equality: the mint reads its own clock, so a second
    // ticking over between `before` and the signature would fail an exact
    // comparison without anything being wrong.
    let after = OffsetDateTime::now_utc().unix_timestamp() as u64;
    let before = before.unix_timestamp() as u64;
    assert!(
        (before - CLOCK_SKEW_GRACE_SECS..=after - CLOCK_SKEW_GRACE_SECS)
            .contains(&certificate.valid_after()),
        "a minute of grace absorbs a server clock that is behind: {} not in {}..={}",
        certificate.valid_after(),
        before - CLOCK_SKEW_GRACE_SECS,
        after - CLOCK_SKEW_GRACE_SECS
    );
    assert!(
        (before + 900..=after + 900).contains(&certificate.valid_before()),
        "{} not in {}..={}",
        certificate.valid_before(),
        before + 900,
        after + 900
    );
    assert_eq!(
        minted.expires_at.unix_timestamp(),
        certificate.valid_before() as i64,
        "the daemon schedules the revoke off `expires_at`, so it must be the \
         moment the certificate stops working"
    );

    let extensions: Vec<&str> = certificate
        .extensions()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(extensions, ["permit-port-forwarding", "permit-pty"]);
}

#[tokio::test]
async fn a_minted_key_is_private_from_the_moment_it_exists() {
    let (_root, _state, minter) = minter();
    let ctx = mint_ctx(PRINCIPALS, ca_key());
    let dir = minter.mint_dir(&ctx.mint_id);
    let minted = minter.mint(ctx).await.unwrap();

    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700, "{}", dir.display());
    assert_eq!(mode(&dir.join(KEY_FILE)), 0o600);
    assert_eq!(mode(&dir.join(CERT_FILE)), 0o644);

    // And the key on disk is the one the certificate was issued for.
    let key = PrivateKey::from_openssh(std::fs::read(dir.join(KEY_FILE)).unwrap()).unwrap();
    let certificate =
        Certificate::from_openssh(std::fs::read_to_string(dir.join(CERT_FILE)).unwrap().trim())
            .unwrap();
    assert_eq!(certificate.public_key(), key.public_key().key_data());

    assert_eq!(
        minted.fields["GIT_SSH_COMMAND"].to_string(),
        format!(
            "ssh -i {} -o CertificateFile={}",
            dir.join(KEY_FILE).display(),
            dir.join(CERT_FILE).display()
        )
    );
    assert_eq!(
        minted.fields["SSH_IDENTITY_FILE"].to_string(),
        dir.join(KEY_FILE).display().to_string()
    );
}

#[tokio::test]
async fn an_encrypted_ca_key_is_refused_with_an_actionable_message() {
    let Some(ssh_keygen) = which_ssh_keygen() else {
        eprintln!("skipping: no `ssh-keygen` on PATH to make a passphrase-protected key with");
        return;
    };
    let (_root, _state, minter) = minter();
    // Written by OpenSSH itself rather than by this crate, so the refusal is
    // checked against the encrypted key an operator would actually have.
    let keys = tempfile::tempdir().unwrap();
    let key_path = keys.path().join("ca");
    let made = std::process::Command::new(&ssh_keygen)
        .args(["-q", "-t", "ed25519", "-N", "hunter2", "-C", "ca", "-f"])
        .arg(&key_path)
        .status()
        .unwrap();
    assert!(made.success());
    let master = Zeroizing::new(std::fs::read_to_string(&key_path).unwrap());

    let err = minter.mint(mint_ctx(PRINCIPALS, master)).await.unwrap_err();
    assert!(err.to_string().contains("passphrase"), "{err}");
}

#[tokio::test]
async fn a_master_that_is_not_a_private_key_is_refused_before_anything_is_written() {
    let (root, _state, minter) = minter();
    let err = minter
        .mint(mint_ctx(PRINCIPALS, Zeroizing::new("hunter2".into())))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("OpenSSH private key"), "{err}");
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn revoking_deletes_the_key_and_records_the_serial() {
    let (_root, state, minter) = minter();
    let master = ca_key();
    let ctx = mint_ctx(PRINCIPALS, master.clone());
    let mint_id = ctx.mint_id.clone();
    let dir = minter.mint_dir(&mint_id);
    let minted = minter.mint(ctx).await.unwrap();

    let serial =
        Certificate::from_openssh(std::fs::read_to_string(dir.join(CERT_FILE)).unwrap().trim())
            .unwrap()
            .serial();

    let outcome = minter
        .revoke(RevokeCtx {
            mint_id: mint_id.clone(),
            config: config(PRINCIPALS),
            master: master.clone(),
            revoke_token: minted.revoke_token.clone(),
        })
        .await;
    assert_eq!(outcome, RevokeOutcome::Revoked);
    assert!(!dir.exists(), "the private key must be gone");

    let krl = krl::read(&state.path().join(KRL_FILE)).unwrap();
    assert!(krl.contains(serial), "{krl:?}");

    // A second revoke of the same mint is `AlreadyGone`, and does not add the
    // serial twice.
    let again = minter
        .revoke(RevokeCtx {
            mint_id,
            config: config(PRINCIPALS),
            master,
            revoke_token: minted.revoke_token,
        })
        .await;
    assert_eq!(again, RevokeOutcome::AlreadyGone);
    assert_eq!(krl::read(&state.path().join(KRL_FILE)).unwrap().len(), 1);
}

#[tokio::test]
async fn a_revoke_token_naming_another_directory_is_refused_rather_than_obeyed() {
    let (_root, _state, minter) = minter();
    let victim = tempfile::tempdir().unwrap();
    let mint_id = MintId::generate();

    let outcome = minter
        .revoke(RevokeCtx {
            mint_id: mint_id.clone(),
            config: config(PRINCIPALS),
            master: ca_key(),
            revoke_token: serde_json::json!({ "serial": 9, "dir": victim.path() }).to_string(),
        })
        .await;

    assert!(
        matches!(outcome, RevokeOutcome::Failed { .. }),
        "{outcome:?}"
    );
    assert!(
        victim.path().exists(),
        "a revoke must never delete a path outside its own mint directory"
    );
}

#[tokio::test]
async fn an_unreadable_revoke_token_says_what_it_could_not_do() {
    let (_root, _state, minter) = minter();
    let outcome = minter
        .revoke(RevokeCtx {
            mint_id: MintId::generate(),
            config: config(PRINCIPALS),
            master: ca_key(),
            revoke_token: String::new(),
        })
        .await;
    match outcome {
        RevokeOutcome::Failed { detail } => {
            assert!(detail.contains("serial"), "{detail}");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn reconcile_sweeps_an_expired_mint_and_leaves_a_live_one_alone() {
    let (root, _state, minter) = minter();
    let master = ca_key();

    let mut live = mint_ctx(PRINCIPALS, master.clone());
    live.ttl = Duration::from_secs(3600);
    let live_id = live.mint_id.clone();
    minter.mint(live).await.unwrap();

    // A mint whose whole validity window is already behind us: `valid_after`
    // is `now - 60s` and the TTL is shorter than the grace, so it has expired
    // by the time it is written.
    let mut dead = mint_ctx(PRINCIPALS, master.clone());
    dead.ttl = Duration::from_secs(0);
    let dead_id = dead.mint_id.clone();
    minter.mint(dead).await.unwrap();

    // Something in the temp directory that is nothing to do with briefcred.
    let foreign = root.path().join("someone-elses-work");
    std::fs::create_dir(&foreign).unwrap();
    // And a briefcred-shaped directory with no certificate in it, which
    // briefcred cannot prove it created.
    let opaque = root
        .path()
        .join(format!("briefcred-{}", MintId::generate()));
    std::fs::create_dir(&opaque).unwrap();

    let report = minter
        .reconcile(ReconcileCtx {
            config: config(PRINCIPALS),
            master,
        })
        .await
        .unwrap();

    assert_eq!(report.revoked, vec![dead_id.clone()]);
    assert!(report.failed.is_empty(), "{report:?}");
    assert!(!minter.mint_dir(&dead_id).exists());
    assert!(
        minter.mint_dir(&live_id).exists(),
        "a live mint must survive"
    );
    assert!(
        foreign.exists(),
        "briefcred sweeps only its own directories"
    );
    assert!(opaque.exists(), "an unprovable directory is left alone");
}

#[tokio::test]
async fn reconcile_on_a_machine_that_has_minted_nothing_is_clean() {
    let state = tempfile::tempdir().unwrap();
    let minter = SshCertMinter::rooted(state.path().join("never-created"), state.path());
    let report = minter
        .reconcile(ReconcileCtx {
            config: config(PRINCIPALS),
            master: ca_key(),
        })
        .await
        .unwrap();
    assert!(report.is_clean(), "{report:?}");
}

#[test]
fn the_minter_never_debug_prints_anything_secret() {
    let (_root, _state, minter) = minter();
    let rendered = format!("{minter:?}");
    assert!(rendered.contains("SshCertMinter"), "{rendered}");
    assert!(!rendered.contains("BEGIN OPENSSH"), "{rendered}");
}

/// The whole point of the KRL is that `sshd` refuses a certificate listed in
/// it, so the file briefcred writes is checked against the real OpenSSH
/// implementation rather than only against briefcred's own reader.
#[tokio::test]
async fn openssh_agrees_that_a_revoked_certificate_is_revoked() {
    let Some(ssh_keygen) = which_ssh_keygen() else {
        eprintln!("skipping: no `ssh-keygen` on PATH to check the KRL against");
        return;
    };

    let (_root, state, minter) = minter();
    let master = ca_key();
    let ctx = mint_ctx(PRINCIPALS, master.clone());
    let mint_id = ctx.mint_id.clone();
    let minted = minter.mint(ctx).await.unwrap();

    // `revoke` deletes the mint directory, so the certificate is copied
    // somewhere that survives it — which is also how a certificate that leaked
    // before the revoke would still be presented to a server.
    let kept = tempfile::tempdir().unwrap();
    let cert_path = kept.path().join("cert.pub");
    std::fs::copy(minted.fields["SSH_CERT_FILE"].as_str(), &cert_path).unwrap();

    let krl_path = state.path().join(KRL_FILE);
    let query = || {
        std::process::Command::new(&ssh_keygen)
            .arg("-Q")
            .arg("-f")
            .arg(&krl_path)
            .arg(&cert_path)
            .output()
            .unwrap()
    };

    // An empty KRL first: this proves the file briefcred writes is one
    // OpenSSH parses at all, so a later "not revoked" cannot be a silently
    // unreadable file.
    krl::write(&krl_path, &krl::Krl::new()).unwrap();
    let before = query();
    assert!(
        before.status.success(),
        "an empty KRL must parse and revoke nothing: {}",
        String::from_utf8_lossy(&before.stderr)
    );

    let outcome = minter
        .revoke(RevokeCtx {
            mint_id,
            config: config(PRINCIPALS),
            master,
            revoke_token: minted.revoke_token,
        })
        .await;
    assert_eq!(outcome, RevokeOutcome::Revoked);

    let after = query();
    let stdout = String::from_utf8_lossy(&after.stdout).to_string();
    assert!(
        !after.status.success() && stdout.contains("REVOKED"),
        "ssh-keygen must report the revoked certificate: {stdout}{}",
        String::from_utf8_lossy(&after.stderr)
    );
}

fn which_ssh_keygen() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("ssh-keygen"))
        .find(|candidate| candidate.is_file())
}
