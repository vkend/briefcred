//! Running a minter inside the daemon.
//!
//! Almost every minter gets a helper process, because almost every minter
//! opens a network connection with a master credential and that is work the
//! daemon should not be doing in its own address space. A minter registered as
//! [`Hosting::Daemon`] is the exception: it talks to nothing, so a process of
//! its own would buy only the cost of one. `ssh-cert` is the case that exists.
//!
//! # Why this speaks the helper protocol
//!
//! An in-daemon minter answers [`HelperParams`] and returns
//! [`briefcred_proto::helper::HelperResult`], exactly as a helper process
//! does, so `crate::exec` and `crate::reconcile` have one code path rather
//! than two. Where a credential is minted is then a property of the
//! *registration*, not something every caller has to remember to branch on —
//! and a minter that later moves into a helper, or out of one, changes one
//! line of its own registration and nothing else.
//!
//! The conversion itself is [`briefcred_core::MinterAdapter`], shared with
//! every helper binary. All this module adds is the daemon's own failure type.
//!
//! [`Hosting::Daemon`]: briefcred_core::registry::Hosting::Daemon

use briefcred_core::registry::Registry;
use briefcred_core::MinterAdapter;
use briefcred_proto::helper::{HelperParams, HelperResult};

use crate::helper::{HelperFailure, MintChannel};

/// A minter the daemon runs itself, behind the helper protocol.
#[derive(Debug)]
pub struct InDaemonMinter {
    adapter: MinterAdapter,
}

impl InDaemonMinter {
    /// Build the minter `kind` from `config`, through the registry.
    ///
    /// The config is the credential's own, exactly as it reaches a helper.
    /// [`Registry::build`] validates it, so a credential whose config is wrong
    /// fails here rather than at the first mint — the same guarantee profile
    /// loading already gives, applied again because this is the other place a
    /// minter is constructed.
    pub fn build(
        kind: &str,
        config: &serde_yaml_ng::Value,
        registry: &Registry,
    ) -> Result<InDaemonMinter, HelperFailure> {
        let minter = registry
            .build(kind, config)
            .map_err(|e| HelperFailure::Refused {
                kind: kind.to_string(),
                source: briefcred_proto::helper::HelperError {
                    code: briefcred_proto::helper::CODE_BACKEND,
                    message: e.to_string(),
                },
            })?;
        Ok(InDaemonMinter {
            adapter: MinterAdapter::new(minter),
        })
    }
}

#[async_trait::async_trait]
impl MintChannel for InDaemonMinter {
    async fn call(&self, params: HelperParams) -> Result<HelperResult, HelperFailure> {
        self.adapter
            .dispatch(params)
            .await
            .map_err(|source| HelperFailure::Refused {
                kind: self.adapter.kind().to_string(),
                source,
            })
    }

    /// There is no process to stop.
    async fn stop(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use briefcred_core::minters::ssh_cert;
    use briefcred_core::types::MintId;
    use briefcred_proto::helper::{MintParams, ShutdownParams};
    use briefcred_proto::SecretString;

    fn ssh_cert_channel() -> InDaemonMinter {
        InDaemonMinter::build(
            ssh_cert::KIND,
            &serde_yaml_ng::from_str("principals: [ubuntu]\n").unwrap(),
            &Registry::discover(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn an_in_daemon_minter_answers_shutdown_without_a_process_to_stop() {
        let channel = ssh_cert_channel();
        let result = channel
            .call(HelperParams::Shutdown(ShutdownParams {}))
            .await
            .unwrap();
        assert!(matches!(result, HelperResult::Shutdown(_)), "{result:?}");
        channel.stop().await;
    }

    #[test]
    fn a_config_the_minter_rejects_fails_when_the_channel_is_built() {
        let err = InDaemonMinter::build(
            ssh_cert::KIND,
            &serde_yaml_ng::from_str("principals: []\n").unwrap(),
            &Registry::discover(),
        )
        .unwrap_err();
        assert!(matches!(err, HelperFailure::Refused { .. }), "{err}");
    }

    #[test]
    fn a_kind_whose_implementation_lives_in_a_helper_cannot_be_run_here() {
        // `aws-sts` registers its schema in the daemon and its minter in
        // `briefcred-helper-aws-sts`. Asking the daemon to run it must say so
        // rather than produce something that fails later.
        let err = InDaemonMinter::build(
            briefcred_core::minters::aws_sts::KIND,
            &serde_yaml_ng::from_str(
                "role_arn: arn:aws:iam::123456789012:role/dev\nregion: eu-west-1\n",
            )
            .unwrap(),
            &Registry::discover(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("briefcred-helper-aws-sts"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_backend_failure_comes_back_as_a_refusal_naming_the_kind() {
        // A master that is not an OpenSSH private key: the minter's own error,
        // surfaced through the channel rather than swallowed.
        let err = ssh_cert_channel()
            .call(HelperParams::Mint(MintParams {
                mint_id: MintId::generate().as_str().to_string(),
                profile: "dev".into(),
                credential: "bastion".into(),
                config: serde_json::json!({ "principals": ["ubuntu"] }),
                master: SecretString::new("hunter2"),
                ttl_secs: 900,
            }))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains(ssh_cert::KIND), "{text}");
        assert!(text.contains("OpenSSH private key"), "{text}");
        assert!(
            !text.contains("hunter2"),
            "a master must not reach an error"
        );
    }

    #[test]
    fn the_channel_never_debug_prints_a_config_or_a_master() {
        assert_eq!(
            format!("{:?}", ssh_cert_channel()),
            "InDaemonMinter { adapter: MinterAdapter { kind: \"ssh-cert\" } }"
        );
    }
}
