//! `proxy: always` on a profile that mints nothing: briefcred as an egress
//! control.
//!
//! The profile here declares no credential at all. There is nothing to swap
//! into a header and nothing the subprocess could leak, and the entire value of
//! routing through briefcred is the Cedar policy deciding which hosts the
//! command may reach. That still needs a token — a token is how the proxy knows
//! whose session, whose policy and whose quota a request belongs to — so `exec`
//! issues one that names no credential, and publishes it as
//! `BRIEFCRED_PROXY_TOKEN`.
//!
//! The requests are made by a real `curl`, over plain HTTP so the CA is not in
//! the picture, against a plaintext upstream in this process. Two hostnames for
//! the same loopback listener — `127.0.0.1` and `localhost` — is what lets one
//! policy permit one and deny the other with everything else held equal.

use std::sync::Arc;

use briefcred_e2e::daemon_harness::Daemon;
use briefcred_proto::{Request, Response};

/// The host the policy permits.
const ALLOWED: &str = "127.0.0.1";

/// The host the policy does not mention, and so denies.
const DENIED: &str = "localhost";

/// A plaintext HTTP upstream that answers everything with `ok`.
struct Upstream {
    port: u16,
    accepting: tokio::task::JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

async fn start_upstream() -> Upstream {
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::service::service_fn;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepting = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(stream),
                        service_fn(|_req| async move {
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                Bytes::from_static(b"ok"),
                            )))
                        }),
                    )
                    .await;
            });
        }
    });
    Upstream { port, accepting }
}

fn profile(port: u16) -> String {
    format!(
        "\
name: egress
unlock:
  policy: none
proxy: always
policy_mode: enforce
policy: |
  permit(principal, action == Action::\"GET\", resource)
  when {{ resource.host == \"{ALLOWED}\" }};
"
    )
    .replace("{port}", &port.to_string())
}

/// A daemon, a session, and the environment one `exec` produced.
struct Fixture {
    daemon: Daemon,
    env: std::collections::BTreeMap<String, String>,
    _upstream: Arc<Upstream>,
    port: u16,
}

async fn start() -> Fixture {
    let upstream = Arc::new(start_upstream().await);
    let daemon = Daemon::prepare(
        "metrics_enabled = false\nmetrics_port = 0\nproxy_port = 0\npg_proxy_port = 0\n\
         master_source = \"file\"\n[ca]\nkeystore = \"file\"\n",
    );
    daemon.write_profile("egress", &profile(upstream.port));

    let mut daemon = daemon;
    daemon.start().await.unwrap_or_else(|e| panic!("{e}"));

    let Response::SessionOpened { session_id, .. } = daemon
        .request(Request::OpenSession {
            profile: "egress".to_string(),
            client_headless: true,
            session_pubkey: None,
        })
        .await
        .unwrap()
    else {
        panic!("the session did not open:\n{}", daemon.log());
    };

    let Response::Minted { mints, env, .. } = daemon
        .request(Request::Exec {
            session_id,
            credentials: None,
            argv0: "curl".to_string(),
            args: Vec::new(),
            pid: std::process::id(),
        })
        .await
        .unwrap()
    else {
        panic!("the exec was refused:\n{}", daemon.log());
    };

    assert_eq!(
        mints.len(),
        0,
        "a policy-only profile mints no credential; the grant is not one"
    );

    Fixture {
        daemon,
        env: env
            .into_iter()
            .map(|(k, v)| (k, v.expose().to_string()))
            .collect(),
        port: upstream.port,
        _upstream: upstream,
    }
}

impl Fixture {
    /// `curl` to `host`, with exactly the environment `exec` handed back.
    async fn curl(&self, host: &str) -> std::process::Output {
        let token = self
            .env
            .get("BRIEFCRED_PROXY_TOKEN")
            .expect("exec must publish a proxy token for a `proxy: always` profile");
        let mut command = tokio::process::Command::new("curl");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args(["-sS", "-o", "/dev/null", "-w", "%{http_code}"])
            // Presented the way a proxy credential is: the proxy reads the
            // token out of whichever header carries it.
            .args(["-H", &format!("Proxy-Authorization: Bearer {token}")])
            .arg(format!("http://{host}:{}/v1/models", self.port));
        for (name, value) in &self.env {
            command.env(name, value);
        }
        command.output().await.expect("curl runs")
    }
}

#[tokio::test]
async fn the_policy_decides_which_hosts_a_credential_less_profile_may_reach() {
    let fixture = start().await;

    let allowed = fixture.curl(ALLOWED).await;
    assert_eq!(
        String::from_utf8_lossy(&allowed.stdout).trim(),
        "200",
        "the permitted host must be reachable: {}\n{}",
        String::from_utf8_lossy(&allowed.stderr),
        fixture.daemon.log()
    );

    let denied = fixture.curl(DENIED).await;
    assert_eq!(
        String::from_utf8_lossy(&denied.stdout).trim(),
        "403",
        "a host the policy does not permit must be refused: {}\n{}",
        String::from_utf8_lossy(&denied.stderr),
        fixture.daemon.log()
    );
}

#[tokio::test]
async fn the_environment_points_at_the_proxy_and_carries_no_credential() {
    let fixture = start().await;

    for name in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"] {
        assert!(
            fixture.env.contains_key(name),
            "`proxy: always` must set {name}: {:?}",
            fixture.env.keys().collect::<Vec<_>>()
        );
    }
    let token = &fixture.env["BRIEFCRED_PROXY_TOKEN"];
    assert!(
        token.starts_with("bc."),
        "the policy grant is a synthetic token"
    );

    // Nothing else in the environment is secret, because there is nothing else:
    // the profile declares no credential, so no substitution can happen and no
    // master is anywhere near this run.
    for (name, value) in &fixture.env {
        assert!(
            !value.contains("__"),
            "{name} looks like an unsubstituted placeholder: {value}"
        );
    }
}
