//! The CA proved end to end: a real TLS server holding a briefcred-issued
//! leaf, and the system `curl` accepting it against `ca.pem`.
//!
//! Every other CA test verifies the chain with the same rustls that built it,
//! which cannot catch a certificate that is well-formed only by briefcred's
//! own reckoning. This one hands the certificate to a program that was never
//! told about briefcred and checks that it is satisfied.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use briefcred_core::ca::CertificateAuthority;
use briefcred_core::keystore::FileKeyStore;
use briefcred_core::paths::{Paths, Platform};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// What the test server answers with, and what `curl` must print.
const BODY: &str = "briefcred ca works";

fn paths_at(root: &Path) -> Paths {
    let root = root.to_path_buf();
    Paths::resolve(Platform::MacOs, &move |key| {
        (key == "BRIEFCRED_HOME").then(|| OsString::from(root.as_os_str()))
    })
    .unwrap()
}

/// Whether the system has a `curl` to test against.
fn have_curl() -> bool {
    Command::new("curl")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

fn server_config(ca: &CertificateAuthority) -> ServerConfig {
    let leaf = ca.issue_leaf(&["localhost".to_string()]).unwrap();

    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(leaf.cert_pem().as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_slice(leaf.key_pem().as_bytes()).unwrap();

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("the leaf and its key must match")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn curl_accepts_an_issued_leaf_against_the_briefcred_ca() {
    if !have_curl() {
        println!("skipping: no curl on this machine");
        return;
    }
    // The process-wide crypto provider is installed once; a second call in
    // another test in this binary is an error, not a problem.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(temp.path());
    paths.ensure_layout().unwrap();
    let store = FileKeyStore::new(paths.ca_dir());
    let (ca, generated) = CertificateAuthority::ensure(&paths, &store, "mac.local").unwrap();
    assert!(generated);

    let acceptor = TlsAcceptor::from(Arc::new(server_config(&ca)));
    // Loopback only, and on a port the OS picks, so the test cannot collide
    // with anything the developer is running.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("the handshake must hold");
        // Read the request line and headers, then answer. `curl` will not
        // look at the body until it has finished sending its request.
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            if tls.read_exact(&mut byte).await.is_err() {
                break;
            }
            request.push(byte[0]);
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
            BODY.len()
        );
        tls.write_all(response.as_bytes()).await.unwrap();
        tls.shutdown().await.ok();
    });

    let url = format!("https://localhost:{port}/");
    println!(
        "curl --resolve localhost:{port}:127.0.0.1 --cacert {} {url}",
        paths.ca_cert().display()
    );
    let output = tokio::task::spawn_blocking(move || {
        Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                // The leaf is for `localhost`, so that is the name curl must
                // verify; `--resolve` keeps it on the loopback address the
                // server actually bound rather than whatever DNS says.
                "--resolve",
                &format!("localhost:{port}:127.0.0.1"),
                "--cacert",
            ])
            .arg(paths.ca_cert())
            .arg(&url)
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    server.await.unwrap();

    assert!(
        output.status.success(),
        "curl exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), BODY);
    println!(
        "curl exited 0 and read: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn curl_rejects_the_same_leaf_without_the_briefcred_ca() {
    if !have_curl() {
        println!("skipping: no curl on this machine");
        return;
    }
    // The negative half of the demo: `curl` succeeding above must be because
    // of `--cacert`, not because it trusts anything a local server offers.
    let temp = tempfile::tempdir().unwrap();
    let paths = paths_at(temp.path());
    paths.ensure_layout().unwrap();
    let store = FileKeyStore::new(paths.ca_dir());
    let (ca, _) = CertificateAuthority::ensure(&paths, &store, "mac.local").unwrap();

    // An unrelated CA's certificate, which the leaf does not chain to.
    let stranger = CertificateAuthority::generate("other.local").unwrap();
    let stranger_pem = temp.path().join("stranger.pem");
    std::fs::write(&stranger_pem, stranger.cert_pem()).unwrap();

    let leaf_pem = temp.path().join("leaf.pem");
    std::fs::write(
        &leaf_pem,
        ca.issue_leaf(&["localhost".to_string()])
            .unwrap()
            .cert_pem(),
    )
    .unwrap();

    // `curl` has no offline verify mode, so check the same thing the way the
    // platform does: the leaf must not validate against the wrong root.
    let output = Command::new("openssl")
        .args(["verify", "-CAfile"])
        .arg(&stranger_pem)
        .arg(&leaf_pem)
        .output();
    let Ok(output) = output else {
        println!("skipping: no openssl on this machine");
        return;
    };
    assert!(
        !output.status.success(),
        "a leaf must not verify against an unrelated CA: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
