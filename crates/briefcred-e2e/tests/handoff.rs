//! `briefcred daemon upgrade`, end to end, with a stream running through it.
//!
//! Every other way of replacing a daemon closes its sockets. The claim this
//! file exists to check is that this one does not: an event stream that was
//! open before the upgrade is still open after it, every byte arrives, the
//! ports do not move, and the session that was open on the old daemon is open
//! on the new one.
//!
//! The upstream here is plain HTTP rather than the TLS one `proxy.rs` stands
//! up. What is under test is continuity across the swap, and a `CONNECT`
//! tunnel would add a certificate authority, a handshake and a second listener
//! to a test whose subject is none of those.

use std::sync::Arc;
use std::time::Duration;

use briefcred_e2e::daemon_harness::{binary_dir, Daemon};
use briefcred_proto::{Request, Response};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

/// How many events the upstream sends, and how far apart.
///
/// A whole second of stream, so the upgrade lands squarely in the middle of it
/// rather than racing the first or last event.
const EVENTS: usize = 100;
const GAP: Duration = Duration::from_millis(10);

/// The host the profile's policy names, and the only one it permits.
const UPSTREAM_HOST: &str = "127.0.0.1";

/// The real credential. It must never leave the daemon.
const REAL_KEY: &str = "sk-the-real-upstream-key";

fn profile() -> String {
    format!(
        "\
name: openai
unlock:
  policy: none
credentials:
  - name: openai
    kind: http-bearer
    ttl_secs: 300
policy_mode: enforce
policy: |
  permit(principal, action == Action::\"GET\", resource)
  when {{ resource.host == \"{UPSTREAM_HOST}\" &&
    [\"/events\", \"/hello\", \"/ws\"].contains(resource.path) }};
env:
  OPENAI_API_KEY: ${{minted.openai.TOKEN}}
"
    )
}

// ------------------------------------------------------------------ upstream

/// A plain-HTTP upstream serving one event stream and one small body.
///
/// Hand-written rather than `hyper`: the responses are two fixed shapes, and
/// what the test needs from them — an event every ten milliseconds, written and
/// flushed one at a time — is easier to be sure of when the bytes are right
/// here in the test.
struct Upstream {
    port: u16,
    /// What each request arrived carrying, so the test can prove the real key
    /// was attached and the token was not.
    seen: Arc<std::sync::Mutex<Vec<String>>>,
    #[allow(dead_code)]
    accepting: tokio::task::JoinHandle<()>,
}

async fn start_upstream() -> Upstream {
    let listener = tokio::net::TcpListener::bind((UPSTREAM_HOST, 0))
        .await
        .expect("bind the upstream");
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));

    let accepting = tokio::spawn({
        let seen = Arc::clone(&seen);
        async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    // Peeked rather than read, so a WebSocket handshake can be
                    // handed to `tokio-tungstenite` whole: it parses the
                    // request itself, and a stream this test had already read
                    // the request line off would be one it could not accept.
                    let mut head = [0u8; 16];
                    if stream.peek(&mut head).await.is_err() {
                        return;
                    }
                    if head.starts_with(b"GET /ws") {
                        use futures_util::SinkExt as _;
                        seen.lock().unwrap().push(String::new());
                        let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await else {
                            return;
                        };
                        for n in 1..=EVENTS {
                            if socket
                                .send(tokio_tungstenite::tungstenite::Message::Text(
                                    n.to_string().into(),
                                ))
                                .await
                                .is_err()
                            {
                                return;
                            }
                            tokio::time::sleep(GAP).await;
                        }
                        let _ = socket.close(None).await;
                        return;
                    }

                    let (read, mut write) = stream.into_split();
                    let mut lines = tokio::io::BufReader::new(read).lines();

                    let Ok(Some(request_line)) = lines.next_line().await else {
                        return;
                    };
                    let mut authorization = String::new();
                    while let Ok(Some(line)) = lines.next_line().await {
                        if line.is_empty() {
                            break;
                        }
                        if let Some(value) = line.strip_prefix("authorization: ") {
                            authorization = value.trim().to_string();
                        }
                    }
                    seen.lock().unwrap().push(authorization);

                    if request_line.starts_with("GET /events") {
                        let _ = write
                            .write_all(
                                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
                                  cache-control: no-cache\r\nconnection: close\r\n\r\n",
                            )
                            .await;
                        let _ = write.flush().await;
                        for n in 1..=EVENTS {
                            if write
                                .write_all(format!("data: {n}\n\n").as_bytes())
                                .await
                                .is_err()
                            {
                                return;
                            }
                            let _ = write.flush().await;
                            tokio::time::sleep(GAP).await;
                        }
                    } else {
                        let _ = write
                            .write_all(
                                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\
                                  connection: close\r\n\r\nhi",
                            )
                            .await;
                        let _ = write.flush().await;
                    }
                });
            }
        }
    });

    Upstream {
        port,
        seen,
        accepting,
    }
}

// -------------------------------------------------------------------- client

/// Ask the proxy for `path` in absolute-URI form, exactly as an `HTTP_PROXY`
/// client does, and read the response as it arrives.
async fn open_stream(
    proxy_addr: &str,
    upstream_port: u16,
    path: &str,
    token: &str,
) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect to the proxy");
    let request = format!(
        "GET http://{UPSTREAM_HOST}:{upstream_port}{path} HTTP/1.1\r\n\
         host: {UPSTREAM_HOST}:{upstream_port}\r\n\
         authorization: Bearer {token}\r\n\
         accept: text/event-stream\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write the request");
    stream.flush().await.expect("flush");
    stream
}

/// Read the whole response off `stream` until the far end closes it.
async fn read_to_end(mut stream: tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt as _;
    let mut body = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut body)).await;
    String::from_utf8_lossy(&body).into_owned()
}

/// The `data:` events in a response, in order.
fn events(body: &str) -> Vec<u32> {
    body.lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter_map(|value| value.trim().parse().ok())
        .collect()
}

// ------------------------------------------------------------------- harness

struct Fixture {
    daemon: Daemon,
    upstream: Upstream,
    proxy_addr: String,
    metrics_addr: String,
    pid: u32,
    session_id: String,
    token: String,
    /// Every daemon this fixture started that the harness does not own.
    ///
    /// An upgrade's replacement is a child of the `briefcred` command, not of
    /// this test, so nothing else would ever reap it — and a test that panicked
    /// halfway would leave a daemon running against a deleted temporary home.
    successors: std::sync::Mutex<Vec<u32>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for pid in self.successors.lock().unwrap().iter() {
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status();
        }
    }
}

impl Fixture {
    /// Run `briefcred daemon upgrade` against this fixture's daemon.
    ///
    /// The real CLI binary, not a library call: the ordering the upgrade
    /// depends on — start the replacement, wait for its socket, only then ask
    /// the old daemon to hand over — lives in the command, and a test that
    /// reimplemented it would be testing its own copy.
    async fn upgrade(&self, extra: &[&str]) -> std::process::Output {
        let mut command = std::process::Command::new(binary_dir().join("briefcred"));
        command
            .args(["daemon", "upgrade"])
            .args(extra)
            .env("BRIEFCRED_HOME", self.daemon.home())
            .env("BRIEFCRED_HELPER_DIR", binary_dir());
        let output = command.output().expect("run briefcred daemon upgrade");
        if let Ok(Response::Status { pid, .. }) = self.daemon.request(Request::Status).await {
            if pid != self.pid {
                self.successors.lock().unwrap().push(pid);
            }
        }
        output
    }
}

async fn start() -> Fixture {
    let upstream = start_upstream().await;

    let mut daemon = Daemon::prepare(
        "master_source = \"file\"\nproxy_enabled = true\n[ca]\nkeystore = \"file\"\n",
    );
    daemon.write_profile("openai", &profile());
    daemon.write_master("openai", REAL_KEY);
    daemon.start().await.unwrap_or_else(|e| panic!("{e}"));

    let Response::Status {
        pid,
        proxy_addr,
        metrics_addr,
        ..
    } = daemon.request(Request::Status).await.unwrap()
    else {
        panic!("expected a status");
    };
    let proxy_addr = proxy_addr.expect("the proxy is enabled");
    let metrics_addr = metrics_addr.expect("metrics are enabled");

    let Response::SessionOpened { session_id, .. } = daemon
        .request(Request::OpenSession {
            profile: "openai".to_string(),
            client_headless: true,
            session_pubkey: None,
        })
        .await
        .unwrap()
    else {
        panic!("the session did not open:\n{}", daemon.log());
    };
    let Response::Minted { mints, .. } = daemon
        .request(Request::Exec {
            session_id: session_id.clone(),
            credentials: None,
            argv0: "curl".to_string(),
            args: Vec::new(),
            pid: std::process::id(),
        })
        .await
        .unwrap()
    else {
        panic!("nothing was minted:\n{}", daemon.log());
    };
    let token = mints[0].fields["TOKEN"].expose().to_string();

    Fixture {
        daemon,
        upstream,
        proxy_addr,
        metrics_addr,
        pid,
        session_id,
        token,
        successors: std::sync::Mutex::new(Vec::new()),
    }
}

/// The pid the socket's current owner reports.
async fn serving_pid(daemon: &Daemon) -> u32 {
    let Ok(Response::Status { pid, .. }) = daemon.request(Request::Status).await else {
        panic!("nothing is answering on the socket:\n{}", daemon.log());
    };
    pid
}

// --------------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upgrade_under_a_live_event_stream_drops_nothing() {
    let mut fixture = start().await;

    // Open the stream and let a few events through, so the upgrade lands in
    // the middle of it rather than before it has started.
    let stream = open_stream(
        &fixture.proxy_addr,
        fixture.upstream.port,
        "/events",
        &fixture.token,
    )
    .await;
    tokio::time::sleep(GAP * 10).await;

    let output = fixture.upgrade(&[]).await;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "the upgrade failed: {stdout}{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        fixture.daemon.log()
    );

    // The stream was being served by the old daemon and goes on being served
    // by it while it drains. Not one event may be missing.
    let body = read_to_end(stream).await;
    let received = events(&body);
    assert_eq!(
        received.len(),
        EVENTS,
        "the upgrade cut the stream after {} of {EVENTS} events:\n{}",
        received.len(),
        fixture.daemon.log()
    );
    assert_eq!(
        received,
        (1..=EVENTS as u32).collect::<Vec<u32>>(),
        "the events arrived out of order or with a gap"
    );

    // Same sockets, same addresses: a client that had cached either is still
    // talking to briefcred.
    let Response::Status {
        pid: new_pid,
        proxy_addr,
        metrics_addr,
        ..
    } = fixture.daemon.request(Request::Status).await.unwrap()
    else {
        panic!("expected a status");
    };
    assert_eq!(proxy_addr.as_deref(), Some(fixture.proxy_addr.as_str()));
    assert_eq!(metrics_addr.as_deref(), Some(fixture.metrics_addr.as_str()));
    assert_ne!(new_pid, fixture.pid, "the daemon was not actually replaced");
    assert!(
        stdout.contains(&new_pid.to_string()),
        "the command must name the pid now serving: {stdout}"
    );

    // The daemon that handed over finishes what it had and goes.
    let log = fixture.daemon.log();
    assert!(
        fixture.daemon.wait_for_exit(Duration::from_secs(30)).await,
        "pid {} is still running after the drain:\n{log}",
        fixture.pid
    );

    // The upstream saw the real key on every request and the token on none.
    for authorization in fixture.upstream.seen.lock().unwrap().iter() {
        assert_eq!(authorization, &format!("Bearer {REAL_KEY}"));
    }

    fixture.daemon.request(Request::Shutdown).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_session_open_before_an_upgrade_still_works_after_it() {
    let fixture = start().await;

    let output = fixture.upgrade(&[]).await;
    assert!(
        output.status.success(),
        "the upgrade failed: {}\n{}",
        String::from_utf8_lossy(&output.stderr),
        fixture.daemon.log()
    );
    let new_pid = serving_pid(&fixture.daemon).await;
    assert_ne!(new_pid, fixture.pid);

    // The handle the client already holds, against a process that never saw it
    // opened. This is the whole point of the state blob.
    let Response::Minted { mints, .. } = fixture
        .daemon
        .request(Request::Exec {
            session_id: fixture.session_id.clone(),
            credentials: None,
            argv0: "curl".to_string(),
            args: Vec::new(),
            pid: std::process::id(),
        })
        .await
        .unwrap()
    else {
        panic!(
            "the handed-over session did not mint:\n{}",
            fixture.daemon.log()
        );
    };

    // Minted from the master the old daemon held, which crossed the handoff
    // socket encrypted and has never been on the disk.
    let token = mints[0].fields["TOKEN"].expose().to_string();
    let body = read_to_end(
        open_stream(&fixture.proxy_addr, fixture.upstream.port, "/hello", &token).await,
    )
    .await;
    assert!(body.contains("hi"), "the proxy did not forward it: {body}");
    assert_eq!(
        fixture.upstream.seen.lock().unwrap().last().unwrap(),
        &format!("Bearer {REAL_KEY}")
    );

    // And a session opened afterwards lands on the new daemon.
    let Response::SessionOpened { session_id, .. } = fixture
        .daemon
        .request(Request::OpenSession {
            profile: "openai".to_string(),
            client_headless: true,
            session_pubkey: None,
        })
        .await
        .unwrap()
    else {
        panic!("a new session did not open after the upgrade");
    };
    assert_ne!(session_id, fixture.session_id);
    assert_eq!(serving_pid(&fixture.daemon).await, new_pid);

    fixture.daemon.request(Request::Shutdown).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_handoff_is_audited_and_counted_on_both_sides() {
    let mut fixture = start().await;
    assert!(fixture.upgrade(&[]).await.status.success());
    let new_pid = serving_pid(&fixture.daemon).await;

    assert!(
        fixture.daemon.wait_for_exit(Duration::from_secs(30)).await,
        "the replaced daemon is still running:\n{}",
        fixture.daemon.log()
    );

    let rows: Vec<serde_json::Value> = fixture
        .daemon
        .audit_rows()
        .into_iter()
        .filter(|row| row["event"] == "daemon_handoff")
        .collect();
    assert_eq!(
        rows.len(),
        2,
        "both halves of the swap must be recorded: {rows:?}"
    );

    let handed = rows
        .iter()
        .find(|row| row["outcome"] == "handed_over")
        .expect("the daemon that stood down writes a row");
    assert_eq!(handed["from_pid"], fixture.pid);
    assert_eq!(handed["to_pid"], new_pid);
    assert_eq!(handed["sessions"], 1);

    let adopted = rows
        .iter()
        .find(|row| row["outcome"] == "adopted")
        .expect("the daemon that took over writes a row");
    assert_eq!(adopted["from_pid"], fixture.pid);
    assert_eq!(adopted["to_pid"], new_pid);
    assert_eq!(adopted["sessions"], 1);

    // The session the old daemon was holding closes with `handoff`, not
    // `shutdown`: it was moved, not ended, and its mints were not revoked.
    let closes: Vec<String> = fixture
        .daemon
        .audit_rows()
        .into_iter()
        .filter(|row| row["event"] == "session_close")
        .filter_map(|row| row["reason"].as_str().map(str::to_string))
        .collect();
    assert_eq!(closes, vec!["handoff".to_string()]);
    assert!(
        !fixture
            .daemon
            .audit_rows()
            .iter()
            .any(|row| row["event"] == "revoke"),
        "a handoff must not revoke the credentials the new daemon is serving"
    );

    let metrics = get(&fixture.metrics_addr, "/metrics").await;
    assert!(
        metrics.contains("briefcred_handoffs_total{outcome=\"adopted\"} 1"),
        "the new daemon must count what it adopted:\n{metrics}"
    );
    assert!(
        metrics.contains("briefcred_handoffs_total{outcome=\"failed\"} 0"),
        "every outcome is seeded, so a zero is a fact rather than a gap:\n{metrics}"
    );

    fixture.daemon.request(Request::Shutdown).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upgrade_to_a_binary_that_is_not_there_leaves_the_daemon_serving() {
    let fixture = start().await;

    let output = fixture
        .upgrade(&["--binary", "/nonexistent/briefcred-daemon"])
        .await;
    assert!(!output.status.success());

    // Untouched: same pid, same sockets, same session. An upgrade that cannot
    // happen must never be a way to take briefcred off the machine.
    assert_eq!(serving_pid(&fixture.daemon).await, fixture.pid);
    let body = read_to_end(
        open_stream(
            &fixture.proxy_addr,
            fixture.upstream.port,
            "/hello",
            &fixture.token,
        )
        .await,
    )
    .await;
    assert!(body.contains("hi"), "{body}");

    fixture.daemon.request(Request::Shutdown).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upgrade_under_a_live_websocket_drops_no_frames() {
    // The WebSocket relay is a task of its own — the handshake response ends
    // the connection future that produced it — so it is counted by the drain
    // separately from an event stream, and separately worth proving.
    use futures_util::StreamExt as _;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let mut fixture = start().await;
    let stream = tokio::net::TcpStream::connect(&fixture.proxy_addr)
        .await
        .expect("connect to the proxy");
    let mut request = format!("ws://{UPSTREAM_HOST}:{}/ws", fixture.upstream.port)
        .into_client_request()
        .expect("a handshake request");
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", fixture.token).parse().unwrap(),
    );
    let (socket, _) = tokio_tungstenite::client_async(request, stream)
        .await
        .unwrap_or_else(|e| panic!("the handshake failed: {e}\n{}", fixture.daemon.log()));

    tokio::time::sleep(GAP * 10).await;
    let output = fixture.upgrade(&[]).await;
    assert!(
        output.status.success(),
        "the upgrade failed: {}\n{}",
        String::from_utf8_lossy(&output.stderr),
        fixture.daemon.log()
    );

    let frames: Vec<u32> = socket
        .filter_map(|message| async move {
            message
                .ok()
                .and_then(|message| message.into_text().ok())
                .and_then(|text| text.trim().parse::<u32>().ok())
        })
        .collect()
        .await;
    assert_eq!(
        frames,
        (1..=EVENTS as u32).collect::<Vec<u32>>(),
        "the upgrade cut the socket after {} of {EVENTS} frames:\n{}",
        frames.len(),
        fixture.daemon.log()
    );

    let log = fixture.daemon.log();
    assert!(
        fixture.daemon.wait_for_exit(Duration::from_secs(30)).await,
        "the replaced daemon is still running:\n{log}"
    );
    assert_ne!(serving_pid(&fixture.daemon).await, fixture.pid);

    fixture.daemon.request(Request::Shutdown).await.ok();
}

/// A one-shot GET, for the metrics endpoint.
///
/// Hand-written for the same reason the upstream is: one fixed request, and no
/// reason to pull an HTTP client into this test binary for it.
async fn get(addr: &str, path: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to the metrics endpoint");
    let request = format!("GET {path} HTTP/1.1\r\nhost: {addr}\r\nconnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("write");
    read_to_end(stream).await
}
