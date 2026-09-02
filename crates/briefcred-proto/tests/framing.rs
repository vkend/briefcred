//! The wire framing contract: a 4-byte big-endian length prefix in front of a
//! JSON payload, with a hard 16 MiB ceiling on either side of the socket.

use std::collections::BTreeMap;
use std::path::PathBuf;

use briefcred_proto::{
    decode_frame, encode_frame, read_frame, write_frame, CredentialSummary, FrameError,
    MintSummary, ProfileSummary, Request, Response, SecretString, MAX_FRAME_BYTES,
};
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;

fn sample_status() -> Response {
    Response::Status {
        version: "0.1.0".into(),
        pid: 4242,
        uptime_secs: 90,
        started_at: OffsetDateTime::UNIX_EPOCH,
        audit_path: PathBuf::from("/tmp/t/audit"),
        metrics_addr: Some("127.0.0.1:9317".into()),
        proxy_addr: Some("127.0.0.1:9318".into()),
    }
}

fn sample_profile() -> ProfileSummary {
    ProfileSummary {
        name: "analytics".into(),
        description: Some("read-only analytics shell".into()),
        unlock_policy: "biometric".into(),
        unlock_cache_secs: 300,
        credentials: vec![CredentialSummary {
            name: "db".into(),
            kind: "postgres-dynamic".into(),
            ttl_secs: 900,
            source_key: "analytics-db".into(),
        }],
    }
}

#[tokio::test]
async fn every_request_and_response_round_trips() {
    let requests = [
        Request::Ping,
        Request::Status,
        Request::Shutdown,
        Request::ListProfiles,
        Request::ShowProfile {
            name: "analytics".into(),
        },
        Request::OpenSession {
            profile: "analytics".into(),
            client_headless: false,
            session_pubkey: None,
        },
        Request::CloseSession {
            session_id: "s-1".into(),
        },
        Request::Unlock {
            profile: "analytics".into(),
            client_headless: false,
        },
        Request::Exec {
            session_id: "s-1".into(),
            credentials: Some(vec!["db".into()]),
            argv0: "psql".into(),
            args: vec!["-c".into(), "SELECT 1".into()],
            pid: 4242,
        },
        Request::ExecDone {
            session_id: "s-1".into(),
            mint_ids: vec!["briefcred_t_0123456789ab".into()],
            exit_code: Some(0),
            duration_ms: 42,
            hold_until_expiry: false,
        },
        Request::HookCheck {
            profile: "analytics".into(),
            argv0: "psql".into(),
            args: vec!["-c".into()],
        },
    ];
    let responses = [
        Response::Pong,
        sample_status(),
        Response::ShuttingDown,
        Response::Profiles {
            profiles: vec![sample_profile()],
        },
        Response::Profile {
            profile: sample_profile(),
        },
        Response::SessionOpened {
            session_id: "s-1".into(),
            expires_at: OffsetDateTime::UNIX_EPOCH,
        },
        Response::SessionClosed {
            session_id: "s-1".into(),
        },
        Response::Locked {
            reason: "cancelled".into(),
            message: "the Touch ID prompt was cancelled".into(),
        },
        Response::Error {
            message: "nope".into(),
        },
        Response::Unlocked {
            profile: "analytics".into(),
        },
        Response::Minted {
            mints: vec![MintSummary {
                credential: "db".into(),
                mint_id: "briefcred_t_0123456789ab".into(),
                fields: BTreeMap::from([(
                    "PGPASSWORD".to_string(),
                    SecretString::new("t0p-s3cret"),
                )]),
            }],
            env: BTreeMap::from([("PGUSER".to_string(), SecretString::new("briefcred_t_x"))]),
            passthrough: vec!["PATH".into()],
        },
        Response::ExecRecorded { queued: 1 },
        Response::Denied {
            message: "`rm` is not permitted by profile `db-ro`".into(),
        },
        Response::HookDecision {
            allowed: false,
            reason: "`rm` is not in `exec.allow_argv0`".into(),
        },
    ];

    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    for request in &requests {
        write_frame(&mut client, request).await.unwrap();
    }
    for response in &responses {
        write_frame(&mut client, response).await.unwrap();
    }
    client.shutdown().await.unwrap();

    for request in &requests {
        let back: Request = read_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(&back, request);
    }
    for response in &responses {
        let back: Response = read_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(&back, response);
    }
    assert!(
        read_frame::<_, Request>(&mut server)
            .await
            .unwrap()
            .is_none(),
        "a clean EOF is not an error"
    );
}

#[test]
fn the_prefix_is_four_bytes_big_endian() {
    let frame = encode_frame(&Request::Ping).unwrap();
    let body = serde_json::to_vec(&Request::Ping).unwrap();
    assert_eq!(frame.len(), 4 + body.len());
    assert_eq!(
        u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
        body.len()
    );
    assert_eq!(&frame[4..], &body[..]);
    assert_eq!(decode_frame::<Request>(&frame[4..]).unwrap(), Request::Ping);
}

#[test]
fn encoding_a_payload_over_the_ceiling_is_refused() {
    let huge = Response::Error {
        message: "x".repeat(MAX_FRAME_BYTES + 1),
    };
    match encode_frame(&huge) {
        Err(FrameError::TooLarge { len, max }) => {
            assert!(len > MAX_FRAME_BYTES);
            assert_eq!(max, MAX_FRAME_BYTES);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn an_oversize_length_prefix_is_refused_before_reading_the_body() {
    let (mut client, mut server) = tokio::io::duplex(64);
    let declared = (MAX_FRAME_BYTES + 1) as u32;
    client.write_all(&declared.to_be_bytes()).await.unwrap();
    client.write_all(b"not 16 MiB of anything").await.unwrap();

    match read_frame::<_, Request>(&mut server).await {
        Err(FrameError::TooLarge { len, max }) => {
            assert_eq!(len, MAX_FRAME_BYTES + 1);
            assert_eq!(max, MAX_FRAME_BYTES);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn a_truncated_frame_is_an_error_not_a_silent_eof() {
    let (mut client, mut server) = tokio::io::duplex(64);
    client.write_all(&64u32.to_be_bytes()).await.unwrap();
    client.write_all(b"{\"request\"").await.unwrap();
    client.shutdown().await.unwrap();

    let err = read_frame::<_, Request>(&mut server).await.unwrap_err();
    assert!(matches!(err, FrameError::Io(_)), "{err:?}");
}

#[test]
fn a_request_names_its_own_variant_for_the_dispatch_table() {
    assert_eq!(Request::Ping.name(), "ping");
    assert_eq!(Request::Status.name(), "status");
    assert_eq!(Request::Shutdown.name(), "shutdown");
    assert_eq!(Request::ListProfiles.name(), "list_profiles");
    assert_eq!(
        Request::ShowProfile { name: "x".into() }.name(),
        "show_profile"
    );
    assert_eq!(
        Request::OpenSession {
            profile: "x".into(),
            client_headless: true,
            session_pubkey: None,
        }
        .name(),
        "open_session"
    );
    assert_eq!(
        Request::CloseSession {
            session_id: "x".into()
        }
        .name(),
        "close_session"
    );
}

/// The dispatch table is keyed on `NAMES`, so a variant missing from it would
/// be a request the daemon silently has no handler for.
#[test]
fn the_name_list_covers_every_request_variant_exactly_once() {
    let variants = [
        Request::Ping,
        Request::Status,
        Request::Shutdown,
        Request::ListProfiles,
        Request::ShowProfile { name: "x".into() },
        Request::OpenSession {
            profile: "x".into(),
            client_headless: false,
            session_pubkey: None,
        },
        Request::CloseSession {
            session_id: "x".into(),
        },
        Request::Unlock {
            profile: "x".into(),
            client_headless: false,
        },
        Request::Exec {
            session_id: "x".into(),
            credentials: None,
            argv0: "psql".into(),
            args: vec![],
            pid: 1,
        },
        Request::ExecDone {
            session_id: "x".into(),
            mint_ids: vec![],
            exit_code: Some(0),
            duration_ms: 1,
            hold_until_expiry: true,
        },
        Request::HookCheck {
            profile: "x".into(),
            argv0: "psql".into(),
            args: vec![],
        },
        Request::Mcp,
        #[cfg(feature = "debug-heapscan")]
        Request::HeapScan {
            needle_sha256: "00".into(),
        },
    ];
    let mut names: Vec<&str> = variants.iter().map(|r| r.name()).collect();
    names.sort_unstable();
    let mut declared = Request::NAMES.to_vec();
    declared.sort_unstable();
    assert_eq!(names, declared);
}

/// A summary is the only profile shape that crosses the socket, so its JSON is
/// where an accidentally exposed field would show up.
#[test]
fn a_profile_summary_carries_key_names_and_never_a_secret() {
    let json = serde_json::to_string(&sample_profile()).unwrap();
    assert!(json.contains("analytics-db"), "{json}");
    assert!(!json.contains("password"), "{json}");
    assert!(!json.contains("config"), "{json}");
}

/// `Minted` is the one reply that carries credential material, and the whole
/// safety argument for it is that it cannot reach a log line by accident.
#[test]
fn a_minted_reply_serialises_its_secrets_and_debug_prints_none_of_them() {
    let reply = Response::Minted {
        mints: vec![MintSummary {
            credential: "db".into(),
            mint_id: "briefcred_t_0123456789ab".into(),
            fields: BTreeMap::from([("PGPASSWORD".to_string(), SecretString::new("t0p-s3cret"))]),
        }],
        env: BTreeMap::from([("PGPASSWORD".to_string(), SecretString::new("t0p-s3cret"))]),
        passthrough: vec!["PATH".into()],
    };

    // It has to serialise: this is how the credential reaches the subprocess.
    let json = serde_json::to_string(&reply).unwrap();
    assert!(json.contains("t0p-s3cret"), "{json}");

    // It must not print. `{:?}` of a response is exactly what an error path
    // reaches for, and that is the accident this guards against.
    let rendered = format!("{reply:?}");
    assert!(!rendered.contains("t0p-s3cret"), "{rendered}");
    assert!(rendered.contains("PGPASSWORD"), "{rendered}");
}

/// The daemon's refusal depends on this flag, so a client that omits it must
/// fail loudly rather than be read as declaring it has a screen.
#[test]
fn open_session_without_the_headless_flag_does_not_deserialise() {
    let missing = br#"{"request":"open_session","profile":"dev"}"#;
    assert!(decode_frame::<Request>(missing).is_err());

    let present = br#"{"request":"open_session","profile":"dev","client_headless":true}"#;
    assert_eq!(
        decode_frame::<Request>(present).unwrap(),
        Request::OpenSession {
            profile: "dev".into(),
            client_headless: true,
            session_pubkey: None,
        }
    );
}

/// The upgrade names have to be real request names, or the daemon's dispatch
/// table would exclude a handler nothing ever removes.
#[test]
fn every_upgrade_is_a_request_the_protocol_defines() {
    for name in Request::UPGRADE_NAMES {
        assert!(Request::NAMES.contains(name), "`{name}` is not a request");
    }
    assert!(Request::Mcp.is_upgrade());
    assert!(!Request::Ping.is_upgrade());
}

/// The acknowledgement that hands the socket over carries no credential.
#[test]
fn the_mcp_acknowledgement_is_metadata_only() {
    let json = serde_json::to_string(&Response::McpReady {
        version: "0.1.0".into(),
    })
    .unwrap();
    assert_eq!(json, r#"{"response":"mcp_ready","version":"0.1.0"}"#);
}
