//! The wire framing contract: a 4-byte big-endian length prefix in front of a
//! JSON payload, with a hard 16 MiB ceiling on either side of the socket.

use std::path::PathBuf;

use briefcred_proto::{
    decode_frame, encode_frame, read_frame, write_frame, FrameError, Request, Response,
    MAX_FRAME_BYTES,
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
    }
}

#[tokio::test]
async fn every_request_and_response_round_trips() {
    let requests = [Request::Ping, Request::Status, Request::Shutdown];
    let responses = [
        Response::Pong,
        sample_status(),
        Response::ShuttingDown,
        Response::Error {
            message: "nope".into(),
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
}
