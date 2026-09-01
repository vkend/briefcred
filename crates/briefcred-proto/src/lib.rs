//! Wire types for the briefcred daemon IPC protocol.
//!
//! One request per frame, one response per frame, over a Unix domain socket.
//! A frame is a 4-byte big-endian payload length followed by that many bytes
//! of JSON. The length ceiling is [`MAX_FRAME_BYTES`], enforced on both the
//! sending and the receiving side so a hostile or confused peer cannot make
//! the daemon allocate 4 GiB from a four-byte header.
//!
//! Nothing on this wire carries credential material. The daemon's replies are
//! metadata, in the same spirit as the audit log.

#![forbid(unsafe_code)]

mod frame;
mod message;

pub use frame::{decode_frame, encode_frame, read_frame, write_frame, FrameError, MAX_FRAME_BYTES};
pub use message::{Request, Response};
