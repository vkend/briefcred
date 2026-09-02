//! Wire types for the briefcred daemon IPC protocol.
//!
//! One request per frame, one response per frame, over a Unix domain socket.
//! A frame is a 4-byte big-endian payload length followed by that many bytes
//! of JSON. The length ceiling is [`MAX_FRAME_BYTES`], enforced on both the
//! sending and the receiving side so a hostile or confused peer cannot make
//! the daemon allocate 4 GiB from a four-byte header.
//!
//! # What crosses this wire
//!
//! Almost all of it is metadata, in the same spirit as the audit log. The
//! exception is [`Response::Minted`], which carries the minted fields and the
//! composed environment: the daemon is the only side that holds the profile,
//! the masters and the CA paths at once, and the client's job is to apply what
//! it is given to a child. That reply is why the socket is mode `0600` inside
//! a `0700` directory and why the daemon checks the peer's uid before reading
//! a frame.
//!
//! Every secret on this wire is a [`SecretString`], which redacts itself in
//! `Debug` and is never written to a file or a log. No **master** credential
//! ever crosses it in any reply: what `Minted` carries is the short-lived
//! credential or the synthetic token that stands in for one.

#![forbid(unsafe_code)]

mod frame;
pub mod helper;
mod message;
mod secret;

pub use frame::{decode_frame, encode_frame, read_frame, write_frame, FrameError, MAX_FRAME_BYTES};
pub use message::{CredentialSummary, MintSummary, ProfileSummary, Request, Response};
pub use secret::SecretString;
