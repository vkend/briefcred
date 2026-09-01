//! Length-prefixed JSON framing.

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest payload a single frame may carry, 16 MiB.
///
/// Requests and responses are small structured metadata; the ceiling exists so
/// a four-byte header cannot be turned into an arbitrary allocation.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Everything that can go wrong reading or writing a frame.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The socket failed, or the peer vanished mid-frame.
    #[error("frame io: {0}")]
    Io(#[from] std::io::Error),

    /// The payload exceeds [`MAX_FRAME_BYTES`].
    ///
    /// On read this is decided from the length prefix alone, before the body
    /// is touched.
    #[error("frame of {len} bytes exceeds the {max} byte maximum")]
    TooLarge {
        /// The declared or computed payload length.
        len: usize,
        /// The ceiling that was exceeded, always [`MAX_FRAME_BYTES`].
        max: usize,
    },

    /// The payload was not the JSON the reader expected.
    #[error("frame json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Serialise `value` into a complete frame: prefix followed by payload.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge {
            len: body.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Deserialise one frame payload, with the length prefix already stripped.
pub fn decode_frame<T: DeserializeOwned>(payload: &[u8]) -> Result<T, FrameError> {
    Ok(serde_json::from_slice(payload)?)
}

/// Write one frame and flush it.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let frame = encode_frame(value)?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one frame.
///
/// Returns `Ok(None)` when the peer closed cleanly on a frame boundary, which
/// is how a client says "I am done" and not an error. A close part-way through
/// a frame is [`FrameError::Io`], because a half-frame is corruption.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut prefix = [0u8; 4];
    let mut filled = 0;
    while filled < prefix.len() {
        match reader.read(&mut prefix[filled..]).await? {
            // End of stream. Clean only if it landed on a frame boundary.
            0 if filled == 0 => return Ok(None),
            0 => {
                return Err(FrameError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream ended part-way through a frame length prefix",
                )));
            }
            n => filled += n,
        }
    }

    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge {
            len,
            max: MAX_FRAME_BYTES,
        });
    }

    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    Ok(Some(decode_frame(&body)?))
}
