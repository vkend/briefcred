//! The OpenSSH key revocation list briefcred writes when an SSH certificate
//! is revoked.
//!
//! A minted SSH certificate cannot be recalled. It is a signed statement that
//! a key is good until its `valid_before`, and every server that trusts the CA
//! will honour it whether or not briefcred still wants it to. The only lever
//! that exists is the one OpenSSH provides on the *server* side: `sshd`'s
//! `RevokedKeys` directive, which names a file of revoked keys and refuses any
//! certificate listed in it. So revoking an SSH certificate here means adding
//! its serial number to that file; making servers read the file is a
//! deployment step, described in `docs/ssh-krl.md`.
//!
//! # The format
//!
//! OpenSSH's binary KRL, as specified in its `PROTOCOL.krl`. Everything is
//! big-endian, and a `string` is a `u32` length followed by that many bytes.
//!
//! ```text
//! u64    magic, "SSHKRL\n\0"
//! u32    format version, 1
//! u64    KRL version, bumped on every rewrite
//! u64    generated date, Unix seconds
//! u64    flags, unused
//! string reserved, empty
//! string comment
//! then sections, each: u8 type, string body
//! ```
//!
//! briefcred writes exactly one section, a certificates section whose CA key
//! is the empty string. OpenSSH reads an empty CA key as "any CA", so a serial
//! listed here is revoked no matter which certificate authority signed it.
//! That is deliberate: a serial is a random `u64`, so the chance of hitting
//! another CA's certificate is negligible, and the direction the ambiguity
//! errs in is refusing a certificate rather than accepting one. Keying the
//! section on a CA would also mean the file's contents depended on which
//! profile ran last, which is a worse property for a file operators copy to
//! their servers.
//!
//! # Why the whole file is rewritten
//!
//! The header carries a version and a generated date, and the serials live
//! inside a length-prefixed section, so "append one serial" is not a byte
//! append. Revoking reads the file, adds the serial, and writes it back. The
//! list is small — one entry per SSH certificate ever revoked on this machine
//! — and the rewrite is atomic, so a KRL is never observed half-written.

use std::collections::BTreeSet;
use std::path::Path;

use time::OffsetDateTime;

use crate::error::{Error, Result};

/// The eight bytes every KRL starts with.
pub const KRL_MAGIC: &[u8; 8] = b"SSHKRL\n\0";

/// The only KRL format version OpenSSH defines.
pub const KRL_FORMAT_VERSION: u32 = 1;

/// The comment briefcred stamps on the files it writes.
pub const KRL_COMMENT: &str = "briefcred";

/// Section type: revocations expressed in terms of certificates.
const SECTION_CERTIFICATES: u8 = 1;

/// Certificate subsection type: an explicit list of serial numbers.
const CERT_SERIAL_LIST: u8 = 0x20;

/// A key revocation list holding serial numbers.
///
/// Serials are a set, so revoking the same certificate twice is idempotent and
/// the file's byte content depends only on which serials are in it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Krl {
    version: u64,
    serials: BTreeSet<u64>,
}

impl Krl {
    /// An empty list at version 0.
    pub fn new() -> Krl {
        Krl::default()
    }

    /// The KRL version, which [`Krl::encode`] writes and a rewrite bumps.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Every revoked serial, ascending.
    pub fn serials(&self) -> impl Iterator<Item = u64> + '_ {
        self.serials.iter().copied()
    }

    /// Whether `serial` is revoked.
    pub fn contains(&self, serial: u64) -> bool {
        self.serials.contains(&serial)
    }

    /// How many serials the list holds.
    pub fn len(&self) -> usize {
        self.serials.len()
    }

    /// Whether the list revokes nothing.
    pub fn is_empty(&self) -> bool {
        self.serials.is_empty()
    }

    /// Add `serial`, returning whether it was not already there.
    pub fn insert(&mut self, serial: u64) -> bool {
        self.serials.insert(serial)
    }

    /// Serialise to OpenSSH's binary KRL format.
    ///
    /// An empty list still produces a well-formed file with no sections, which
    /// is what OpenSSH reads as "nothing is revoked".
    pub fn encode(&self, generated_at: OffsetDateTime) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.serials.len() * 8);
        out.extend_from_slice(KRL_MAGIC);
        out.extend_from_slice(&KRL_FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(generated_at.unix_timestamp().max(0) as u64).to_be_bytes());
        // Flags. OpenSSH defines none, and writes zero.
        out.extend_from_slice(&0u64.to_be_bytes());
        put_string(&mut out, b"");
        put_string(&mut out, KRL_COMMENT.as_bytes());

        if !self.serials.is_empty() {
            let mut serial_list = Vec::with_capacity(self.serials.len() * 8);
            for serial in &self.serials {
                serial_list.extend_from_slice(&serial.to_be_bytes());
            }

            let mut section = Vec::new();
            // An empty CA key means "certificates from any CA".
            put_string(&mut section, b"");
            put_string(&mut section, b"");
            section.push(CERT_SERIAL_LIST);
            put_string(&mut section, &serial_list);

            out.push(SECTION_CERTIFICATES);
            put_string(&mut out, &section);
        }
        out
    }

    /// Parse a KRL, keeping the serials briefcred understands.
    ///
    /// Sections of a type briefcred does not write are skipped rather than
    /// refused: a file an operator merged with their own revocations is still
    /// readable, and the alternative — refusing — would mean a revoke could
    /// not record itself at all.
    pub fn decode(bytes: &[u8]) -> Result<Krl> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(KRL_MAGIC.len())? != KRL_MAGIC {
            return Err(malformed("not a KRL: the magic does not match"));
        }
        let format = cursor.u32()?;
        if format != KRL_FORMAT_VERSION {
            return Err(malformed(format!(
                "KRL format version {format} is not the version {KRL_FORMAT_VERSION} briefcred writes"
            )));
        }
        let version = cursor.u64()?;
        let _generated_at = cursor.u64()?;
        let _flags = cursor.u64()?;
        let _reserved = cursor.string()?;
        let _comment = cursor.string()?;

        let mut serials = BTreeSet::new();
        while !cursor.is_empty() {
            let section_type = cursor.u8()?;
            let body = cursor.string()?;
            if section_type == SECTION_CERTIFICATES {
                read_certificates_section(body, &mut serials)?;
            }
        }
        Ok(Krl { version, serials })
    }
}

/// Collect the serials a certificates section lists explicitly.
///
/// Ranges and bitmaps are the compact encodings OpenSSH's own `ssh-keygen`
/// produces for long runs; briefcred never writes one, and a file that has one
/// is still read for the serials it does list.
fn read_certificates_section(body: &[u8], serials: &mut BTreeSet<u64>) -> Result<()> {
    let mut cursor = Cursor::new(body);
    let _ca_key = cursor.string()?;
    let _reserved = cursor.string()?;
    while !cursor.is_empty() {
        let subsection_type = cursor.u8()?;
        let subsection = cursor.string()?;
        if subsection_type != CERT_SERIAL_LIST {
            continue;
        }
        if !subsection.len().is_multiple_of(8) {
            return Err(malformed(
                "a serial list is not a whole number of 8-byte serials",
            ));
        }
        let (chunks, _) = subsection.as_chunks::<8>();
        for chunk in chunks {
            serials.insert(u64::from_be_bytes(*chunk));
        }
    }
    Ok(())
}

/// Add `serial` to the KRL at `path`, creating the file if it is not there.
///
/// The file is written for everyone to read: a KRL is a list of things that no
/// longer work, it holds no secret, and an `sshd` running as another user has
/// to be able to read the copy an operator distributes.
pub fn revoke_serial(path: &Path, serial: u64) -> Result<()> {
    let mut krl = read(path)?;
    krl.insert(serial);
    krl.version += 1;
    write(path, &krl)
}

/// Read the KRL at `path`, treating an absent file as an empty list.
pub fn read(path: &Path) -> Result<Krl> {
    match std::fs::read(path) {
        Ok(bytes) => Krl::decode(&bytes).map_err(|e| match e {
            Error::Ssh(message) => Error::Ssh(format!("{}: {message}", path.display())),
            other => other,
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Krl::new()),
        Err(source) => Err(Error::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Write `krl` to `path` atomically.
///
/// Through a temporary file in the same directory and a rename, so a reader —
/// which is an `sshd` deciding whether to let somebody in — never sees a
/// half-written list and concludes that nothing is revoked.
pub fn write(path: &Path, krl: &Krl) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).map_err(|source| Error::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let temporary = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&temporary, krl.encode(OffsetDateTime::now_utc())).map_err(|source| {
        Error::Io {
            path: temporary.clone(),
            source,
        }
    })?;
    if let Err(source) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(Error::Io {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn malformed(message: impl Into<String>) -> Error {
    Error::Ssh(message.into())
}

/// A bounds-checked reader over SSH wire encoding.
struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Cursor<'a> {
        Cursor { rest: bytes }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.rest.len() < n {
            return Err(malformed("the KRL ends in the middle of a field"));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_list_encodes_a_header_and_no_sections() {
        let bytes = Krl::new().encode(OffsetDateTime::UNIX_EPOCH);
        assert_eq!(&bytes[..8], KRL_MAGIC);
        // magic, format, version, date, flags, two empty-ish strings.
        assert_eq!(bytes.len(), 8 + 4 + 8 + 8 + 8 + 4 + 4 + KRL_COMMENT.len());
        assert!(Krl::decode(&bytes).unwrap().is_empty());
    }

    #[test]
    fn serials_survive_a_round_trip() {
        let mut krl = Krl::new();
        assert!(krl.insert(7));
        assert!(krl.insert(u64::MAX));
        assert!(!krl.insert(7), "inserting a serial twice must be a no-op");

        let decoded = Krl::decode(&krl.encode(OffsetDateTime::now_utc())).unwrap();
        assert_eq!(decoded.serials().collect::<Vec<_>>(), vec![7, u64::MAX]);
        assert!(decoded.contains(u64::MAX));
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn a_file_that_is_not_a_krl_is_refused_by_name() {
        let err = Krl::decode(b"not a krl at all").unwrap_err();
        assert!(err.to_string().contains("magic"), "{err}");
    }

    #[test]
    fn a_truncated_krl_is_refused_rather_than_read_as_empty() {
        let bytes = {
            let mut krl = Krl::new();
            krl.insert(99);
            krl.encode(OffsetDateTime::now_utc())
        };
        for cut in [10, 20, bytes.len() - 1] {
            let err = Krl::decode(&bytes[..cut]).unwrap_err();
            assert!(matches!(err, Error::Ssh(_)), "{err}");
        }
    }

    #[test]
    fn a_future_format_version_is_refused_rather_than_guessed_at() {
        let mut bytes = Krl::new().encode(OffsetDateTime::now_utc());
        bytes[8..12].copy_from_slice(&2u32.to_be_bytes());
        let err = Krl::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("format version 2"), "{err}");
    }

    #[test]
    fn a_section_briefcred_does_not_write_is_skipped_rather_than_refused() {
        let mut krl = Krl::new();
        krl.insert(5);
        let mut bytes = krl.encode(OffsetDateTime::now_utc());
        // An explicit-key section (type 2) holding something briefcred has no
        // opinion about, of the kind `ssh-keygen -k` writes.
        bytes.push(2);
        put_string(&mut bytes, b"a blob briefcred does not parse");

        let decoded = Krl::decode(&bytes).unwrap();
        assert_eq!(decoded.serials().collect::<Vec<_>>(), vec![5]);
    }

    #[test]
    fn revoking_creates_the_file_and_then_adds_to_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("ssh-krl");

        revoke_serial(&path, 1).unwrap();
        assert_eq!(read(&path).unwrap().serials().collect::<Vec<_>>(), vec![1]);

        revoke_serial(&path, 2).unwrap();
        let krl = read(&path).unwrap();
        assert_eq!(krl.serials().collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(krl.version(), 2, "every rewrite bumps the KRL version");
    }

    #[test]
    fn revoking_the_same_serial_twice_leaves_one_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-krl");
        revoke_serial(&path, 42).unwrap();
        revoke_serial(&path, 42).unwrap();
        assert_eq!(read(&path).unwrap().serials().collect::<Vec<_>>(), vec![42]);
    }

    #[test]
    fn reading_a_missing_file_is_an_empty_list_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(&dir.path().join("absent")).unwrap().is_empty());
    }

    #[test]
    fn reading_a_corrupt_file_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-krl");
        std::fs::write(&path, b"rubbish").unwrap();
        let err = read(&path).unwrap_err();
        assert!(err.to_string().contains("ssh-krl"), "{err}");
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        revoke_serial(&dir.path().join("ssh-krl"), 3).unwrap();
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("ssh-krl")], "{left:?}");
    }
}
