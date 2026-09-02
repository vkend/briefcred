//! Debug-only: does a known 32-byte marker still exist in this process?
//!
//! This module answers exactly one question, for exactly one test. briefcred
//! claims that a master credential is wiped when the session holding it is
//! closed. That claim rests on `Zeroizing` and on every path that touches a
//! master dropping it rather than copying it, and a claim like that is worth
//! having a machine check.
//!
//! Checking it from outside would need `task_for_pid`, which needs an
//! entitlement and a code signature. So the daemon scans *itself*, which needs
//! nothing: `mach_vm_region` walks its own map and `mach_vm_read_overwrite`
//! reads its own pages.
//!
//! # Why it takes a digest
//!
//! The caller sends `sha256(marker)`, never the marker. If the marker crossed
//! the socket, it would land in the daemon's own receive buffer, and the scan
//! would find the copy it had just been handed. Sending only the digest means
//! the daemon never holds the needle at all, so a hit is a real hit.
//!
//! The cost is that the scan hashes a 32-byte window at every byte offset of
//! every readable private region, which is tens of millions of SHA-256 blocks
//! and takes seconds. That is fine for one ignored test and is why this is
//! behind a feature rather than in the shipping daemon: a same-uid caller who
//! could ask a production daemon to grep its own memory would have a
//! confirmation oracle for guessed secrets.

#![allow(unsafe_code)]

use sha2::{Digest, Sha256};

/// The marker length this scan looks for.
pub const NEEDLE_LEN: usize = 32;

/// What one self-scan found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanResult {
    /// Whether a window hashing to the requested digest was found.
    pub present: bool,
    /// How many readable private regions were examined.
    pub regions_scanned: usize,
    /// How many bytes those regions covered.
    pub bytes_scanned: u64,
}

/// Scan this process's own readable private memory for `needle_sha256`.
///
/// Returns as soon as it finds a match, so a positive answer is fast and a
/// negative one is the expensive case — which is the right way round, because
/// the negative answer is the one the test is asserting.
#[cfg(target_os = "macos")]
pub fn scan_self(needle_sha256: &str) -> ScanResult {
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::traps::mach_task_self;
    use mach2::vm::mach_vm_region;
    use mach2::vm_prot::VM_PROT_READ;
    use mach2::vm_region::{vm_region_basic_info_data_64_t, VM_REGION_BASIC_INFO_64};

    let wanted = needle_sha256.to_ascii_lowercase();
    let task = unsafe { mach_task_self() };
    let mut address: mach2::vm_types::mach_vm_address_t = 1;
    let mut regions_scanned = 0usize;
    let mut bytes_scanned = 0u64;
    let mut buffer = vec![0u8; 1 << 20];

    loop {
        let mut size: mach2::vm_types::mach_vm_size_t = 0;
        let mut info = vm_region_basic_info_data_64_t::default();
        let mut count = (std::mem::size_of::<vm_region_basic_info_data_64_t>()
            / std::mem::size_of::<i32>()) as u32;
        let mut object: mach2::port::mach_port_t = 0;

        // SAFETY: every out-parameter is live and correctly sized, `count` is
        // the documented element count for `vm_region_basic_info_data_64_t`,
        // and the call only writes through those pointers.
        let status = unsafe {
            mach_vm_region(
                task,
                &mut address,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                (&mut info as *mut vm_region_basic_info_data_64_t).cast(),
                &mut count,
                &mut object,
            )
        };
        if status != KERN_SUCCESS {
            break;
        }

        let readable = info.protection & VM_PROT_READ != 0;
        // Shared regions are the dyld cache and mapped files: megabytes of
        // read-only library text that cannot hold a heap allocation. Skipping
        // them is what makes this take seconds instead of minutes.
        if readable && info.shared == 0 {
            regions_scanned += 1;
            bytes_scanned += size;
            if scan_region(task, address, size, &wanted, &mut buffer) {
                return ScanResult {
                    present: true,
                    regions_scanned,
                    bytes_scanned,
                };
            }
        }

        let Some(next) = address.checked_add(size) else {
            break;
        };
        if next <= address {
            break;
        }
        address = next;
    }

    ScanResult {
        present: false,
        regions_scanned,
        bytes_scanned,
    }
}

/// Read one region in chunks and hash every 32-byte window in it.
#[cfg(target_os = "macos")]
fn scan_region(
    task: mach2::port::mach_port_t,
    start: mach2::vm_types::mach_vm_address_t,
    size: mach2::vm_types::mach_vm_size_t,
    wanted: &str,
    buffer: &mut [u8],
) -> bool {
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::vm::mach_vm_read_overwrite;

    let mut offset: u64 = 0;
    while offset < size {
        // Chunks overlap by `NEEDLE_LEN - 1` so a marker straddling a chunk
        // boundary is still seen whole.
        let want = u64::min(buffer.len() as u64, size - offset);
        let mut got: mach2::vm_types::mach_vm_size_t = 0;
        // SAFETY: the destination is `buffer`, which is at least `want` bytes;
        // the source is a region this walk just reported as readable, and a
        // page unmapped in between makes the call fail rather than fault.
        let status = unsafe {
            mach_vm_read_overwrite(
                task,
                start + offset,
                want,
                buffer.as_mut_ptr() as mach2::vm_types::mach_vm_address_t,
                &mut got,
            )
        };
        if status != KERN_SUCCESS || got == 0 {
            return false;
        }
        let chunk = &buffer[..got as usize];
        if let Some(windows) = chunk.len().checked_sub(NEEDLE_LEN - 1) {
            for start in 0..windows {
                if hex::encode(Sha256::digest(&chunk[start..start + NEEDLE_LEN])) == wanted {
                    return true;
                }
            }
        }
        if got as usize <= NEEDLE_LEN {
            return false;
        }
        offset += got - (NEEDLE_LEN as u64 - 1);
    }
    false
}

/// Off macOS there is no `mach_vm_region`, and no test that needs one.
#[cfg(not(target_os = "macos"))]
pub fn scan_self(_needle_sha256: &str) -> ScanResult {
    ScanResult {
        present: false,
        regions_scanned: 0,
        bytes_scanned: 0,
    }
}

/// The digest a caller sends for `needle`.
pub fn digest(needle: &[u8]) -> String {
    hex::encode(Sha256::digest(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn the_scan_finds_a_marker_this_process_is_deliberately_holding() {
        // A live, un-optimisable allocation. If the scan cannot find this, it
        // cannot find anything, and a "not present" answer from it would be
        // worthless.
        let marker: Vec<u8> = (0u8..32)
            .map(|b| b.wrapping_mul(7).wrapping_add(3))
            .collect();
        let found = scan_self(&digest(&marker));
        assert!(
            found.present,
            "the scan must find a marker that is definitely resident: {found:?}"
        );
        assert!(found.regions_scanned > 0, "{found:?}");
        // Keep the marker alive past the scan.
        assert_eq!(marker.len(), NEEDLE_LEN);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn a_digest_of_something_absent_is_not_found() {
        // 32 bytes drawn fresh from the CSPRNG, hashed and then dropped: this
        // process has never held the marker, only its digest.
        let mut absent = [0u8; NEEDLE_LEN];
        getrandom::fill(&mut absent).unwrap();
        let wanted = digest(&absent);
        absent.fill(0);

        let found = scan_self(&wanted);
        assert!(!found.present, "{found:?}");
    }
}
