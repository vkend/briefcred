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

/// Scan this process's own resident, writable, private memory.
///
/// Three filters, and each one is load-bearing rather than an optimisation:
///
/// - **Writable.** A master arrives from a keychain or a file and lives on the
///   heap or a stack. It is never in read-only text or in a constant, so a
///   read-only region cannot hold one.
/// - **Private.** Shared regions are the dyld cache and mapped files:
///   gigabytes of library text that no allocation can be in.
/// - **Resident.** A process's address space is mostly *reserved* rather than
///   mapped — macOS's allocator reserves multi-gigabyte ranges it has never
///   touched. Those pages hold nothing by definition, and hashing a window at
///   every byte of them turns a four-second scan into an hour-long one.
///
/// Returns as soon as it finds a match, so a positive answer is fast and a
/// negative one is the expensive case — which is the right way round, because
/// the negative answer is the one the test is asserting.
#[cfg(target_os = "macos")]
pub fn scan_self(needle_sha256: &str) -> ScanResult {
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::traps::mach_task_self;
    use mach2::vm::mach_vm_region;
    use mach2::vm_prot::{VM_PROT_READ, VM_PROT_WRITE};
    use mach2::vm_region::{vm_region_extended_info_data_t, VM_REGION_EXTENDED_INFO};

    /// `SM_SHARED` and friends: anything but private is a mapped file or the
    /// shared cache.
    const SM_PRIVATE: u8 = 2;
    const SM_PRIVATE_ALIASED: u8 = 6;

    // Decoded once. Comparing raw digests rather than hex strings is not a
    // micro-optimisation: hex-encoding per offset is one heap allocation per
    // byte of the daemon's heap, and it dominates the hashing itself.
    let Some(wanted) = decode_digest(needle_sha256) else {
        return ScanResult {
            present: false,
            regions_scanned: 0,
            bytes_scanned: 0,
        };
    };
    let task = unsafe { mach_task_self() };
    let mut address: mach2::vm_types::mach_vm_address_t = 1;
    let mut regions_scanned = 0usize;
    let mut bytes_scanned = 0u64;
    let mut buffer = vec![0u8; 1 << 20];

    loop {
        let mut size: mach2::vm_types::mach_vm_size_t = 0;
        let mut info = vm_region_extended_info_data_t::default();
        let mut count = vm_region_extended_info_data_t::count();
        let mut object: mach2::port::mach_port_t = 0;

        // SAFETY: every out-parameter is live and correctly sized, `count` is
        // the documented element count for the flavour being asked for, and
        // the call only writes through those pointers.
        let status = unsafe {
            mach_vm_region(
                task,
                &mut address,
                &mut size,
                VM_REGION_EXTENDED_INFO,
                (&mut info as *mut vm_region_extended_info_data_t).cast(),
                &mut count,
                &mut object,
            )
        };
        if status != KERN_SUCCESS {
            break;
        }

        let writable =
            info.protection & (VM_PROT_READ | VM_PROT_WRITE) == (VM_PROT_READ | VM_PROT_WRITE);
        let private = info.share_mode == SM_PRIVATE || info.share_mode == SM_PRIVATE_ALIASED;
        if writable && private && info.pages_resident > 0 {
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

/// Hash every 32-byte window of the region's **resident** pages.
///
/// A region's size is the address range it covers, not the memory in it. A
/// 64 MiB `MALLOC_LARGE` reserve with one resident page is a normal thing for
/// a process to have, and hashing all 64 MiB of it would be sixty-four million
/// pointless digests. So the walk asks the kernel which pages are actually
/// present and hashes only runs of those.
///
/// Runs are hashed with an overlap of `NEEDLE_LEN - 1` at each end, so a
/// marker straddling a page boundary inside a run is still seen whole. A
/// marker straddling the boundary *between* two runs is not, which cannot
/// happen: an allocation big enough to hold one is on pages that are either
/// both present or both absent.
#[cfg(target_os = "macos")]
fn scan_region(
    task: mach2::port::mach_port_t,
    start: mach2::vm_types::mach_vm_address_t,
    size: mach2::vm_types::mach_vm_size_t,
    wanted: &[u8; 32],
    buffer: &mut [u8],
) -> bool {
    let page = page_size();
    let mut offset: u64 = 0;
    while offset < size {
        // Find the next present page, then the end of the run it starts.
        while offset < size && !page_present(task, start + offset) {
            offset += page;
        }
        if offset >= size {
            return false;
        }
        let run_start = offset;
        while offset < size && page_present(task, start + offset) {
            offset += page;
        }
        let run_end = u64::min(offset, size);
        if scan_run(task, start + run_start, run_end - run_start, wanted, buffer) {
            return true;
        }
    }
    false
}

/// Hash every window of one contiguous run of resident pages.
#[cfg(target_os = "macos")]
fn scan_run(
    task: mach2::port::mach_port_t,
    start: mach2::vm_types::mach_vm_address_t,
    length: u64,
    wanted: &[u8; 32],
    buffer: &mut [u8],
) -> bool {
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::vm::mach_vm_read_overwrite;
    use sha2::{Digest, Sha256};

    let mut offset: u64 = 0;
    while offset < length {
        let want = u64::min(buffer.len() as u64, length - offset);
        let mut got: mach2::vm_types::mach_vm_size_t = 0;
        // SAFETY: the destination is `buffer`, which is at least `want` bytes;
        // the source is a range the walk above found present, and a page
        // unmapped in between makes the call fail rather than fault.
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
        for window in buffer[..got as usize].windows(NEEDLE_LEN) {
            if Sha256::digest(window).as_slice() == wanted {
                return true;
            }
        }
        if (got as usize) <= NEEDLE_LEN {
            return false;
        }
        // Chunks overlap so a marker across a chunk boundary is still whole.
        offset += got - (NEEDLE_LEN as u64 - 1);
    }
    false
}

/// Whether the page containing `address` is resident.
#[cfg(target_os = "macos")]
fn page_present(
    task: mach2::port::mach_port_t,
    address: mach2::vm_types::mach_vm_address_t,
) -> bool {
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::vm::mach_vm_page_query;
    use mach2::vm_statistics::VM_PAGE_QUERY_PAGE_PRESENT;

    let mut disposition: libc::c_int = 0;
    let mut ref_count: libc::c_int = 0;
    // SAFETY: both out-parameters are live `c_int`s and the call writes one
    // value to each.
    let status = unsafe { mach_vm_page_query(task, address, &mut disposition, &mut ref_count) };
    status == KERN_SUCCESS && disposition & VM_PAGE_QUERY_PAGE_PRESENT != 0
}

/// The host's page size.
#[cfg(target_os = "macos")]
fn page_size() -> u64 {
    // SAFETY: `sysconf` takes an integer name and returns a long; it touches
    // no memory the caller owns.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(size).unwrap_or(4096)
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

/// Turn a hex digest back into the 32 bytes to compare against.
///
/// `None` for anything that is not exactly 64 hex characters, which is how a
/// malformed request becomes "found nothing" rather than a panic.
fn decode_digest(hex_digest: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_digest.trim(), &mut out).ok()?;
    Some(out)
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
