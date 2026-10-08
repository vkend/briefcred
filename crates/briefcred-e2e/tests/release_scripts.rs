//! `release/scripts/stamp-formula.sh` rewrites two lines and nothing else.
//!
//! The formula in the tree carries a placeholder checksum, and the release
//! workflow stamps the real one in from the tarball it just built. That script
//! runs once per release, on a runner, at the moment nobody is watching — so
//! the property worth asserting is the narrow one: the stamped formula differs
//! from the template in the `url` and `sha256` lines and is byte-identical
//! everywhere else. A `sed` that quietly matched a third line would otherwise
//! ship a formula whose `test do` block had been rewritten.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/briefcred-e2e")
        .to_path_buf()
}

/// Run the stamp script over the committed formula and return what it wrote.
///
/// The tarball is a temporary file with known contents rather than a real
/// release archive: the script only ever hashes it, so its bytes are the whole
/// of what it has to be.
fn stamp(version: &str, tarball_name: &str, body: &[u8]) -> (String, String, PathBuf) {
    let root = workspace_root();
    let temp = tempfile::tempdir().expect("temp dir");
    let tarball = temp.path().join(tarball_name);
    std::fs::write(&tarball, body).expect("write tarball");
    let out = temp.path().join("briefcred.rb");
    let template = root.join("release").join("Formula").join("briefcred.rb");

    let status = Command::new("bash")
        .arg(
            root.join("release")
                .join("scripts")
                .join("stamp-formula.sh"),
        )
        .arg(version)
        .arg(&tarball)
        .arg(&template)
        .arg(&out)
        .current_dir(&root)
        .status()
        .expect("run stamp-formula.sh");
    assert!(status.success(), "stamp-formula.sh failed: {status}");

    let before = std::fs::read_to_string(&template).expect("read the template");
    let after = std::fs::read_to_string(&out).expect("read the stamped formula");
    // The temp dir has to outlive the read, so it is returned and dropped by
    // the caller rather than here.
    let kept = temp.keep();
    (before, after, kept)
}

#[test]
fn stamping_rewrites_the_url_and_the_checksum_and_leaves_everything_else_alone() {
    let (before, after, dir) = stamp("9.9.9", "briefcred-9.9.9-macos-universal.tar.gz", b"hello");

    let differing: Vec<(usize, &str, &str)> = before
        .lines()
        .zip(after.lines())
        .enumerate()
        .filter(|(_, (b, a))| b != a)
        .map(|(n, (b, a))| (n + 1, b, a))
        .collect();

    assert_eq!(
        before.lines().count(),
        after.lines().count(),
        "stamping must not add or remove a line"
    );
    assert_eq!(
        differing.len(),
        2,
        "expected exactly two changed lines, got {differing:#?}"
    );
    assert!(
        differing[0].1.trim_start().starts_with("url "),
        "the first changed line must be `url`, was {:?}",
        differing[0].1
    );
    assert!(
        differing[1].1.trim_start().starts_with("sha256 "),
        "the second changed line must be `sha256`, was {:?}",
        differing[1].1
    );

    // The SHA-256 of "hello", so the test asserts the script hashes the
    // tarball rather than merely writing something checksum-shaped.
    assert_eq!(
        differing[1].2.trim(),
        "sha256 \"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\""
    );
    assert_eq!(
        differing[0].2.trim(),
        "url \"https://github.com/vkend/briefcred/releases/download/\
         v9.9.9/briefcred-9.9.9-macos-universal.tar.gz\""
    );

    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn a_missing_tarball_is_refused_rather_than_stamped_with_nothing() {
    let root = workspace_root();
    let temp = tempfile::tempdir().expect("temp dir");
    let out = temp.path().join("briefcred.rb");

    let status = Command::new("bash")
        .arg(
            root.join("release")
                .join("scripts")
                .join("stamp-formula.sh"),
        )
        .arg("9.9.9")
        .arg(temp.path().join("does-not-exist.tar.gz"))
        .arg(root.join("release").join("Formula").join("briefcred.rb"))
        .arg(&out)
        .current_dir(&root)
        .status()
        .expect("run stamp-formula.sh");

    assert!(
        !status.success(),
        "a formula stamped from a tarball that does not exist would carry the \
         checksum of nothing"
    );
}

/// The committed formula still has somewhere for the stamp to land.
///
/// Renaming or reformatting either line would make the script a no-op, and its
/// own line-count check would catch that on a release day rather than here.
#[test]
fn the_committed_formula_still_has_the_two_lines_the_stamp_targets() {
    let formula = std::fs::read_to_string(
        workspace_root()
            .join("release")
            .join("Formula")
            .join("briefcred.rb"),
    )
    .expect("read the formula");

    for key in ["  url ", "  sha256 "] {
        assert_eq!(
            formula.lines().filter(|l| l.starts_with(key)).count(),
            1,
            "the formula must have exactly one line starting `{key}`"
        );
    }
}
