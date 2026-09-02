#!/usr/bin/env bash
#
# Turn a staging directory into the tarball and checksum a release ships.
#
# Usage: package.sh <version> <staging-dir> <output-dir>
#
# One tarball, not one per architecture: the binaries inside are universal, so
# splitting them would produce two downloads that differ only in what they
# cannot run.

set -euo pipefail

VERSION="${1:?usage: package.sh <version> <staging-dir> <output-dir>}"
STAGING="${2:?usage: package.sh <version> <staging-dir> <output-dir>}"
OUT="${3:?usage: package.sh <version> <staging-dir> <output-dir>}"

NAME="briefcred-${VERSION}-macos-universal"

mkdir -p "$OUT"
# Copied one at a time rather than in one `cp`: the licence files are not in
# the tree yet, and a single `cp a b c d` that fails on the first missing name
# would silently drop the README and the changelog with it.
for extra in LICENSE-MIT LICENSE-APACHE README.md CHANGELOG.md; do
  if [[ -f "$extra" ]]; then
    cp "$extra" "$STAGING/"
  else
    echo "package: $extra is not in the tree; the tarball ships without it" >&2
  fi
done

tar -czf "$OUT/$NAME.tar.gz" -C "$STAGING" .

# Computed in the output directory so the sums file names the archives and not
# the paths of whoever built them. A checksum whose left column is somebody's
# home directory is one nobody can check.
(cd "$OUT" && shasum -a 256 "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
# `*.tar.gz` rather than `./*.tar.gz`: `shasum` prints the path it was given,
# and a `SHA256SUMS` whose right column starts `./` does not match what
# `shasum -c` is run against from a directory of downloaded files.
(cd "$OUT" && shasum -a 256 -- *.tar.gz > SHA256SUMS)

echo "package: wrote $OUT/$NAME.tar.gz"
cat "$OUT/SHA256SUMS"
