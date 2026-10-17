#!/usr/bin/env bash
#
# Fill in a formula's `url` and `sha256` from a built tarball.
#
# Usage: stamp-formula.sh <version> <tarball> <formula-in> <formula-out>
#
# The formula in the tree carries a placeholder checksum, because the checksum
# of a release that has not been built yet does not exist. This is what turns
# that template into the formula a tap serves: two lines change and nothing
# else does, which is a property `release_scripts.rs` asserts byte for byte.
#
# Publishing is deliberately not part of this. The release workflow uploads the
# stamped formula as an asset named `briefcred.rb`; copying it into the tap
# repository is done out of band, because the tap is a separate repository with
# its own history and this workflow has no business holding a token for it.

set -euo pipefail

VERSION="${1:?usage: stamp-formula.sh <version> <tarball> <formula-in> <formula-out>}"
TARBALL="${2:?usage: stamp-formula.sh <version> <tarball> <formula-in> <formula-out>}"
IN="${3:?usage: stamp-formula.sh <version> <tarball> <formula-in> <formula-out>}"
OUT="${4:?usage: stamp-formula.sh <version> <tarball> <formula-in> <formula-out>}"

REPO="${BRIEFCRED_REPO:-vkend/briefcred}"

if [[ ! -f "$TARBALL" ]]; then
  echo "stamp-formula: no tarball at $TARBALL" >&2
  exit 1
fi

sha="$(shasum -a 256 "$TARBALL" | cut -d' ' -f1)"
url="https://github.com/$REPO/releases/download/v$VERSION/$(basename "$TARBALL")"

# Anchored on the leading whitespace and the key, so a `url` or `sha256` that
# appeared inside a comment or a `test do` block could not be rewritten by
# accident. `|` as the delimiter because the replacement is a URL.
sed \
  -e "s|^\(  url \).*$|\1\"$url\"|" \
  -e "s|^\(  sha256 \).*$|\1\"$sha\"|" \
  "$IN" > "$OUT"

# Check the result rather than trusting the `sed`, which is the whole reason
# this is a script and not an inline step. The output must carry exactly one
# `url` and one `sha256` line with the values just computed, and be otherwise
# byte-identical to the template. The changed-line count is not the test: when
# the template's placeholder `url` already names this version, as it does for
# the version in the tree, a correct stamp changes only the checksum.
if [[ "$(grep -c "^  url \"$url\"$" "$OUT")" -ne 1 ]]; then
  echo "stamp-formula: the output does not have exactly one url line for $url" >&2
  exit 1
fi
if [[ "$(grep -c "^  sha256 \"$sha\"$" "$OUT")" -ne 1 ]]; then
  echo "stamp-formula: the output does not have exactly one sha256 line for $sha" >&2
  exit 1
fi
if ! diff -q <(grep -v -e '^  url ' -e '^  sha256 ' "$IN") \
             <(grep -v -e '^  url ' -e '^  sha256 ' "$OUT") > /dev/null; then
  echo "stamp-formula: a line other than url and sha256 changed" >&2
  exit 1
fi

echo "stamp-formula: $OUT"
echo "  url    $url"
echo "  sha256 $sha"
