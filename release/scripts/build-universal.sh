#!/usr/bin/env bash
#
# Build every shipping binary as a universal (arm64 + x86_64) Mach-O.
#
# Usage: build-universal.sh <staging-dir>
#
# Cargo cannot emit a universal binary itself, so this builds the release
# profile once per architecture and joins the pairs with `lipo`. The result is
# one file per binary that runs on both an Apple-silicon and an Intel Mac,
# which is what a Homebrew formula and a downloaded tarball both want: a user
# should not have to know which machine they are on.

set -euo pipefail

STAGING="${1:?usage: build-universal.sh <staging-dir>}"

# Every binary briefcred installs. Helpers are named for the minter kind they
# serve rather than for their crate, which is why the list is spelled out
# rather than derived from the crate names.
BINARIES=(
  briefcred
  briefcred-daemon
  briefcred-hook
  briefcred-helper-postgres-dynamic
  briefcred-helper-aws-sts
)

TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)

for target in "${TARGETS[@]}"; do
  rustup target add "$target"
  # `--locked` so a release is built from the lockfile that was reviewed, not
  # from whatever resolved on the morning of the release.
  cargo build --release --locked --workspace --bins --target "$target"
done

mkdir -p "$STAGING/bin"
for binary in "${BINARIES[@]}"; do
  inputs=()
  for target in "${TARGETS[@]}"; do
    path="target/$target/release/$binary"
    if [[ ! -x "$path" ]]; then
      echo "build-universal: $path was not built" >&2
      exit 1
    fi
    inputs+=("$path")
  done
  lipo -create -output "$STAGING/bin/$binary" "${inputs[@]}"
  lipo -info "$STAGING/bin/$binary"
done

echo "build-universal: staged ${#BINARIES[@]} universal binaries in $STAGING/bin"
