#!/usr/bin/env bash
#
# Code-sign and notarise the staged binaries, when Apple credentials exist.
#
# Usage: sign-and-notarize.sh <staging-dir>
#
# Exits 0 and signs nothing when the credentials are absent. That is deliberate:
# a fork, a pull request, and anybody building a release on their own machine
# should all get a working tarball, and the release notes say which kind it is.
# A release that could only ever be built by the one person holding the
# certificate is one that stops being built.
#
# Environment, all required together:
#   APPLE_CERTIFICATE        base64 of the Developer ID Application .p12
#   APPLE_CERTIFICATE_PASSWORD  its password
#   APPLE_SIGNING_IDENTITY   e.g. "Developer ID Application: Example (TEAMID)"
#   APPLE_API_KEY            base64 of the App Store Connect .p8 private key
#   APPLE_API_KEY_ID         its key id
#   APPLE_API_ISSUER         the issuer UUID

set -euo pipefail

STAGING="${1:?usage: sign-and-notarize.sh <staging-dir>}"

required=(
  APPLE_CERTIFICATE
  APPLE_CERTIFICATE_PASSWORD
  APPLE_SIGNING_IDENTITY
  APPLE_API_KEY
  APPLE_API_KEY_ID
  APPLE_API_ISSUER
)
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "sign-and-notarize: $name is not set; leaving the build unsigned"
    exit 0
  fi
done

workdir="$(mktemp -d)"
trap 'security delete-keychain "$workdir/build.keychain" 2>/dev/null || true; rm -rf "$workdir"' EXIT

# A throwaway keychain rather than the login one. The runner is ephemeral, but
# the certificate is not: an import into a keychain something else can read is
# how a signing identity leaves the job it was meant for.
keychain="$workdir/build.keychain"
keychain_password="$(uuidgen)"
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"

printf '%s' "$APPLE_CERTIFICATE" | base64 --decode > "$workdir/certificate.p12"
security import "$workdir/certificate.p12" \
  -k "$keychain" \
  -P "$APPLE_CERTIFICATE_PASSWORD" \
  -T /usr/bin/codesign
# Without this, `codesign` puts an interactive prompt on a machine with no
# screen and the job hangs until it times out.
security set-key-partition-list -S apple-tool:,apple:,codesign: \
  -s -k "$keychain_password" "$keychain" > /dev/null
security list-keychains -d user -s "$keychain" "$(security default-keychain | tr -d ' "')"

# `--options runtime` is not optional: notarisation refuses anything without
# the hardened runtime. `--timestamp` is what keeps the signature valid after
# the certificate expires.
for binary in "$STAGING"/bin/*; do
  codesign --force --sign "$APPLE_SIGNING_IDENTITY" \
    --options runtime --timestamp "$binary"
  codesign --verify --strict --verbose=2 "$binary"
done

printf '%s' "$APPLE_API_KEY" | base64 --decode > "$workdir/api-key.p8"

# Notarisation takes an archive, not a directory of executables.
ditto -c -k --keepParent "$STAGING/bin" "$workdir/notarize.zip"
xcrun notarytool submit "$workdir/notarize.zip" \
  --key "$workdir/api-key.p8" \
  --key-id "$APPLE_API_KEY_ID" \
  --issuer "$APPLE_API_ISSUER" \
  --wait

# There is no `stapler staple` step here, and that is correct rather than
# missing: a ticket can only be stapled to a bundle, a disk image or an
# installer package, never to a bare Mach-O executable. A notarised command
# line tool is checked against Apple's service the first time it runs, so the
# submission above is the whole of what a tarball can carry.
echo "sign-and-notarize: signed and notarised $(ls "$STAGING/bin" | wc -l | tr -d ' ') binaries"
echo "BRIEFCRED_SIGNED=1" >> "${GITHUB_ENV:-/dev/null}"
