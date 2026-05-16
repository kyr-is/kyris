#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Kyris
# SPDX-License-Identifier: Apache-2.0
#
# Sign, notarize, and staple a Kyrisd.app bundle so macOS Gatekeeper
# accepts it on any machine without a "could not verify" popup. Designed
# for both local releases and CI use — the only difference between the
# two paths is where the signing identity comes from (here we read it
# from the user's keychain).
#
# One-time prerequisites on the build machine:
#   1. Developer ID Application cert installed in login keychain
#      (verify with: security find-identity -v -p codesigning)
#   2. Notarization credentials stored:
#        xcrun notarytool store-credentials kyris-notarization \
#            --apple-id ... --team-id ... --password ...
#
# Usage:
#   VERSION=0.1.2 ./scripts/sign-and-notarize.sh path/to/Kyrisd.app
#
# Env vars (all optional except VERSION):
#   KEYCHAIN_PROFILE   notarytool profile name (default: kyris-notarization)
#   SIGNING_IDENTITY   prefix match against `find-identity` (default:
#                      "Developer ID Application")
#   SKIP_NOTARIZE      if set, only sign + stop. Useful for fast local
#                      tests where you don't want to wait for Apple's
#                      notarization service (~1-5 min per submission).

set -euo pipefail

: "${VERSION:?VERSION is required (e.g. 0.1.2)}"
VERSION="${VERSION#v}"
APP_PATH="${1:?path to Kyrisd.app}"
KEYCHAIN_PROFILE="${KEYCHAIN_PROFILE:-kyris-notarization}"
SIGNING_IDENTITY="${SIGNING_IDENTITY:-Developer ID Application}"

[ -d "$APP_PATH" ] || { echo "$APP_PATH is not a directory" >&2; exit 1; }
[ "${APP_PATH##*.}" = "app" ] || { echo "$APP_PATH does not end in .app" >&2; exit 1; }
APP_PATH="$(cd "$APP_PATH/.." && pwd)/$(basename "$APP_PATH")"

# --- 1. Sign with real Developer ID ---------------------------------------

identity_match=$(security find-identity -v -p codesigning \
                 | grep -F "$SIGNING_IDENTITY" | head -1 || true)
[ -n "$identity_match" ] || {
    echo "No signing identity matching '$SIGNING_IDENTITY' in keychain." >&2
    echo "Run: security find-identity -v -p codesigning" >&2
    exit 1
}
echo "==> Signing with: $identity_match"

codesign --force --deep --options runtime --timestamp \
    --sign "$SIGNING_IDENTITY" "$APP_PATH"

codesign --verify --deep --strict --verbose=1 "$APP_PATH" 2>&1 | tail -3
echo "==> Signed."

if [ -n "${SKIP_NOTARIZE:-}" ]; then
    echo "SKIP_NOTARIZE set — stopping after signing."
    exit 0
fi

# --- 2. Notarize ----------------------------------------------------------

ZIP_PATH="$(dirname "$APP_PATH")/$(basename "$APP_PATH" .app)-${VERSION}-for-notarization.zip"
rm -f "$ZIP_PATH"
ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"

echo "==> Submitting for notarization (1-5 min typical, occasionally longer)..."
SUBMIT_OUT=$(xcrun notarytool submit "$ZIP_PATH" \
    --keychain-profile "$KEYCHAIN_PROFILE" \
    --wait \
    --output-format json)
rm -f "$ZIP_PATH"

status=$(echo "$SUBMIT_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
if [ "$status" != "Accepted" ]; then
    echo "Notarization failed with status: $status" >&2
    echo "$SUBMIT_OUT" >&2
    submission_id=$(echo "$SUBMIT_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
    if [ -n "$submission_id" ]; then
        echo "==> Fetching notarization log for submission $submission_id..." >&2
        xcrun notarytool log "$submission_id" --keychain-profile "$KEYCHAIN_PROFILE" >&2 || true
    fi
    exit 1
fi
echo "==> Notarization Accepted."

# --- 3. Staple the ticket so Gatekeeper works offline --------------------

xcrun stapler staple "$APP_PATH"
xcrun stapler validate "$APP_PATH"

echo "==> Gatekeeper assessment:"
spctl --assess --type execute --verbose=2 "$APP_PATH" 2>&1 | head -5

echo
echo "$APP_PATH is signed, notarized, and stapled."
echo "Ready for distribution."
