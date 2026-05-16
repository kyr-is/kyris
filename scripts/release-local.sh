#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Kyris
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end local release for Kyris. Builds all four binaries,
# packs them into Kyrisd.app (all of kyrisd, kyris, kyris-mcp,
# kyris-hook live inside Contents/MacOS/), then signs + notarizes +
# staples the bundle as a single unit. Apple's notarization of the
# bundle covers all four embedded binaries — no separate signing
# rounds needed.
#
# Output:
#   target/Kyrisd-${VERSION}-${TARGET}.app.tar.gz     (+ .sha256)
#
# Usage:
#   VERSION=0.1.2 ./scripts/release-local.sh
#
# Skipping notarization (faster, but artifact won't pass Gatekeeper
# on other machines):
#   VERSION=0.1.2 SKIP_NOTARIZE=1 ./scripts/release-local.sh

set -euo pipefail

: "${VERSION:?VERSION is required (e.g. 0.1.2)}"
VERSION="${VERSION#v}"
TARGET="${TARGET:-aarch64-apple-darwin}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "===> Building all kyris binaries (release)..."
cargo build --release --target "$TARGET" \
    -p kyris -p kyrisd -p kyris-mcp -p kyris-hook 2>&1 | tail -3

BIN_DIR="$REPO_ROOT/target/${TARGET}/release"
[ -x "$BIN_DIR/kyrisd" ] || BIN_DIR="$REPO_ROOT/target/release"
for bin in kyris kyrisd kyris-mcp kyris-hook; do
    [ -x "$BIN_DIR/$bin" ] || { echo "Missing binary: $BIN_DIR/$bin" >&2; exit 1; }
    xattr -d com.apple.quarantine "$BIN_DIR/$bin" 2>/dev/null || true
done

echo "===> Wrapping all four binaries in Kyrisd.app..."
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BINARY_DIR="$BIN_DIR" VERSION="$VERSION" COMMIT="$COMMIT" OUT_DIR="$BUILD_DIR" \
    bash "$REPO_ROOT/scripts/build-app-bundle.sh"
APP_PATH="$BUILD_DIR/Kyrisd.app"

# Sign + notarize + staple the bundle. codesign --deep (inside
# sign-and-notarize.sh) recurses into Contents/MacOS/ and signs every
# embedded binary with the Developer ID. Apple's notarization
# submission then covers the whole bundle, including the three CLI
# binaries that ride along inside.
echo "===> Signing and notarizing the bundle (all four binaries inside)..."
VERSION="$VERSION" bash "$REPO_ROOT/scripts/sign-and-notarize.sh" "$APP_PATH"

echo "===> Building distribution tarball..."
BINARY_DIR="$BIN_DIR" VERSION="$VERSION" TARGET="$TARGET" \
    PREBUILT_APP="$APP_PATH" \
    bash "$REPO_ROOT/scripts/build-tar.sh"

APP_TAR="$REPO_ROOT/target/Kyrisd-${VERSION}-${TARGET}.app.tar.gz"

echo
echo "==============================================================="
echo "Bundle tarball:  $APP_TAR"
echo "  SHA256:        $(awk '{print $1}' "${APP_TAR}.sha256")"
echo "==============================================================="
echo
echo "To upload to GitHub Releases:"
echo "  gh release create v${VERSION} \\"
echo "    --title 'kyris ${VERSION}' \\"
echo "    \"$APP_TAR\" \"${APP_TAR}.sha256\""
