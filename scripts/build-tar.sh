#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Kyris
# SPDX-License-Identifier: Apache-2.0
#
# Produces the single release artifact:
#
#   Kyrisd-${VERSION}-${TARGET}.app.tar.gz   (+ .sha256)
#
# All four binaries (kyris, kyrisd, kyris-mcp, kyris-hook) live inside
# Contents/MacOS/, so one notarization covers the whole set and Gatekeeper
# accepts each one. Both install.sh and the Homebrew Cask consume this
# bundle directly — no other artifact ships.
#
# The bundle ships its launchd plist template at
# Contents/Resources/is.kyr.kyrisd.plist and the build-time Cargo.toml at
# Contents/Resources/Cargo.toml so installers can read the pinned agentpact
# dependency version without cloning the repo.

set -euo pipefail

VERSION="${VERSION:?VERSION is required (e.g. v0.1.0 or 0.1.0)}"
VERSION="${VERSION#v}"
BINARY_DIR="${BINARY_DIR:?BINARY_DIR path containing kyris binaries is required}"
TARGET="${TARGET:-aarch64-apple-darwin}"
# PREBUILT_APP, when set to a path to an existing Kyrisd.app, skips
# the bundle rebuild step and tars the supplied bundle directly. Used
# by the release pipeline so a Developer-ID-signed + notarized
# bundle isn't silently replaced with an ad-hoc-signed one.
PREBUILT_APP="${PREBUILT_APP:-}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

case "$TARGET" in
    *-apple-darwin) ;;
    *) echo "Unsupported TARGET: $TARGET (only *-apple-darwin)" >&2; exit 1 ;;
esac

BUNDLE_STAGING=$(mktemp -d)
trap 'rm -rf "$BUNDLE_STAGING"' EXIT

if [ -n "$PREBUILT_APP" ]; then
    # Pre-built bundle (Developer-ID-signed + notarized).
    # Tar it directly; don't re-run build-app-bundle.sh,
    # which would replace the real signature with an ad-hoc
    # one and invalidate notarization.
    [ -d "$PREBUILT_APP" ] || { echo "PREBUILT_APP not a directory: $PREBUILT_APP" >&2; exit 1; }
    [ "${PREBUILT_APP##*.}" = "app" ] || { echo "PREBUILT_APP does not look like a .app: $PREBUILT_APP" >&2; exit 1; }
    cp -R "$PREBUILT_APP" "${BUNDLE_STAGING}/Kyrisd.app"
else
    COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    BINARY_DIR="$BINARY_DIR" VERSION="$VERSION" COMMIT="$COMMIT" OUT_DIR="$BUNDLE_STAGING" \
        "${REPO_ROOT}/scripts/build-app-bundle.sh"
fi

APP_TAR_NAME="Kyrisd-${VERSION}-${TARGET}.app.tar.gz"
APP_OUTPUT="${REPO_ROOT}/target/${APP_TAR_NAME}"
mkdir -p "$(dirname "$APP_OUTPUT")"
# Tar only the bundle. All four binaries live inside; no
# top-level files needed.
tar czf "$APP_OUTPUT" -C "$BUNDLE_STAGING" Kyrisd.app
echo "Built: $APP_OUTPUT"
(cd "$(dirname "$APP_OUTPUT")" && shasum -a 256 "$(basename "$APP_OUTPUT")" | tee "$(basename "$APP_OUTPUT").sha256")
