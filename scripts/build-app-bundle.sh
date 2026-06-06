#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Kyris
# SPDX-License-Identifier: Apache-2.0
#
# Builds Kyrisd.app, the macOS app bundle that wraps every kyris
# binary (kyrisd + kyris + kyris-mcp + kyris-hook) under a single
# Developer ID identity. Putting all four executables inside
# Contents/MacOS/ means:
#   - One codesign + notarization submission covers the whole set
#   - Gatekeeper sees them as belonging to a notarized bundle, no
#     "could not verify" popups on any of the four
#   - Drag-to-Trash removes everything cleanly
#   - install.sh and the Homebrew Cask use the exact same on-disk
#     layout, so callers (shell hooks, agents that exec `kyris`)
#     don't care which channel installed it
#
# The bundle's CFBundleExecutable is `kyrisd` — that's what launchd
# runs. The other three binaries are along for the ride and exposed
# via symlinks in ~/.local/bin (install.sh) or HOMEBREW_PREFIX/bin
# (Cask).
#
# Inputs (env vars):
#   BINARY_DIR — directory containing kyrisd + kyris + kyris-mcp +
#                kyris-hook (required)
#   OUT_DIR    — directory to create Kyrisd.app inside (required)
#   VERSION    — for CFBundleShortVersionString (required; accepts
#                "v0.1.2" or "0.1.2")
#   COMMIT     — short git commit for CFBundleVersion (optional)
#
# Backwards-compat: BINARY (single path to kyrisd) is still accepted
# if BINARY_DIR isn't set. In that case we derive BINARY_DIR from
# BINARY's directory and expect the other three binaries to live
# alongside.
#
# Output:
#   ${OUT_DIR}/Kyrisd.app/
#     Contents/
#       Info.plist
#       MacOS/
#         kyrisd         (CFBundleExecutable; launchd starts this)
#         kyris
#         kyris-mcp
#         kyris-hook
#       Resources/
#         is.kyr.kyrisd.plist   (launchd template colocated with binary)
#         Cargo.toml            (source of truth for pinned agentpact version)
#
# Ad-hoc codesigns the result. Distribution-grade signing happens in
# sign-and-notarize.sh.

set -euo pipefail

: "${OUT_DIR:?OUT_DIR env var is required (directory to create Kyrisd.app inside)}"
: "${VERSION:?VERSION env var is required (e.g. 0.1.2 or v0.1.2)}"
VERSION="${VERSION#v}"
COMMIT="${COMMIT:-unknown}"

# Allow either BINARY_DIR (preferred) or BINARY (single-path
# back-compat). The bundle wants all four binaries, so resolve a
# directory either way.
if [ -z "${BINARY_DIR:-}" ]; then
    : "${BINARY:?BINARY_DIR or BINARY env var is required}"
    BINARY_DIR="$(cd "$(dirname "$BINARY")" && pwd)"
fi

for bin in kyrisd kyris kyris-mcp kyris-hook; do
    [ -x "$BINARY_DIR/$bin" ] || { echo "missing executable: $BINARY_DIR/$bin" >&2; exit 1; }
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="${REPO_ROOT}/service/Info.plist.template"
LAUNCHD_TEMPLATE="${REPO_ROOT}/service/is.kyr.kyrisd.plist"
[ -f "$TEMPLATE" ] || { echo "missing Info.plist template at $TEMPLATE" >&2; exit 1; }
[ -f "$LAUNCHD_TEMPLATE" ] || { echo "missing launchd plist template at $LAUNCHD_TEMPLATE" >&2; exit 1; }

APP_DIR="${OUT_DIR}/Kyrisd.app"
CONTENTS="${APP_DIR}/Contents"
MACOS_DIR="${CONTENTS}/MacOS"
RESOURCES_DIR="${CONTENTS}/Resources"

# Wipe any prior bundle at this location before rebuilding — partial
# bundles confuse codesign.
rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

# Generate Info.plist with substituted version + commit.
sed -e "s|{{VERSION}}|${VERSION}|g" \
    -e "s|{{COMMIT}}|${COMMIT}|g" \
    "$TEMPLATE" > "${CONTENTS}/Info.plist"

# Drop all four binaries into Contents/MacOS/. cp -p preserves mode +
# mtime so the bundle is reproducible regardless of where you ran us.
#
# Notification delivery: NOT via a sibling helper binary. We tried
# that (Swift `kyris-notify`); macOS rejected it because LaunchServices
# only registers the bundle's CFBundleExecutable (kyrisd), not
# arbitrary other Mach-O files in Contents/MacOS/. UN center calls
# now live in-process in kyrisd via objc2 — see daemon/src/notify_macos.rs.
for bin in kyrisd kyris kyris-mcp kyris-hook; do
    cp -p "$BINARY_DIR/$bin" "$MACOS_DIR/$bin"
    chmod 755 "$MACOS_DIR/$bin"
done

# Ship the launchd plist template inside the bundle so the Homebrew
# Cask + install.sh can find it without needing the repo cloned.
cp -p "$LAUNCHD_TEMPLATE" "${RESOURCES_DIR}/is.kyr.kyrisd.plist"

# Ship Cargo.toml so install.sh and the Homebrew Cask can read the
# pinned agentpact dependency version from the same source the binaries
# were built against. The workspace [workspace.dependencies] agentpact
# entry is the single source of truth — installers extract `tag` /
# `version` from it to know which agentpact to install or update to.
cp -p "${REPO_ROOT}/Cargo.toml" "${RESOURCES_DIR}/Cargo.toml"

# Ad-hoc codesign. Required so UNUserNotificationCenter can resolve
# our bundle identity; replaced with a real Developer ID signature in
# CI / by sign-and-notarize.sh.
#
# TODO: Replace --deep with per-binary signing before notarization.
# --deep is deprecated for distribution builds: each binary should be
# signed individually with its own entitlements before the bundle is
# signed.  --deep is acceptable for ad-hoc (development) use only.
codesign --sign - --force --deep "$APP_DIR" >/dev/null 2>&1

codesign --verify --strict "$APP_DIR" >/dev/null 2>&1 || {
    echo "codesign --verify failed for $APP_DIR" >&2
    exit 1
}

echo "Built bundle: $APP_DIR"
