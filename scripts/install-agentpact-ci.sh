#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# CI helper: installs a pinned agentpactd release for cross-repo integration tests.
set -euo pipefail

AGENTPACT_VERSION="${AGENTPACT_VERSION:-latest}"
REPO="kyr-is/agentpact"

if [ "$AGENTPACT_VERSION" = "latest" ]; then
    AGENTPACT_VERSION=$(gh release view --repo "$REPO" --json tagName -q .tagName)
fi

ARCH=$(uname -m)
case "$ARCH" in
    arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
    x86_64)        TARGET="x86_64-apple-darwin" ;;
    *)             echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

gh release download "$AGENTPACT_VERSION" \
    --repo "$REPO" \
    --pattern "agentpactd" \
    --pattern "agentpactd.sha256" \
    --dir "$TMPDIR"

cd "$TMPDIR"
shasum -a 256 -c agentpactd.sha256

chmod +x agentpactd
sudo mv agentpactd /usr/local/bin/

echo "Installed agentpactd $AGENTPACT_VERSION"
agentpactd --version
