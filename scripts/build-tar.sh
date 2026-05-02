#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:?VERSION is required (e.g. v0.1.0 or 0.1.0)}"
VERSION="${VERSION#v}"
BINARY_DIR="${BINARY_DIR:?BINARY_DIR path containing kyris binaries is required}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

for bin in kyris kyrisd kyris-mcp kyris-hook; do
  cp "${BINARY_DIR}/${bin}" "${STAGING}/${bin}"
  chmod 755 "${STAGING}/${bin}"
done

mkdir -p "${STAGING}/service"
cp "${REPO_ROOT}/service/is.kyr.kyrisd.plist" "${STAGING}/service/"

TAR_NAME="kyris-${VERSION}-aarch64-apple-darwin.tar.gz"
OUTPUT="${REPO_ROOT}/target/${TAR_NAME}"
mkdir -p "$(dirname "$OUTPUT")"

tar czf "$OUTPUT" -C "$STAGING" .

echo "Built: $OUTPUT"
(cd "$(dirname "$OUTPUT")" && shasum -a 256 "$(basename "$OUTPUT")" | tee "$(basename "$OUTPUT").sha256")
