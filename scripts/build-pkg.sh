#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:?VERSION is required (e.g. v0.1.0 or 0.1.0)}"
VERSION="${VERSION#v}"
BINARY_DIR="${BINARY_DIR:?BINARY_DIR path containing kyris binaries is required}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

STAGING=$(mktemp -d)
SCRIPTS_DIR=$(mktemp -d)
trap 'rm -rf "$STAGING" "$SCRIPTS_DIR"' EXIT

mkdir -p "${STAGING}/usr/local/bin"
for bin in kyris kyrisd kyris-mcp kyris-hook; do
  cp "${BINARY_DIR}/${bin}" "${STAGING}/usr/local/bin/${bin}"
  chmod 755 "${STAGING}/usr/local/bin/${bin}"
done

mkdir -p "${STAGING}/etc/kyris/service"
cp "${REPO_ROOT}/service/is.kyr.kyrisd.plist" "${STAGING}/etc/kyris/service/"

cp "${REPO_ROOT}/scripts/pkg-postinstall" "${SCRIPTS_DIR}/postinstall"
chmod 755 "${SCRIPTS_DIR}/postinstall"

COMPONENT_PKG=$(mktemp -d)/kyris-component.pkg
pkgbuild \
  --identifier "is.kyr.kyris" \
  --version "$VERSION" \
  --root "$STAGING" \
  --install-location "/" \
  --scripts "$SCRIPTS_DIR" \
  "$COMPONENT_PKG"

OUTPUT="${REPO_ROOT}/target/kyris-${VERSION}.pkg"
mkdir -p "$(dirname "$OUTPUT")"
productbuild \
  --identifier "is.kyr.kyris" \
  --version "$VERSION" \
  --package "$COMPONENT_PKG" \
  "$OUTPUT"

echo "Built: $OUTPUT"
(cd "$(dirname "$OUTPUT")" && shasum -a 256 "$(basename "$OUTPUT")" | tee "$(basename "$OUTPUT").sha256")
