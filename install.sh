#!/usr/bin/env bash
set -euo pipefail

REPO="kyr-is/kyris"
MODE="system"

info() { printf '[kyris] %s\n' "$*"; }
err()  { printf '[kyris] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: install.sh [--user | --system]

  --system   Install to /usr/local/bin/ and /etc/kyris/ (default, needs sudo)
  --user     Install to ~/.local/bin/ (no sudo)
EOF
  exit 0
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --user)   MODE="user" ;;
      --system) MODE="system" ;;
      --help|-h) usage ;;
      *) err "Unknown option: $1" ;;
    esac
    shift
  done
}

detect_target() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "${OS}" in
    Darwin) ;;
    *) err "Unsupported OS: ${OS}. Only macOS is supported." ;;
  esac

  case "${ARCH}" in
    arm64|aarch64) ;;
    *) err "Unsupported architecture: ${ARCH}. Only Apple Silicon (aarch64) is supported." ;;
  esac
}

resolve_version() {
  if [ -n "${VERSION:-}" ]; then
    return
  fi
  info "Fetching latest release..."
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')"
  [ -n "${VERSION}" ] || err "Could not determine latest release version"
}

check_existing() {
  local bin_path
  if [ "$MODE" = "user" ]; then
    bin_path="$HOME/.local/bin/kyrisd"
  else
    bin_path="/usr/local/bin/kyrisd"
  fi

  if [ -x "$bin_path" ]; then
    INSTALLED_VERSION="$("$bin_path" --version 2>/dev/null | awk '{print $2}')" || true
    RELEASE_VERSION="${VERSION#v}"
    if [ "${INSTALLED_VERSION}" = "${RELEASE_VERSION}" ]; then
      info "kyris ${INSTALLED_VERSION} is already installed and up-to-date."
      exit 0
    fi
    info "Updating kyris ${INSTALLED_VERSION} → ${RELEASE_VERSION}"
  fi
}

install_system() {
  PKG_NAME="kyris-${VERSION#v}.pkg"
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${PKG_NAME}"
  CHECKSUM_URL="${DOWNLOAD_URL}.sha256"
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT

  info "Downloading kyris ${VERSION} (.pkg)..."
  curl -fsSL -o "${TMP_DIR}/${PKG_NAME}" "${DOWNLOAD_URL}"
  curl -fsSL -o "${TMP_DIR}/${PKG_NAME}.sha256" "${CHECKSUM_URL}"

  info "Verifying checksum..."
  (cd "${TMP_DIR}" && shasum -a 256 -c "${PKG_NAME}.sha256") \
    || err "Checksum verification failed"

  info "Installing (may prompt for password)..."
  sudo INSTALLER_USER="$USER" installer -pkg "${TMP_DIR}/${PKG_NAME}" -target /

  echo ""
  info "Installation complete (system mode)."
  info "  Binaries: /usr/local/bin/{kyris,kyrisd,kyris-mcp,kyris-hook}"
  info "  Service:  is.kyr.kyrisd (launchd)"
}

install_user() {
  RELEASE_VERSION="${VERSION#v}"
  TAR_NAME="kyris-${RELEASE_VERSION}-aarch64-apple-darwin.tar.gz"
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TAR_NAME}"
  CHECKSUM_URL="${DOWNLOAD_URL}.sha256"
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT

  info "Downloading kyris ${VERSION} (.tar.gz)..."
  curl -fsSL -o "${TMP_DIR}/${TAR_NAME}" "${DOWNLOAD_URL}"
  curl -fsSL -o "${TMP_DIR}/${TAR_NAME}.sha256" "${CHECKSUM_URL}"

  info "Verifying checksum..."
  (cd "${TMP_DIR}" && shasum -a 256 -c "${TAR_NAME}.sha256") \
    || err "Checksum verification failed"

  info "Extracting..."
  tar xzf "${TMP_DIR}/${TAR_NAME}" -C "${TMP_DIR}"

  BIN_DIR="$HOME/.local/bin"
  mkdir -p "$BIN_DIR"
  for bin in kyris kyrisd kyris-mcp kyris-hook; do
    cp "${TMP_DIR}/${bin}" "$BIN_DIR/${bin}"
    chmod 755 "$BIN_DIR/${bin}"
  done

  PLIST_LABEL="is.kyr.kyrisd"
  PLIST_TEMPLATE="${TMP_DIR}/service/${PLIST_LABEL}.plist"
  PLIST_DIR="$HOME/Library/LaunchAgents"
  PLIST_DEST="${PLIST_DIR}/${PLIST_LABEL}.plist"

  mkdir -p "$PLIST_DIR"
  sed -e "s|{{BINARY_PATH}}|${BIN_DIR}/kyrisd|g" \
      -e "s|{{HOME}}|${HOME}|g" \
      "$PLIST_TEMPLATE" > "$PLIST_DEST"
  chmod 644 "$PLIST_DEST"

  REAL_UID=$(id -u)
  launchctl bootout "gui/${REAL_UID}/${PLIST_LABEL}" 2>/dev/null || true
  launchctl bootstrap "gui/${REAL_UID}" "$PLIST_DEST"

  echo ""
  info "Installation complete (user mode)."
  info "  Binaries: $BIN_DIR/{kyris,kyrisd,kyris-mcp,kyris-hook}"
  info "  Service:  ${PLIST_LABEL} (launchd)"
}

main() {
  parse_args "$@"
  info "kyris installer (${MODE} mode)"
  detect_target
  resolve_version
  check_existing

  if [ "$MODE" = "user" ]; then
    install_user
  else
    install_system
  fi

  info ""
  info "Run 'kyris status' to verify."
}

main "$@"
