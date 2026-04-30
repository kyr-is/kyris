#!/usr/bin/env bash
set -euo pipefail

REPO="kyr-is/kyris"
PLIST_LABEL="is.kyr.kyrisd"
CONFIG_DIR="${HOME}/.kyris"
BINARIES=(kyris kyrisd kyris-mcp kyris-hook)

info() { printf '[kyris] %s\n' "$*"; }
err()  { printf '[kyris] ERROR: %s\n' "$*" >&2; exit 1; }

# --- Detect architecture ---
detect_target() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "${OS}" in
    Darwin) ;;
    *) err "Unsupported OS: ${OS}. Only macOS is supported." ;;
  esac

  case "${ARCH}" in
    arm64|aarch64) TARGET="aarch64-apple-darwin"; ARCH_LABEL="aarch64" ;;
    *) err "Unsupported architecture: ${ARCH}. Only Apple Silicon (aarch64) is supported." ;;
  esac
}

# --- Resolve latest version if not specified ---
resolve_version() {
  if [ -n "${VERSION:-}" ]; then
    return
  fi
  info "Fetching latest release..."
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')"
  [ -n "${VERSION}" ] || err "Could not determine latest release version"
}

# --- Choose install directory ---
choose_install_dir() {
  if [ -w /usr/local/bin ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "${INSTALL_DIR}"
    case ":${PATH}:" in
      *":${INSTALL_DIR}:"*) ;;
      *) info "NOTE: Add ${INSTALL_DIR} to your PATH" ;;
    esac
  fi
}

# --- Check if already installed and up-to-date ---
check_existing() {
  if command -v kyrisd >/dev/null 2>&1; then
    INSTALLED_VERSION="$(kyrisd --version 2>/dev/null | awk '{print $2}')" || true
    RELEASE_VERSION="${VERSION#v}"
    if [ "${INSTALLED_VERSION}" = "${RELEASE_VERSION}" ]; then
      info "kyris ${INSTALLED_VERSION} is already installed and up-to-date."
      exit 0
    fi
    info "Updating kyris ${INSTALLED_VERSION} → ${RELEASE_VERSION}"
  fi
}

# --- Download and verify tarball ---
download_binaries() {
  TARBALL="kyris-darwin-${ARCH_LABEL}.tar.gz"
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"
  CHECKSUM_URL="${DOWNLOAD_URL}.sha256"
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT

  info "Downloading kyris ${VERSION} for ${TARGET}..."
  curl -fsSL -o "${TMP_DIR}/${TARBALL}" "${DOWNLOAD_URL}"
  curl -fsSL -o "${TMP_DIR}/${TARBALL}.sha256" "${CHECKSUM_URL}"

  info "Verifying checksum..."
  (cd "${TMP_DIR}" && shasum -a 256 -c "${TARBALL}.sha256") || err "Checksum verification failed"

  info "Extracting binaries..."
  tar -xzf "${TMP_DIR}/${TARBALL}" -C "${TMP_DIR}"

  for bin in "${BINARIES[@]}"; do
    [ -f "${TMP_DIR}/${bin}" ] || err "Missing binary in tarball: ${bin}"
    chmod +x "${TMP_DIR}/${bin}"
    mv "${TMP_DIR}/${bin}" "${INSTALL_DIR}/${bin}"
  done

  info "Installed binaries to ${INSTALL_DIR}"
}

# --- Create config directory ---
setup_config_dir() {
  mkdir -p "${CONFIG_DIR}"
  info "Config directory: ${CONFIG_DIR}"
}

# --- Install and load launchd plist ---
install_launchd() {
  PLIST_SRC="$(dirname "$0")/service/${PLIST_LABEL}.plist"
  PLIST_DEST="${HOME}/Library/LaunchAgents/${PLIST_LABEL}.plist"
  BINARY_PATH="${INSTALL_DIR}/kyrisd"

  mkdir -p "${HOME}/Library/LaunchAgents"

  if [ -f "${PLIST_SRC}" ]; then
    info "Installing launchd plist from ${PLIST_SRC}..."
    sed -e "s|{{BINARY_PATH}}|${BINARY_PATH}|g" \
        -e "s|{{HOME}}|${HOME}|g" \
        "${PLIST_SRC}" > "${PLIST_DEST}"
  else
    info "Generating launchd plist..."
    cat > "${PLIST_DEST}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BINARY_PATH}</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${HOME}/.kyris/kyrisd.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${HOME}/.kyris/kyrisd.stderr.log</string>
</dict>
</plist>
PLIST
  fi

  launchctl bootout "gui/$(id -u)/${PLIST_LABEL}" 2>/dev/null || true

  info "Loading launchd service..."
  launchctl bootstrap "gui/$(id -u)" "${PLIST_DEST}"

  info "Service loaded: ${PLIST_LABEL}"
}

# --- Main ---
main() {
  info "kyris installer"
  detect_target
  resolve_version
  choose_install_dir
  check_existing
  download_binaries
  setup_config_dir
  install_launchd

  echo ""
  info "Installation complete!"
  info "  Binaries: ${INSTALL_DIR}/{kyris,kyrisd,kyris-mcp,kyris-hook}"
  info "  Config:   ${CONFIG_DIR}/"
  info "  Service:  ${PLIST_LABEL} (launchd)"
  info ""
  info "Next steps:"
  info "  kyris agents              # show detected agents"
  info "  kyris agents setup claude-code  # configure an agent"
}

main "$@"
