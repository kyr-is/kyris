#!/usr/bin/env bash
set -euo pipefail

REPO="kyr-is/kyris"
MODE="system"
LOCAL_DIR=""

info() { printf '[kyris] %s\n' "$*"; }
err()  { printf '[kyris] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: install.sh [--user | --system] [--local <dir>]

  --system       Install to /usr/local/bin/ and /etc/kyris/ (default, needs sudo)
  --user         Install to ~/.local/bin/ (no sudo)
  --local <dir>  Copy binaries from local directory instead of downloading.
                 <dir> should contain kyris, kyrisd, kyris-mcp, kyris-hook binaries
                 (e.g. target/release/).
EOF
  exit 0
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --user)   MODE="user" ;;
      --system) MODE="system" ;;
      --local)
        shift
        [ $# -gt 0 ] || err "--local requires a directory argument"
        LOCAL_DIR="$1"
        ;;
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

validate_local_dir() {
  [ -d "$LOCAL_DIR" ] || err "Local directory does not exist: $LOCAL_DIR"
  for bin in kyris kyrisd kyris-mcp kyris-hook; do
    [ -f "$LOCAL_DIR/$bin" ] || err "$bin binary not found in $LOCAL_DIR"
  done
  LOCAL_DIR="$(cd "$LOCAL_DIR" && pwd)"

  # Resolve project root: look for service/ directory up from binary dir
  LOCAL_PROJECT_ROOT=""
  for candidate in "$LOCAL_DIR/.." "$LOCAL_DIR/../.."; do
    if [ -d "$candidate/service" ]; then
      LOCAL_PROJECT_ROOT="$(cd "$candidate" && pwd)"
      break
    fi
  done
  [ -n "$LOCAL_PROJECT_ROOT" ] || err "Cannot find project root (service/ directory) relative to $LOCAL_DIR"
}

uninstall_existing() {
  local bin_dir plist_label plist_dest real_uid
  plist_label="is.kyr.kyrisd"
  real_uid=$(id -u)

  if [ "$MODE" = "user" ]; then
    bin_dir="$HOME/.local/bin"
  else
    bin_dir="/usr/local/bin"
  fi
  plist_dest="$HOME/Library/LaunchAgents/${plist_label}.plist"

  launchctl bootout "gui/${real_uid}/${plist_label}" 2>/dev/null || true

  for bin in kyris kyrisd kyris-mcp kyris-hook; do
    if [ -f "$bin_dir/$bin" ]; then
      if [ "$MODE" = "system" ]; then
        sudo rm -f "$bin_dir/$bin"
      else
        rm -f "$bin_dir/$bin"
      fi
    fi
  done
  info "Removed old binaries from $bin_dir"

  if [ -f "$plist_dest" ]; then
    rm -f "$plist_dest"
    info "Removed old plist at $plist_dest"
  fi
}

install_local_system() {
  info "Installing (may prompt for password)..."
  for bin in kyris kyrisd kyris-mcp kyris-hook; do
    sudo cp "$LOCAL_DIR/$bin" "/usr/local/bin/$bin"
    sudo chmod 755 "/usr/local/bin/$bin"
  done

  PLIST_LABEL="is.kyr.kyrisd"
  PLIST_TEMPLATE="$LOCAL_PROJECT_ROOT/service/${PLIST_LABEL}.plist"
  PLIST_DIR="$HOME/Library/LaunchAgents"
  PLIST_DEST="${PLIST_DIR}/${PLIST_LABEL}.plist"

  [ -f "$PLIST_TEMPLATE" ] || err "Plist template not found at $PLIST_TEMPLATE"
  mkdir -p "$PLIST_DIR"
  sed -e "s|{{BINARY_PATH}}|/usr/local/bin/kyrisd|g" \
      -e "s|{{HOME}}|${HOME}|g" \
      "$PLIST_TEMPLATE" > "$PLIST_DEST"
  chmod 644 "$PLIST_DEST"

  REAL_UID=$(id -u)
  launchctl bootstrap "gui/${REAL_UID}" "$PLIST_DEST"

  echo ""
  info "Installation complete (system mode, from local build)."
  info "  Binaries: /usr/local/bin/{kyris,kyrisd,kyris-mcp,kyris-hook}"
  info "  Service:  ${PLIST_LABEL} (launchd)"
}

install_local_user() {
  BIN_DIR="$HOME/.local/bin"
  mkdir -p "$BIN_DIR"
  for bin in kyris kyrisd kyris-mcp kyris-hook; do
    cp "$LOCAL_DIR/$bin" "$BIN_DIR/$bin"
    chmod 755 "$BIN_DIR/$bin"
  done

  PLIST_LABEL="is.kyr.kyrisd"
  PLIST_TEMPLATE="$LOCAL_PROJECT_ROOT/service/${PLIST_LABEL}.plist"
  PLIST_DIR="$HOME/Library/LaunchAgents"
  PLIST_DEST="${PLIST_DIR}/${PLIST_LABEL}.plist"

  [ -f "$PLIST_TEMPLATE" ] || err "Plist template not found at $PLIST_TEMPLATE"
  mkdir -p "$PLIST_DIR"
  sed -e "s|{{BINARY_PATH}}|${BIN_DIR}/kyrisd|g" \
      -e "s|{{HOME}}|${HOME}|g" \
      "$PLIST_TEMPLATE" > "$PLIST_DEST"
  chmod 644 "$PLIST_DEST"

  REAL_UID=$(id -u)
  launchctl bootstrap "gui/${REAL_UID}" "$PLIST_DEST"

  echo ""
  info "Installation complete (user mode, from local build)."
  info "  Binaries: $BIN_DIR/{kyris,kyrisd,kyris-mcp,kyris-hook}"
  info "  Service:  ${PLIST_LABEL} (launchd)"
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

verify_install() {
  local bin_dir
  if [ "$MODE" = "user" ]; then
    bin_dir="$HOME/.local/bin"
  else
    bin_dir="/usr/local/bin"
  fi

  info "Running post-install verification..."
  local failures=0

  for bin in kyris kyrisd kyris-mcp kyris-hook; do
    if [ ! -x "$bin_dir/$bin" ]; then
      info "FAIL: $bin not found at $bin_dir/$bin"
      failures=$((failures + 1))
    fi
  done

  if [ -x "$bin_dir/kyrisd" ]; then
    if ! "$bin_dir/kyrisd" --version >/dev/null 2>&1; then
      info "FAIL: kyrisd does not respond to --version"
      failures=$((failures + 1))
    fi
  fi

  local plist="$HOME/Library/LaunchAgents/is.kyr.kyrisd.plist"
  if [ ! -f "$plist" ]; then
    info "FAIL: launchd plist missing at $plist"
    failures=$((failures + 1))
  fi

  local real_uid
  real_uid=$(id -u)
  if ! launchctl print "gui/${real_uid}/is.kyr.kyrisd" >/dev/null 2>&1; then
    info "FAIL: is.kyr.kyrisd not loaded in launchd"
    failures=$((failures + 1))
  fi

  if [ $failures -gt 0 ]; then
    err "Post-install verification failed ($failures check(s))."
  fi

  info "Post-install verification passed."
  info ""
  info "Next: run 'kyris install' to configure shell hooks and agent integrations."
}

main() {
  parse_args "$@"
  info "kyris installer (${MODE} mode${LOCAL_DIR:+, local})"
  detect_target

  if [ -n "$LOCAL_DIR" ]; then
    validate_local_dir
    uninstall_existing
    if [ "$MODE" = "user" ]; then
      install_local_user
    else
      install_local_system
    fi
  else
    resolve_version
    check_existing
    if [ "$MODE" = "user" ]; then
      install_user
    else
      install_system
    fi
  fi

  verify_install
}

main "$@"
