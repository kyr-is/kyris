#!/usr/bin/env bash
set -euo pipefail

# Kyris installer.
#
# Phase 1 ships only user mode. Enterprise mode (root LaunchDaemon, tamper-proof
# logs, signed audit) is planned for phase 2 and is not accepted here.
#
# Uninstall is intentionally broader than install: it clears any residue from
# prior installs (including the legacy system-mode layout under /usr/local/bin
# and /etc/kyris) so upgrades from older releases leave no trace.

REPO="kyr-is/kyris"
AGENTPACT_REPO="kyr-is/agentpact"
TAP="kyr-is/tap"
CASK="${TAP}/kyris"
ACTION="install"
LOCAL_DIR=""
SKIP_AGENTPACT=0
NO_BREW=0
UPGRADE_FROM=""

# Files inside ~/.kyris/ that hold genuine USER state (not kyris-install
# scaffolding). Preserved across upgrades by copying aside before the
# uninstall-then-reinstall cycle and restoring after the new install completes.
# The list is intentionally short — these three are the runtime state the
# daemon owns; everything else under ~/.kyris/ (manifest, backups, hooks,
# env) is managed by kyris install and gets regenerated.
USER_STATE_FILES=(
  "kyrisd.yaml"
  "credentials.json"
  "kyrisd.duckdb"
)

# Shared package registry — vendor-namespaced, follows XDG_DATA_HOME convention.
# Each kyr-is package writes a manifest here at install time and removes it at
# uninstall time. kyris registers itself with depends_on=["agentpact"] so that
# agentpact's uninstall can detect kyris generically (without hardcoding the
# name "kyris" in agentpact's installer).
REGISTRY_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/kyr-packages"
SELF_MANIFEST="$REGISTRY_DIR/kyris.json"

info() { printf '[kyris] %s\n' "$*"; }
err()  { printf '[kyris] ERROR: %s\n' "$*" >&2; exit 1; }

launchctl_print_succeeds() {
  local target="$1"
  local timeout_decisecs="${2:-50}"
  local status_file pid elapsed
  status_file="$(mktemp)"
  elapsed=0

  (
    if launchctl print "$target" >/dev/null 2>&1; then
      echo 0 >"$status_file"
    else
      echo 1 >"$status_file"
    fi
  ) &
  pid=$!

  while kill -0 "$pid" >/dev/null 2>&1; do
    if [ "$elapsed" -ge "$timeout_decisecs" ]; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" 2>/dev/null || true
      rm -f "$status_file"
      return 124
    fi
    sleep 0.1
    elapsed=$((elapsed + 1))
  done

  wait "$pid" 2>/dev/null || true
  if [ -f "$status_file" ] && [ "$(cat "$status_file")" = "0" ]; then
    rm -f "$status_file"
    return 0
  fi
  rm -f "$status_file"
  return 1
}

ensure_kyris_runtime_dir() {
  mkdir -p "$HOME/.kyris"
}

# `launchctl bootout` is async — without this, the new daemon can race the old
# one for the DuckDB file lock.
wait_for_pid_exit() {
  local name="$1"
  local timeout_secs="${2:-15}"
  local elapsed=0

  pgrep -x "$name" >/dev/null 2>&1 || return 0
  info "Waiting for old $name to exit..."

  while pgrep -x "$name" >/dev/null 2>&1; do
    if [ "$elapsed" -ge "$timeout_secs" ]; then
      info "$name still running after ${timeout_secs}s, sending SIGKILL"
      pkill -9 -x "$name" 2>/dev/null || true
      sleep 1
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
}

bootstrap_user_launchagent() {
  local label="$1"
  local plist_dest="$2"
  local real_uid
  real_uid=$(id -u)
  launchctl bootout "gui/${real_uid}/${label}" 2>/dev/null || true
  wait_for_pid_exit "${label#is.kyr.}" 15
  launchctl enable "gui/${real_uid}/${label}" 2>/dev/null || true
  launchctl bootstrap "gui/${real_uid}" "$plist_dest" \
    || err "Failed to load ${label} in launchd. Run 'launchctl bootstrap gui/${real_uid} $plist_dest' for richer errors."
}

register_package() {
  local version="$1"
  local binary_path="$2"
  mkdir -p "$REGISTRY_DIR"
  cat > "$SELF_MANIFEST" <<EOF
{
  "name": "kyris",
  "version": "$version",
  "install_method": "script",
  "depends_on": ["agentpact"],
  "uninstall_url": "https://raw.githubusercontent.com/${REPO}/main/install.sh",
  "uninstall_args": "--uninstall",
  "binary_path": "$binary_path"
}
EOF
}

unregister_package() {
  if [ -f "$SELF_MANIFEST" ]; then
    rm -f "$SELF_MANIFEST"
    info "Removed package manifest at $SELF_MANIFEST"
  fi
  if [ -d "$REGISTRY_DIR" ] && [ -z "$(ls -A "$REGISTRY_DIR" 2>/dev/null)" ]; then
    rmdir "$REGISTRY_DIR" 2>/dev/null || true
  fi
}

# Detect agentpactd in any of the locations install.sh or brew might have used.
# kyris is the dependent here, so it CAN know about its dependency by name —
# this is the legitimate downward direction.
agentpactd_present() {
  local path
  for path in \
    "$HOME/.local/bin/agentpactd" \
    "/opt/homebrew/bin/agentpactd" \
    "/usr/local/bin/agentpactd"
  do
    if [ -x "$path" ]; then
      return 0
    fi
  done
  return 1
}

# Install agentpact via its official install script. Used when kyris is being
# installed but agentpact isn't already present. The auto-install honors the
# same channel-detection logic agentpact's own install.sh uses.
ensure_agentpact_installed() {
  if [ "$SKIP_AGENTPACT" -eq 1 ]; then
    info "Skipping agentpact dependency check (--no-agentpact)."
    return 0
  fi

  if agentpactd_present; then
    info "agentpact already installed; continuing."
    return 0
  fi

  # In --local mode, prefer a sibling agentpact source dir if one exists with
  # a built binary. Falls back to chained curl from upstream.
  if [ -n "$LOCAL_DIR" ]; then
    local candidate
    for candidate in "$LOCAL_PROJECT_ROOT/../agentpact" "$LOCAL_PROJECT_ROOT/../../agentpact"; do
      if [ -d "$candidate" ] && [ -f "$candidate/install.sh" ] \
         && [ -x "$candidate/target/release/agentpactd" ]; then
        local agentpact_root
        agentpact_root="$(cd "$candidate" && pwd)"
        info "Auto-installing agentpact from sibling source at $agentpact_root..."
        "$agentpact_root/install.sh" --local "$agentpact_root/target/release" \
          || err "Failed to auto-install agentpact from local source."
        return 0
      fi
    done
  fi

  info "kyris requires agentpact. Installing agentpact first via chained curl..."
  curl -fsSL "https://raw.githubusercontent.com/${AGENTPACT_REPO}/main/install.sh" | bash \
    || err "Failed to auto-install agentpact. Install it manually, then re-run with --no-agentpact."
  info "agentpact installed; continuing with kyris install."
}

brew_available() { command -v brew >/dev/null 2>&1; }

brew_installed_via_cask() {
  brew_available || return 1
  brew list --cask "$CASK" >/dev/null 2>&1
}

# Routing: when brew is present, prefer it. Brew handles the depends_on for
# agentpact automatically, so the script-side ensure_agentpact_installed isn't
# needed in this path.
try_brew_install() {
  brew_available || return 1
  info "brew detected; attempting install via the ${TAP} cask..."
  if ! brew tap "$TAP" >/dev/null 2>&1; then
    info "Tap ${TAP} unavailable; falling back to script install."
    return 1
  fi
  if ! brew install --cask "$CASK"; then
    info "brew install --cask ${CASK} failed; falling back to script install."
    return 1
  fi
  info "Installed via brew."
  return 0
}

usage() {
  cat <<EOF
Usage: install.sh [--user] [--local <dir>] [--no-agentpact] [--no-brew]
       install.sh --uninstall [--no-brew]

  (no flag)      Install in user mode (default).
  --user         Explicit form of the default. No sudo required.
  --local <dir>  Copy binaries from local directory instead of downloading.
                 <dir> should contain kyris, kyrisd, kyris-mcp, kyris-hook binaries
                 (e.g. target/release/).
  --no-agentpact Skip the agentpact dependency check (script install path only;
                 brew handles depends_on natively). Use if agentpact is installed
                 via a channel kyris cannot detect. kyris will not function until
                 agentpact is available at runtime.
  --no-brew      Skip brew detection and install via the script path even when
                 Homebrew is available. Symmetric on --uninstall.
  --uninstall    Stop kyrisd and remove all installed files, runtime state,
                 config, launchd files, and package receipts. Also cleans up any
                 residue from prior system-mode installs (may prompt for sudo).
                 Does NOT remove agentpact (kyris is the dependent, not the
                 dependency). Run agentpact/install.sh --uninstall separately.
                 If brew installed kyris, delegates to 'brew uninstall --cask --zap'.

Enterprise mode (root LaunchDaemon, tamper-proof logs, /var/run/kyrisd.sock,
/etc/kyris/-managed policy) is planned for phase 2 and is not yet available.
EOF
  exit 0
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --user) ;;
      --uninstall) ACTION="uninstall" ;;
      --no-agentpact|--skip-deps) SKIP_AGENTPACT=1 ;;
      --no-brew) NO_BREW=1 ;;
      --local)
        shift
        [ $# -gt 0 ] || err "--local requires a directory argument"
        LOCAL_DIR="$1"
        ;;
      --system|--enterprise)
        err "$1 is not available in this release. Phase 1 ships only user mode; enterprise mode (root LaunchDaemon) is planned for phase 2."
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
  local bin_path="$HOME/.local/bin/kyrisd"
  if [ -x "$bin_path" ]; then
    INSTALLED_VERSION="$("$bin_path" --version 2>/dev/null | awk '{print $2}')" || true
    RELEASE_VERSION="${VERSION#v}"
    if [ "${INSTALLED_VERSION}" = "${RELEASE_VERSION}" ]; then
      info "kyris ${INSTALLED_VERSION} is already installed and up-to-date."
      exit 0
    fi
    info "Upgrading kyris ${INSTALLED_VERSION} → ${RELEASE_VERSION}"
    UPGRADE_FROM="${INSTALLED_VERSION}"
  fi
}

validate_local_dir() {
  [ -d "$LOCAL_DIR" ] || err "Local directory does not exist: $LOCAL_DIR"
  for bin in kyris kyrisd kyris-mcp kyris-hook; do
    [ -f "$LOCAL_DIR/$bin" ] || err "$bin binary not found in $LOCAL_DIR"
  done
  LOCAL_DIR="$(cd "$LOCAL_DIR" && pwd)"

  LOCAL_PROJECT_ROOT=""
  for candidate in "$LOCAL_DIR/.." "$LOCAL_DIR/../.."; do
    if [ -d "$candidate/service" ]; then
      LOCAL_PROJECT_ROOT="$(cd "$candidate" && pwd)"
      break
    fi
  done
  [ -n "$LOCAL_PROJECT_ROOT" ] || err "Cannot find project root (service/ directory) relative to $LOCAL_DIR"
}

remove_path() {
  local path="$1"
  if [ -e "$path" ] || [ -L "$path" ]; then
    rm -rf "$path"
    info "Removed $path"
  fi
}

remove_path_sudo() {
  local path="$1"
  if [ -e "$path" ] || [ -L "$path" ]; then
    sudo rm -rf "$path"
    info "Removed $path"
  fi
}

# Filter all lines containing `.kyris/` out of a shell rc file. If the result
# is empty (file was 100% kyris-managed), delete the file. Used in scorched-
# earth cleanup so a uninstall after the kyris binary is gone still removes
# stale `source "$HOME/.kyris/..."` and `export PATH="$HOME/.kyris/bin:..."`
# lines from ~/.zshenv, ~/.zshrc, ~/.bashrc, ~/.bash_profile, etc.
clean_shell_rc() {
  local file="$1"
  [ -f "$file" ] || return 0
  if ! grep -q '\.kyris/' "$file" 2>/dev/null; then
    return 0
  fi
  local tmp
  tmp="$(mktemp)"
  if grep -v '\.kyris/' "$file" > "$tmp"; then
    :
  fi
  if [ -s "$tmp" ]; then
    mv "$tmp" "$file"
    info "Cleaned kyris lines from $file"
  else
    rm -f "$file" "$tmp"
    info "Removed $file (was 100% kyris-managed)"
  fi
}

# Read kyris's manifest.json (one entry per file kyris ever wrote) and either
# restore each entry from its backup (for files kyris APPENDED to, like
# shell rc and agent settings.json) or delete the file (for files kyris
# CREATED, like agent hook scripts). Works without the kyris binary.
manifest_driven_cleanup() {
  local manifest="$HOME/.kyris/manifest.json"
  [ -f "$manifest" ] || return 0
  if ! command -v python3 >/dev/null 2>&1; then
    info "WARN: python3 not available; skipping manifest-driven cleanup."
    return 0
  fi
  info "Reading kyris manifest at $manifest..."
  python3 - "$manifest" <<'PY' || true
import json, os, shutil, sys
manifest_path = sys.argv[1]
try:
    with open(manifest_path) as f:
        entries = json.load(f)
except Exception as exc:
    print(f"[kyris] WARN: could not parse manifest ({exc}); skipping.")
    sys.exit(0)
for entry in entries:
    target = entry.get("path")
    backup = entry.get("backup_path")
    if not target:
        continue
    try:
        if backup and os.path.exists(backup):
            shutil.copy(backup, target)
            print(f"[kyris] Restored {target} from backup")
        elif os.path.exists(target):
            os.unlink(target)
            print(f"[kyris] Removed {target}")
    except Exception as exc:
        print(f"[kyris] WARN: cleanup of {target} failed: {exc}")
PY
}

# Substring markers that uniquely identify kyris-installed content. Designed
# narrow enough that user-installed entries containing the bare word "kyris"
# (e.g. an unrelated plugin or extension) don't false-positive.
#
# kept centralized so verify_uninstall and clean_agent_json_config agree.
KYRIS_MARKER_REGEX='/\.kyris/|kyris-mcp|kyris-hook|kyris_pretooluse|agentpact_pretooluse'

# Surgically remove kyris entries from a JSON config file (like ~/.codex/hooks.json
# or ~/.claude/settings.json). If the file becomes empty after cleanup, delete it.
# Only writes the file back if something actually changed (preserves original
# formatting otherwise) and creates a `.kyris-uninstall.bak` first as insurance.
clean_agent_json_config() {
  local file="$1"
  [ -f "$file" ] || return 0
  if ! grep -q -E "$KYRIS_MARKER_REGEX" "$file" 2>/dev/null; then
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    info "WARN: python3 not available; cannot surgically clean $file."
    return 0
  fi
  python3 - "$file" <<'PY' || true
import json, os, shutil, sys
path = sys.argv[1]
try:
    with open(path) as f:
        original = f.read()
        data = json.loads(original)
except Exception as exc:
    print(f"[kyris] WARN: could not parse {path} ({exc}); skipping.")
    sys.exit(0)

# Narrow markers — must match the bash regex above so behavior stays in sync.
KYRIS_MARKERS = ("/.kyris/", "kyris-mcp", "kyris-hook", "kyris_pretooluse", "agentpact_pretooluse")

def contains_kyris(node):
    if isinstance(node, str):
        return any(m in node for m in KYRIS_MARKERS)
    if isinstance(node, list):
        return any(contains_kyris(x) for x in node)
    if isinstance(node, dict):
        return any(contains_kyris(v) for v in node.values()) \
            or any(contains_kyris(k) for k in node.keys())
    return False

def prune(node):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if contains_kyris(k):
                continue
            cleaned = prune(v)
            if cleaned in (None, [], {}) and contains_kyris(v):
                continue
            out[k] = cleaned
        return out
    if isinstance(node, list):
        return [prune(x) for x in node if not contains_kyris(x)]
    return node

cleaned = prune(data)

if cleaned == data:
    # Marker matched somewhere our pruner did not consider an edit — bail
    # without modifying the file. Conservative: only write if we have a real
    # diff to apply.
    sys.exit(0)

def is_empty(node):
    if node in (None, [], {}, ""):
        return True
    if isinstance(node, dict):
        return all(is_empty(v) for v in node.values())
    if isinstance(node, list):
        return all(is_empty(v) for v in node)
    return False

# Backup before any mutation so the user can recover if our pruning was wrong.
backup = path + ".kyris-uninstall.bak"
shutil.copy(path, backup)

if is_empty(cleaned):
    os.unlink(path)
    print(f"[kyris] Removed {path} (was 100% kyris-managed after cleanup; backup at {backup})")
else:
    with open(path, "w") as f:
        json.dump(cleaned, f, indent=2)
    print(f"[kyris] Cleaned kyris entries from {path} (backup at {backup})")
PY
}

# Scorched-earth cleanup: walks well-known paths kyris install may have touched
# and removes anything kyris. Works without manifest, without binary, even if a
# prior uninstall attempt was incomplete. Idempotent.
scorched_earth_cleanup() {
  info "Running scorched-earth cleanup of well-known paths..."

  # Shell rc files — surgical line removal matching `.kyris/`.
  local rc
  for rc in \
    "$HOME/.zshenv" \
    "$HOME/.zshrc" \
    "$HOME/.zprofile" \
    "$HOME/.bashrc" \
    "$HOME/.bash_profile" \
    "$HOME/.profile"
  do
    clean_shell_rc "$rc"
  done

  # Well-known agent hook script paths — kyris install writes these directly,
  # so remove them outright.
  local hook
  for hook in \
    "$HOME/.claude/hooks/agentpact_pretooluse.sh" \
    "$HOME/.codex/kyris_pretooluse.sh" \
    "$HOME/.gemini/kyris_pretooluse.sh"
  do
    if [ -f "$hook" ]; then
      rm -f "$hook"
      info "Removed $hook"
    fi
  done

  # Agent JSON configs — surgically remove kyris entries (preserves any non-
  # kyris content the user or other tools added).
  local cfg
  for cfg in \
    "$HOME/.codex/hooks.json" \
    "$HOME/.claude/settings.json" \
    "$HOME/.gemini/settings.json"
  do
    clean_agent_json_config "$cfg"
  done
}

uninstall_all() {
  local plist_label plist_dest real_uid bin path
  plist_label="is.kyr.kyrisd"
  plist_dest="$HOME/Library/LaunchAgents/${plist_label}.plist"
  real_uid=$(id -u)

  # If brew owns this install, delegate the actual removal to brew so its
  # bookkeeping (Cellar, receipts, services state) stays consistent. Run
  # `kyris uninstall` first regardless to clean shell hooks before brew
  # removes the binary it relies on.
  if [ "$NO_BREW" -ne 1 ] && brew_installed_via_cask; then
    local brew_kyris_cli=""
    for path in "$HOME/.local/bin/kyris" "/opt/homebrew/bin/kyris" "/usr/local/bin/kyris"; do
      if [ -x "$path" ]; then
        brew_kyris_cli="$path"
        break
      fi
    done
    if [ -n "$brew_kyris_cli" ]; then
      info "Running 'kyris uninstall' to remove shell hooks and agent integrations..."
      "$brew_kyris_cli" uninstall || info "WARN: 'kyris uninstall' exited non-zero; continuing."
    fi
    # Same defense-in-depth as the script path: walk the manifest if present,
    # then scorched-earth over well-known paths. Done BEFORE brew removes the
    # binary so manifest is still readable from ~/.kyris/.
    manifest_driven_cleanup
    scorched_earth_cleanup
    info "Detected brew-installed kyris; delegating to 'brew uninstall --cask --zap ${CASK}'..."
    brew uninstall --cask --zap "$CASK" \
      || err "brew uninstall failed; resolve manually before re-running."
    unregister_package
    verify_uninstall
    echo ""
    info "Uninstall complete (via brew)."
    return 0
  fi

  info "Uninstalling kyris completely..."

  # Run `kyris uninstall` first to remove shell hooks and agent integrations.
  # That command operates on user dotfiles (~/.zshrc, ~/.claude/settings.json,
  # etc.) which install.sh otherwise wouldn't touch. Runs only if the kyris
  # CLI is reachable; tolerates failure so we don't strand half-removed state.
  local kyris_cli=""
  for path in "$HOME/.local/bin/kyris" "/opt/homebrew/bin/kyris" "/usr/local/bin/kyris"; do
    if [ -x "$path" ]; then
      kyris_cli="$path"
      break
    fi
  done
  if [ -n "$kyris_cli" ]; then
    info "Running 'kyris uninstall' to remove shell hooks and agent integrations..."
    if ! "$kyris_cli" uninstall; then
      info "WARN: 'kyris uninstall' exited non-zero; continuing with binary removal."
    fi
  fi

  # Defense in depth: even if `kyris uninstall` ran successfully, walk the
  # manifest ourselves to catch anything it missed. If `kyris uninstall`
  # didn't run (binary missing — common when uninstall is invoked after a
  # prior partial removal), this is the primary cleanup path.
  manifest_driven_cleanup

  # Final scorched-earth pass over well-known paths. Catches the case where
  # both the binary AND manifest are gone but stale agent hooks / shell rc
  # lines remain. Surgical: only removes lines/entries matching kyris markers.
  scorched_earth_cleanup

  launchctl bootout "gui/${real_uid}/${plist_label}" 2>/dev/null || true
  launchctl disable "gui/${real_uid}/${plist_label}" 2>/dev/null || true
  wait_for_pid_exit kyrisd 15

  remove_path "$plist_dest"
  for bin in kyris kyrisd kyris-mcp kyris-hook; do
    remove_path "$HOME/.local/bin/$bin"
  done
  remove_path "$HOME/.kyris"

  # Clean residue from legacy system-mode installs. Only prompts for sudo if
  # something actually exists at these paths.
  local need_sudo=0
  for bin in kyris kyrisd kyris-mcp kyris-hook; do
    if [ -e "/usr/local/bin/$bin" ]; then
      need_sudo=1
      break
    fi
  done
  if [ "$need_sudo" -eq 0 ] && { [ -e "/etc/kyris" ] || pkgutil --pkg-info "is.kyr.kyris" >/dev/null 2>&1; }; then
    need_sudo=1
  fi

  if [ "$need_sudo" -eq 1 ]; then
    info "Detected legacy system-mode install; sudo required to remove."
    for bin in kyris kyrisd kyris-mcp kyris-hook; do
      remove_path_sudo "/usr/local/bin/$bin"
    done
    remove_path_sudo "/etc/kyris"
    if pkgutil --pkg-info "is.kyr.kyris" >/dev/null 2>&1; then
      sudo pkgutil --forget "is.kyr.kyris" >/dev/null || true
      info "Forgot package receipt is.kyr.kyris"
    fi
  fi

  unregister_package

  if [ "${UPGRADE_IN_PROGRESS:-0}" -eq 1 ]; then
    # Don't run verify_uninstall during upgrade — the new install will
    # immediately rewrite paths and fail it. Don't print "uninstall complete"
    # either since this is a transient phase of upgrade.
    return 0
  fi

  verify_uninstall

  echo ""
  info "Uninstall complete."
}

install_local() {
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
  ensure_kyris_runtime_dir
  sed -e "s|{{BINARY_PATH}}|${BIN_DIR}/kyrisd|g" \
      -e "s|{{HOME}}|${HOME}|g" \
      -e "s|{{PATH}}|${BIN_DIR}:/usr/local/bin:/usr/bin:/bin|g" \
      "$PLIST_TEMPLATE" > "$PLIST_DEST"
  chmod 644 "$PLIST_DEST"

  bootstrap_user_launchagent "$PLIST_LABEL" "$PLIST_DEST"

  local installed_version
  installed_version="$("$BIN_DIR/kyrisd" --version 2>/dev/null | awk '{print $2}')" || installed_version=""
  [ -n "$installed_version" ] || installed_version="unknown"
  register_package "$installed_version" "$BIN_DIR/kyrisd"

  echo ""
  info "Installation complete (user mode, from local build)."
  info "  Binaries: $BIN_DIR/{kyris,kyrisd,kyris-mcp,kyris-hook}"
  info "  Service:  ${PLIST_LABEL} (launchd)"
}

install_remote() {
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
  ensure_kyris_runtime_dir
  sed -e "s|{{BINARY_PATH}}|${BIN_DIR}/kyrisd|g" \
      -e "s|{{HOME}}|${HOME}|g" \
      -e "s|{{PATH}}|${BIN_DIR}:/usr/local/bin:/usr/bin:/bin|g" \
      "$PLIST_TEMPLATE" > "$PLIST_DEST"
  chmod 644 "$PLIST_DEST"

  bootstrap_user_launchagent "$PLIST_LABEL" "$PLIST_DEST"

  register_package "${RELEASE_VERSION}" "$BIN_DIR/kyrisd"

  echo ""
  info "Installation complete (user mode)."
  info "  Binaries: $BIN_DIR/{kyris,kyrisd,kyris-mcp,kyris-hook}"
  info "  Service:  ${PLIST_LABEL} (launchd)"
}

verify_install() {
  local bin_dir="$HOME/.local/bin"

  info "Running post-install verification..."
  local verify_status=0
  (
    if [ -x "$bin_dir/kyris" ]; then
      "$bin_dir/kyris" verify --post-install
    else
      exit 127
    fi
  ) &
  local verify_pid=$!
  local elapsed=0
  while kill -0 "$verify_pid" >/dev/null 2>&1; do
    if [ "$elapsed" -ge 100 ]; then
      kill "$verify_pid" >/dev/null 2>&1 || true
      wait "$verify_pid" 2>/dev/null || true
      err "Post-install verification timed out."
    fi
    sleep 0.1
    elapsed=$((elapsed + 1))
  done

  if ! wait "$verify_pid"; then
    verify_status=$?
  fi

  if [ "$verify_status" -ne 0 ]; then
    err "Post-install verification failed."
  fi

  info "Post-install verification passed."
  info ""
  info "Next: run 'kyris install' to configure shell hooks and agent integrations."
}

verify_uninstall() {
  local failures=0
  local real_uid bin path
  real_uid=$(id -u)

  if launchctl_print_succeeds "gui/${real_uid}/is.kyr.kyrisd" 20; then
    info "FAIL: is.kyr.kyrisd still loaded in launchd"
    failures=$((failures + 1))
  fi

  if pgrep -x kyrisd >/dev/null 2>&1; then
    info "FAIL: kyrisd process is still running"
    failures=$((failures + 1))
  fi

  for path in \
    "$HOME/Library/LaunchAgents/is.kyr.kyrisd.plist" \
    "$HOME/.kyris" \
    "$SELF_MANIFEST" \
    "/etc/kyris"
  do
    if [ -e "$path" ] || [ -L "$path" ]; then
      info "FAIL: uninstall residue remains at $path"
      failures=$((failures + 1))
    fi
  done

  for bin in kyris kyrisd kyris-mcp kyris-hook; do
    for path in "$HOME/.local/bin/$bin" "/usr/local/bin/$bin"; do
      if [ -e "$path" ] || [ -L "$path" ]; then
        info "FAIL: uninstall residue remains at $path"
        failures=$((failures + 1))
      fi
    done
  done

  # Well-known agent hook scripts kyris install writes — should be gone.
  local hook
  for hook in \
    "$HOME/.claude/hooks/agentpact_pretooluse.sh" \
    "$HOME/.codex/kyris_pretooluse.sh" \
    "$HOME/.gemini/kyris_pretooluse.sh"
  do
    if [ -e "$hook" ] || [ -L "$hook" ]; then
      info "FAIL: agent hook script remains at $hook"
      failures=$((failures + 1))
    fi
  done

  # Shell rc files — no kyris-referencing lines should remain.
  local rc
  for rc in \
    "$HOME/.zshenv" \
    "$HOME/.zshrc" \
    "$HOME/.zprofile" \
    "$HOME/.bashrc" \
    "$HOME/.bash_profile" \
    "$HOME/.profile"
  do
    if [ -f "$rc" ] && grep -q '\.kyris/' "$rc" 2>/dev/null; then
      info "FAIL: kyris references remain in $rc"
      failures=$((failures + 1))
    fi
  done

  # Agent JSON configs — no kyris markers should remain.
  local cfg
  for cfg in \
    "$HOME/.codex/hooks.json" \
    "$HOME/.claude/settings.json" \
    "$HOME/.gemini/settings.json"
  do
    if [ -f "$cfg" ] && \
       grep -q -E "$KYRIS_MARKER_REGEX" "$cfg" 2>/dev/null; then
      info "FAIL: kyris markers remain in $cfg"
      failures=$((failures + 1))
    fi
  done

  if pkgutil --pkg-info "is.kyr.kyris" >/dev/null 2>&1; then
    info "FAIL: package receipt is.kyr.kyris still exists"
    failures=$((failures + 1))
  fi

  if [ $failures -gt 0 ]; then
    err "Uninstall verification failed ($failures trace(s) remain)."
  fi

  info "Uninstall verification passed."
}

# Copy user-state files into a temp directory so the upgrade can wipe ~/.kyris/
# without losing the user's config, credentials, or event-log history. Sets
# the global UPGRADE_STATE_DIR for restore_user_state to read.
preserve_user_state() {
  UPGRADE_STATE_DIR="$(mktemp -d)"
  local file copied=0
  for file in "${USER_STATE_FILES[@]}"; do
    if [ -f "$HOME/.kyris/$file" ]; then
      cp "$HOME/.kyris/$file" "$UPGRADE_STATE_DIR/$file"
      copied=$((copied + 1))
    fi
  done
  info "Preserved $copied user-state file(s) for upgrade at $UPGRADE_STATE_DIR"
}

# Restore the preserved user-state files into ~/.kyris/ after the new install
# completes. Idempotent — silently skips files that aren't in the temp dir.
restore_user_state() {
  if [ -z "${UPGRADE_STATE_DIR:-}" ] || [ ! -d "$UPGRADE_STATE_DIR" ]; then
    return 0
  fi
  ensure_kyris_runtime_dir
  local file restored=0
  for file in "${USER_STATE_FILES[@]}"; do
    if [ -f "$UPGRADE_STATE_DIR/$file" ]; then
      cp "$UPGRADE_STATE_DIR/$file" "$HOME/.kyris/$file"
      chmod 600 "$HOME/.kyris/$file"
      restored=$((restored + 1))
    fi
  done
  rm -rf "$UPGRADE_STATE_DIR"
  UPGRADE_STATE_DIR=""
  info "Restored $restored user-state file(s) after upgrade"
}

# Full uninstall-then-reinstall cycle to handle file drift across versions.
# Called when check_existing detected an installed-version mismatch. Triggers
# the same tier 1+2+3 cleanup as a real uninstall (so renamed/removed files
# from the old release are purged) but preserves user state.
upgrade_via_full_reset() {
  info "Resetting old install before fresh install of ${RELEASE_VERSION:-new version}..."
  preserve_user_state
  # Run uninstall_all in upgrade mode by setting a flag the function honors.
  UPGRADE_IN_PROGRESS=1
  uninstall_all
  UPGRADE_IN_PROGRESS=0
  # uninstall_all removed ~/.kyris/ along with everything else; recreate it
  # and put user state back so the daemon's first start sees its config.
  ensure_kyris_runtime_dir
  restore_user_state
}

main() {
  parse_args "$@"
  if [ "$ACTION" = "uninstall" ]; then
    detect_target
    uninstall_all
    exit 0
  fi

  info "kyris installer (user mode${LOCAL_DIR:+, local})"
  detect_target

  # --local always uses the script path (the developer wants their local build,
  # not whatever brew has). For non-local installs, prefer brew when present —
  # brew handles the depends_on for agentpact natively.
  if [ -z "$LOCAL_DIR" ] && [ "$NO_BREW" -ne 1 ] && try_brew_install; then
    exit 0
  fi

  if [ -n "$LOCAL_DIR" ]; then
    validate_local_dir
    ensure_agentpact_installed
    # --local upgrades pass through full uninstall first too (file drift can
    # come from local builds across branches just as easily as remote tags).
    if [ -x "$HOME/.local/bin/kyrisd" ]; then
      RELEASE_VERSION="local"
      UPGRADE_FROM="$("$HOME/.local/bin/kyrisd" --version 2>/dev/null | awk '{print $2}')" || UPGRADE_FROM=""
      [ -n "$UPGRADE_FROM" ] && upgrade_via_full_reset
    fi
    install_local
  else
    resolve_version
    check_existing
    ensure_agentpact_installed
    # If check_existing detected a version change, do a full reset before
    # installing the new bits. Otherwise just install fresh.
    if [ -n "$UPGRADE_FROM" ]; then
      upgrade_via_full_reset
    fi
    install_remote
  fi

  verify_install
}

main "$@"
