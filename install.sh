#!/usr/bin/env bash
set -euo pipefail

# Kyris installer.
#
# Phase 1 ships only user mode. Enterprise mode (root LaunchDaemon, tamper-proof
# logs, signed audit) is planned for phase 2 and is not accepted here.
#
# Uninstall is intentionally broader than install: it clears any residue from
# prior installs (including the legacy system-mode layout under /usr/local/bin
# and /etc/kyris) so upgrades from older releases leave no trace. It also
# cascade-removes agentpact when kyris was its last dependent — same
# version reconciliation that a fresh `install.sh` would apply on the next
# install, so the user never ends up with a stale orphan agentpact.
# Cascade is gated on the kyr-packages registry: if any other manifest
# declares `depends_on: ["agentpact"]`, agentpact is preserved.
#
# MODES (see usage() for full flag reference and file layout):
#   install.sh                              install (user mode, default)
#   install.sh --local <dir>                install from a local build (e.g. target/release/)
#   install.sh --no-brew                    install via script even when brew is present
#   install.sh --no-agentpact               install without the agentpact dependency check
#   install.sh --uninstall                  uninstall, preserve user data (config/data/state)
#   install.sh --uninstall --reset-data     uninstall, also wipe XDG dirs (true clean slate)
#   install.sh --uninstall --no-brew        force script-path uninstall even if brew installed it
#   install.sh --help                       full usage including file layout and examples

REPO="kyr-is/kyris"
AGENTPACT_REPO="kyr-is/agentpact"
TAP="kyr-is/tap"
CASK="${TAP}/kyris"
ACTION="install"
# Required agentpact version is derived at runtime from the Cargo.toml
# bundled inside Kyrisd.app/Contents/Resources/Cargo.toml (or from the local
# checkout in --local mode). Single source of truth, no constants to drift.
AGENTPACT_VERSION=""
LOCAL_DIR=""
SKIP_AGENTPACT=0
NO_BREW=0
RESET_DATA=0

# Name of the auth-key store subdir under DATA_DIR. The local hook<->daemon
# secrets live here as 0600 files; must match kyris_core::paths::secret_dir()
# (its leaf component). Preserved even by --reset-data so keys never regenerate.
SECRET_SUBDIR="secret"

# Bundle layout. Only kyrisd (the long-running daemon) is wrapped in a
# .app bundle — the bundle gives macOS a stable CFBundleIdentifier so
# notifications, SMAppService, and TCC can attribute the daemon
# properly. The CLI binaries (kyris, kyris-mcp, kyris-hook) are
# transient and stay as bare files in ~/.local/bin/. We symlink the
# kyrisd CLI shim from ~/.local/bin to inside the bundle so callers
# (shell hooks, integration tests, ad-hoc `kyrisd doctor` invocations)
# keep working unchanged.
APP_INSTALL_DIR="$HOME/Applications"
APP_NAME="Kyrisd.app"
APP_PATH="${APP_INSTALL_DIR}/${APP_NAME}"
APP_BINARY="${APP_PATH}/Contents/MacOS/kyrisd"
BIN_SHIM_DIR="$HOME/.local/bin"

# File-system layout (XDG Base Directory + an install-managed runtime dir).
# User data lives outside the install-managed runtime dir so upgrade —
# which is uninstall + install — wipes the runtime freely without losing
# keys, credentials, or event-log history.
#
#   $HOME/.kyris/                   install-managed runtime (manifest,
#                                   hooks, env, backups, pid) — wiped by
#                                   uninstall.
#   $XDG_CONFIG_HOME/kyris/         kyrisd.yaml — survives uninstall.
#   $XDG_DATA_HOME/kyris/           credentials.json, kyrisd.duckdb (event
#                                   log) — survives uninstall.
#   $XDG_STATE_HOME/kyris/          kyris.log, kyrisd.{stderr,stdout}.log,
#                                   crash/, diagnostics/, fail-open.jsonl —
#                                   survives uninstall; wiped only by
#                                   --reset-data or `brew uninstall --zap`.
RUNTIME_DIR="$HOME/.kyris"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/kyris"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/kyris"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/kyris"
LOG_DIR="${STATE_DIR}/log"

# Cached installer (same pattern as agentpact). Written on every successful
# install so any future uninstall — including cascades from a dependent —
# can run a script that exactly matches the on-disk layout, without
# network dependency or tag-URL fragility.
INSTALLER_CACHE="${RUNTIME_DIR}/installer.sh"

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
  mkdir -p "$RUNTIME_DIR"
}

# Create the runtime dir plus every XDG dir the daemon will write into.
# Called before launchd bootstrap so the plist's StandardErrorPath under
# STATE_DIR/log/ resolves on first run — launchd silently drops output
# if the parent dir is missing.
ensure_all_dirs() {
  mkdir -p "$RUNTIME_DIR" "$CONFIG_DIR" "$DATA_DIR" "$STATE_DIR" "$LOG_DIR"
}

# Cache a copy of the install.sh for this exact version at
# ~/.kyris/installer.sh. The cached script is what dependents and future
# uninstalls prefer over a network fetch — same code that placed the
# files removes them.
cache_installer() {
  local version_ref="${1:-main}"
  ensure_kyris_runtime_dir
  local source_url="https://raw.githubusercontent.com/${REPO}/${version_ref}/install.sh"

  # --local mode: just copy our own on-disk script when $0 points at a
  # real file. (curl|bash sets $0 to "bash"; fall through to network.)
  if [ -n "$LOCAL_DIR" ] && [ -f "$0" ]; then
    cp "$0" "$INSTALLER_CACHE"
    chmod 755 "$INSTALLER_CACHE"
    info "Cached installer from local source at $INSTALLER_CACHE"
    return 0
  fi

  if curl -fsSL "$source_url" -o "${INSTALLER_CACHE}.tmp" 2>/dev/null; then
    mv "${INSTALLER_CACHE}.tmp" "$INSTALLER_CACHE"
    chmod 755 "$INSTALLER_CACHE"
    info "Cached installer at $INSTALLER_CACHE (from ${source_url})"
  else
    rm -f "${INSTALLER_CACHE}.tmp"
    info "WARN: could not cache installer from ${source_url}; uninstall will fall back to network fetch."
  fi
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
  # installer_script_path is the cached installer (see cache_installer);
  # dependents and any future uninstall prefer it over the uninstall_url
  # network fetch. uninstall_url is pinned to the version-matched tag so a
  # network fallback still gets a script matching this on-disk layout.
  cat > "$SELF_MANIFEST" <<EOF
{
  "name": "kyris",
  "version": "$version",
  "install_method": "script",
  "depends_on": ["agentpact"],
  "uninstall_url": "https://raw.githubusercontent.com/${REPO}/v${version}/install.sh",
  "uninstall_args": "--uninstall",
  "binary_path": "$binary_path",
  "installer_script_path": "$INSTALLER_CACHE"
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

# Locate the agentpactd binary kyris will talk to. Checks every path
# install.sh or brew might have used so we detect cross-channel installs.
agentpactd_path() {
  local path
  for path in \
    "$HOME/.local/bin/agentpactd" \
    "/opt/homebrew/bin/agentpactd" \
    "/usr/local/bin/agentpactd"
  do
    if [ -x "$path" ]; then
      printf '%s\n' "$path"
      return 0
    fi
  done
  return 1
}

# Read agentpact version from a kyris Cargo.toml. The workspace
# [workspace.dependencies] agentpact entry is the single source of truth —
# build-app-bundle.sh copies Cargo.toml into Contents/Resources/ so the
# installed bundle carries the exact version it was built against.
extract_agentpact_version_from_cargo() {
  local cargo_toml="$1"
  [ -f "$cargo_toml" ] || return 1
  awk '
    /^agentpact[[:space:]]*=/ {
      if (match($0, /version[[:space:]]*=[[:space:]]*"[^"]+"/)) {
        v = substr($0, RSTART, RLENGTH)
        sub(/^version[[:space:]]*=[[:space:]]*"/, "", v)
        sub(/"$/, "", v)
        print v
        exit 0
      }
      if (match($0, /tag[[:space:]]*=[[:space:]]*"v?[^"]+"/)) {
        v = substr($0, RSTART, RLENGTH)
        sub(/^tag[[:space:]]*=[[:space:]]*"v?/, "", v)
        sub(/"$/, "", v)
        print v
        exit 0
      }
    }
  ' "$cargo_toml"
}

# Sets AGENTPACT_VERSION. Sources, in order:
#   1. $AGENTPACT_VERSION already set (env override; for debugging)
#   2. The Cargo.toml shipped inside the bundle ($BUNDLE_CARGO_TOML, set by
#      install_remote after extraction)
#   3. The local checkout's Cargo.toml ($LOCAL_PROJECT_ROOT/Cargo.toml in
#      --local mode)
resolve_agentpact_version() {
  if [ -n "$AGENTPACT_VERSION" ]; then
    return 0
  fi

  local source=""
  if [ -n "${BUNDLE_CARGO_TOML:-}" ] && [ -f "$BUNDLE_CARGO_TOML" ]; then
    AGENTPACT_VERSION="$(extract_agentpact_version_from_cargo "$BUNDLE_CARGO_TOML")" || true
    source="$BUNDLE_CARGO_TOML"
  elif [ -n "$LOCAL_DIR" ] && [ -f "$LOCAL_PROJECT_ROOT/Cargo.toml" ]; then
    AGENTPACT_VERSION="$(extract_agentpact_version_from_cargo "$LOCAL_PROJECT_ROOT/Cargo.toml")" || true
    source="$LOCAL_PROJECT_ROOT/Cargo.toml"
  fi

  [ -n "$AGENTPACT_VERSION" ] \
    || err "Could not determine required agentpact version from $source. The bundled Cargo.toml is missing the [workspace.dependencies] agentpact entry."
  info "Required agentpact version: ${AGENTPACT_VERSION} (from $source)"
}

# Build a raw.githubusercontent.com URL for agentpact's install.sh at a given
# version tag (or "main"). Versioned URLs let us run an installer that knows
# the exact file layout of the version being uninstalled — critical when
# layouts change across releases.
agentpact_installer_url() {
  local ref="$1"
  printf 'https://raw.githubusercontent.com/%s/%s/install.sh\n' \
    "$AGENTPACT_REPO" "$ref"
}

# Run the agentpact installer remotely with VERSION pinned. The installer is
# always fetched at the target version's tag — its layout and the binary's
# layout agree.
install_agentpact_remote() {
  local version="$1"
  info "Installing agentpact v${version} via chained curl..."
  curl -fsSL "$(agentpact_installer_url "v${version}")" \
    | VERSION="v${version}" bash \
    || err "Failed to install agentpact v${version}. Install it manually, then re-run with --no-agentpact."
}

# Run the agentpact installer remotely in --uninstall mode. Fetches the
# installer matching the currently-installed version (not main) so its
# uninstall logic matches the on-disk layout. Tolerates failure (e.g. a
# partial prior install) so the subsequent reinstall can still proceed.
# Read a string field from a JSON manifest written by register_package.
# Tightly coupled to our own writer format (one field per line); not a
# general JSON parser.
manifest_field() {
  local manifest="$1"
  local field="$2"
  grep -E "\"${field}\":" "$manifest" 2>/dev/null \
    | sed -E "s/.*\"${field}\":[[:space:]]*\"([^\"]+)\".*/\1/" \
    | head -1
}

# Path to agentpact's cached install.sh, if present. Returns empty when the
# kyr-packages manifest doesn't exist, lacks an installer_script_path entry,
# or that path doesn't resolve to an executable file.
agentpact_cached_installer() {
  local manifest="${REGISTRY_DIR}/agentpact.json"
  [ -f "$manifest" ] || return 1
  local cached
  cached="$(manifest_field "$manifest" installer_script_path)"
  [ -n "$cached" ] || return 1
  [ -x "$cached" ] || return 1
  printf '%s\n' "$cached"
}

uninstall_agentpact_remote() {
  local installed_version="$1"

  # Prefer the cached installer that agentpact wrote on its own install —
  # it's the exact code that placed the on-disk layout, no network,
  # no risk of tag-URL drift. Falls back to a version-matched curl, then
  # to main, in increasing-fragility order.
  local cached
  if cached="$(agentpact_cached_installer 2>/dev/null)"; then
    info "Removing existing agentpact via cached installer at $cached"
    if "$cached" --uninstall; then
      return 0
    fi
    info "Cached agentpact installer failed; falling back to network fetch."
  fi

  local ref
  if [ -n "$installed_version" ]; then
    ref="v${installed_version}"
    info "Removing existing agentpact v${installed_version} via its version-matched installer..."
  else
    ref="main"
    info "Removing existing agentpact (version unknown) via the main installer..."
  fi
  if ! curl -fsSL "$(agentpact_installer_url "$ref")" \
       | bash -s -- --uninstall; then
    if [ "$ref" != "main" ]; then
      info "Version-matched agentpact installer failed; retrying via main..."
      curl -fsSL "$(agentpact_installer_url "main")" \
        | bash -s -- --uninstall \
        || info "WARN: agentpact --uninstall exited non-zero on fallback; continuing with reinstall."
    else
      info "WARN: agentpact --uninstall exited non-zero; continuing with reinstall."
    fi
  fi
}

# Return 0 if any OTHER kyr-package in the registry declares agentpact as
# a dependency. Called after kyris's own manifest is removed so the only
# matches should be non-kyris dependents. Used to gate the cascade
# uninstall of agentpact: keep it if anything else still needs it.
#
# Skips `agentpact.json` itself — its own `"name": "agentpact"` line would
# falsely match a naive grep and make the check always claim there's a
# dependent. Skips `kyris.json` defensively too (it's already removed at
# call time). Uses python3 to inspect the `depends_on` array specifically
# so other JSON fields containing the substring "agentpact" can't
# false-positive either.
agentpact_has_other_dependents() {
  [ -d "$REGISTRY_DIR" ] || return 1
  command -v python3 >/dev/null 2>&1 || {
    info "WARN: python3 missing; conservatively assuming agentpact has other dependents."
    return 0
  }
  python3 - "$REGISTRY_DIR" <<'PY'
import json, os, sys
registry = sys.argv[1]
for name in os.listdir(registry):
    if name in ("agentpact.json", "kyris.json"):
        continue
    if not name.endswith(".json"):
        continue
    path = os.path.join(registry, name)
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        continue
    deps = data.get("depends_on")
    if isinstance(deps, list) and "agentpact" in deps:
        sys.exit(0)  # found a dependent
sys.exit(1)  # no dependents
PY
}

# Cascade-remove agentpact when kyris is its last dependent.
#
# When: called from uninstall_all AFTER kyris's manifest is unregistered.
# Skips if --no-agentpact was passed (SKIP_AGENTPACT=1), or if any other
# kyr-package still declares depends_on on agentpact.
#
# Channel detection: reads agentpact.json's install_method. brew installs
# delegate to `brew uninstall --cask` (+ --zap on --reset-data). Script
# installs use agentpact's cached installer first (~/.agentpact/installer.sh)
# and fall back to the existing network-fetch path in
# uninstall_agentpact_remote.
#
# --reset-data propagation: passed through to agentpact's uninstaller as
# `--reset-data` (script) or `--zap` (brew) so a "full wipe" of kyris is
# also a full wipe of agentpact.
cascade_remove_agentpact() {
  if [ "$SKIP_AGENTPACT" -eq 1 ]; then
    info "Skipping agentpact cascade-uninstall (--no-agentpact)."
    return 0
  fi
  if agentpact_has_other_dependents; then
    info "Leaving agentpact installed: still required by another kyr-package."
    return 0
  fi

  local manifest="${REGISTRY_DIR}/agentpact.json"
  local install_method=""
  if [ -f "$manifest" ]; then
    install_method="$(manifest_field "$manifest" install_method)"
  fi

  # Brew-installed agentpact: delegate to brew so its receipts stay consistent.
  # We do this even if `--no-brew` was passed for KYRIS, because the channel
  # choice is per-package and agentpact's channel is what governs its removal.
  if [ "$install_method" = "brew" ] && brew_available; then
    if brew list --cask "${TAP}/agentpact" >/dev/null 2>&1; then
      if [ "$RESET_DATA" -eq 1 ]; then
        info "Cascade: removing brew-installed agentpact via 'brew uninstall --cask --zap ${TAP}/agentpact'..."
        brew uninstall --cask --zap "${TAP}/agentpact" \
          || info "WARN: brew uninstall of agentpact exited non-zero; please run it manually."
      else
        info "Cascade: removing brew-installed agentpact via 'brew uninstall --cask ${TAP}/agentpact'..."
        brew uninstall --cask "${TAP}/agentpact" \
          || info "WARN: brew uninstall of agentpact exited non-zero; please run it manually."
      fi
      return 0
    fi
    info "agentpact manifest claims brew install but cask not present; falling through to script path."
  fi

  # Script-installed agentpact: prefer the cached installer at
  # ~/.agentpact/installer.sh. uninstall_agentpact_remote already handles
  # cached-first-then-network; we just need to thread --reset-data through.
  local cached
  if cached="$(agentpact_cached_installer 2>/dev/null)"; then
    info "Cascade: removing agentpact via its cached installer ($cached)..."
    if [ "$RESET_DATA" -eq 1 ]; then
      "$cached" --uninstall --reset-data \
        || info "WARN: agentpact --uninstall --reset-data exited non-zero; please run it manually."
    else
      "$cached" --uninstall \
        || info "WARN: agentpact --uninstall exited non-zero; please run it manually."
    fi
    return 0
  fi

  # No cached installer — fall back to the network path. Pull the version
  # from the manifest if we have it so the URL is version-matched.
  local installed_version=""
  if [ -f "$manifest" ]; then
    installed_version="$(manifest_field "$manifest" version)"
  fi
  info "Cascade: removing agentpact via network fetch (no cached installer found)..."
  # uninstall_agentpact_remote doesn't support --reset-data today; when set,
  # warn so the user knows the data dirs may linger and how to finish the job.
  uninstall_agentpact_remote "$installed_version"
  if [ "$RESET_DATA" -eq 1 ]; then
    info "WARN: network-fallback uninstall of agentpact ran without --reset-data; XDG dirs may remain."
    info "      Run agentpact's own installer with --uninstall --reset-data to finish the wipe."
  fi
}

# Install or update agentpact to the exact version this kyris build requires.
# If agentpact is missing → install. If installed at the correct version →
# skip. If installed at a different version → uninstall + install. Mirrors
# the postflight logic in the homebrew kyris cask.
ensure_agentpact_installed() {
  if [ "$SKIP_AGENTPACT" -eq 1 ]; then
    info "Skipping agentpact dependency management (--no-agentpact)."
    return 0
  fi

  resolve_agentpact_version

  local installed_path installed_version=""
  if installed_path="$(agentpactd_path 2>/dev/null)"; then
    installed_version="$("$installed_path" --version 2>/dev/null | awk '{print $2}')" || true
  fi

  if [ -n "$installed_version" ] && [ "$installed_version" = "$AGENTPACT_VERSION" ]; then
    info "agentpact ${installed_version} already installed at the required version; continuing."
    return 0
  fi

  # In --local mode, prefer the sibling agentpact source dir if it has a
  # built binary at the right version. Lets the dev iterate without touching
  # the upstream installer at all.
  if [ -n "$LOCAL_DIR" ]; then
    local candidate
    for candidate in "$LOCAL_PROJECT_ROOT/../agentpact" "$LOCAL_PROJECT_ROOT/../../agentpact"; do
      if [ -d "$candidate" ] && [ -f "$candidate/install.sh" ] \
         && [ -x "$candidate/target/release/agentpactd" ]; then
        local agentpact_root local_version=""
        agentpact_root="$(cd "$candidate" && pwd)"
        local_version="$("$candidate/target/release/agentpactd" --version 2>/dev/null | awk '{print $2}')" || true
        if [ -n "$local_version" ] && [ "$local_version" = "$AGENTPACT_VERSION" ]; then
          info "Auto-installing agentpact ${AGENTPACT_VERSION} from sibling source at $agentpact_root..."
          if [ -n "$installed_version" ]; then
            "$agentpact_root/install.sh" --uninstall \
              || info "WARN: local agentpact --uninstall exited non-zero; continuing."
          fi
          "$agentpact_root/install.sh" --local "$agentpact_root/target/release" \
            || err "Failed to install agentpact from local source."
          return 0
        fi
        info "Sibling agentpact at $agentpact_root reports ${local_version:-unknown}, need ${AGENTPACT_VERSION}; falling back to upstream."
        break
      fi
    done
  fi

  if [ -n "$installed_version" ]; then
    info "agentpact ${installed_version} installed but kyris requires ${AGENTPACT_VERSION}; uninstalling first..."
    uninstall_agentpact_remote "$installed_version"
  else
    info "agentpact not installed; installing v${AGENTPACT_VERSION}..."
  fi
  install_agentpact_remote "$AGENTPACT_VERSION"
  info "agentpact v${AGENTPACT_VERSION} ready; continuing with kyris install."
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
       install.sh --uninstall [--no-brew] [--reset-data]

  (no flag)      Install in user mode (default).
  --user         Explicit form of the default. No sudo required.
  --local <dir>  Copy binaries from local directory instead of downloading.
                 <dir> should contain kyris, kyrisd, kyris-mcp, kyris-hook,
                 kyris-exec binaries (e.g. target/release/).
  --no-brew      Skip brew detection and install via the script path even when
                 Homebrew is available. Symmetric on --uninstall.
  --uninstall    Stop kyrisd and remove install-managed files (binary bundle,
                 launchd plist, ~/.kyris/ runtime dir, package receipt). User
                 data under ~/.config/kyris/, ~/.local/share/kyris/, and
                 ~/.local/state/kyris/ is PRESERVED. Cascades to agentpact:
                 if no other kyr-package in ~/.local/share/kyr-packages/
                 declares depends_on agentpact, agentpact is removed too
                 (preferred via its own cached installer, then network
                 fallback; brew-installed agentpact uses brew). Pass
                 --no-agentpact to keep agentpact installed. If brew
                 installed kyris, delegates to 'brew uninstall --cask'.
  --no-agentpact On install: skip the agentpact dependency check (script path
                 only; brew handles depends_on natively). Use if agentpact is
                 installed via a channel kyris cannot detect — kyris will not
                 function until agentpact is available at runtime.
                 On --uninstall: skip the cascade-remove of agentpact, leaving
                 it installed regardless of dependent count.
  --reset-data   Only with --uninstall: also wipe the XDG dirs (config, data,
                 state). For brew installs, adds --zap. For script installs,
                 removes them directly. Propagates to agentpact's cascaded
                 uninstall too (script path: --reset-data; brew path: --zap)
                 so a full wipe of kyris is a full wipe of agentpact.
                 Does NOT touch the auth keys — those live under
                 ~/.local/share/kyris/secret/ and are preserved (to rotate
                 them, delete that directory: rm -rf ~/.local/share/kyris/secret).

File layout (XDG Base Directory):
  ~/.kyris/                      install-managed runtime (manifest, hooks, env)
  ~/.config/kyris/               kyrisd.yaml
  ~/.local/share/kyris/          credentials.json, kyrisd.duckdb (event log)
  ~/.local/share/kyris/secret/   inbound_key, operator_key (auth keys, 0600)
  ~/.local/state/kyris/          log/, crash/, diagnostics/, fail-open.jsonl,
                                 approvals.jsonl

What --uninstall removes (default):
  binaries (kyris, kyrisd, kyris-mcp, kyris-hook), Kyrisd.app bundle, launchd
  plist, ~/.kyris/ runtime dir, package receipt.
What --uninstall keeps (use --reset-data to also wipe):
  ~/.config/kyris/  ~/.local/share/kyris/  ~/.local/state/kyris/
What survives even --reset-data:
  ~/.local/share/kyris/secret/ (auth keys; rm it to rotate)

Examples (install):
  install.sh                                  # standard install (auto-detects brew)
  install.sh --local target/release/          # dev install from a local build dir
  install.sh --no-brew                        # force script path even if brew is present

Examples (uninstall — prefer the cached installer for a version-matched run):
  ~/.kyris/installer.sh --uninstall              # remove binaries; preserve config/data/state + keys
  ~/.kyris/installer.sh --uninstall --reset-data # wipe config/data/state; keep auth keys (~/.local/share/kyris/secret)
  brew uninstall --cask kyr-is/tap/kyris         # brew equivalent of --uninstall
  brew uninstall --cask --zap kyr-is/tap/kyris   # brew equivalent of --uninstall --reset-data

  # Network fallback only if ~/.kyris/installer.sh is missing (not version-matched):
  curl -fsSL https://raw.githubusercontent.com/kyr-is/kyris/main/install.sh | bash -s -- --uninstall

Notes:
  * Install caches a copy of this script at ~/.kyris/installer.sh; uninstall should
    run from there so the same code that placed the files removes them.
  * Uninstall cascades to agentpact when kyris is its last dependent (registry-gated).
    Pass --no-agentpact to keep agentpact installed.
  * Mixing channels (brew + script across kyris and agentpact) is unsupported; pick one.

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
      --reset-data) RESET_DATA=1 ;;
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
  if [ "$RESET_DATA" -eq 1 ] && [ "$ACTION" != "uninstall" ]; then
    err "--reset-data only makes sense with --uninstall"
  fi
  if [ "$ACTION" = "uninstall" ] && [ -n "$LOCAL_DIR" ]; then
    err "--local has no effect with --uninstall; remove one"
  fi
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

validate_local_dir() {
  [ -d "$LOCAL_DIR" ] || err "Local directory does not exist: $LOCAL_DIR"
  for bin in kyris kyrisd kyris-mcp kyris-hook kyris-exec; do
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
#
# Hook script names vary per agent: Claude/Codex use `*_pretooluse.sh`;
# Gemini uses `*_beforetool.sh` because its hook phase is named `BeforeTool`.
# Both naming conventions must be matched so neither agent leaves an entry
# pointing at a deleted hook script after uninstall.
KYRIS_MARKER_REGEX='/\.kyris/|kyris-mcp|kyris-hook|kyris_pretooluse|kyris_beforetool|agentpact_pretooluse|agentpact_beforetool'

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
KYRIS_MARKERS = (
    "/.kyris/",
    "kyris-mcp",
    "kyris-hook",
    "kyris_pretooluse",
    "kyris_beforetool",
    "agentpact_pretooluse",
    "agentpact_beforetool",
)

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
  # so remove them outright. Also sweep the `.disabled` siblings: `kyris
  # uninstall` (Level 1, CLI) intentionally renames these for reversibility
  # rather than deleting them. install.sh --uninstall is the full wipe so
  # the renamed versions must go too. Gemini's hook lives at
  # `agentpact_beforetool.sh` (its hook phase is `BeforeTool`), not the
  # `_pretooluse` name pattern.
  local hook
  for hook in \
    "$HOME/.claude/hooks/agentpact_pretooluse.sh" \
    "$HOME/.claude/hooks/agentpact_pretooluse.sh.disabled" \
    "$HOME/.codex/kyris_pretooluse.sh" \
    "$HOME/.codex/kyris_pretooluse.sh.disabled" \
    "$HOME/.codex/hooks/agentpact_pretooluse.sh" \
    "$HOME/.codex/hooks/agentpact_pretooluse.sh.disabled" \
    "$HOME/.gemini/kyris_pretooluse.sh" \
    "$HOME/.gemini/kyris_pretooluse.sh.disabled" \
    "$HOME/.gemini/hooks/agentpact_beforetool.sh" \
    "$HOME/.gemini/hooks/agentpact_beforetool.sh.disabled"
  do
    if [ -f "$hook" ]; then
      rm -f "$hook"
      info "Removed $hook"
    fi
  done

  # Agent JSON configs — surgically remove kyris entries (preserves any non-
  # kyris content the user or other tools added). Also sweep the
  # `.kyris-uninstall.bak` backups clean_agent_json_config writes before any
  # mutation: they're a Level-1 safety net, no longer needed once we're
  # doing a full uninstall.
  local cfg
  for cfg in \
    "$HOME/.codex/hooks.json" \
    "$HOME/.claude/settings.json" \
    "$HOME/.gemini/settings.json"
  do
    clean_agent_json_config "$cfg"
    if [ -f "${cfg}.kyris-uninstall.bak" ]; then
      rm -f "${cfg}.kyris-uninstall.bak"
      info "Removed ${cfg}.kyris-uninstall.bak"
    fi
  done

  # Best-effort rmdir of agent-owned hook directories kyris install created.
  # `rmdir` fails silently if the directory has any non-kyris contents (or
  # is gone already) — exactly the behavior we want.
  local hookdir
  for hookdir in \
    "$HOME/.claude/hooks" \
    "$HOME/.codex/hooks" \
    "$HOME/.gemini/hooks"
  do
    rmdir "$hookdir" 2>/dev/null && info "Removed empty $hookdir" || true
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
    # --reset-data adds --zap so brew also wipes the XDG dirs (per kyris.rb's
    # zap stanza); without it, plain `brew uninstall --cask` keeps user data.
    if [ "$RESET_DATA" -eq 1 ]; then
      info "Detected brew-installed kyris; delegating to 'brew uninstall --cask --zap ${CASK}' (--reset-data)..."
      brew uninstall --cask --zap "$CASK" \
        || err "brew uninstall --zap failed; resolve manually before re-running."
    else
      info "Detected brew-installed kyris; delegating to 'brew uninstall --cask ${CASK}'..."
      brew uninstall --cask "$CASK" \
        || err "brew uninstall failed; resolve manually before re-running."
    fi
    unregister_package
    cascade_remove_agentpact
    verify_uninstall
    echo ""
    if [ "$RESET_DATA" -eq 1 ]; then
      info "Uninstall complete (data wiped via --reset-data → brew uninstall --zap)."
    else
      info "Uninstall complete (via brew). User data preserved at:"
      info "  Config: $CONFIG_DIR"
      info "  Data:   $DATA_DIR (credentials.json, kyrisd.duckdb)"
      info "  State:  $STATE_DIR (logs, crash dumps)"
      info "Run with --reset-data to wipe them too."
    fi
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
  # Bundle holds all four binaries; the CLI shims in ~/.local/bin
  # are symlinks pointing inside the bundle. Pre-bundle installs had
  # regular files at the same shim paths, which remove_path handles
  # equivalently (rm -rf strips either symlinks or regular files).
  remove_path "$APP_PATH"
  for bin in kyrisd kyris kyris-mcp kyris-hook kyris-exec; do
    remove_path "$HOME/.local/bin/$bin"
  done
  remove_path "$HOME/.kyris"

  # Clean residue from legacy system-mode installs. Only prompts for sudo if
  # something actually exists at these paths.
  local need_sudo=0
  for bin in kyris kyrisd kyris-mcp kyris-hook kyris-exec; do
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
    for bin in kyris kyrisd kyris-mcp kyris-hook kyris-exec; do
      remove_path_sudo "/usr/local/bin/$bin"
    done
    remove_path_sudo "/etc/kyris"
    if pkgutil --pkg-info "is.kyr.kyris" >/dev/null 2>&1; then
      sudo pkgutil --forget "is.kyr.kyris" >/dev/null || true
      info "Forgot package receipt is.kyr.kyris"
    fi
  fi

  unregister_package
  cascade_remove_agentpact

  if [ "$RESET_DATA" -eq 1 ]; then
    reset_data
  fi

  verify_uninstall

  echo ""
  if [ "$RESET_DATA" -eq 1 ]; then
    info "Uninstall complete (data wiped via --reset-data)."
  else
    info "Uninstall complete. User data preserved at:"
    info "  Config: $CONFIG_DIR"
    info "  Data:   $DATA_DIR (credentials.json, kyrisd.duckdb)"
    info "  State:  $STATE_DIR (logs, crash dumps)"
    info "Run with --reset-data to wipe them too."
  fi
  # The auth keys live under $DATA_DIR/$SECRET_SUBDIR and are preserved even by
  # --reset-data, so they never regenerate (no daemon/hook drift). Note it so
  # it isn't a surprise on reinstall.
  info "Auth keys preserved at $DATA_DIR/$SECRET_SUBDIR."
}

# Wipe the XDG dirs that uninstall_all preserves by default. Only invoked when
# --reset-data is passed alongside --uninstall. The auth-key store
# ($DATA_DIR/$SECRET_SUBDIR) is deliberately PRESERVED: the keys must survive a
# data reset so the daemon and hook never drift / lock out. To rotate them,
# delete that directory explicitly.
reset_data() {
  info "--reset-data: wiping user data dirs (auth keys under $SECRET_SUBDIR/ preserved)..."
  remove_path "$CONFIG_DIR"
  # Wipe DATA_DIR's contents but keep the secret store.
  if [ -d "$DATA_DIR" ]; then
    find "$DATA_DIR" -mindepth 1 -maxdepth 1 ! -name "$SECRET_SUBDIR" -exec rm -rf {} +
  fi
  remove_path "$STATE_DIR"
}

# Residue left under DATA_DIR after `--reset-data`: everything EXCEPT the
# preserved auth-key store ($secret). Echoes the offending paths, one per line
# (empty output = clean). Pure (no globals, no side effects) so it's unit-
# testable by sourcing this script — see kyris/cli/tests/install_reset_data.rs.
# `verify_uninstall` uses it instead of requiring DATA_DIR to be entirely gone,
# since the secret store survives --reset-data by design.
data_dir_reset_residue() {
  local data_dir="$1" secret="$2"
  [ -d "$data_dir" ] || return 0
  find "$data_dir" -mindepth 1 -maxdepth 1 ! -name "$secret" 2>/dev/null
}

# Place Kyrisd.app at $APP_PATH and wire up the launchd service to load
# kyrisd from inside the bundle, then symlink ALL FOUR CLI binaries
# (kyrisd, kyris, kyris-mcp, kyris-hook) from inside the bundle into
# ~/.local/bin/. Two input modes, self-detected from $1:
#
#   1. Pre-built bundle (release path): $1 is a Kyrisd.app directory.
#      Used by install_remote. The bundle already ships the launchd
#      plist template at Contents/Resources/is.kyr.kyrisd.plist.
#
#   2. Bare binaries (dev path): $1 is a directory containing the four
#      binaries. Used by install_local. We invoke build-app-bundle.sh
#      from $LOCAL_PROJECT_ROOT/scripts/ against $LOCAL_PROJECT_ROOT/
#      to wrap them into a Kyrisd.app on the fly.
install_kyrisd_bundle() {
  local source_path="$1"

  mkdir -p "$APP_INSTALL_DIR" "$BIN_SHIM_DIR"

  # Wipe any prior bundle + shims. Drop shims first so the old bundle
  # isn't held by stale symlinks while we replace it.
  for bin in kyrisd kyris kyris-mcp kyris-hook kyris-exec; do
    rm -f "$BIN_SHIM_DIR/$bin"
  done
  rm -rf "$APP_PATH"

  if [ -d "$source_path" ] && [ -f "$source_path/Contents/Info.plist" ]; then
    info "Installing pre-built Kyrisd.app to $APP_PATH"
    cp -R "$source_path" "$APP_INSTALL_DIR/"
  elif [ -d "$source_path" ] && [ -x "$source_path/kyrisd" ]; then
    # Directory of bare binaries — build the bundle locally using the
    # dev's checkout. Only reachable via --local mode, where
    # LOCAL_PROJECT_ROOT is guaranteed to point at the kyris source.
    [ -n "${LOCAL_PROJECT_ROOT:-}" ] \
      || err "Bare-binary install path requires --local mode (LOCAL_PROJECT_ROOT not set)"
    local build_script="${LOCAL_PROJECT_ROOT}/scripts/build-app-bundle.sh"
    [ -x "$build_script" ] || err "Missing $build_script"
    [ -f "${LOCAL_PROJECT_ROOT}/service/Info.plist.template" ] \
      || err "Missing ${LOCAL_PROJECT_ROOT}/service/Info.plist.template"
    info "Wrapping binaries from $source_path in Kyrisd.app at $APP_PATH"
    local bundle_tmp commit version
    bundle_tmp="$(mktemp -d)"
    commit="$(git -C "$LOCAL_PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    version="$("$source_path/kyrisd" --version 2>/dev/null | awk '{print $2}')" || version=""
    [ -n "$version" ] || version="0.0.0"

    BINARY_DIR="$source_path" VERSION="$version" COMMIT="$commit" OUT_DIR="$bundle_tmp" \
      bash "$build_script" \
      || { rm -rf "$bundle_tmp"; err "Bundle build failed"; }
    mv "${bundle_tmp}/Kyrisd.app" "$APP_PATH"
    rm -rf "$bundle_tmp"
  else
    err "install_kyrisd_bundle: source $source_path is neither a Kyrisd.app nor a directory containing kyrisd"
  fi

  # CLI shims for ALL FIVE binaries. Each is a symlink from
  # ~/.local/bin/<name> into the bundle. Keeps the user's PATH clean
  # (only Contents/MacOS/ holds the real binaries) while making
  # `kyrisd doctor`, `kyris install`, `kyris-exec`, etc. work unchanged.
  for bin in kyrisd kyris kyris-mcp kyris-hook kyris-exec; do
    ln -sf "$APP_PATH/Contents/MacOS/$bin" "$BIN_SHIM_DIR/$bin"
    chmod 755 "$BIN_SHIM_DIR/$bin"
  done

  PLIST_LABEL="is.kyr.kyrisd"
  PLIST_DIR="$HOME/Library/LaunchAgents"
  PLIST_DEST="${PLIST_DIR}/${PLIST_LABEL}.plist"

  # The launchd template ships inside the bundle (Contents/Resources/),
  # whether we got the bundle pre-built or just built it via mode 2.
  local plist_template="${APP_PATH}/Contents/Resources/${PLIST_LABEL}.plist"
  [ -f "$plist_template" ] \
    || err "Bundle is missing launchd template at $plist_template"
  mkdir -p "$PLIST_DIR"
  # Create the runtime dir AND all XDG dirs before launchd loads the plist.
  # The plist's StandardErrorPath is under STATE_DIR/log/, and launchd
  # silently drops output if the parent dir is missing.
  ensure_all_dirs

  # Point launchd at the binary INSIDE the bundle. macOS reads the
  # bundle's CFBundleIdentifier at launch time, so the running process
  # gets the bundle identity for free.
  #
  # Notification permission: requested on daemon first-run, not here.
  # macOS UNUserNotificationCenter only honors `requestAuthorization`
  # from a process registered with LaunchServices as a foreground-
  # eligible app — which launchctl-bootstrapped Kyrisd.app is, but a
  # script-invoked helper binary is not. The dialog appears the
  # instant launchd starts the daemon below; the user is still
  # looking at the install output, so the UX is effectively
  # install-time anyway. See `daemon/src/notify.rs` for the request
  # path, and Apple Forums thread 679326 for the platform constraint.
  sed -e "s|{{BINARY_PATH}}|${APP_BINARY}|g" \
      -e "s|{{HOME}}|${HOME}|g" \
      -e "s|{{PATH}}|${BIN_SHIM_DIR}:/usr/local/bin:/usr/bin:/bin|g" \
      "$plist_template" > "$PLIST_DEST"
  chmod 644 "$PLIST_DEST"

  bootstrap_user_launchagent "$PLIST_LABEL" "$PLIST_DEST"
}

install_local() {
  # --local mode reads the agentpact version from the local Cargo.toml
  # checkout (the bundle hasn't been built yet at this point).
  BUNDLE_CARGO_TOML="${LOCAL_PROJECT_ROOT}/Cargo.toml"
  [ -f "$BUNDLE_CARGO_TOML" ] \
    || err "Missing $BUNDLE_CARGO_TOML — cannot determine required agentpact version."

  ensure_agentpact_installed

  # All four binaries get bundled into Kyrisd.app and exposed via
  # symlinks in ~/.local/bin. install_kyrisd_bundle self-detects the
  # bare-binaries-vs-pre-built-bundle path and reads the launchd plist
  # template from inside the resulting bundle.
  install_kyrisd_bundle "$LOCAL_DIR"

  local installed_version
  installed_version="$("$APP_BINARY" --version 2>/dev/null | awk '{print $2}')" || installed_version=""
  [ -n "$installed_version" ] || installed_version="unknown"

  # Cache the installer. In --local mode cache_installer prefers $0 (the
  # on-disk script in the checkout) over a network fetch.
  if [ "$installed_version" != "unknown" ]; then
    cache_installer "v${installed_version}"
  else
    cache_installer "main"
  fi
  register_package "$installed_version" "$APP_BINARY"

  echo ""
  info "Installation complete (user mode, from local build)."
  info "  Bundle:   $APP_PATH"
  info "  CLI shims: $BIN_SHIM_DIR/{kyrisd,kyris,kyris-mcp,kyris-hook}"
  info "  Service:  $PLIST_LABEL (launchd)"
}

install_remote() {
  RELEASE_VERSION="${VERSION#v}"
  TARGET="aarch64-apple-darwin"
  APP_TAR_NAME="Kyrisd-${RELEASE_VERSION}-${TARGET}.app.tar.gz"
  APP_DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${APP_TAR_NAME}"
  APP_CHECKSUM_URL="${APP_DOWNLOAD_URL}.sha256"
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT

  info "Downloading kyris ${VERSION} bundle..."
  curl -fsSL -o "${TMP_DIR}/${APP_TAR_NAME}" "${APP_DOWNLOAD_URL}" \
    || err "Download failed: ${APP_DOWNLOAD_URL}"
  curl -fsSL -o "${TMP_DIR}/${APP_TAR_NAME}.sha256" "${APP_CHECKSUM_URL}" \
    || err "Checksum download failed: ${APP_CHECKSUM_URL}"
  info "Verifying bundle checksum..."
  (cd "${TMP_DIR}" && shasum -a 256 -c "${APP_TAR_NAME}.sha256") \
    || err "Bundle checksum verification failed"
  info "Extracting bundle..."
  tar xzf "${TMP_DIR}/${APP_TAR_NAME}" -C "${TMP_DIR}"

  local bundle_source="${TMP_DIR}/Kyrisd.app"
  [ -d "$bundle_source" ] || err "Extracted bundle missing at $bundle_source"

  # Point the agentpact version resolver at the Cargo.toml that ships
  # inside the bundle. ensure_agentpact_installed (called next from main)
  # reads it to know which agentpact version this kyris build expects.
  BUNDLE_CARGO_TOML="${bundle_source}/Contents/Resources/Cargo.toml"
  [ -f "$BUNDLE_CARGO_TOML" ] \
    || err "Bundle is missing Contents/Resources/Cargo.toml; release was built without the version-pinning manifest."

  ensure_agentpact_installed

  install_kyrisd_bundle "$bundle_source"

  # Cache the installer at the version-matched tag URL. cache_installer
  # uses RELEASE_VERSION (set above) to pick the right tag.
  if [ -n "${RELEASE_VERSION:-}" ]; then
    cache_installer "v${RELEASE_VERSION}"
  else
    cache_installer "main"
  fi
  register_package "${RELEASE_VERSION}" "$APP_BINARY"

  echo ""
  info "Installation complete (user mode)."
  info "  Bundle:   $APP_PATH"
  info "  CLI shims: $BIN_SHIM_DIR/{kyrisd,kyris,kyris-mcp,kyris-hook}"
  info "  Service:  $PLIST_LABEL (launchd)"
}

configure_and_verify() {
  local kyris_bin="$BIN_SHIM_DIR/kyris"

  [ -x "$kyris_bin" ] || err "kyris CLI not found at $kyris_bin after install."

  info "Configuring shell hooks and agent integrations..."
  # `kyris install` writes hook scripts, edits shell rc files, bootstraps the
  # BASH_ENV launchagent, prestages + reconciles agent integrations, and runs
  # verify_post_install internally. Its exit status reflects the full state.
  "$kyris_bin" install || err "kyris install failed; see output above."

  info "Install log: $LOG_DIR/kyris.log"
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

  # Paths that uninstall must always remove. XDG dirs ($CONFIG_DIR,
  # $DATA_DIR, $STATE_DIR) are intentionally NOT in this list — they hold
  # user data and survive uninstall by design. Only --reset-data wipes
  # them; that case is checked separately below.
  for path in \
    "$HOME/Library/LaunchAgents/is.kyr.kyrisd.plist" \
    "$APP_PATH" \
    "$RUNTIME_DIR" \
    "$SELF_MANIFEST" \
    "/etc/kyris"
  do
    if [ -e "$path" ] || [ -L "$path" ]; then
      info "FAIL: uninstall residue remains at $path"
      failures=$((failures + 1))
    fi
  done

  if [ "$RESET_DATA" -eq 1 ]; then
    # CONFIG_DIR and STATE_DIR must be wiped entirely.
    for path in "$CONFIG_DIR" "$STATE_DIR"; do
      if [ -e "$path" ] || [ -L "$path" ]; then
        info "FAIL: --reset-data left residue at $path"
        failures=$((failures + 1))
      fi
    done
    # DATA_DIR is NOT required to be gone: reset_data() deliberately preserves
    # the auth-key store ($DATA_DIR/$SECRET_SUBDIR) so keys never regenerate.
    # The directory legitimately remains to hold it. Residue = anything under
    # DATA_DIR OTHER than the secret store (see data_dir_reset_residue).
    if [ -d "$DATA_DIR" ]; then
      residue="$(data_dir_reset_residue "$DATA_DIR" "$SECRET_SUBDIR")"
      if [ -n "$residue" ]; then
        info "FAIL: --reset-data left residue under $DATA_DIR (only $SECRET_SUBDIR/ should remain):"
        info "$residue"
        failures=$((failures + 1))
      fi
    fi
  fi

  for bin in kyris kyrisd kyris-mcp kyris-hook kyris-exec; do
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

# If an old kyris is installed, run a full uninstall first so file drift
# (renamed files, removed paths) from the old release is purged cleanly.
# XDG user data survives — uninstall_all does not touch CONFIG/DATA/STATE
# dirs unless --reset-data is set, which install path doesn't pass.
upgrade_if_installed() {
  local bin_path="$HOME/.local/bin/kyrisd"
  [ -x "$bin_path" ] || return 0
  local installed_version
  installed_version="$("$bin_path" --version 2>/dev/null | awk '{print $2}')" || installed_version=""
  local target_version="${RELEASE_VERSION:-${VERSION#v}}"
  if [ -n "$installed_version" ] && [ -n "$target_version" ] \
     && [ "$installed_version" = "$target_version" ]; then
    info "kyris ${installed_version} already installed at the target version; reinstalling cleanly."
  elif [ -n "$installed_version" ]; then
    info "Upgrading kyris ${installed_version} → ${target_version:-(unknown)}"
  fi
  uninstall_all
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
    RELEASE_VERSION="local"
    upgrade_if_installed
    install_local
  else
    resolve_version
    RELEASE_VERSION="${VERSION#v}"
    upgrade_if_installed
    install_remote
  fi

  configure_and_verify
}

# Optional local override hook (permanent). Any *.sh dropped into
# install.sh.local.d/ next to this script is sourced here — AFTER every function
# is defined, so it can redefine one (the kyris-dev override repoints
# `ensure_agentpact_installed` at a sibling agentpact checkout). Absent in normal
# brew/curl installs → a silent no-op. This hook lives here permanently so the
# dev toggle is just a dropped file, never an install.sh patch hunk that breaks
# whenever this tail changes.
__ovr_dir="$(dirname "${BASH_SOURCE[0]:-$0}")/install.sh.local.d"
if [ -d "$__ovr_dir" ]; then
  for __ovr in "$__ovr_dir"/*.sh; do
    [ -f "$__ovr" ] && source "$__ovr"
  done
fi
unset __ovr_dir __ovr

# Run main only when EXECUTED, not when sourced — so tests can source this
# script to exercise individual functions (e.g. data_dir_reset_residue) without
# running the installer. Bash sets BASH_SOURCE[0]==$0 only on direct execution.
if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
  main "$@"
fi
