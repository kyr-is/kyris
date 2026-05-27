# SPDX-FileCopyrightText: Copyright 2026 Kyris
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# Kyris Bash hook: extdebug + DEBUG trap. Requires kyris-hook on PATH.
# Compatible with macOS system Bash (3.2) and modern Bash (5.x).
# No Bash 4+ features (no associative arrays, no readarray, no ${var,,}).
#
# This file is sourced (not executed); the shellcheck shell directive
# above tells shellcheck which dialect to apply without polluting the
# file with a shebang that would mislead "is this script executable?"
# tooling.

# Skip the trap entirely when this shell is a subprocess of a governed
# agent (Claude Code, Codex CLI, Gemini CLI, OpenCode, Cline). The
# agent's PreToolUse hook already approved the parent command — letting
# the DEBUG trap re-fire on every line of /etc/profile and every
# sub-command inside the approved compound triggered ~10x redundant
# popups. See kyris/daemon/src/approvals_log.rs for empirical evidence.
__kyris_running_under_governed_agent() {
    # Fast path: env vars known to be injected by specific agents.
    # CLAUDECODE=1 is the canonical Claude Code marker (verified via
    # `env | grep CLAUDE` inside a Claude-spawned subprocess).
    # KYRIS_GOVERNED_SUBPROCESS is the universal override for agents
    # we don't auto-detect.
    [ -n "${CLAUDECODE:-}" ] && return 0
    [ -n "${KYRIS_GOVERNED_SUBPROCESS:-}" ] && return 0

    # Slow path (only reached when env vars don't match): walk the
    # parent process chain looking for known agent binaries. Bounded
    # to 32 hops so we don't loop on a degenerate ancestry. One-time
    # cost at trap-install time, NOT per command.
    local _kyris_pid _kyris_comm _kyris_hops=0
    _kyris_pid="${PPID:-0}"
    while [ "$_kyris_pid" -gt 1 ] && [ "$_kyris_hops" -lt 32 ]; do
        _kyris_comm=$(ps -p "$_kyris_pid" -o comm= 2>/dev/null | tr -d ' ')
        _kyris_comm="${_kyris_comm##*/}"
        case "$_kyris_comm" in
            claude|claude-code|codex|gemini|opencode|cline)
                return 0
                ;;
        esac
        _kyris_pid=$(ps -p "$_kyris_pid" -o ppid= 2>/dev/null | tr -d ' ')
        [ -z "$_kyris_pid" ] && return 1
        _kyris_hops=$((_kyris_hops + 1))
    done
    return 1
}

if __kyris_running_under_governed_agent; then
    return 0 2>/dev/null || exit 0
fi

if command -v kyris >/dev/null 2>&1; then
    kyris agents reconcile --auto >/dev/null 2>&1 &
    disown 2>/dev/null
fi

shopt -s extdebug
trap '__kyris_preexec "$BASH_COMMAND"' DEBUG

__kyris_preexec() {
    local cmd="$1"
    local sock="${AGENTPACT_SOCK:-$HOME/.agentpact/agentpact.sock}"
    local sentinel="$HOME/.kyris/.daemon-unreachable"

    if __kyris_sentinel_active "$sentinel"; then
        return 1
    fi

    if [ ! -S "$sock" ]; then
        __kyris_restart_daemon "$sock" || {
            if __kyris_daemon_state_allows "$sock"; then
                logger -t agentpact "fail-open: $cmd"
                __kyris_record_fail_open "$cmd"
                return 0
            fi
            __kyris_write_sentinel "$sentinel"
            printf '\033[31m[agentpact]\033[0m daemon unreachable — run agentpactd or set on_daemon_unavailable: allow\n' >&2
            return 1
        }
    fi

    if ! __kyris_protocol_ok "$sock"; then
        printf '\033[31m[agentpact]\033[0m %s\n' "$__kyris_protocol_error" >&2
        return 1
    fi

    if ! command -v kyris-hook >/dev/null 2>&1; then
        logger -t agentpact "fail-open (kyris-hook not on PATH): $cmd"
        __kyris_record_fail_open "$cmd"
        return 0
    fi

    local output exit_code
    output=$(kyris-hook check "$cmd" --cwd "$PWD" --socket "$sock")
    exit_code=$?

    if [ $exit_code -eq 10 ]; then
        __kyris_restart_daemon "$sock" || {
            if __kyris_daemon_state_allows "$sock"; then
                logger -t agentpact "fail-open: $cmd"
                __kyris_record_fail_open "$cmd"
                return 0
            fi
            __kyris_write_sentinel "$sentinel"
            printf '\033[31m[agentpact]\033[0m daemon unreachable — run agentpactd or set on_daemon_unavailable: allow\n' >&2
            return 1
        }
        output=$(kyris-hook check "$cmd" --cwd "$PWD" --socket "$sock")
        exit_code=$?
        if [ $exit_code -eq 10 ]; then
            if __kyris_daemon_state_allows "$sock"; then
                logger -t agentpact "fail-open: $cmd"
                __kyris_record_fail_open "$cmd"
                return 0
            fi
            __kyris_write_sentinel "$sentinel"
            printf '\033[31m[agentpact]\033[0m daemon unreachable — run agentpactd or set on_daemon_unavailable: allow\n' >&2
            return 1
        fi
    fi

    case $exit_code in
        0|11) return 0 ;;
        1) return 1 ;;
        2)
            # Normal PACT_ASK: resolve per compound segment (kyris-hook has
            # already voided the whole-command token). resolve-shell prompts
            # on the TTY per segment, or delegates to kyrisd when there is none.
            __kyris_resolve_shell "$cmd" "$sock"
            return $?
            ;;
        3)
            local req_id token count
            req_id=$(printf '%s' "$output" | cut -f1)
            token=$(printf '%s' "$output" | cut -f2)
            count=$(printf '%s' "$output" | cut -f3)
            __kyris_circuit_breaker_prompt "$cmd" "$sock" "$req_id" "$token" "$count"
            return $?
            ;;
        *)
            printf '\033[31m[agentpact]\033[0m unexpected kyris-hook exit code: %s\n' "$exit_code" >&2
            return 1
            ;;
    esac
}

__kyris_have_tty() {
    [ -e /dev/tty ] && { exec 3</dev/tty; } 2>/dev/null && exec 3>&-
}

__kyris_circuit_breaker_prompt() {
    local cmd="$1" sock="$2" req_id="$3" token="$4" count="$5"
    if ! __kyris_have_tty; then
        if command -v kyris >/dev/null 2>&1; then
            kyris hook hold --req-id "$req_id" --token "$token" \
                --display "circuit-breaker (${count} commands): $cmd" \
                --socket "$sock" 2>/dev/null
            return $?
        else
            kyris-hook respond --socket "$sock" --req-id "$req_id" \
                --token "$token" --response denied 2>/dev/null
            return 1
        fi
    fi
    printf '\033[33m[kyris] circuit breaker:\033[0m %s commands without human input. Review: kyris timeline --last 10. [y/n] ' "$count" >&2
    read -r answer < /dev/tty
    case "$answer" in
        y|Y|yes)
            if kyris-hook respond --socket "$sock" --req-id "$req_id" --token "$token" --response approved; then
                return 0
            else
                printf '\033[31m[kyris] continue rejected by daemon\033[0m\n' >&2; return 1
            fi
            ;;
        *)
            kyris-hook respond --socket "$sock" --req-id "$req_id" --token "$token" --response denied 2>/dev/null
            return 1
            ;;
    esac
}

# Hand a normal PACT_ASK to `kyris hook resolve-shell`, which re-derives the
# compound split and prompts per segment (on the TTY when present, else via
# kyrisd's pending-approval popup). The fast `kyris-hook check` path has
# already voided the whole-command token, so there is nothing to clean up
# here when kyris is absent — just deny.
__kyris_resolve_shell() {
    local cmd="$1" sock="$2"
    if command -v kyris >/dev/null 2>&1; then
        kyris hook resolve-shell --cmd "$cmd" --cwd "$PWD" --socket "$sock"
        return $?
    fi
    printf '\033[31m[agentpact]\033[0m kyris not on PATH — cannot resolve approval\n' >&2
    return 1
}

__kyris_record_fail_open() {
    local cmd="$1"
    # fail-open log lives under $XDG_STATE_HOME/kyris/ after the XDG
    # migration (default $HOME/.local/state/kyris/fail-open.jsonl). The
    # daemon's reader resolves the same path, so writer and reader agree.
    local log_dir="${XDG_STATE_HOME:-$HOME/.local/state}/kyris"
    local log="$log_dir/fail-open.jsonl"
    mkdir -p "$log_dir" 2>/dev/null
    local id ts esc_cmd esc_pwd
    id=$(uuidgen 2>/dev/null | tr '[:upper:]' '[:lower:]') || return
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    esc_cmd="${cmd//\\/\\\\}"
    esc_cmd="${esc_cmd//\"/\\\"}"
    esc_cmd="${esc_cmd//$'\n'/\\n}"
    esc_cmd="${esc_cmd//$'\t'/\\t}"
    esc_cmd="${esc_cmd//$'\r'/\\r}"
    esc_pwd="${PWD//\\/\\\\}"
    esc_pwd="${esc_pwd//\"/\\\"}"
    printf '{"id":"%s","timestamp":"%s","agent":"unknown","action":"execute","detail":"%s","decision":"auto","working_dir":"%s","attribution_method":"unknown","mode":"log","event_kind":"action","coverage_state":"unknown","source":"fail-open"}\n' \
        "$id" "$ts" "$esc_cmd" "$esc_pwd" >> "$log" 2>/dev/null
}

__kyris_daemon_state_allows() {
    local sock="$1"
    local state_file="${sock%/*}/daemon.state"
    [ -f "$state_file" ] || return 1
    local content
    content=$(cat "$state_file" 2>/dev/null) || return 1
    case "$content" in
        *'"on_daemon_unavailable":"allow"'*|*'"on_daemon_unavailable": "allow"'*) return 0 ;;
        *) return 1 ;;
    esac
}

__kyris_sentinel_active() {
    local sentinel="$1"
    [ -f "$sentinel" ] || return 1
    local now file_epoch age
    now=$(date +%s)
    file_epoch=$(stat -f %m "$sentinel" 2>/dev/null || echo 0)
    age=$((now - file_epoch))
    [ "$age" -lt 30 ]
}

__kyris_write_sentinel() {
    printf '' > "$1" 2>/dev/null
}

__kyris_protocol_ok() {
    local sock="$1"
    local state_file="${sock%/*}/daemon.state"
    [ -f "$state_file" ] || return 0
    local content
    content=$(cat "$state_file" 2>/dev/null) || return 0
    local version
    version="${content##*\"protocol_version\":}"
    version="${version%%[,\}]*}"
    version="$(printf '%s' "$version" | tr -d ' ')"
    [ -z "$version" ] && return 0
    [ "$version" = "$content" ] && return 0
    if [ "$version" != "1" ]; then
        if [ "$version" -gt 1 ] 2>/dev/null; then
            __kyris_protocol_error="agentpactd protocol version ${version} is newer than kyris expects (1). Upgrade kyris: brew upgrade kyris"
        else
            __kyris_protocol_error="agentpactd protocol version ${version} is older than kyris expects (1). Upgrade agentpact: brew upgrade agentpact"
        fi
        return 1
    fi
    return 0
}

__kyris_restart_daemon() {
    local sock="$1"
    local delay

    # The daemon is likely already starting (launchd RunAtLoad after reboot).
    # Wait for it before attempting a kickstart.
    for delay in 0.05 0.1 0.15 0.2 0.25 0.25; do
        [ -S "$sock" ] && return 0
        sleep "$delay"
    done

    # Socket absent after 1s — ask launchd to start the service.
    # No -k: don't kill a potentially mid-startup instance.
    launchctl kickstart "gui/$(id -u)/is.kyr.agentpactd" 2>/dev/null

    for delay in 0.1 0.2 0.3 0.4; do
        [ -S "$sock" ] && return 0
        sleep "$delay"
    done
    return 1
}
