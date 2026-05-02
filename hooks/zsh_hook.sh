# SPDX-FileCopyrightText: Copyright 2026 Kyris
# SPDX-License-Identifier: Apache-2.0
# Kyris Zsh hook: preexec via add-zsh-hook. Requires kyris-hook on PATH.
# Compatible with macOS system Zsh (5.8+) and modern Zsh (5.9+).

if (( $+commands[kyris] )); then
    kyris agents reconcile --auto >/dev/null 2>&1 &!
fi

autoload -Uz add-zsh-hook

__kyris_preexec() {
    local cmd="$1"
    local sock="${AGENTPACT_SOCK:-$HOME/.agentpact/agentpact.sock}"
    local sentinel="$HOME/.kyris/.daemon-unreachable"

    if __kyris_sentinel_active "$sentinel"; then
        return 1
    fi

    if [[ ! -S "$sock" ]]; then
        __kyris_restart_daemon "$sock" || {
            if __kyris_daemon_state_allows "$sock"; then
                logger -t agentpact "fail-open: $cmd"
                __kyris_record_fail_open "$cmd"
                return 0
            fi
            __kyris_write_sentinel "$sentinel"
            printf '\033[31m[agentpact]\033[0m daemon unreachable — run `agentpactd` or set on_daemon_unavailable: allow\n' >&2
            return 1
        }
    fi

    if ! __kyris_protocol_ok "$sock"; then
        printf '\033[31m[agentpact]\033[0m %s\n' "$__kyris_protocol_error" >&2
        return 1
    fi

    if (( ! $+commands[kyris-hook] )); then
        logger -t agentpact "fail-open (kyris-hook not on PATH): $cmd"
        __kyris_record_fail_open "$cmd"
        return 0
    fi

    local output exit_code attempt=0
    while (( attempt < 2 )); do
        output=$(kyris-hook check "$cmd" --cwd "$PWD" --socket "$sock")
        exit_code=$?
        [[ $exit_code -ne 10 ]] && break
        (( attempt++ ))
        if (( attempt == 1 )); then
            __kyris_restart_daemon "$sock" || break
        fi
    done

    if [[ $exit_code -eq 10 ]]; then
        if __kyris_daemon_state_allows "$sock"; then
            logger -t agentpact "fail-open: $cmd"
            __kyris_record_fail_open "$cmd"
            return 0
        fi
        __kyris_write_sentinel "$sentinel"
        printf '\033[31m[agentpact]\033[0m daemon unreachable — run `agentpactd` or set on_daemon_unavailable: allow\n' >&2
        return 1
    fi

    case $exit_code in
        0|11) return 0 ;;
        1) return 1 ;;
        2)
            local req_id="${output%%$'\t'*}"
            local token="${output#*$'\t'}"
            __kyris_prompt_user "$cmd" "$sock" "$req_id" "$token"
            return $?
            ;;
        3)
            local req_id="${output%%$'\t'*}"
            local rest="${output#*$'\t'}"
            local token="${rest%%$'\t'*}"
            local count="${rest#*$'\t'}"
            __kyris_circuit_breaker_prompt "$cmd" "$sock" "$req_id" "$token" "$count"
            return $?
            ;;
        *)
            printf '\033[31m[agentpact]\033[0m unexpected kyris-hook exit code: %s\n' "$exit_code" >&2
            return 1
            ;;
    esac
}

__kyris_circuit_breaker_prompt() {
    local cmd="$1" sock="$2" req_id="$3" token="$4" count="$5"
    local answer
    print -Pn "%F{yellow}[kyris] circuit breaker:%f ${count} commands without human input. Review: kyris timeline --last 10. [y/n] " >&2
    read -r answer < /dev/tty
    case "$answer" in
        y|Y|yes)
            if kyris-hook respond --socket "$sock" --req-id "$req_id" --token "$token" --response approved; then
                return 0
            else
                print -P "%F{red}[kyris] continue rejected by daemon%f" >&2; return 1
            fi
            ;;
        *)
            kyris-hook respond --socket "$sock" --req-id "$req_id" --token "$token" --response denied 2>/dev/null
            return 1
            ;;
    esac
}

__kyris_prompt_user() {
    local cmd="$1" sock="$2" req_id="$3" token="$4"
    local answer
    print -Pn "%F{yellow}[kyris] allow?%f $cmd [y/n/always] " >&2
    read -r answer < /dev/tty
    case "$answer" in
        y|Y|yes)
            if kyris-hook respond --socket "$sock" --req-id "$req_id" --token "$token" --response approved; then
                return 0
            else
                print -P "%F{red}[kyris] approval rejected by daemon%f" >&2; return 1
            fi
            ;;
        a|A|always)
            if kyris-hook respond --socket "$sock" --req-id "$req_id" --token "$token" --response always; then
                return 0
            else
                print -P "%F{red}[kyris] approval rejected by daemon%f" >&2; return 1
            fi
            ;;
        *)
            kyris-hook respond --socket "$sock" --req-id "$req_id" --token "$token" --response denied 2>/dev/null
            return 1
            ;;
    esac
}

__kyris_record_fail_open() {
    local cmd="$1"
    local log="$HOME/.kyris/fail-open.jsonl"
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
    [[ -f "$state_file" ]] || return 1
    local content
    content=$(<"$state_file" 2>/dev/null) || return 1
    [[ "$content" == *'"on_daemon_unavailable":"allow"'* || "$content" == *'"on_daemon_unavailable": "allow"'* ]]
}

__kyris_sentinel_active() {
    local sentinel="$1"
    [[ -f "$sentinel" ]] || return 1
    local now file_epoch age
    now=$(date +%s)
    file_epoch=$(stat -f %m "$sentinel" 2>/dev/null || echo 0)
    age=$((now - file_epoch))
    (( age < 30 ))
}

__kyris_write_sentinel() {
    printf '' > "$1" 2>/dev/null
}

__kyris_restart_daemon() {
    local sock="$1"
    local delay

    # The daemon is likely already starting (launchd RunAtLoad after reboot).
    # Wait for it before attempting a kickstart.
    for delay in 0.05 0.1 0.15 0.2 0.25 0.25; do
        [[ -S "$sock" ]] && return 0
        sleep "$delay"
    done

    # Socket absent after 1s — ask launchd to start the service.
    # No -k: don't kill a potentially mid-startup instance.
    launchctl kickstart gui/$(id -u)/is.kyr.agentpactd 2>/dev/null

    for delay in 0.1 0.2 0.3 0.4; do
        [[ -S "$sock" ]] && return 0
        sleep "$delay"
    done
    return 1
}

__kyris_protocol_ok() {
    local sock="$1"
    local state_file="${sock%/*}/daemon.state"
    [[ -f "$state_file" ]] || return 0
    local content
    content=$(<"$state_file" 2>/dev/null) || return 0
    local version
    version=${content##*\"protocol_version\":}
    version=${version%%[,\}]*}
    version=${version// /}
    [[ -z "$version" || "$version" == "$content" ]] && return 0
    if [[ "$version" != "1" ]]; then
        if (( version > 1 )); then
            __kyris_protocol_error="agentpactd protocol version ${version} is newer than kyris expects (1). Upgrade kyris: brew upgrade kyris"
        else
            __kyris_protocol_error="agentpactd protocol version ${version} is older than kyris expects (1). Upgrade agentpact: brew upgrade agentpact"
        fi
        return 1
    fi
    return 0
}

add-zsh-hook preexec __kyris_preexec
