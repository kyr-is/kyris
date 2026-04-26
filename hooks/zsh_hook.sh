# SPDX-FileCopyrightText: Copyright 2026 Kyris
# SPDX-License-Identifier: Apache-2.0
# Kyris Zsh hook: preexec via add-zsh-hook. Requires kyris-hook on PATH.
# Compatible with macOS system Zsh (5.8+) and modern Zsh (5.9+).

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
                return 0
            fi
            __kyris_write_sentinel "$sentinel"
            printf '\033[31m[agentpact]\033[0m daemon unreachable — run `agentpactd` or set on_daemon_unavailable: allow\n' >&2
            return 1
        }
    fi

    (( $+commands[kyris-hook] )) || return 0

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
            return 0
        fi
        __kyris_write_sentinel "$sentinel"
        printf '\033[31m[agentpact]\033[0m daemon unreachable — run `agentpactd` or set on_daemon_unavailable: allow\n' >&2
        return 1
    fi

    case $exit_code in
        0) return 0 ;;
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
    launchctl kickstart -k gui/$(id -u)/is.kyr.agentpactd 2>/dev/null || return 1
    local delay
    for delay in 0.05 0.1 0.25; do
        sleep "$delay"
        [[ -S "$sock" ]] && return 0
    done
    return 1
}

add-zsh-hook preexec __kyris_preexec
