#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Kyris
# SPDX-License-Identifier: Apache-2.0
# Codex CLI PreToolUse hook — reads JSON from stdin, queries agentpactd.
# All JSON parsing and construction handled by kyris-hook (§8.1).
set -euo pipefail

kyris-hook check-hook --agent codex-cli
