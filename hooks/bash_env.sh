# SPDX-FileCopyrightText: Copyright 2026 Kyris
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC1090,SC1091
# Loaded via BASH_ENV for non-interactive bash (agent subshells).
#
# If a BASH_ENV was active before kyris was installed, kyris's install
# captured it as _KYRIS_ORIG_BASH_ENV.  Source it first so both hooks
# run in every non-interactive shell — kyris does not displace the
# user's own BASH_ENV script.
[ -n "${_KYRIS_ORIG_BASH_ENV:-}" ] && source "$_KYRIS_ORIG_BASH_ENV" 2>/dev/null || true
source "$(dirname "${BASH_SOURCE[0]}")/bash_hook.sh"
