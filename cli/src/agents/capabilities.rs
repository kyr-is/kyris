// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! The native-capability overlay type. The agent's native declaration now comes
//! from its in-code `AgentCapabilities` document (`manifest`/`documents`) and,
//! when an agent ships one, a live `<agent> agentpact` response (`engine`). The
//! former orphan `~/.config/agentpact/agents/<vendor>/<product>/capabilities.json`
//! file reader has been retired — it had no producer.

/// The four native-capability flags overlaid onto an integration plan when an
/// agent declares it enforces a surface itself. A `true` flag flips that surface
/// to `AgentPactNative`, so the daemon installs no adaptation for it. The
/// standard wire key for burn-control is `cost` (agentpact README §13.4); kyris
/// keeps `burn_control` as the internal name.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeCapabilityDeclaration {
    pub execution: bool,
    pub tool: bool,
    pub burn_control: bool,
    pub attribution: bool,
}
