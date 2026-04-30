// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use crate::integration::{
    claude_settings_path, codex_hooks_path, gemini_settings_path, opencode_config_path,
    read_json_value, read_toml_value,
};
use crate::state::env_dir;

use super::profile::{AdaptedMechanism, ManagedFileFingerprint, SurfaceState};

pub struct ProbeResult {
    pub detected: bool,
    pub execution: SurfaceState,
    pub tool: SurfaceState,
    pub burn_control: SurfaceState,
    pub managed_files: Vec<ManagedFileFingerprint>,
}

pub fn sha256_file(path: &std::path::Path) -> Option<String> {
    let contents = std::fs::read(path).ok()?;
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &contents);
    Some(hex_encode(digest.as_ref()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn fingerprint(path: &std::path::Path) -> Option<ManagedFileFingerprint> {
    sha256_file(path).map(|hash| ManagedFileFingerprint {
        path: path.to_string_lossy().to_string(),
        content_hash: hash,
    })
}

fn env_file_has_var(agent_id: &str, var_name: &str) -> bool {
    let Ok(env_file) = env_dir().map(|d| d.join(format!("{agent_id}.sh"))) else {
        return false;
    };
    std::fs::read_to_string(env_file).is_ok_and(|contents| contents.contains(var_name))
}

fn json_has_hook(path: &std::path::Path, phase: &str, marker: &str) -> bool {
    let Ok(value) = read_json_value(path) else {
        return false;
    };
    value
        .get("hooks")
        .and_then(|h| h.get(phase))
        .and_then(|a| a.as_array())
        .is_some_and(|hooks| {
            let serialized = serde_json::to_string(hooks).unwrap_or_default();
            serialized.contains(marker)
        })
}

pub fn probe_claude_code() -> ProbeResult {
    let home = std::env::var("HOME").unwrap_or_default();
    let detected = std::path::Path::new(&format!("{home}/.claude")).is_dir();
    if !detected {
        return ProbeResult {
            detected: false,
            execution: SurfaceState::none(),
            tool: SurfaceState::none(),
            burn_control: SurfaceState::none(),
            managed_files: Vec::new(),
        };
    }

    let settings_path = claude_settings_path().ok();
    let has_hook = settings_path
        .as_deref()
        .is_some_and(|p| json_has_hook(p, "PreToolUse", "agentpact_pretooluse"));

    let execution = if has_hook {
        SurfaceState::adapted(AdaptedMechanism::LiveHook)
    } else {
        SurfaceState::none()
    };
    let tool = if has_hook {
        SurfaceState::adapted(AdaptedMechanism::LiveHook)
    } else {
        SurfaceState::none()
    };
    let burn_control = if env_file_has_var("claude-code", "ANTHROPIC_BASE_URL") {
        SurfaceState::adapted(AdaptedMechanism::EnvVarProxy)
    } else {
        SurfaceState::none()
    };

    let mut managed_files = Vec::new();
    if let Some(path) = settings_path.as_deref()
        && let Some(fp) = fingerprint(path)
    {
        managed_files.push(fp);
    }

    ProbeResult {
        detected,
        execution,
        tool,
        burn_control,
        managed_files,
    }
}

pub fn probe_codex_cli() -> ProbeResult {
    let detected = crate::integration::codex_config_exists();
    if !detected {
        return ProbeResult {
            detected: false,
            execution: SurfaceState::none(),
            tool: SurfaceState::none(),
            burn_control: SurfaceState::none(),
            managed_files: Vec::new(),
        };
    }

    let hooks_path = codex_hooks_path().ok();
    let has_hook = hooks_path.as_deref().is_some_and(|p| {
        p.exists() && std::fs::read_to_string(p).is_ok_and(|c| c.contains("kyris"))
    });

    let config_path = crate::integration::codex_config_path().ok();
    let has_mcp_wrap = config_path.as_deref().is_some_and(|p| {
        read_toml_value(p).is_ok_and(|v| {
            let serialized = toml::to_string(&v).unwrap_or_default();
            serialized.contains("kyris-mcp")
        })
    });

    let execution = if has_hook {
        SurfaceState::adapted(AdaptedMechanism::LiveHook)
    } else {
        SurfaceState::none()
    };
    let tool = if has_mcp_wrap {
        SurfaceState::adapted(AdaptedMechanism::McpWrapping)
    } else {
        SurfaceState::none()
    };
    let burn_control = if env_file_has_var("codex-cli", "OPENAI_BASE_URL") {
        SurfaceState::adapted(AdaptedMechanism::EnvVarProxy)
    } else {
        SurfaceState::none()
    };

    let mut managed_files = Vec::new();
    if let Some(path) = config_path.as_deref()
        && let Some(fp) = fingerprint(path)
    {
        managed_files.push(fp);
    }
    if let Some(path) = hooks_path.as_deref()
        && let Some(fp) = fingerprint(path)
    {
        managed_files.push(fp);
    }

    ProbeResult {
        detected,
        execution,
        tool,
        burn_control,
        managed_files,
    }
}

pub fn probe_gemini_cli() -> ProbeResult {
    let detected = crate::integration::gemini_settings_exists()
        || crate::agents::registry::which_exists("gemini");
    if !detected {
        return ProbeResult {
            detected: false,
            execution: SurfaceState::none(),
            tool: SurfaceState::none(),
            burn_control: SurfaceState::none(),
            managed_files: Vec::new(),
        };
    }

    let settings_path = gemini_settings_path().ok();
    let has_hook = settings_path
        .as_deref()
        .is_some_and(|p| json_has_hook(p, "BeforeTool", "agentpact_beforetool"));

    let execution = if has_hook {
        SurfaceState::adapted(AdaptedMechanism::LiveHook)
    } else {
        SurfaceState::none()
    };
    let tool = if has_hook {
        SurfaceState::adapted(AdaptedMechanism::LiveHook)
    } else {
        SurfaceState::none()
    };
    let burn_control = if env_file_has_var("gemini-cli", "GOOGLE_GEMINI_BASE_URL") {
        SurfaceState::adapted(AdaptedMechanism::EnvVarProxy)
    } else {
        SurfaceState::none()
    };

    let mut managed_files = Vec::new();
    if let Some(path) = settings_path.as_deref()
        && let Some(fp) = fingerprint(path)
    {
        managed_files.push(fp);
    }

    ProbeResult {
        detected,
        execution,
        tool,
        burn_control,
        managed_files,
    }
}

pub fn probe_cline() -> ProbeResult {
    let detected = crate::agents::registry::cline_extension_installed();
    if !detected {
        return ProbeResult {
            detected: false,
            execution: SurfaceState::none(),
            tool: SurfaceState::none(),
            burn_control: SurfaceState::none(),
            managed_files: Vec::new(),
        };
    }

    let has_compiled_policy = env_file_has_var("cline", "CLINE_COMMAND_PERMISSIONS");
    let execution = if has_compiled_policy {
        SurfaceState::adapted(AdaptedMechanism::CompiledPolicy)
    } else {
        SurfaceState::none()
    };
    let tool = if has_compiled_policy {
        SurfaceState::adapted(AdaptedMechanism::CompiledPolicy)
    } else {
        SurfaceState::none()
    };

    let settings_path = crate::integration::cline_settings_path().ok();
    let has_base_url = settings_path
        .as_deref()
        .is_some_and(|p| read_json_value(p).is_ok_and(|v| v.get("anthropicBaseUrl").is_some()));
    let has_env_proxy = env_file_has_var("cline", "ANTHROPIC_BASE_URL");
    let burn_control = if has_base_url || has_env_proxy {
        SurfaceState::adapted(AdaptedMechanism::ConfigRewrite)
    } else {
        SurfaceState::none()
    };

    let mut managed_files = Vec::new();
    if let Some(path) = settings_path.as_deref()
        && let Some(fp) = fingerprint(path)
    {
        managed_files.push(fp);
    }

    ProbeResult {
        detected,
        execution,
        tool,
        burn_control,
        managed_files,
    }
}

pub fn probe_opencode() -> ProbeResult {
    let detected = crate::integration::opencode_config_exists()
        || crate::agents::registry::which_exists("opencode");
    if !detected {
        return ProbeResult {
            detected: false,
            execution: SurfaceState::none(),
            tool: SurfaceState::none(),
            burn_control: SurfaceState::none(),
            managed_files: Vec::new(),
        };
    }

    let config_path = opencode_config_path().ok();
    let has_base_url = config_path.as_deref().is_some_and(|p| {
        read_json_value(p).is_ok_and(|v| {
            v.get("provider")
                .and_then(|p| p.get("anthropic"))
                .and_then(|a| a.get("options"))
                .and_then(|o| o.get("baseURL"))
                .is_some()
        })
    });
    let has_env_proxy = env_file_has_var("opencode", "ANTHROPIC_BASE_URL");

    let burn_control = if has_base_url || has_env_proxy {
        SurfaceState::adapted(AdaptedMechanism::ConfigRewrite)
    } else {
        SurfaceState::none()
    };

    let mut managed_files = Vec::new();
    if let Some(path) = config_path.as_deref()
        && let Some(fp) = fingerprint(path)
    {
        managed_files.push(fp);
    }

    ProbeResult {
        detected,
        execution: SurfaceState::none(),
        tool: SurfaceState::none(),
        burn_control,
        managed_files,
    }
}
