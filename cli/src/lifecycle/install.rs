// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use std::path::PathBuf;

use crate::service::{ServiceKind, service_state, start_service};
use crate::state::{
    bin_dir, ensure_line, ensure_parent, hooks_dir, load_or_init_config, write_managed_bytes,
    write_managed_file,
};

const HOOKS_COMPONENT: &str = "hooks";
const KYRISD_COMPONENT: &str = "kyrisd";
const KYRIS_MCP_COMPONENT: &str = "kyris-mcp";
const KYRIS_HOOK_COMPONENT: &str = "kyris-hook";
const ZSH_HOOK_SOURCE: &str = include_str!("../../../hooks/zsh_hook.sh");
const ZSHENV_HOOK_SOURCE: &str = include_str!("../../../hooks/zshenv_hook.sh");
const BASH_HOOK_SOURCE: &str = include_str!("../../../hooks/bash_hook.sh");
const BASH_ENV_SOURCE: &str = include_str!("../../../hooks/bash_env.sh");

#[derive(Args)]
pub struct InstallArgs {
    #[arg(long)]
    pub all: bool,
    #[arg(long, value_delimiter = ',')]
    pub components: Option<Vec<String>>,
}

pub fn run(args: InstallArgs) {
    if let Err(error) = load_or_init_config() {
        eprintln!("{error}");
        std::process::exit(1);
    }

    let requested = requested_components(&args);
    if let Err(error) = validate_components(&requested) {
        eprintln!("{error}");
        std::process::exit(1);
    }

    if !check_agentpactd_available() {
        eprintln!(
            "agentpactd not found. Kyris requires AgentPact — install it first via AgentPact's \
             own installer, then re-run `kyris install`."
        );
        std::process::exit(1);
    }

    println!("Kyris Installer");
    println!("===============");

    let mut installed_any = false;
    for (component, installer) in [
        (
            HOOKS_COMPONENT,
            install_shell_hooks as fn() -> Result<Vec<String>, String>,
        ),
        (KYRISD_COMPONENT, install_kyrisd_binary),
        (KYRIS_MCP_COMPONENT, install_kyris_mcp_binary),
        (KYRIS_HOOK_COMPONENT, install_kyris_hook_binary),
    ] {
        if !requested.iter().any(|requested| requested == component) {
            continue;
        }

        match installer() {
            Ok(changes) => {
                installed_any = true;
                if changes.is_empty() {
                    println!("{component}: already configured.");
                } else {
                    println!("Installed {component}:");
                    for change in changes {
                        println!("  - {change}");
                    }
                }
            }
            Err(error) => {
                eprintln!("{component}: {error}");
                std::process::exit(1);
            }
        }
    }

    println!();
    if !installed_any {
        println!("No components were installed.");
    }

    println!("Component status:");
    let kyrisd_ok = check_binary("kyrisd");
    let kyris_mcp_ok = check_binary("kyris-mcp");
    let kyris_hook_ok = check_binary("kyris-hook");
    let shell_hook_ok = check_shell_hooks();
    let agentpactd_ok = check_binary("agentpactd");

    if kyrisd_ok && kyris_mcp_ok && kyris_hook_ok && shell_hook_ok && agentpactd_ok {
        println!("All known components detected.");
    } else {
        println!("Missing components:");
        if !kyrisd_ok {
            println!("  kyrisd     - Install via: curl -fsSL https://kyr.is/install | sh");
        }
        if !kyris_mcp_ok {
            println!("  kyris-mcp  - Install via: curl -fsSL https://kyr.is/install | sh");
        }
        if !kyris_hook_ok {
            println!("  kyris-hook - Install via: curl -fsSL https://kyr.is/install | sh");
        }
        if !shell_hook_ok {
            println!("  shell hook - Run `kyris install --components hooks`.");
        }
        if !agentpactd_ok {
            println!("  agentpactd - Install separately via AgentPact's own installer.");
        }
    }

    println!("\nPrestaging agent integrations...");
    if let Err(e) = crate::agents::prestage::prestage_all() {
        eprintln!("Agent prestage: {e}");
    }

    println!("\nReconciling agent integrations...");
    if let Err(e) = crate::agents::reconcile::reconcile_all(false) {
        eprintln!("Reconciliation: {e}");
    }
}

fn requested_components(args: &InstallArgs) -> Vec<String> {
    if args.all {
        return detected_components();
    }
    if args.components.is_none() {
        return vec![HOOKS_COMPONENT.to_string()];
    }
    args.components.clone().unwrap_or_default()
}

fn validate_components(requested: &[String]) -> Result<(), String> {
    let unsupported: Vec<&str> = requested
        .iter()
        .map(String::as_str)
        .filter(|component| {
            !matches!(
                *component,
                HOOKS_COMPONENT | KYRISD_COMPONENT | KYRIS_MCP_COMPONENT | KYRIS_HOOK_COMPONENT
            )
        })
        .collect();

    if unsupported.is_empty() {
        return Ok(());
    }

    Err(format!(
        "Unsupported install components: {}. Currently supported: {HOOKS_COMPONENT}, \
         {KYRISD_COMPONENT}, {KYRIS_MCP_COMPONENT}, {KYRIS_HOOK_COMPONENT}.",
        unsupported.join(", ")
    ))
}

fn detected_components() -> Vec<String> {
    vec![
        HOOKS_COMPONENT.to_string(),
        KYRISD_COMPONENT.to_string(),
        KYRIS_MCP_COMPONENT.to_string(),
        KYRIS_HOOK_COMPONENT.to_string(),
    ]
}

fn install_shell_hooks() -> Result<Vec<String>, String> {
    let hooks_dir = hooks_dir()?;
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let mut changes = Vec::new();

    for (name, contents) in [
        ("zsh_hook.sh", ZSH_HOOK_SOURCE),
        ("zshenv_hook.sh", ZSHENV_HOOK_SOURCE),
        ("bash_hook.sh", BASH_HOOK_SOURCE),
        ("bash_env.sh", BASH_ENV_SOURCE),
    ] {
        let path = hooks_dir.join(name);
        if write_managed_file(&path, contents, "hooks", Some(0o755))? {
            changes.push(format!("wrote {}", path.display()));
        }
    }

    for (path, line, label) in [
        (
            PathBuf::from(&home).join(".zshrc"),
            "source \"$HOME/.kyris/hooks/zsh_hook.sh\"",
            "~/.zshrc",
        ),
        (
            PathBuf::from(&home).join(".zshenv"),
            "source \"$HOME/.kyris/hooks/zshenv_hook.sh\"",
            "~/.zshenv",
        ),
        (
            PathBuf::from(&home).join(".bashrc"),
            "source \"$HOME/.kyris/hooks/bash_hook.sh\"",
            "~/.bashrc",
        ),
        (
            PathBuf::from(&home).join(".bashrc"),
            "export BASH_ENV=\"$HOME/.kyris/hooks/bash_env.sh\"",
            "~/.bashrc",
        ),
    ] {
        if ensure_line(&path, line, "hooks")? {
            changes.push(format!("updated {label}"));
        }
    }

    Ok(changes)
}

fn install_kyrisd_binary() -> Result<Vec<String>, String> {
    install_release_binary(
        "kyr-is",
        "kyris",
        "kyris",
        "kyrisd",
        Some(ServiceKind::Kyrisd),
    )
}

fn install_kyris_mcp_binary() -> Result<Vec<String>, String> {
    install_release_binary("kyr-is", "kyris", "kyris", "kyris-mcp", None)
}

fn install_kyris_hook_binary() -> Result<Vec<String>, String> {
    install_release_binary("kyr-is", "kyris", "kyris", "kyris-hook", None)
}

fn install_release_binary(
    owner: &str,
    repo: &str,
    formula: &str,
    binary: &str,
    service: Option<ServiceKind>,
) -> Result<Vec<String>, String> {
    if super::release::brew_formula_installed(formula) {
        return Ok(vec![format!(
            "detected Homebrew-managed {formula}; skipped local {binary} install"
        )]);
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Cannot build runtime for {binary} install: {e}"))?;
    let bundle_dir = runtime.block_on(download_verified_bundle(owner, repo))?;
    let binary_path = bundle_dir.join(binary);
    let binary_bytes = std::fs::read(&binary_path)
        .map_err(|e| format!("Cannot read {}: {e}", binary_path.display()))?;
    let install_path = bin_dir()?.join(binary);

    let mut changes = ensure_bin_path("install")?;
    if write_managed_bytes(&install_path, &binary_bytes, binary, Some(0o755))? {
        changes.push(format!("wrote {}", install_path.display()));
    }

    if let Some(kind) = service {
        changes.extend(install_launchd_service(kind, &install_path, binary)?);
    }

    let _ = std::fs::remove_dir_all(&bundle_dir);
    Ok(changes)
}

async fn download_verified_bundle(owner: &str, repo: &str) -> Result<PathBuf, String> {
    let target = super::release::release_target()?;
    let release = super::release::fetch_latest_release(owner, repo).await?;
    let asset_name = format!("{repo}-{target}.tar.gz");
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == asset_name)
        .ok_or_else(|| format!("Missing release asset {asset_name} for {owner}/{repo}"))?;

    let verified_bytes = super::release::download_and_verify(&release, asset).await?;
    super::release::extract_tarball(&verified_bytes, &asset_name)
}

fn ensure_bin_path(component: &str) -> Result<Vec<String>, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let mut changes = Vec::new();
    for (path, label) in [
        (PathBuf::from(&home).join(".zshrc"), "~/.zshrc"),
        (PathBuf::from(&home).join(".bashrc"), "~/.bashrc"),
    ] {
        if ensure_line(&path, "export PATH=\"$HOME/.kyris/bin:$PATH\"", component)? {
            changes.push(format!("updated {label}"));
        }
    }
    Ok(changes)
}

fn install_launchd_service(
    kind: ServiceKind,
    binary_path: &std::path::Path,
    component: &str,
) -> Result<Vec<String>, String> {
    let state = service_state(kind);
    if state.managed_by_homebrew {
        return Ok(vec![format!(
            "detected Homebrew-managed {:?} service",
            kind
        )]);
    }

    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let plist_path = PathBuf::from(&home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{}.plist", launchd_label(kind)));
    let log_path = PathBuf::from(&home)
        .join(".kyris")
        .join("kyrisd.stderr.log");

    let mut changes = Vec::new();
    ensure_parent(&log_path)?;
    let plist_contents = launchd_plist(launchd_label(kind), binary_path, &log_path);
    if write_managed_file(&plist_path, &plist_contents, component, Some(0o644))? {
        changes.push(format!("wrote {}", plist_path.display()));
    }

    if !state.launchd_loaded {
        start_service(kind)?;
        changes.push(format!("started {kind:?}"));
    }

    Ok(changes)
}

fn launchd_plist(label: &str, binary_path: &std::path::Path, log_path: &std::path::Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{binary}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#,
        binary = binary_path.display(),
        log = log_path.display(),
    )
}

fn launchd_label(_kind: ServiceKind) -> &'static str {
    "is.kyr.kyrisd"
}

fn which_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn check_agentpactd_available() -> bool {
    which_exists("agentpactd")
        || bin_dir().is_ok_and(|dir| dir.join("agentpactd").exists())
        || super::release::brew_formula_installed("agentpact")
}

fn check_binary(name: &str) -> bool {
    let found = std::process::Command::new("which")
        .arg(name)
        .output()
        .is_ok_and(|o| o.status.success())
        || bin_dir().is_ok_and(|dir| dir.join(name).exists());
    let marker = if found { "+" } else { "-" };
    println!("  [{marker}] {name}");
    found
}

fn check_shell_hooks() -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let zshrc = std::fs::read_to_string(format!("{home}/.zshrc")).unwrap_or_default();
    let zshenv = std::fs::read_to_string(format!("{home}/.zshenv")).unwrap_or_default();
    let bashrc = std::fs::read_to_string(format!("{home}/.bashrc")).unwrap_or_default();
    let found = zshrc.contains("kyris hook")
        || bashrc.contains("kyris hook")
        || zshenv.contains("zshenv_hook.sh")
        || zshrc.contains("zsh_hook.sh")
        || bashrc.contains("bash_hook.sh");
    let marker = if found { "+" } else { "-" };
    println!("  [{marker}] shell hooks");
    found
}
