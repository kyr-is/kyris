// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use std::path::PathBuf;

use crate::config_writer::NoopValidator;
use crate::lifecycle::log::InstallLog;
use crate::service::{ServiceKind, service_state, start_service};
use crate::state::{
    bin_dir, ensure_line, ensure_parent, hooks_dir, load_or_init_config, write_managed_bytes,
    write_managed_file,
};

const HOOKS_COMPONENT: &str = "hooks";
const KYRIS_COMPONENT: &str = "kyris";
const KYRISD_COMPONENT: &str = "kyrisd";
const KYRIS_MCP_COMPONENT: &str = "kyris-mcp";
const KYRIS_HOOK_COMPONENT: &str = "kyris-hook";
const ZSH_HOOK_SOURCE: &str = include_str!("../../../hooks/zsh_hook.sh");
const ZSHENV_HOOK_SOURCE: &str = include_str!("../../../hooks/zshenv_hook.sh");
const BASH_HOOK_SOURCE: &str = include_str!("../../../hooks/bash_hook.sh");
const BASH_ENV_SOURCE: &str = include_str!("../../../hooks/bash_env.sh");
// BASH_ENV chaining: when the user already has a BASH_ENV set, install captures
// it in _KYRIS_ORIG_BASH_ENV so bash_env.sh can source both scripts.
const KYRIS_BASH_ENV_MARKER: &str = "/.kyris/hooks/bash_env.sh";
const KYRIS_BASH_ENV_LINE: &str = "export BASH_ENV=\"$HOME/.kyris/hooks/bash_env.sh\"";
const KYRIS_ORIG_CAPTURE: &str = "export _KYRIS_ORIG_BASH_ENV=\"${BASH_ENV:-}\"";

#[derive(Args)]
pub struct InstallArgs;

// `run` is a top-to-bottom narrative of the install sequence — service plist,
// shell hooks, agent integrations, manifest writes, post-install verify.
// Splitting it into helpers would obscure the install transcript (which is
// the user-facing artifact) without making the logic easier to follow.
#[allow(clippy::too_many_lines)]
pub fn run(_args: InstallArgs) {
    let log = InstallLog::open_install();
    log.info("=== kyris install started ===");

    // Install implies "I want governance on" — clear any leftover
    // `kyris stop` sentinel so the freshly-installed hooks don't
    // immediately bypass themselves. Quiet best-effort: the file may
    // not exist (common), and a remove failure shouldn't block the
    // install.
    let sentinel = kyris_core::paths::disabled_marker_path();
    if sentinel.exists() {
        match std::fs::remove_file(&sentinel) {
            Ok(()) => log.info(&format!("cleared sentinel {}", sentinel.display())),
            Err(e) => log.warn(&format!(
                "could not clear sentinel {}: {e}",
                sentinel.display()
            )),
        }
    }

    if let Err(error) = load_or_init_config() {
        log.error(&format!("load_or_init_config: {error}"));
        eprintln!("{error}");
        std::process::exit(1);
    }

    if !check_agentpactd_available() {
        let msg = "agentpactd not found. Kyris requires AgentPact — install it first via \
                   AgentPact's own installer, then re-run `kyris install`.";
        log.error(msg);
        eprintln!("{msg}");
        std::process::exit(1);
    }

    println!("Kyris Installer");
    println!("===============");

    for (component, installer) in [
        (
            HOOKS_COMPONENT,
            install_shell_hooks as fn(&InstallLog) -> Result<Vec<String>, String>,
        ),
        (KYRIS_COMPONENT, install_kyris_binary),
        (KYRISD_COMPONENT, install_kyrisd_binary),
        (KYRIS_MCP_COMPONENT, install_kyris_mcp_binary),
        (KYRIS_HOOK_COMPONENT, install_kyris_hook_binary),
    ] {
        log.info(&format!("--- component: {component} ---"));
        match installer(&log) {
            Ok(changes) => {
                if changes.is_empty() {
                    log.info(&format!("{component}: already configured"));
                    println!("{component}: already configured.");
                } else {
                    println!("Installed {component}:");
                    for change in changes {
                        println!("  - {change}");
                    }
                }
            }
            Err(error) => {
                log.error(&format!("{component}: {error}"));
                eprintln!("{component}: {error}");
                std::process::exit(1);
            }
        }
    }

    println!("Component status:");
    let kyrisd_ok = check_binary("kyrisd");
    let kyris_mcp_ok = check_binary("kyris-mcp");
    let kyris_hook_ok = check_binary("kyris-hook");
    let agentpactd_ok = check_binary("agentpactd");
    let bash_env_ok = check_bash_env();
    let agents_ok = check_agent_surfaces();

    let core_ok = kyrisd_ok && kyris_mcp_ok && kyris_hook_ok && agentpactd_ok && bash_env_ok;
    if core_ok && agents_ok {
        log.info("all known components detected");
        println!("All known components detected.");
    } else if !core_ok {
        // Agent surfaces are probed pre-config; missing entries get fixed by
        // prestage/reconcile below. Only flag core (binary/BASH_ENV) gaps here.
        println!("Missing components:");
        if !kyrisd_ok {
            log.warn("kyrisd not found on PATH");
            println!("  kyrisd     - Install via: curl -fsSL https://kyr.is/install | sh");
        }
        if !kyris_mcp_ok {
            log.warn("kyris-mcp not found on PATH");
            println!("  kyris-mcp  - Install via: curl -fsSL https://kyr.is/install | sh");
        }
        if !kyris_hook_ok {
            log.warn("kyris-hook not found on PATH");
            println!("  kyris-hook - Install via: curl -fsSL https://kyr.is/install | sh");
        }
        if !agentpactd_ok {
            log.warn("agentpactd not found on PATH");
            println!("  agentpactd - Install separately via AgentPact's own installer.");
        }
        if !bash_env_ok {
            log.warn("BASH_ENV not configured");
            println!(
                "  BASH_ENV   - Run `kyris install` to configure non-interactive shell hooks."
            );
        }
    }

    println!("\nPrestaging agent integrations...");
    log.info("--- prestage_all ---");
    if let Err(e) = crate::agents::prestage::prestage_all(Some(&log)) {
        log.error(&format!("prestage_all: {e}"));
        eprintln!("Agent prestage: {e}");
    }

    // Wait for kyrisd to be fully ready before reconciling agents. The
    // component installer started kyrisd moments ago; without a wait,
    // the health check inside configure_burn_control races the daemon's
    // startup and may fail even though the daemon is healthy.
    if let Ok(config) = load_or_init_config() {
        let base_url = config.base_url();
        if !crate::agents::configure::wait_for_kyrisd_ready(&base_url, 10) {
            log.warn("kyrisd did not become ready within 10s — agent burn-control setup may fail");
            eprintln!(
                "Warning: kyrisd is not responding at {base_url}/healthz. \
                 Run `kyris start` if it is not running."
            );
        }
    }

    if let Err(e) = seed_user_policy_if_missing(&log) {
        log.warn(&format!("seed_user_policy: {e}"));
    }

    println!("\nReconciling agent integrations...");
    log.info("--- reconcile_all ---");
    if let Err(e) = crate::agents::reconcile::reconcile_all(false, Some(&log)) {
        log.error(&format!("reconcile_all: {e}"));
        eprintln!("Reconciliation: {e}");
    }

    if !super::verify::verify_post_install() {
        log.error("post-install verification failed");
        std::process::exit(1);
    }

    log.info("=== kyris install complete ===");
    if !log.path().as_os_str().is_empty() {
        println!("\nInstall log: {}", log.path().display());
    }
}

fn install_shell_hooks(log: &InstallLog) -> Result<Vec<String>, String> {
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
        let existed = path.exists();
        // Shell hook scripts — opaque text.
        if write_managed_file(&path, contents, "hooks", Some(0o755), &NoopValidator)? {
            let display = path.display().to_string();
            if existed {
                log.updated(&display);
                changes.push(format!("updated {display}"));
            } else {
                log.created(&display);
                changes.push(format!("created {display}"));
            }
        } else {
            log.skipped(&path.display().to_string(), "unchanged");
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
    ] {
        if ensure_line(&path, line, "hooks")? {
            log.appended(&path.display().to_string(), line);
            changes.push(format!("updated {label}"));
        } else {
            log.skipped(&path.display().to_string(), "line already present");
        }
    }

    // BASH_ENV can only hold one value; if the user already has a non-kyris
    // BASH_ENV, capture it in _KYRIS_ORIG_BASH_ENV so bash_env.sh can chain
    // both scripts in every non-interactive shell.
    for (path, label) in [
        (PathBuf::from(&home).join(".bashrc"), "~/.bashrc"),
        (
            PathBuf::from(&home).join(".bash_profile"),
            "~/.bash_profile",
        ),
    ] {
        let has_other_bash_env = std::fs::read_to_string(&path).is_ok_and(|c| {
            c.lines().any(|l| {
                let t = l.trim();
                (t.starts_with("BASH_ENV=") || t.starts_with("export BASH_ENV="))
                    && !t.contains(KYRIS_BASH_ENV_MARKER)
            })
        });
        if has_other_bash_env && ensure_line(&path, KYRIS_ORIG_CAPTURE, "hooks")? {
            log.appended(&path.display().to_string(), KYRIS_ORIG_CAPTURE);
            changes.push(format!("captured original BASH_ENV in {label}"));
        }
        if ensure_line(&path, KYRIS_BASH_ENV_LINE, "hooks")? {
            log.appended(&path.display().to_string(), KYRIS_BASH_ENV_LINE);
            changes.push(format!("updated {label}"));
        } else {
            log.skipped(&path.display().to_string(), "BASH_ENV line already present");
        }
    }

    install_bash_env_launchd(&home, &mut changes, log)?;

    Ok(changes)
}

fn install_bash_env_launchd(
    home: &str,
    changes: &mut Vec<String>,
    log: &InstallLog,
) -> Result<(), String> {
    let bash_env_value = format!("{home}/.kyris/hooks/bash_env.sh");
    let plist_path = PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join("is.kyr.env.plist");

    let plist_contents = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>is.kyr.env</string>
  <key>ProgramArguments</key>
  <array>
    <string>launchctl</string>
    <string>setenv</string>
    <string>BASH_ENV</string>
    <string>{bash_env_value}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
"#
    );

    let existed = plist_path.exists();
    // launchd plist (XML) — no XML validator wired yet; safe to skip.
    if write_managed_file(
        &plist_path,
        &plist_contents,
        "hooks",
        Some(0o644),
        &NoopValidator,
    )? {
        let display = plist_path.display().to_string();
        if existed {
            log.updated(&display);
            changes.push(format!("updated {display}"));
        } else {
            log.created(&display);
            changes.push(format!("created {display}"));
        }
    } else {
        log.skipped(&plist_path.display().to_string(), "unchanged");
    }

    // Set immediately for the current session
    let status = std::process::Command::new("launchctl")
        .args(["setenv", "BASH_ENV", &bash_env_value])
        .status()
        .map_err(|e| format!("Failed to run launchctl setenv: {e}"))?;
    if status.success() {
        log.info("set BASH_ENV in launchd session");
        changes.push("set BASH_ENV in launchd session".to_string());
    } else {
        log.warn("launchctl setenv BASH_ENV exited non-zero");
    }

    // Bootstrap the plist so it runs at next login
    let domain = format!("gui/{}", crate::service::uid());
    let boot_status = std::process::Command::new("launchctl")
        .args(["bootstrap", &domain, &plist_path.to_string_lossy()])
        .status();
    match boot_status {
        Ok(s) if !s.success() => {
            log.warn(&format!(
                "launchctl bootstrap {domain} is.kyr.env exited non-zero (may already be loaded)"
            ));
        }
        Err(e) => {
            log.warn(&format!("launchctl bootstrap failed to run: {e}"));
        }
        _ => {}
    }

    Ok(())
}

fn install_kyrisd_binary(log: &InstallLog) -> Result<Vec<String>, String> {
    install_release_binary(
        "kyr-is",
        "kyris",
        "kyris",
        "kyrisd",
        Some(ServiceKind::Kyrisd),
        log,
    )
}

fn install_kyris_binary(log: &InstallLog) -> Result<Vec<String>, String> {
    let current_exe =
        std::env::current_exe().map_err(|e| format!("Cannot locate running kyris binary: {e}"))?;
    let binary_bytes = std::fs::read(&current_exe)
        .map_err(|e| format!("Cannot read {}: {e}", current_exe.display()))?;
    let install_path = bin_dir()?.join("kyris");

    let mut changes = ensure_bin_path(KYRIS_COMPONENT, log)?;
    let existed = install_path.exists();
    // Compiled binary — no schema check applies.
    if write_managed_bytes(
        &install_path,
        &binary_bytes,
        KYRIS_COMPONENT,
        Some(0o755),
        &NoopValidator,
    )? {
        let display = install_path.display().to_string();
        if existed {
            log.updated(&display);
            changes.push(format!("updated {display}"));
        } else {
            log.created(&display);
            changes.push(format!("created {display}"));
        }
    } else {
        log.skipped(&install_path.display().to_string(), "unchanged");
    }
    Ok(changes)
}

fn install_kyris_mcp_binary(log: &InstallLog) -> Result<Vec<String>, String> {
    install_release_binary("kyr-is", "kyris", "kyris", "kyris-mcp", None, log)
}

fn install_kyris_hook_binary(log: &InstallLog) -> Result<Vec<String>, String> {
    install_release_binary("kyr-is", "kyris", "kyris", "kyris-hook", None, log)
}

fn install_release_binary(
    owner: &str,
    repo: &str,
    formula: &str,
    binary: &str,
    service: Option<ServiceKind>,
    log: &InstallLog,
) -> Result<Vec<String>, String> {
    if super::release::brew_formula_installed(formula) {
        let msg = format!("detected Homebrew-managed {formula}; skipped local {binary} install");
        log.info(&msg);
        return Ok(vec![msg]);
    }

    if crate::state::find_in_path(binary).is_some()
        || bin_dir().is_ok_and(|dir| dir.join(binary).exists())
    {
        let msg = format!("{binary}: already on PATH");
        log.skipped(binary, "already on PATH");
        return Ok(vec![msg]);
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

    let mut changes = ensure_bin_path("install", log)?;
    let existed = install_path.exists();
    // Compiled binary — no schema check applies.
    if write_managed_bytes(
        &install_path,
        &binary_bytes,
        binary,
        Some(0o755),
        &NoopValidator,
    )? {
        let display = install_path.display().to_string();
        if existed {
            log.updated(&display);
            changes.push(format!("updated {display}"));
        } else {
            log.created(&display);
            changes.push(format!("created {display}"));
        }
    } else {
        log.skipped(&install_path.display().to_string(), "unchanged");
    }

    if let Some(kind) = service {
        changes.extend(install_launchd_service(kind, &install_path, binary, log)?);
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

fn ensure_bin_path(component: &str, log: &InstallLog) -> Result<Vec<String>, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let mut changes = Vec::new();
    for (path, label) in [
        (PathBuf::from(&home).join(".zshrc"), "~/.zshrc"),
        (PathBuf::from(&home).join(".bashrc"), "~/.bashrc"),
    ] {
        if ensure_line(&path, "export PATH=\"$HOME/.kyris/bin:$PATH\"", component)? {
            log.appended(
                &path.display().to_string(),
                "export PATH=\"$HOME/.kyris/bin:$PATH\"",
            );
            changes.push(format!("updated {label}"));
        } else {
            log.skipped(&path.display().to_string(), "PATH line already present");
        }
    }
    Ok(changes)
}

fn install_launchd_service(
    kind: ServiceKind,
    binary_path: &std::path::Path,
    component: &str,
    log: &InstallLog,
) -> Result<Vec<String>, String> {
    let state = service_state(kind);
    if state.managed_by_homebrew {
        let msg = format!("detected Homebrew-managed {kind:?} service");
        log.info(&msg);
        return Ok(vec![msg]);
    }

    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let plist_path = PathBuf::from(&home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{}.plist", launchd_label(kind)));
    let log_path = PathBuf::from(&home).join(".kyris").join("kyrisd.log");

    let mut changes = Vec::new();
    ensure_parent(&log_path)?;
    let plist_contents = launchd_plist(launchd_label(kind), binary_path, &log_path);
    let existed = plist_path.exists();
    // launchd plist (XML) — no XML validator wired yet.
    if write_managed_file(
        &plist_path,
        &plist_contents,
        component,
        Some(0o644),
        &NoopValidator,
    )? {
        let display = plist_path.display().to_string();
        if existed {
            log.updated(&display);
            changes.push(format!("updated {display}"));
        } else {
            log.created(&display);
            changes.push(format!("created {display}"));
        }
    } else {
        log.skipped(&plist_path.display().to_string(), "unchanged");
    }

    if !state.launchd_loaded {
        start_service(kind)?;
        log.info(&format!("started {kind:?}"));
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

fn check_agentpactd_available() -> bool {
    crate::state::find_in_path("agentpactd").is_some()
        || bin_dir().is_ok_and(|dir| dir.join("agentpactd").exists())
        || super::release::brew_formula_installed("agentpact")
}

fn check_binary(name: &str) -> bool {
    let found = crate::state::find_in_path(name).is_some()
        || bin_dir().is_ok_and(|dir| dir.join(name).exists());
    let marker = if found { "+" } else { "-" };
    println!("  [{marker}] {name}");
    found
}

fn check_bash_env() -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let bashrc = std::fs::read_to_string(format!("{home}/.bashrc")).unwrap_or_default();
    let bash_profile = std::fs::read_to_string(format!("{home}/.bash_profile")).unwrap_or_default();
    let plist_exists = PathBuf::from(&home)
        .join("Library")
        .join("LaunchAgents")
        .join("is.kyr.env.plist")
        .exists();
    let ok = bashrc.contains("BASH_ENV") || bash_profile.contains("BASH_ENV") || plist_exists;
    let marker = if ok { "+" } else { "-" };
    println!("  [{marker}] BASH_ENV");
    ok
}

fn check_agent_surfaces() -> bool {
    use crate::agents::profile::CapLevel;
    let mut all_ok = true;
    for agent in crate::agents::registry::all_agents() {
        let probe = agent.probe();
        if !probe.detected {
            continue;
        }
        let (need_exec, need_tool, need_burn) = agent.expected_surfaces();
        let exec_ok = !need_exec || probe.execution.level != CapLevel::None;
        let tool_ok = !need_tool || probe.tool.level != CapLevel::None;
        let burn_ok = !need_burn || probe.burn_control.level != CapLevel::None;
        let agent_ok = exec_ok && tool_ok && burn_ok;
        if !agent_ok {
            all_ok = false;
        }
        let marker = if agent_ok { "+" } else { "-" };
        let mut missing = Vec::new();
        if !exec_ok {
            missing.push("command");
        }
        if !tool_ok {
            missing.push("mcp");
        }
        if !burn_ok {
            missing.push("burn");
        }
        if missing.is_empty() {
            println!("  [{marker}] {}", agent.id());
        } else {
            println!(
                "  [{marker}] {} (missing: {})",
                agent.id(),
                missing.join(", ")
            );
        }
    }
    all_ok
}

// Seed a minimal user-level Pact at the canonical XDG path
// `$XDG_CONFIG_HOME/agentpact/policy/pact.yaml` so that both the
// agentpactd runtime and the kyris compile-policy walk-up have something
// to read. The single canonical path is provided by
// `agentpact::config::default_user_policy_dir`, which mirrors the daemon's
// `DaemonConfig.user_policy_dir`. XDG dirs are preserved across uninstall,
// so user customizations survive upgrade. Without this seed, agents
// whose only command-control mechanism is compiled policy (e.g., cline)
// can never finish setup on a fresh machine. Idempotent: skips if any
// *.yaml is already present in the user policy dir.
fn seed_user_policy_if_missing(log: &InstallLog) -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|e| format!("HOME not set: {e}"))?;
    let policy_dir = agentpact::config::default_user_policy_dir(&PathBuf::from(&home));
    if let Ok(entries) = std::fs::read_dir(&policy_dir)
        && entries.flatten().any(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
        })
    {
        return Ok(());
    }
    std::fs::create_dir_all(&policy_dir)
        .map_err(|e| format!("create {}: {e}", policy_dir.display()))?;
    let seed_path = policy_dir.join("pact.yaml");
    let body = "# SPDX-License-Identifier: Apache-2.0\n\
                # Minimal starter policy seeded by `kyris install`. Mode `log`\n\
                # records command attribution without blocking — replace with\n\
                # `enforce` and add `commands:` rules to start mediating. Delete\n\
                # this file to opt out; the installer will not re-seed if any\n\
                # *.yaml is present.\n\
                apiVersion: agentpact/v1\n\
                kind: Pact\n\
                metadata:\n  name: user-default\n\
                spec:\n  mode: log\n";
    std::fs::write(&seed_path, body).map_err(|e| format!("write {}: {e}", seed_path.display()))?;
    log.info(&format!("seeded starter policy: {}", seed_path.display()));
    println!("Seeded starter policy: {}", seed_path.display());
    Ok(())
}
