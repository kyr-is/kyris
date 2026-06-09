// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
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

// `run` is a top-to-bottom narrative of the install sequence — service plist,
// shell hooks, agent integrations, manifest writes, post-install verify.
// Splitting it into helpers would obscure the install transcript (which is
// the user-facing artifact) without making the logic easier to follow.
// Install takes no flags: enrollment is the separate explicit `kyris enroll`.
#[allow(clippy::too_many_lines)]
pub fn run() {
    let log = InstallLog::open_install();
    log.info("=== kyris install started ===");

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
    // the health check inside burn-control surface setup races the daemon's
    // startup and may fail even though the daemon is healthy.
    if let Ok(config) = load_or_init_config() {
        let base_url = config.base_url();
        if !crate::agents::configure::wait_for_kyrisd_ready(&base_url, 10) {
            log.warn("kyrisd did not become ready within 10s — agent burn-control setup may fail");
            eprintln!(
                "Warning: kyrisd is not responding at {base_url}/healthz. \
                 Inspect `kyris logs` or try `launchctl kickstart gui/$UID/is.kyr.kyrisd`."
            );
        }
    }

    // Note: agentpact materializes its default user policy
    // (`~/.config/agentpact/policy/pact.yaml`) on daemon startup —
    // see `agentpact::config::DaemonConfig::ensure_dirs` /
    // `copy_default_policy_if_missing`. kyris no longer reaches
    // across the boundary to write into agentpact's namespace.

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

    // Fetch the live pricing table now so install yields a fresh, working cost
    // table (the bundled table is release-stale). Pricing is public — no
    // enrollment needed. Best-effort: never fails the install.
    fetch_pricing_at_install(&log);

    // Install succeeded. Report enrollment status — install never enrolls;
    // `kyris enroll` is a separate explicit step. Standalone is supported and
    // indicated (here, in status/doctor, and the tray).
    report_enrollment_status(&log);

    log.info("=== kyris install complete ===");
    if !log.path().as_os_str().is_empty() {
        println!("\nInstall log: {}", log.path().display());
    }
}

/// Fetch the live pricing table at install so the machine has a fresh, working
/// cost table immediately. The bundled table is release-stale, so a fetched
/// table is strictly better. Best-effort on every axis: a missing `relay.url`,
/// an unreachable relay, or a cache-write failure all leave the bundled table
/// in place until the daemon refreshes — install never fails here.
fn fetch_pricing_at_install(log: &InstallLog) {
    let relay_base = match load_or_init_config() {
        Ok(config) => config.relay.url.trim_end_matches('/').to_string(),
        Err(e) => {
            log.warn(&format!("pricing fetch skipped: cannot load config: {e}"));
            return;
        }
    };
    if relay_base.is_empty() {
        log.info("pricing fetch skipped: relay.url unset (bundled table until configured)");
        return;
    }

    let url = format!("{relay_base}/api/v1/pricing");
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log.warn(&format!("pricing fetch skipped: cannot build runtime: {e}"));
            return;
        }
    };

    let table = runtime.block_on(async {
        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body = resp.text().await.ok()?;
        serde_saphyr::from_str::<kyris_core::pricing::PricingTable>(&body).ok()
    });

    let Some(table) = table else {
        log.warn(&format!(
            "pricing not fetched (relay {relay_base} unreachable); using bundled table until the daemon refreshes"
        ));
        println!(
            "\nCould not fetch pricing from {relay_base} right now — using the built-in table until the daemon refreshes."
        );
        return;
    };
    match kyris_core::pricing_cache::store(&table) {
        Ok(()) => {
            log.info(&format!(
                "fetched pricing table {} from {relay_base}",
                table.version
            ));
            println!("\nPricing table fetched from {relay_base}.");
        }
        Err(e) => log.warn(&format!("fetched pricing but failed to cache it: {e}")),
    }
}

/// Final install step: report enrollment status. Install never enrolls —
/// enrollment is a separate, explicit `kyris enroll` (a GitHub device flow).
/// Standalone is a supported state, indicated here, in `kyris status`/`doctor`,
/// and by the tray warning; pricing and model costs work without it.
fn report_enrollment_status(log: &InstallLog) {
    if let Some(creds) = kyris_core::credentials::load() {
        log.info("enrolled");
        println!("\nEnrolled (machine {}).", creds.machine_id);
        return;
    }
    log.info("standalone (not enrolled)");
    println!(
        "\nThis machine is standalone (not enrolled): event sync is disabled.\n\
         Pricing and model costs work without enrolling.\n\
         Enable sync later with: kyris enroll"
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// G-K6: the launchd plist renderer is pure but had no unit test. A typo in
    /// the Label, the binary path, the log paths, or the RunAtLoad/KeepAlive keys
    /// silently breaks `launchctl bootstrap` (the integration test runs real
    /// `launchctl` but never asserts the rendered contents).
    #[test]
    fn testLaunchdPlistRendersAllRequiredFields() {
        let binary = "/Users/dev/.kyris/bin/kyrisd";
        let log = "/Users/dev/.local/state/kyris/log/kyrisd.log";
        let plist = launchd_plist("is.kyr.kyrisd", Path::new(binary), Path::new(log));

        // Well-formed plist envelope.
        assert!(plist.starts_with(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
        assert!(plist.contains("<!DOCTYPE plist"));
        assert!(plist.contains(r#"<plist version="1.0">"#));
        assert!(plist.trim_end().ends_with("</plist>"));

        // Label + the binary as the sole ProgramArgument.
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("<string>is.kyr.kyrisd</string>"));
        assert!(plist.contains(&format!("<string>{binary}</string>")));

        // launchd starts it at load and keeps it alive (both keys → <true/>).
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert_eq!(
            plist.matches("<true/>").count(),
            2,
            "both RunAtLoad and KeepAlive must be true"
        );

        // stdout AND stderr both go to the log path.
        assert!(plist.contains("<key>StandardOutPath</key>"));
        assert!(plist.contains("<key>StandardErrorPath</key>"));
        assert_eq!(
            plist.matches(&format!("<string>{log}</string>")).count(),
            2,
            "the log path must appear for both StandardOutPath and StandardErrorPath",
        );
    }

    /// The label is what `launchctl bootout/kickstart` target — pin it so a rename
    /// can't silently desync the install from the documented service id.
    #[test]
    fn testLaunchdLabelIsStable() {
        assert_eq!(launchd_label(ServiceKind::Kyrisd), "is.kyr.kyrisd");
    }
}
