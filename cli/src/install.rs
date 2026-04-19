// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use std::path::PathBuf;

use crate::compile_policy;
use crate::integration::{
    claude_hooks_dir, claude_settings_path, codex_config_exists, codex_config_path, codex_dir,
    codex_hooks_path, ensure_json_command_hook, ensure_toml_bool_path, gemini_settings_path,
    read_json_value, read_toml_value, write_json_value, write_toml_value,
};
use crate::service::{ServiceKind, service_state, start_service};
use crate::state::{
    bin_dir, ensure_line, ensure_parent, env_dir, hooks_dir, load_or_init_config,
    write_managed_bytes, write_managed_file,
};

const HOOKS_COMPONENT: &str = "hooks";
const AGENTPACTD_COMPONENT: &str = "agentpactd";
const KYRISD_COMPONENT: &str = "kyrisd";
const KYRIS_MCP_COMPONENT: &str = "kyris-mcp";
const KYRIS_HOOK_COMPONENT: &str = "kyris-hook";
const CLAUDE_COMPONENT: &str = "claude-code";
const CODEX_COMPONENT: &str = "codex-cli";
const GEMINI_COMPONENT: &str = "gemini-cli";
const CLINE_COMPONENT: &str = "cline";
const ZSH_HOOK_SOURCE: &str = include_str!("../../hooks/zsh_hook.sh");
const ZSHENV_HOOK_SOURCE: &str = include_str!("../../hooks/zshenv_hook.sh");
const BASH_HOOK_SOURCE: &str = include_str!("../../hooks/bash_hook.sh");
const BASH_ENV_SOURCE: &str = include_str!("../../hooks/bash_env.sh");
const CLAUDE_PRETOOL_SOURCE: &str =
    include_str!("../../integrations/live-hooks/claude-code/pretooluse.sh");
const CODEX_PRETOOL_SOURCE: &str =
    include_str!("../../integrations/live-hooks/codex-cli/pretooluse.sh");
const GEMINI_BEFORETOOL_SOURCE: &str =
    include_str!("../../integrations/live-hooks/gemini-cli/beforetool.sh");

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

    println!("Kyris Installer");
    println!("===============");

    let mut installed_any = false;
    for (component, installer) in [
        (
            HOOKS_COMPONENT,
            install_shell_hooks as fn() -> Result<Vec<String>, String>,
        ),
        (AGENTPACTD_COMPONENT, install_agentpactd_binary),
        (KYRISD_COMPONENT, install_kyrisd_binary),
        (KYRIS_MCP_COMPONENT, install_kyris_mcp_binary),
        (KYRIS_HOOK_COMPONENT, install_kyris_hook_binary),
        (CLAUDE_COMPONENT, install_claude_adapter),
        (CODEX_COMPONENT, install_codex_adapter),
        (GEMINI_COMPONENT, install_gemini_adapter),
        (CLINE_COMPONENT, install_cline_permissions),
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
    let agentpactd_ok = check_binary("agentpactd");
    let kyrisd_ok = check_binary("kyrisd");
    let kyris_mcp_ok = check_binary("kyris-mcp");
    let kyris_hook_ok = check_binary("kyris-hook");
    let shell_hook_ok = check_shell_hooks();

    if agentpactd_ok && kyrisd_ok && kyris_mcp_ok && kyris_hook_ok && shell_hook_ok {
        println!("All known components detected.");
    } else {
        println!("Missing components:");
        if !agentpactd_ok {
            println!("  agentpactd - Install via: curl -fsSL https://get.kyri.so | sh");
        }
        if !kyrisd_ok {
            println!("  kyrisd     - Install via: curl -fsSL https://get.kyri.so | sh");
        }
        if !kyris_mcp_ok {
            println!("  kyris-mcp  - Install via: curl -fsSL https://get.kyri.so | sh");
        }
        if !kyris_hook_ok {
            println!("  kyris-hook - Install via: curl -fsSL https://get.kyri.so | sh");
        }
        if !shell_hook_ok {
            println!("  shell hook - Run `kyris install --components hooks`.");
        }
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
                HOOKS_COMPONENT
                    | AGENTPACTD_COMPONENT
                    | KYRISD_COMPONENT
                    | KYRIS_MCP_COMPONENT
                    | KYRIS_HOOK_COMPONENT
                    | CLAUDE_COMPONENT
                    | CODEX_COMPONENT
                    | GEMINI_COMPONENT
                    | CLINE_COMPONENT
            )
        })
        .collect();

    if unsupported.is_empty() {
        return Ok(());
    }

    Err(format!(
        "Unsupported install components: {}. Currently supported: {HOOKS_COMPONENT}, \
         {AGENTPACTD_COMPONENT}, {KYRISD_COMPONENT}, {KYRIS_MCP_COMPONENT}, \
         {KYRIS_HOOK_COMPONENT}, {CLAUDE_COMPONENT}, {CODEX_COMPONENT}, \
         {GEMINI_COMPONENT}, {CLINE_COMPONENT}.",
        unsupported.join(", ")
    ))
}

fn detected_components() -> Vec<String> {
    let mut components = vec![
        HOOKS_COMPONENT.to_string(),
        AGENTPACTD_COMPONENT.to_string(),
        KYRISD_COMPONENT.to_string(),
        KYRIS_MCP_COMPONENT.to_string(),
        KYRIS_HOOK_COMPONENT.to_string(),
    ];
    let home = std::env::var("HOME").unwrap_or_default();

    if claude_settings_path().is_ok_and(|path| path.exists())
        || PathBuf::from(&home).join(".claude").is_dir()
    {
        components.push(CLAUDE_COMPONENT.to_string());
    }
    if codex_config_exists() {
        components.push(CODEX_COMPONENT.to_string());
    }
    if which_exists("gemini") || gemini_settings_path().is_ok_and(|path| path.exists()) {
        components.push(GEMINI_COMPONENT.to_string());
    }
    if cline_extension_installed(&home) {
        components.push(CLINE_COMPONENT.to_string());
    }

    components
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

fn install_agentpactd_binary() -> Result<Vec<String>, String> {
    install_release_binary(
        "kyr-is",
        "agentpact",
        "agentpact",
        "agentpactd",
        Some(ServiceKind::Agentpactd),
    )
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
    if brew_formula_installed(formula) {
        return Ok(vec![format!(
            "detected Homebrew-managed {formula}; skipped local {binary} install"
        )]);
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Cannot build runtime for {binary} install: {e}"))?;
    let bundle_dir = runtime.block_on(download_release_bundle(owner, repo))?;
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
    let log_path = match kind {
        ServiceKind::Kyrisd => PathBuf::from(&home)
            .join(".kyris")
            .join("kyrisd.stderr.log"),
        ServiceKind::Agentpactd => PathBuf::from(&home)
            .join(".agentpact")
            .join("agentpactd.log"),
    };

    let mut changes = Vec::new();
    ensure_parent(&log_path)?;
    let plist_contents = launchd_plist(launchd_label(kind), binary_path, &log_path);
    if write_managed_file(&plist_path, &plist_contents, component, Some(0o644))? {
        changes.push(format!("wrote {}", plist_path.display()));
    }

    if !state.launchd_loaded {
        start_service(kind)?;
        changes.push(format!("started {:?}", kind));
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

fn launchd_label(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Kyrisd => "so.kyri.kyrisd",
        ServiceKind::Agentpactd => "so.kyri.agentpactd",
    }
}

fn install_claude_adapter() -> Result<Vec<String>, String> {
    let hooks_dir = claude_hooks_dir()?;
    let script_path = hooks_dir.join("agentpact_pretooluse.sh");
    let settings_path = claude_settings_path()?;
    let mut changes = Vec::new();

    if write_managed_file(
        &script_path,
        CLAUDE_PRETOOL_SOURCE,
        CLAUDE_COMPONENT,
        Some(0o755),
    )? {
        changes.push(format!("wrote {}", script_path.display()));
    }

    let mut settings = read_json_value(&settings_path)?;
    if ensure_json_command_hook(&mut settings, "PreToolUse", &shell_command(&script_path)) {
        write_json_value(&settings_path, &settings, CLAUDE_COMPONENT)?;
        changes.push(format!("updated {}", settings_path.display()));
    }

    Ok(changes)
}

fn install_codex_adapter() -> Result<Vec<String>, String> {
    let config_path = codex_config_path()?;
    let hooks_path = codex_hooks_path()?;
    let script_path = codex_dir()?.join("kyris_pretooluse.sh");
    let mut changes = Vec::new();

    if write_managed_file(
        &script_path,
        CODEX_PRETOOL_SOURCE,
        CODEX_COMPONENT,
        Some(0o755),
    )? {
        changes.push(format!("wrote {}", script_path.display()));
    }

    let mut config = read_toml_value(&config_path)?;
    if ensure_toml_bool_path(&mut config, &["features", "codex_hooks"], true) {
        write_toml_value(&config_path, &config, CODEX_COMPONENT)?;
        changes.push(format!("updated {}", config_path.display()));
    }

    let mut hooks = read_json_value(&hooks_path)?;
    if ensure_json_command_hook(&mut hooks, "PreToolUse", &shell_command(&script_path)) {
        write_json_value(&hooks_path, &hooks, CODEX_COMPONENT)?;
        changes.push(format!("updated {}", hooks_path.display()));
    }

    Ok(changes)
}

fn install_gemini_adapter() -> Result<Vec<String>, String> {
    let settings_path = gemini_settings_path()?;
    let script_path = settings_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("hooks")
        .join("agentpact_beforetool.sh");
    let mut changes = Vec::new();

    if write_managed_file(
        &script_path,
        GEMINI_BEFORETOOL_SOURCE,
        GEMINI_COMPONENT,
        Some(0o755),
    )? {
        changes.push(format!("wrote {}", script_path.display()));
    }

    let mut settings = read_json_value(&settings_path)?;
    if ensure_json_command_hook(&mut settings, "BeforeTool", &shell_command(&script_path)) {
        write_json_value(&settings_path, &settings, GEMINI_COMPONENT)?;
        changes.push(format!("updated {}", settings_path.display()));
    }

    Ok(changes)
}

fn install_cline_permissions() -> Result<Vec<String>, String> {
    let (permissions, ask_dropped) = compile_policy::compile_cline_permissions(None)?;
    let env_file = env_dir()?.join("cline.sh");
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let json = serde_json::to_string(&permissions)
        .map_err(|e| format!("Cannot serialize compiled Cline permissions: {e}"))?;
    let contents = format!(
        "# SPDX-License-Identifier: Apache-2.0\nexport CLINE_COMMAND_PERMISSIONS='{}'\n",
        json.replace('\'', "\\'")
    );
    let mut changes = Vec::new();

    if write_managed_file(&env_file, &contents, CLINE_COMPONENT, Some(0o600))? {
        changes.push(format!("wrote {}", env_file.display()));
    }

    let loader_path = env_dir()?.join("load.sh");
    if ensure_line(
        &PathBuf::from(&home).join(".zshrc"),
        "source \"$HOME/.kyris/env/load.sh\"",
        CLINE_COMPONENT,
    )? {
        changes.push("updated ~/.zshrc".to_string());
    }
    if ensure_line(
        &PathBuf::from(&home).join(".bashrc"),
        "source \"$HOME/.kyris/env/load.sh\"",
        CLINE_COMPONENT,
    )? {
        changes.push("updated ~/.bashrc".to_string());
    }
    if !loader_path.exists() {
        // `setup` owns the shared loader, but install should not depend on setup having run.
        let loader = "# SPDX-License-Identifier: Apache-2.0\nfor file in \"$HOME/.kyris/env/\"*.sh; do\n    [ -f \"$file\" ] || continue\n    [ \"$file\" = \"$HOME/.kyris/env/load.sh\" ] && continue\n    . \"$file\"\ndone\n";
        if write_managed_file(&loader_path, loader, CLINE_COMPONENT, Some(0o600))? {
            changes.push(format!("wrote {}", loader_path.display()));
        }
    }

    if ask_dropped > 0 {
        changes.push(format!(
            "warning: dropped {ask_dropped} ask rules while compiling Cline permissions"
        ));
    }

    Ok(changes)
}

fn shell_command(path: &std::path::Path) -> String {
    format!("bash \"{}\"", path.display())
}

fn cline_extension_installed(home: &str) -> bool {
    let ext_dir = PathBuf::from(home).join(".vscode").join("extensions");
    ext_dir.is_dir()
        && std::fs::read_dir(ext_dir).is_ok_and(|entries| {
            entries.filter_map(Result::ok).any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("saoudrizwan.claude-dev")
            })
        })
}

fn brew_formula_installed(formula: &str) -> bool {
    if env_flag("KYRIS_TEST_DISABLE_HOMEBREW_DETECTION") {
        return false;
    }
    std::process::Command::new("brew")
        .args(["list", formula])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn which_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        let normalized = value.trim().to_ascii_lowercase();
        matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
    })
}

#[derive(serde::Deserialize)]
struct GitHubRelease {
    assets: Vec<GitHubAsset>,
}

#[derive(serde::Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

async fn download_release_bundle(owner: &str, repo: &str) -> Result<PathBuf, String> {
    let target = release_target()?;
    let release = fetch_latest_release(owner, repo).await?;
    let asset_name = format!("{repo}-{target}.tar.gz");
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == asset_name)
        .ok_or_else(|| format!("Missing release asset {asset_name} for {owner}/{repo}"))?;

    download_and_extract(asset).await
}

async fn fetch_latest_release(owner: &str, repo: &str) -> Result<GitHubRelease, String> {
    let url = format!(
        "{}/repos/{owner}/{repo}/releases/latest",
        github_releases_base_url()
    );
    reqwest::Client::new()
        .get(url)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", user_agent())
        .send()
        .await
        .map_err(|e| format!("Failed to query GitHub Releases for {owner}/{repo}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("GitHub Releases request failed for {owner}/{repo}: {e}"))?
        .json::<GitHubRelease>()
        .await
        .map_err(|e| format!("Failed to parse GitHub release for {owner}/{repo}: {e}"))
}

async fn download_and_extract(asset: &GitHubAsset) -> Result<PathBuf, String> {
    let bytes = reqwest::Client::new()
        .get(&asset.browser_download_url)
        .header("user-agent", user_agent())
        .send()
        .await
        .map_err(|e| format!("Failed to download {}: {e}", asset.name))?
        .error_for_status()
        .map_err(|e| format!("Download failed for {}: {e}", asset.name))?
        .bytes()
        .await
        .map_err(|e| format!("Failed to read {}: {e}", asset.name))?;

    let temp_dir = std::env::temp_dir().join(format!(
        "kyris-install-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("Cannot create {}: {e}", temp_dir.display()))?;

    let archive_path = temp_dir.join(&asset.name);
    std::fs::write(&archive_path, &bytes)
        .map_err(|e| format!("Cannot write {}: {e}", archive_path.display()))?;

    let archive_path_string = archive_path.to_string_lossy().to_string();
    let temp_dir_string = temp_dir.to_string_lossy().to_string();
    let status = std::process::Command::new("tar")
        .args(["-xzf", &archive_path_string, "-C", &temp_dir_string])
        .status()
        .map_err(|e| format!("Failed to run tar for {}: {e}", asset.name))?;
    if !status.success() {
        return Err(format!("tar failed while extracting {}", asset.name));
    }

    Ok(temp_dir)
}

fn release_target() -> Result<&'static str, String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") | ("macos", "arm64") => Ok("darwin-aarch64"),
        ("macos", "x86_64") => Ok("darwin-x86_64"),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("linux", "aarch64") => Ok("linux-aarch64"),
        (os, arch) => Err(format!("Unsupported install target: {os}/{arch}")),
    }
}

fn user_agent() -> String {
    format!("kyris/{}", env!("CARGO_PKG_VERSION"))
}

fn github_releases_base_url() -> String {
    std::env::var("KYRIS_TEST_GITHUB_RELEASES_BASE_URL")
        .unwrap_or_else(|_| "https://api.github.com".to_string())
        .trim_end_matches('/')
        .to_string()
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
