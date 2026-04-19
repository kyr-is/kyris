// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use regex::Regex;
use serde::Deserialize;
use std::path::PathBuf;

use crate::service::{ServiceKind, restart_service, service_state};
use crate::state::write_managed_bytes;

#[derive(Args)]
pub struct UpdateArgs {
    #[arg(long)]
    pub check: bool,
}

pub fn run(args: UpdateArgs) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| {
            eprintln!("Cannot build runtime for update: {error}");
            std::process::exit(1);
        });

    if let Err(error) = runtime.block_on(run_update(args.check)) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

struct RepoUpdate {
    owner: &'static str,
    repo: &'static str,
    formula: &'static str,
    primary_binary: &'static str,
    binaries: &'static [&'static str],
    service: Option<ServiceKind>,
}

async fn run_update(check_only: bool) -> Result<(), String> {
    let target = release_target()?;
    let repos = [
        RepoUpdate {
            owner: "kyr-is",
            repo: "kyris",
            formula: "kyris",
            primary_binary: "kyris",
            binaries: &["kyris", "kyrisd", "kyris-mcp", "kyris-hook"],
            service: Some(ServiceKind::Kyrisd),
        },
        RepoUpdate {
            owner: "kyr-is",
            repo: "agentpact",
            formula: "agentpact",
            primary_binary: "agentpactd",
            binaries: &["agentpactd"],
            service: Some(ServiceKind::Agentpactd),
        },
    ];

    let mut updates_available = 0;
    let mut updates_applied = 0;
    for repo in repos {
        if brew_formula_installed(repo.formula) {
            println!(
                "{}: Homebrew-managed install detected, use `brew upgrade {}`.",
                repo.repo, repo.formula
            );
            continue;
        }

        let Some(current_version) = installed_version(repo.primary_binary) else {
            println!("{}: not installed, skipping.", repo.repo);
            continue;
        };

        let release = fetch_latest_release(repo.owner, repo.repo).await?;
        let latest_version = normalize_version(&release.tag_name);
        if compare_versions(&current_version, &latest_version) >= 0 {
            println!("{}: up to date ({current_version}).", repo.repo);
            continue;
        }

        updates_available += 1;
        println!(
            "{}: update available {} -> {}.",
            repo.repo, current_version, latest_version
        );
        if check_only {
            continue;
        }

        let asset_name = format!("{}-{target}.tar.gz", repo.repo);
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == asset_name)
            .ok_or_else(|| format!("Missing release asset {asset_name} for {}", repo.repo))?;

        let temp_dir = download_and_extract(asset).await?;
        let mut replaced_any = false;
        for binary in repo.binaries {
            let Some(path) = which_path(binary) else {
                continue;
            };
            let extracted_path = temp_dir.join(binary);
            if !extracted_path.exists() {
                continue;
            }
            let contents = std::fs::read(&extracted_path)
                .map_err(|e| format!("Cannot read extracted {}: {e}", extracted_path.display()))?;
            if write_managed_bytes(&path, &contents, "update", Some(0o755))? {
                println!("  replaced {}", path.display());
                replaced_any = true;
            }
        }

        if replaced_any {
            updates_applied += 1;
            if let Some(service) = repo.service {
                let state = service_state(service);
                if state.managed_by_homebrew || state.launchd_loaded {
                    restart_service(service)?;
                }
            }
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    if check_only && updates_available == 0 {
        println!("No updates available.");
    }
    if !check_only && updates_applied == 0 {
        println!("No installed binaries required replacement.");
    }
    Ok(())
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
        "kyris-update-{}-{}",
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

    let status = std::process::Command::new("tar")
        .args([
            "-xzf",
            &archive_path.to_string_lossy(),
            "-C",
            &temp_dir.to_string_lossy(),
        ])
        .status()
        .map_err(|e| format!("Failed to run tar for {}: {e}", asset.name))?;
    if !status.success() {
        return Err(format!("tar failed while extracting {}", asset.name));
    }

    Ok(temp_dir)
}

fn installed_version(binary: &str) -> Option<String> {
    let output = std::process::Command::new(binary)
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    extract_version(&stdout)
}

fn which_path(binary: &str) -> Option<PathBuf> {
    let output = std::process::Command::new("which")
        .arg(binary)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?;
    let trimmed = path.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn release_target() -> Result<&'static str, String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") | ("macos", "arm64") => Ok("darwin-aarch64"),
        ("macos", "x86_64") => Ok("darwin-x86_64"),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("linux", "aarch64") => Ok("linux-aarch64"),
        (os, arch) => Err(format!("Unsupported update target: {os}/{arch}")),
    }
}

fn extract_version(output: &str) -> Option<String> {
    let regex = Regex::new(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.\-]+)?").ok()?;
    regex.find(output).map(|match_| match_.as_str().to_string())
}

fn normalize_version(version: &str) -> String {
    version.trim().trim_start_matches('v').to_string()
}

fn compare_versions(current: &str, latest: &str) -> i32 {
    let current_parts = version_parts(current);
    let latest_parts = version_parts(latest);
    for (current_part, latest_part) in current_parts.iter().zip(latest_parts.iter()) {
        match current_part.cmp(latest_part) {
            std::cmp::Ordering::Less => return -1,
            std::cmp::Ordering::Greater => return 1,
            std::cmp::Ordering::Equal => {}
        }
    }
    0
}

fn version_parts(version: &str) -> [u64; 3] {
    let mut parts = [0u64; 3];
    for (index, piece) in version
        .split('.')
        .take(3)
        .map(|piece| piece.split_once('-').map_or(piece, |(head, _)| head))
        .enumerate()
    {
        parts[index] = piece.parse().unwrap_or(0);
    }
    parts
}

fn user_agent() -> String {
    format!("kyris/{}", env!("CARGO_PKG_VERSION"))
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

fn github_releases_base_url() -> String {
    std::env::var("KYRIS_TEST_GITHUB_RELEASES_BASE_URL")
        .unwrap_or_else(|_| "https://api.github.com".to_string())
        .trim_end_matches('/')
        .to_string()
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        let normalized = value.trim().to_ascii_lowercase();
        matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testExtractVersion() {
        assert_eq!(extract_version("kyris 0.1.2"), Some("0.1.2".to_string()));
    }

    #[test]
    fn testCompareVersions() {
        assert_eq!(compare_versions("0.1.0", "0.2.0"), -1);
        assert_eq!(compare_versions("0.2.0", "0.1.0"), 1);
        assert_eq!(compare_versions("0.2.0", "0.2.0"), 0);
    }
}
