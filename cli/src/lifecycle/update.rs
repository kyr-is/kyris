// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use regex::Regex;
use std::path::PathBuf;

use crate::service::{ServiceKind, restart_service, service_state};
use crate::state::write_managed_bytes;

use super::release;

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

struct RepoUpdate {
    owner: &'static str,
    repo: &'static str,
    formula: &'static str,
    primary_binary: &'static str,
    binaries: &'static [&'static str],
    service: Option<ServiceKind>,
}

async fn run_update(check_only: bool) -> Result<(), String> {
    let target = release::release_target()?;
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
        if release::brew_formula_installed(repo.formula) {
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

        let fetched_release = release::fetch_latest_release(repo.owner, repo.repo).await?;
        let latest_version = normalize_version(&fetched_release.tag_name);
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
        let asset = fetched_release
            .assets
            .iter()
            .find(|a| a.name == asset_name)
            .ok_or_else(|| format!("Missing release asset {asset_name} for {}", repo.repo))?;

        let verified_bytes = release::download_and_verify(&fetched_release, asset).await?;
        let temp_dir = release::extract_tarball(&verified_bytes, &asset_name)?;

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
    crate::state::find_in_path(binary)
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
