// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::config_writer::NoopValidator;
use crate::service::{ServiceKind, restart_service, service_state};
use crate::state::write_managed_bytes;

use super::release;

#[derive(Args)]
pub struct UpdateArgs {
    /// Report what's available without applying anything.
    #[arg(long)]
    pub check: bool,
    /// Refresh the update cache silently with no stdout. Used by `kyris status`
    /// to background-refresh the daily check window. Implies --check.
    #[arg(long, hide = true)]
    pub background: bool,
}

pub fn run(args: UpdateArgs) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| {
            eprintln!("Cannot build runtime for update: {error}");
            std::process::exit(1);
        });

    let mode = if args.background {
        UpdateMode::Background
    } else if args.check {
        UpdateMode::Check
    } else {
        UpdateMode::Apply
    };

    if let Err(error) = runtime.block_on(run_update(mode)) {
        if mode == UpdateMode::Background {
            // Suppress errors in background mode — we don't want a network
            // hiccup to surface as a noisy error to the user when they're
            // doing something unrelated. Telemetry would go here in a
            // longer-running deployment.
            std::process::exit(0);
        }
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateMode {
    /// Refresh cache, print results, apply available updates.
    Apply,
    /// Refresh cache, print results, do not apply.
    Check,
    /// Refresh cache only — no stdout. Spawned by `kyris status`.
    Background,
}

struct RepoUpdate {
    owner: &'static str,
    repo: &'static str,
    formula: &'static str,
    primary_binary: &'static str,
    binaries: &'static [&'static str],
    service: Option<ServiceKind>,
}

/// Cached result of the most recent update check. Read by `kyris status` to
/// surface "X.Y → X.Z available" inline; refreshed by `kyris update` (any
/// invocation) and by the `--background` self-spawn from `kyris status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    /// RFC3339 timestamp of when the check ran.
    pub checked_at: String,
    pub repos: Vec<RepoUpdateStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoUpdateStatus {
    pub repo: String,
    /// None if the binary isn't installed (or its --version failed).
    pub current: Option<String>,
    /// None if the GitHub API call failed.
    pub latest: Option<String>,
    /// "script" | "brew" | "missing"
    pub channel: String,
}

impl UpdateCheckResult {
    pub fn cache_path() -> Result<PathBuf, String> {
        Ok(crate::state::kyris_home()?.join("last-update-check.json"))
    }

    /// Load the cached result. Returns None if the file is missing or unparseable.
    pub fn load() -> Option<Self> {
        let path = Self::cache_path().ok()?;
        let bytes = std::fs::read(&path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Persist the result. Best-effort — failure to write the cache should
    /// never block the update flow itself.
    pub fn save(&self) -> Result<(), String> {
        let path = Self::cache_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())
    }

    /// True when the cache is older than `max_age_hours`. Treats unparseable
    /// timestamps as stale (defensive — better to refresh than trust garbage).
    #[must_use]
    pub fn is_stale(&self, max_age_hours: i64) -> bool {
        let Ok(checked) = chrono::DateTime::parse_from_rfc3339(&self.checked_at) else {
            return true;
        };
        let now = chrono::Utc::now();
        let age = now.signed_duration_since(checked.with_timezone(&chrono::Utc));
        age.num_hours() >= max_age_hours
    }
}

impl RepoUpdateStatus {
    /// True when this repo has a script-installed binary at an older version
    /// than the latest release. Brew-managed installs are surfaced separately
    /// (the user runs `brew upgrade`, not `kyris update`).
    #[must_use]
    pub fn has_script_update(&self) -> bool {
        if self.channel != "script" {
            return false;
        }
        match (self.current.as_deref(), self.latest.as_deref()) {
            (Some(c), Some(l)) => compare_versions(c, l) < 0,
            _ => false,
        }
    }
}

async fn run_update(mode: UpdateMode) -> Result<(), String> {
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

    // Phase 1 — gather status for every repo. Always done regardless of mode
    // so the cache stays current even on `--check`-only and `--background`
    // invocations.
    let mut statuses: Vec<RepoUpdateStatus> = Vec::with_capacity(repos.len());
    for repo in &repos {
        statuses.push(probe_repo(repo).await);
    }

    // Phase 2 — persist cache. Best-effort: cache failures don't break the
    // update flow itself (next invocation will retry).
    let cache = UpdateCheckResult {
        checked_at: chrono::Utc::now().to_rfc3339(),
        repos: statuses.clone(),
    };
    let _ = cache.save();

    if mode == UpdateMode::Background {
        return Ok(());
    }

    // Phase 3 — display + optionally apply (extracted into helpers to keep
    // run_update under the clippy too_many_lines threshold).
    let mut updates_available = 0;
    let mut updates_applied = 0;
    for (repo, status) in repos.iter().zip(statuses.iter()) {
        match apply_or_report(repo, status, mode, target).await? {
            ApplyOutcome::UpdateAvailable { applied } => {
                updates_available += 1;
                if applied {
                    updates_applied += 1;
                }
            }
            ApplyOutcome::Noop => {}
        }
    }

    if mode == UpdateMode::Check && updates_available == 0 {
        println!("No updates available.");
    }
    if mode == UpdateMode::Apply && updates_applied == 0 {
        println!("No installed binaries required replacement.");
    }
    Ok(())
}

enum ApplyOutcome {
    UpdateAvailable { applied: bool },
    Noop,
}

async fn apply_or_report(
    repo: &RepoUpdate,
    status: &RepoUpdateStatus,
    mode: UpdateMode,
    target: &str,
) -> Result<ApplyOutcome, String> {
    match status.channel.as_str() {
        "brew" => {
            println!(
                "{}: Homebrew-managed install detected, use `brew upgrade {}`.",
                repo.repo, repo.formula
            );
            return Ok(ApplyOutcome::Noop);
        }
        "missing" => {
            println!("{}: not installed, skipping.", repo.repo);
            return Ok(ApplyOutcome::Noop);
        }
        _ => {}
    }

    let (Some(current_version), Some(latest_version)) =
        (status.current.as_deref(), status.latest.as_deref())
    else {
        println!("{}: could not determine version.", repo.repo);
        return Ok(ApplyOutcome::Noop);
    };

    if compare_versions(current_version, latest_version) >= 0 {
        println!("{}: up to date ({current_version}).", repo.repo);
        return Ok(ApplyOutcome::Noop);
    }

    println!(
        "{}: update available {} -> {}.",
        repo.repo, current_version, latest_version
    );
    if mode == UpdateMode::Check {
        return Ok(ApplyOutcome::UpdateAvailable { applied: false });
    }

    // Apply mode — fetch the release and replace binaries.
    let fetched_release = release::fetch_latest_release(repo.owner, repo.repo).await?;
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
        // Replacing a binary on disk — no schema check.
        if write_managed_bytes(&path, &contents, "update", Some(0o755), &NoopValidator)? {
            println!("  replaced {}", path.display());
            replaced_any = true;
        }
    }

    if replaced_any && let Some(service) = repo.service {
        let state = service_state(service);
        if state.managed_by_homebrew || state.launchd_loaded {
            restart_service(service)?;
        }
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
    Ok(ApplyOutcome::UpdateAvailable {
        applied: replaced_any,
    })
}

/// Inspect a single repo and produce its status entry. Doesn't print or
/// download anything — pure probe so the cache can be populated from any mode.
async fn probe_repo(repo: &RepoUpdate) -> RepoUpdateStatus {
    if release::brew_formula_installed(repo.formula) {
        return RepoUpdateStatus {
            repo: repo.repo.to_string(),
            current: installed_version(repo.primary_binary),
            latest: None,
            channel: "brew".to_string(),
        };
    }

    let Some(current_version) = installed_version(repo.primary_binary) else {
        return RepoUpdateStatus {
            repo: repo.repo.to_string(),
            current: None,
            latest: None,
            channel: "missing".to_string(),
        };
    };

    let latest_version = match release::fetch_latest_release(repo.owner, repo.repo).await {
        Ok(release) => Some(normalize_version(&release.tag_name)),
        Err(_) => None,
    };

    RepoUpdateStatus {
        repo: repo.repo.to_string(),
        current: Some(current_version),
        latest: latest_version,
        channel: "script".to_string(),
    }
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

    #[test]
    fn testRepoUpdateStatusHasScriptUpdate() {
        let stale = RepoUpdateStatus {
            repo: "kyris".into(),
            current: Some("0.1.0".into()),
            latest: Some("0.2.0".into()),
            channel: "script".into(),
        };
        assert!(stale.has_script_update());

        let same = RepoUpdateStatus {
            repo: "kyris".into(),
            current: Some("0.2.0".into()),
            latest: Some("0.2.0".into()),
            channel: "script".into(),
        };
        assert!(!same.has_script_update());

        // Brew-managed installs never report a script update — the brew
        // upgrade flow handles them, not `kyris update`.
        let brew = RepoUpdateStatus {
            repo: "kyris".into(),
            current: Some("0.1.0".into()),
            latest: Some("0.2.0".into()),
            channel: "brew".into(),
        };
        assert!(!brew.has_script_update());

        // Missing latest (network failure) — can't confidently report update.
        let unknown_latest = RepoUpdateStatus {
            repo: "kyris".into(),
            current: Some("0.1.0".into()),
            latest: None,
            channel: "script".into(),
        };
        assert!(!unknown_latest.has_script_update());
    }

    #[test]
    fn testUpdateCheckResultIsStale() {
        let fresh = UpdateCheckResult {
            checked_at: chrono::Utc::now().to_rfc3339(),
            repos: vec![],
        };
        assert!(!fresh.is_stale(24));

        let yesterday = chrono::Utc::now() - chrono::Duration::hours(25);
        let stale = UpdateCheckResult {
            checked_at: yesterday.to_rfc3339(),
            repos: vec![],
        };
        assert!(stale.is_stale(24));

        // Unparseable timestamp — defensive: treat as stale rather than fresh.
        let garbage = UpdateCheckResult {
            checked_at: "not-a-date".to_string(),
            repos: vec![],
        };
        assert!(garbage.is_stale(24));
    }

    #[test]
    fn testUpdateCheckResultRoundTripsViaSerde() {
        let original = UpdateCheckResult {
            checked_at: "2026-05-10T10:30:00Z".to_string(),
            repos: vec![
                RepoUpdateStatus {
                    repo: "kyris".into(),
                    current: Some("0.1.6".into()),
                    latest: Some("0.1.7".into()),
                    channel: "script".into(),
                },
                RepoUpdateStatus {
                    repo: "agentpact".into(),
                    current: None,
                    latest: None,
                    channel: "missing".into(),
                },
            ],
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: UpdateCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.checked_at, original.checked_at);
        assert_eq!(parsed.repos.len(), 2);
        assert!(parsed.repos[0].has_script_update());
        assert_eq!(parsed.repos[1].channel, "missing");
    }
}
