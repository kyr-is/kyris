// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use notify_debouncer_mini::new_debouncer;

use crate::server::AppState;

fn agent_profile_dir() -> PathBuf {
    kyris_core::paths::agents_dir()
}

fn watch_paths() -> Vec<PathBuf> {
    let dir = agent_profile_dir();
    let mut paths = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return paths;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json")
            && let Ok(contents) = std::fs::read_to_string(&path)
            && let Ok(profile) = serde_json::from_str::<serde_json::Value>(&contents)
            && let Some(files) = profile.get("managed_files").and_then(|v| v.as_array())
        {
            for file in files {
                if let Some(p) = file.get("path").and_then(|v| v.as_str()) {
                    let file_path = PathBuf::from(p);
                    if let Some(parent) = file_path.parent()
                        && parent.exists()
                        && !paths.contains(&parent.to_path_buf())
                    {
                        paths.push(parent.to_path_buf());
                    }
                }
            }
        }
    }
    paths
}

fn run_reconcile() -> bool {
    let output = std::process::Command::new(kyris_binary())
        .args(["agents", "reconcile"])
        .output();
    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let repaired = stdout.contains("Repaired") || stdout.contains("Auto-configured");
            if repaired {
                tracing::info!(output = %stdout.trim(), "agent reconcile detected and repaired drift");
            }
            repaired
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to run kyris agents reconcile");
            false
        }
    }
}

fn kyris_binary() -> PathBuf {
    // ~/.kyris/bin/kyris is the install-managed fallback location used by
    // the install.sh script when the user opted out of the ~/.local/bin
    // shim. Both that and the PATH lookup are install-managed.
    let bin = kyris_core::paths::runtime_dir().join("bin").join("kyris");
    if bin.exists() {
        return bin;
    }
    PathBuf::from("kyris")
}

pub async fn run_reconcile_loop(state: Arc<AppState>) {
    let config = state.config.load();
    let interval_mins = config.agents.reconcile_interval_minutes;
    if interval_mins == 0 {
        tracing::debug!("agent reconcile loop disabled (interval=0)");
        return;
    }

    let interval = Duration::from_secs(interval_mins * 60);

    let (fs_tx, mut fs_rx) = tokio::sync::mpsc::channel::<()>(1);
    let debounce_duration = Duration::from_secs(5);

    let watch_dirs = watch_paths();
    if !watch_dirs.is_empty() {
        let fs_tx_clone = fs_tx.clone();
        match new_debouncer(debounce_duration, move |_res| {
            let _ = fs_tx_clone.try_send(());
        }) {
            Ok(mut debouncer) => {
                let mut watched = 0;
                for dir in &watch_dirs {
                    if debouncer
                        .watcher()
                        .watch(dir, notify::RecursiveMode::NonRecursive)
                        .is_ok()
                    {
                        watched += 1;
                    }
                }
                if watched > 0 {
                    tracing::info!(dirs = watched, "watching agent config directories");
                    std::mem::forget(debouncer);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to create agent config watcher");
            }
        }
    }

    loop {
        tokio::select! {
            _ = fs_rx.recv() => {
                tracing::debug!("agent config change detected, running reconcile");
            }
            () = tokio::time::sleep(interval) => {
                tracing::debug!("periodic agent reconcile tick");
            }
        }

        let repaired = tokio::task::spawn_blocking(run_reconcile)
            .await
            .unwrap_or(false);

        if repaired {
            crate::notify::agent_drift_repaired_toast();
            crate::tray::set_state(crate::tray::TrayState::Degraded);
            tokio::time::sleep(Duration::from_secs(30)).await;
            crate::tray::set_state(crate::tray::TrayState::Normal);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testKyrisBinaryFallsBackToPathLookup() {
        unsafe {
            std::env::set_var("HOME", "/nonexistent");
            std::env::remove_var("KYRIS_HOME");
        }
        let bin = kyris_binary();
        assert_eq!(bin, PathBuf::from("kyris"));
    }

    #[test]
    fn testAgentProfileDirUsesRuntimeDir() {
        unsafe {
            std::env::set_var("HOME", "/tmp/test-home");
            std::env::remove_var("KYRIS_HOME");
        }
        let dir = agent_profile_dir();
        assert_eq!(dir, PathBuf::from("/tmp/test-home/.kyris/agents"));
    }
}
