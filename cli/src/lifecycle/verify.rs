// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Post-install and post-uninstall verification.
//!
//! Defines the expected system state for "installed" and "clean" and checks
//! the real system against it. Used by:
//! - `kyris verify` (standalone diagnostic)
//! - `kyris install` (post-install gate)
//! - `kyris uninstall` (post-uninstall gate)
//! - `install.sh` / Homebrew postflight (via `kyris verify --post-install`)

use clap::Args;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct VerifyArgs {
    /// Check that install completed correctly (exit non-zero on failure)
    #[arg(long)]
    pub post_install: bool,

    /// Check that uninstall left no traces (exit non-zero on residue)
    #[arg(long)]
    pub post_uninstall: bool,

    /// JSON output for programmatic consumption
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone)]
struct Check {
    name: &'static str,
    component: &'static str,
    passed: bool,
    detail: String,
}

pub fn run(args: VerifyArgs) {
    let mode = if args.post_uninstall {
        Mode::PostUninstall
    } else {
        Mode::PostInstall
    };

    let checks = run_checks(mode);
    let all_passed = checks.iter().all(|c| c.passed);

    if args.json {
        print_json(&checks, all_passed);
    } else {
        print_human(&checks, mode);
    }

    if args.post_uninstall && !all_passed {
        std::process::exit(1);
    }
    if args.post_install {
        // Only gate on binaries + core services (kyrisd, agentpactd).
        // Hooks, shell-rc, and is.kyr.env are configured by `kyris install`,
        // not by install.sh — their absence at this point is expected.
        let critical_passed = checks
            .iter()
            .filter(|c| {
                c.component == "binaries"
                    || (c.component == "services"
                        && matches!(c.name, "is.kyr.kyrisd" | "is.kyr.agentpactd"))
            })
            .all(|c| c.passed);
        if !critical_passed {
            std::process::exit(1);
        }
    }
}

/// Called by `kyris install` after completing installation.
pub fn verify_post_install() -> bool {
    let checks = run_checks(Mode::PostInstall);
    let install_passed = checks
        .iter()
        .filter(|c| !is_runtime_check(c.component))
        .all(|c| c.passed);

    println!("\nVerification:");
    for check in &checks {
        let marker = if check.passed { "+" } else { "-" };
        println!("  [{marker}] {}: {}", check.name, check.detail);
    }

    if checks.iter().all(|c| c.passed) {
        println!("  All checks passed.");
    } else if install_passed {
        println!("  Install OK — runtime services not yet responding (start with `kyris up`).");
    } else {
        println!("  FAILED — run `kyris verify` for diagnostics.");
    }
    install_passed
}

fn is_runtime_check(component: &str) -> bool {
    matches!(component, "runtime" | "services")
}

/// Called by `kyris uninstall` after reversing all manifest entries.
pub fn verify_post_uninstall() -> bool {
    let checks = run_checks(Mode::PostUninstall);
    let all_passed = checks.iter().all(|c| c.passed);

    println!("\nClean check:");
    for check in &checks {
        let marker = if check.passed { "+" } else { "!" };
        println!("  [{marker}] {}: {}", check.name, check.detail);
    }

    if all_passed {
        println!("  System is clean.");
    } else {
        println!("  Residue detected — manual cleanup may be needed.");
    }
    all_passed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    PostInstall,
    PostUninstall,
}

fn run_checks(mode: Mode) -> Vec<Check> {
    match mode {
        Mode::PostInstall => installed_checks(),
        Mode::PostUninstall => clean_checks(),
    }
}

// --- Post-install checks: these things MUST be true ---

#[allow(clippy::too_many_lines)]
fn installed_checks() -> Vec<Check> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut checks = Vec::new();

    // Kyris binaries (skip if Homebrew manages kyris)
    let brew_managed = super::release::brew_formula_installed("kyris");
    for bin in ["kyris", "kyrisd", "kyris-mcp", "kyris-hook"] {
        let found = brew_managed || binary_exists(bin);
        checks.push(Check {
            name: bin,
            component: "binaries",
            passed: found,
            detail: if brew_managed {
                "managed by Homebrew".into()
            } else if found {
                format!("found at {}", binary_location(bin))
            } else {
                "not found in PATH or ~/.kyris/bin".into()
            },
        });
    }

    // AgentPact binary
    let apd_found = binary_exists("agentpactd");
    checks.push(Check {
        name: "agentpactd",
        component: "binaries",
        passed: apd_found,
        detail: if apd_found {
            format!("found at {}", binary_location("agentpactd"))
        } else {
            "not found — install AgentPact first".into()
        },
    });

    // launchd services
    let kyrisd_loaded = launchd_loaded("is.kyr.kyrisd");
    checks.push(Check {
        name: "is.kyr.kyrisd",
        component: "services",
        passed: kyrisd_loaded,
        detail: if kyrisd_loaded {
            "loaded".into()
        } else {
            "not loaded in launchd".into()
        },
    });

    let agentpactd_loaded = launchd_loaded("is.kyr.agentpactd");
    checks.push(Check {
        name: "is.kyr.agentpactd",
        component: "services",
        passed: agentpactd_loaded,
        detail: if agentpactd_loaded {
            "loaded".into()
        } else {
            "not loaded in launchd".into()
        },
    });

    // is.kyr.env sets BASH_ENV for non-interactive shells via launchd.
    // install_bash_env_launchd writes and bootstraps it; verify that
    // bootstrap actually succeeded, not just that the plist file exists.
    let env_loaded = launchd_loaded("is.kyr.env");
    checks.push(Check {
        name: "is.kyr.env",
        component: "services",
        passed: env_loaded,
        detail: if env_loaded {
            "loaded".into()
        } else {
            "not loaded in launchd (BASH_ENV will not apply to GUI apps)".into()
        },
    });

    // Shell hooks
    let hooks_dir = PathBuf::from(&home).join(".kyris").join("hooks");
    for hook in [
        "bash_hook.sh",
        "bash_env.sh",
        "zsh_hook.sh",
        "zshenv_hook.sh",
    ] {
        let path = hooks_dir.join(hook);
        let exists = path.exists();
        checks.push(Check {
            name: hook,
            component: "hooks",
            passed: exists,
            detail: if exists {
                format!("{}", path.display())
            } else {
                format!("missing: {}", path.display())
            },
        });
    }

    // Shell RC lines
    let rc_checks = [
        (".zshrc", "source \"$HOME/.kyris/hooks/zsh_hook.sh\""),
        (".zshenv", "source \"$HOME/.kyris/hooks/zshenv_hook.sh\""),
        (".bashrc", "source \"$HOME/.kyris/hooks/bash_hook.sh\""),
        (".bashrc", "BASH_ENV=\"$HOME/.kyris/hooks/bash_env.sh\""),
        (
            ".bash_profile",
            "BASH_ENV=\"$HOME/.kyris/hooks/bash_env.sh\"",
        ),
    ];
    for (rc_file, needle) in rc_checks {
        let path = PathBuf::from(&home).join(rc_file);
        let contains = file_contains(&path, needle);
        checks.push(Check {
            name: rc_file,
            component: "shell-rc",
            passed: contains,
            detail: if contains {
                "contains kyris hook line".to_string()
            } else {
                "missing kyris hook line".to_string()
            },
        });
    }

    // AgentPact socket responsive
    let socket_path = agentpact_socket_path();
    let responsive = UnixStream::connect(&socket_path).is_ok();
    checks.push(Check {
        name: "agentpactd socket",
        component: "runtime",
        passed: responsive,
        detail: if responsive {
            format!("responsive at {socket_path}")
        } else {
            format!("not responding at {socket_path}")
        },
    });

    // kyrisd healthy
    let healthy = kyrisd_healthy();
    checks.push(Check {
        name: "kyrisd healthz",
        component: "runtime",
        passed: healthy,
        detail: if healthy {
            "healthy".into()
        } else {
            "not responding".into()
        },
    });

    checks
}

// --- Post-uninstall checks: NONE of these should exist ---

#[allow(clippy::too_many_lines)]
fn clean_checks() -> Vec<Check> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut checks = Vec::new();

    // No kyris-related launchd services
    for label in [
        "is.kyr.kyrisd",
        "is.kyr.agentpactd",
        "is.kyr.env",
        "is.kyr.cline-policy",
    ] {
        let loaded = launchd_loaded(label);
        checks.push(Check {
            name: label,
            component: "services",
            passed: !loaded,
            detail: if loaded {
                "still loaded — run: launchctl bootout gui/$(id -u)/".to_string() + label
            } else {
                "not loaded".into()
            },
        });
    }

    // No plists
    let plist_dir = PathBuf::from(&home).join("Library").join("LaunchAgents");
    for plist in [
        "is.kyr.kyrisd.plist",
        "is.kyr.agentpactd.plist",
        "is.kyr.env.plist",
    ] {
        let path = plist_dir.join(plist);
        let exists = path.exists();
        checks.push(Check {
            name: plist,
            component: "plists",
            passed: !exists,
            detail: if exists {
                format!("residue: {}", path.display())
            } else {
                "removed".into()
            },
        });
    }

    // No ~/.kyris/ directory (or empty)
    let kyris_home = PathBuf::from(&home).join(".kyris");
    let kyris_residue = kyris_home.exists() && !dir_is_empty(&kyris_home);
    checks.push(Check {
        name: "~/.kyris",
        component: "directories",
        passed: !kyris_residue,
        detail: if kyris_residue {
            format!("residue: {}", list_dir_contents(&kyris_home))
        } else {
            "clean".into()
        },
    });

    // No ~/.agentpact/ socket (data dirs are fine)
    let agentpact_home = PathBuf::from(&home).join(".agentpact");
    let socket_exists = agentpact_home.join("agentpact.sock").exists();
    checks.push(Check {
        name: "agentpact socket",
        component: "runtime",
        passed: !socket_exists,
        detail: if socket_exists {
            "socket still exists — daemon may still be running".into()
        } else {
            "removed".into()
        },
    });

    // No kyris lines in shell RCs
    let rc_needles = [
        (".zshrc", ".kyris/"),
        (".zshenv", ".kyris/"),
        (".bashrc", ".kyris/"),
        (".bash_profile", ".kyris/"),
    ];
    for (rc_file, needle) in rc_needles {
        let path = PathBuf::from(&home).join(rc_file);
        let contains = file_contains(&path, needle);
        checks.push(Check {
            name: rc_file,
            component: "shell-rc",
            passed: !contains,
            detail: if contains {
                "still contains kyris references".to_string()
            } else {
                "clean".into()
            },
        });
    }

    // Agent hook scripts kyris installs into per-agent config dirs.
    for rel in super::uninstall::WELL_KNOWN_HOOK_PATHS {
        let path = PathBuf::from(&home).join(rel);
        let exists = path.exists();
        checks.push(Check {
            name: rel,
            component: "agent-hooks",
            passed: !exists,
            detail: if exists {
                format!("residue: {}", path.display())
            } else {
                "removed".into()
            },
        });
    }

    // Agent JSON / TOML config files — must not contain any kyris markers.
    // These are the files kyris surgically modifies (hooks, MCP servers,
    // base URLs).  If they still contain kyris content, uninstall was
    // incomplete.
    let kyris_markers = [
        "kyris-mcp",
        "kyris-hook",
        "kyris_pretooluse",
        "agentpact_pretooluse",
        "agentpact_beforetool",
        "/.kyris/",
    ];

    // Relative-to-HOME paths for agents with stable dot-directory configs.
    let agent_configs: &[(&str, &str)] = &[
        (".claude/settings.json", "claude-code"),
        (".codex/hooks.json", "codex-cli"),
        (".gemini/settings.json", "gemini-cli"),
        (".cline/data/globalState.json", "cline (global state)"),
        (".config/opencode/opencode.json", "opencode"),
    ];
    for (rel, label) in agent_configs {
        let path = PathBuf::from(&home).join(rel);
        if !path.exists() {
            continue; // absent is clean
        }
        let has_residue = kyris_markers.iter().any(|m| file_contains(&path, m));
        checks.push(Check {
            name: label,
            component: "agent-configs",
            passed: !has_residue,
            detail: if has_residue {
                format!("kyris entries remain in {}", path.display())
            } else {
                "clean".into()
            },
        });
    }

    // Cline MCP settings live in VS Code extension global storage — not
    // under HOME directly, so path-join separately with the full relative path.
    let cline_mcp = PathBuf::from(&home)
        .join("Library")
        .join("Application Support")
        .join("Code")
        .join("User")
        .join("globalStorage")
        .join("saoudrizwan.claude-dev")
        .join("cline_mcp_settings.json");
    if cline_mcp.exists() {
        let has_residue = kyris_markers.iter().any(|m| file_contains(&cline_mcp, m));
        checks.push(Check {
            name: "cline (MCP settings)",
            component: "agent-configs",
            passed: !has_residue,
            detail: if has_residue {
                format!("kyris entries remain in {}", cline_mcp.display())
            } else {
                "clean".into()
            },
        });
    }

    // Package registry — must be gone so agentpact does not see kyris as installed.
    let registry_path = std::env::var("XDG_DATA_HOME")
        .ok()
        .map_or_else(
            || PathBuf::from(&home).join(".local").join("share"),
            PathBuf::from,
        )
        .join("kyr-packages")
        .join("kyris.json");
    let registry_exists = registry_path.exists();
    checks.push(Check {
        name: "package registry",
        component: "registry",
        passed: !registry_exists,
        detail: if registry_exists {
            format!("residue: {}", registry_path.display())
        } else {
            "removed".into()
        },
    });

    checks
}

// --- Helpers ---

fn binary_exists(name: &str) -> bool {
    crate::state::find_in_path(name).is_some()
        || crate::state::bin_dir().is_ok_and(|dir| dir.join(name).exists())
}

fn binary_location(name: &str) -> String {
    if let Some(path) = crate::state::find_in_path(name) {
        return path.display().to_string();
    }
    if let Ok(dir) = crate::state::bin_dir() {
        let local = dir.join(name);
        if local.exists() {
            return local.display().to_string();
        }
    }
    "unknown".into()
}

fn launchd_loaded(label: &str) -> bool {
    let uid = crate::service::uid();
    let target = format!("gui/{uid}/{label}");
    std::process::Command::new("launchctl")
        .args(["print", &target])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn file_contains(path: &Path, needle: &str) -> bool {
    std::fs::read_to_string(path).is_ok_and(|contents| contents.contains(needle))
}

fn agentpact_socket_path() -> String {
    std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    })
}

fn kyrisd_healthy() -> bool {
    let base_url = crate::state::load_config()
        .map_or_else(|_| "http://127.0.0.1:4710".to_string(), |c| c.base_url());
    let url = format!("{base_url}/healthz");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let Ok(rt) = runtime else { return false };
    rt.block_on(async {
        reqwest::get(&url)
            .await
            .is_ok_and(|r| r.status().is_success())
    })
}

fn dir_is_empty(path: &Path) -> bool {
    path.read_dir()
        .map_or(true, |mut entries| entries.next().is_none())
}

fn list_dir_contents(path: &Path) -> String {
    let Ok(entries) = path.read_dir() else {
        return "unreadable".into();
    };
    let names: Vec<String> = entries
        .filter_map(std::result::Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .take(10)
        .collect();
    if names.is_empty() {
        "empty".into()
    } else {
        names.join(", ")
    }
}

fn print_json(checks: &[Check], all_passed: bool) {
    let items: Vec<serde_json::Value> = checks
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "component": c.component,
                "passed": c.passed,
                "detail": c.detail,
            })
        })
        .collect();
    let output = serde_json::json!({
        "passed": all_passed,
        "checks": items,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

fn print_human(checks: &[Check], mode: Mode) {
    let title = match mode {
        Mode::PostInstall => "Install Verification",
        Mode::PostUninstall => "Uninstall Clean Check",
    };
    println!("{title}");
    println!("{}", "=".repeat(title.len()));

    let mut current_component = "";
    for check in checks {
        if check.component != current_component {
            current_component = check.component;
            println!("\n  {current_component}:");
        }
        let marker = if check.passed { "+" } else { "-" };
        println!("    [{marker}] {}: {}", check.name, check.detail);
    }

    let failed: Vec<_> = checks.iter().filter(|c| !c.passed).collect();
    println!();
    if failed.is_empty() {
        println!("All checks passed.");
    } else {
        // For PostInstall mode: distinguish critical failures from pending
        // configuration that `kyris install` will supply.
        let pending: Vec<_> = failed
            .iter()
            .filter(|c| {
                matches!(c.component, "hooks" | "shell-rc" | "runtime")
                    || (c.component == "services" && c.name == "is.kyr.env")
            })
            .collect();
        let critical: Vec<_> = failed
            .iter()
            .filter(|c| {
                !(matches!(c.component, "hooks" | "shell-rc" | "runtime")
                    || (c.component == "services" && c.name == "is.kyr.env"))
            })
            .collect();

        if !critical.is_empty() {
            println!("{} critical check(s) failed:", critical.len());
            for check in &critical {
                println!("  - {}: {}", check.name, check.detail);
            }
        }
        if !pending.is_empty() {
            if mode == Mode::PostInstall {
                println!("{} check(s) pending `kyris install`:", pending.len());
            } else {
                println!("{} check(s) failed:", pending.len());
            }
            for check in &pending {
                println!("  - {}: {}", check.name, check.detail);
            }
        }
        if mode == Mode::PostInstall && critical.is_empty() && !pending.is_empty() {
            println!(
                "\nBinary install complete. Run `kyris install` to configure shell hooks and agent integrations."
            );
        }
    }
}
