// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;

#[derive(Args)]
pub struct VersionArgs {}

pub fn run(_args: VersionArgs) {
    println!("kyris {}", env!("CARGO_PKG_VERSION"));
    print_component_version("kyrisd");
    print_component_version("kyris-mcp");
    print_component_version("kyris-hook");
    print_component_version("agentpactd");
}

fn print_component_version(name: &str) {
    let (version_str, found) = query_component_version(name);
    if found {
        println!("{version_str}");
    } else {
        println!("{name}: not found");
    }
}

fn query_component_version(name: &str) -> (String, bool) {
    match std::process::Command::new(name).arg("--version").output() {
        Ok(output) => {
            let version = String::from_utf8_lossy(&output.stdout);
            let trimmed = version.trim().to_string();
            if trimmed.is_empty() {
                (String::new(), false)
            } else {
                (trimmed, true)
            }
        }
        Err(_) => (String::new(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testQueryComponentVersionNotFound() {
        let (_, found) = query_component_version("nonexistent-binary-xyz");
        assert!(!found);
    }

    #[test]
    fn testQueryComponentVersionKnownBinary() {
        let (_version, _found) = query_component_version("echo");
    }
}
