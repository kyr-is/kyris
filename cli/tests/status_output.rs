// SPDX-License-Identifier: Apache-2.0
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn write_kyrisd_config(home: &Path, listen: &str) {
    let kyris_dir = home.join(".kyris");
    fs::create_dir_all(&kyris_dir).expect("create .kyris");
    fs::write(
        kyris_dir.join("kyrisd.yaml"),
        format!(
            "server:\n  listen: \"{listen}\"\n  inbound_key: sk-kyris-test\n  operator_key: sk-kyris-ops-test\n"
        ),
    )
    .expect("write kyrisd config");
}

fn write_fake_binary(dir: &Path, name: &str, version: &str) {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\necho \"{name} {version}\"\n")).expect("write fake binary");
    let permissions = fs::Permissions::from_mode(0o755);
    fs::set_permissions(&path, permissions).expect("chmod fake binary");
}

fn run_status(home: &Path, fake_bin_dir: Option<&Path>) -> std::process::Output {
    let path = match fake_bin_dir {
        Some(fake_bin_dir) => format!(
            "{}:{}",
            fake_bin_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        ),
        None => std::env::var("PATH").unwrap_or_default(),
    };

    Command::new(env!("CARGO_BIN_EXE_kyris"))
        .current_dir(home)
        .env("HOME", home)
        .env("PATH", path)
        .arg("status")
        .output()
        .expect("run kyris status")
}

#[test]
fn test_status_reports_version_skew() {
    let temp_home = TempDir::new().expect("temp home");
    let fake_bin = TempDir::new().expect("fake bin");
    write_kyrisd_config(temp_home.path(), "127.0.0.1:1");

    write_fake_binary(fake_bin.path(), "kyrisd", "0.2.0");
    write_fake_binary(fake_bin.path(), "kyris-mcp", env!("CARGO_PKG_VERSION"));
    write_fake_binary(fake_bin.path(), "agentpactd", env!("CARGO_PKG_VERSION"));

    let output = run_status(temp_home.path(), Some(fake_bin.path()));
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("version skew"), "{stdout}");
}

#[test]
fn test_status_reports_degraded_cline_policy() {
    let temp_home = TempDir::new().expect("temp home");
    write_kyrisd_config(temp_home.path(), "127.0.0.1:1");

    let env_dir = temp_home.path().join(".kyris").join("env");
    fs::create_dir_all(&env_dir).expect("create env dir");
    fs::write(
        env_dir.join("cline.sh"),
        "export CLINE_COMMAND_PERMISSIONS='{}'\n",
    )
    .expect("write cline env");

    let policy_dir = temp_home.path().join(".agentpact").join("policy");
    fs::create_dir_all(&policy_dir).expect("create policy dir");
    fs::write(
        policy_dir.join("pact.yaml"),
        "apiVersion: agentpact/v1\nkind: Pact\nmetadata:\n  name: test\nspec:\n  commands:\n    \"rm·-rf·*\": ask\n",
    )
    .expect("write pact policy");

    let output = run_status(temp_home.path(), None);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("cline compiled policy degraded"),
        "{stdout}"
    );
    assert!(stdout.contains("ask rules dropped"), "{stdout}");
}
