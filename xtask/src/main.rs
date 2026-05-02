// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::fs;
use std::path::PathBuf;

use schemars::schema_for;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("schemas") => emit_schemas(),
        _ => {
            eprintln!("usage: cargo xtask schemas");
            std::process::exit(1);
        }
    }
}

fn emit_schemas() {
    let out_dir = workspace_target().join("schemas");
    fs::create_dir_all(&out_dir).expect("create target/schemas");

    let contracts: Vec<(&str, schemars::Schema)> = vec![
        (
            "agentpact-event-log",
            schema_for!(kyris_types::event::Event),
        ),
        (
            "kyrisd-gateway-records",
            schema_for!(kyris_types::record::GatewayRecord),
        ),
        (
            "kyrisd-session-tokens",
            schema_for!(kyris_types::record::SessionTokenRow),
        ),
        (
            "relay-enrollment-request",
            schema_for!(kyris_types::sync::EnrollRequest),
        ),
        (
            "relay-enrollment-response",
            schema_for!(kyris_types::sync::EnrollmentResponse),
        ),
    ];

    let version = kyris_types::VERSION;

    for (name, schema) in &contracts {
        let json_value = serde_json::to_value(schema).expect("schema to JSON");

        let yaml = serde_saphyr::to_string(&json_value).expect("JSON to YAML");
        let yaml_content = format!("# Generated from kyris-types v{version} — do not edit\n{yaml}");
        let yaml_path = out_dir.join(format!("{name}.yaml"));
        fs::write(&yaml_path, yaml_content).expect("write yaml schema");

        let json_pretty = serde_json::to_string_pretty(&json_value).expect("pretty JSON");
        let json_path = out_dir.join(format!("{name}.json"));
        fs::write(&json_path, json_pretty).expect("write json schema");

        println!("{}", yaml_path.display());
    }
}

fn workspace_target() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .expect("workspace root")
        .join("target")
}
