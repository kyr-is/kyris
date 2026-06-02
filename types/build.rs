// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Build-time pricing snapshot.
//!
//! `PricingTable::bundled()` is the runtime fallback served when the live
//! LiteLLM feed is unreachable. We fetch that feed **here, at build time**, and
//! bake it into the binary via `OUT_DIR`, so the bundled table is real LiteLLM
//! data run through the same transform as the runtime path — never a
//! hand-maintained list. The feed URL comes from `../config/pricing-source.yaml`
//! (config, not a hardcoded constant). There is **no fallback**: if the fetch
//! fails, the build fails.
//!
//! NOTE: this is the one I/O exception to this crate's "pure schema, no I/O"
//! charter, and it is strictly build-time. `rerun-if-changed` keeps it from
//! re-fetching on every incremental rebuild — only on a clean build or when the
//! source config / this script changes.
use std::path::Path;

#[derive(serde::Deserialize)]
struct PricingSource {
    litellm_url: String,
}

fn main() {
    let cfg_path = "../config/pricing-source.yaml";
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={cfg_path}");

    let cfg = std::fs::read_to_string(cfg_path)
        .unwrap_or_else(|e| panic!("cannot read pricing source config {cfg_path}: {e}"));
    let source: PricingSource =
        serde_saphyr::from_str(&cfg).unwrap_or_else(|e| panic!("invalid {cfg_path}: {e}"));

    // reqwest is built with `rustls-no-provider`, so install a provider first.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    // Single attempt, fail-fast by design: there is no fallback URL and no
    // bundled fallback list, so any failure to fetch the live feed must fail the
    // build loudly rather than bake a stale or partial table.
    let body = reqwest::blocking::Client::builder()
        .user_agent("kyris-build")
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|e| panic!("cannot build HTTP client: {e}"))
        .get(&source.litellm_url)
        .send()
        .unwrap_or_else(|e| {
            panic!(
                "build-time pricing fetch from {} failed: {e}",
                source.litellm_url
            )
        })
        .error_for_status()
        .unwrap_or_else(|e| panic!("pricing feed returned an error status: {e}"))
        .text()
        .unwrap_or_else(|e| panic!("reading pricing response body failed: {e}"));

    // Cheap sanity check that we got the LiteLLM object map, not an HTML error.
    if !body.trim_start().starts_with('{') {
        panic!(
            "pricing feed did not return a JSON object ({} bytes) — wrong URL?",
            body.len()
        );
    }

    let out = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR set by cargo"))
        .join("litellm_bundled.json");
    std::fs::write(&out, body).unwrap_or_else(|e| panic!("writing bundled snapshot failed: {e}"));
}
