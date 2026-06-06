// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! On-disk cache for the relay-fetched pricing table.
//!
//! Pricing is public reference data fetched from the relay (`/api/v1/pricing`,
//! no enrollment needed). `kyris install` fetches it once so install yields a
//! working table, and the daemon refreshes it. The cache is the freshest table
//! the machine has actually seen — unlike the release-baked bundled table,
//! which is stale by the time it ships and is only a last-resort floor. The
//! HTTP fetch lives in each binary (which already carry `reqwest`); this module
//! owns the format/path so reads and writes never drift.

use std::path::{Path, PathBuf};

use kyris_types::pricing::PricingTable;

/// Path of the on-disk pricing cache.
#[must_use]
pub fn path() -> PathBuf {
    crate::paths::pricing_cache_path()
}

/// Load the cached pricing table, or `None` if absent/unreadable/unparseable.
#[must_use]
pub fn load() -> Option<PricingTable> {
    load_from(&path())
}

/// Persist `table` to the cache (creating the parent dir). Best-effort: the
/// caller decides whether a write failure matters.
///
/// # Errors
/// Returns an error if the directory can't be created, serialization fails, or
/// the file can't be written.
pub fn store(table: &PricingTable) -> std::io::Result<()> {
    store_to(&path(), table)
}

fn load_from(path: &Path) -> Option<PricingTable> {
    let contents = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<PricingTable>(&contents).ok()
}

fn store_to(path: &Path, table: &PricingTable) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let contents = serde_json::to_string_pretty(table)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    // Write to a sibling temp file then rename, so a concurrent reader (the
    // daemon reading the cache while install or the daemon's own refresh writes
    // it) never sees a half-written file — it gets either the old or the new
    // table, never a truncated one. The temp name is pid-suffixed so two
    // writers don't clobber each other's temp.
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample() -> PricingTable {
        let mut models = HashMap::new();
        models.insert(
            "claude-opus-4-7".to_string(),
            kyris_types::pricing::ModelPricing {
                provider: "anthropic".to_string(),
                input_per_million: 15.0,
                output_per_million: 75.0,
                cache_create_per_million: None,
                cache_read_per_million: None,
            },
        );
        PricingTable {
            version: "v-test".to_string(),
            models,
        }
    }

    #[test]
    fn testStoreLoadRoundTrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("pricing.json");
        store_to(&path, &sample()).unwrap();
        let loaded = load_from(&path).expect("cache round-trips");
        assert_eq!(loaded.version, "v-test");
        assert!(loaded.models.contains_key("claude-opus-4-7"));
    }

    #[test]
    fn testLoadAbsentIsNone() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_from(&dir.path().join("absent.json")).is_none());
    }
}
