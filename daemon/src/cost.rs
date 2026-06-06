// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;

use arc_swap::ArcSwap;
use kyris_core::pricing::PricingTable;

pub struct CostCalculator {
    pricing: Arc<ArcSwap<PricingTable>>,
}

impl Default for CostCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl CostCalculator {
    pub fn new() -> Self {
        // Seed from the on-disk cache (the freshest table the machine has
        // actually fetched). The bundled table is only a last-resort floor for
        // a never-fetched / offline-installed machine — release-stale, so it
        // must never be the first choice when a fetched table exists.
        let seed = kyris_core::pricing_cache::load().unwrap_or_else(|| {
            tracing::warn!(
                "no cached pricing table: using release-bundled table (stale) until first relay fetch"
            );
            PricingTable::bundled()
        });
        Self::from_table(seed)
    }

    /// Construct with an explicit table — production seeding goes through
    /// [`new`]; tests use this to stay hermetic (no on-disk cache dependency).
    #[must_use]
    pub fn from_table(table: PricingTable) -> Self {
        Self {
            pricing: Arc::new(ArcSwap::from_pointee(table)),
        }
    }

    pub fn calculate(
        &self,
        model: &str,
        tokens_in: i64,
        tokens_out: i64,
        cache_create: Option<i64>,
        cache_read: Option<i64>,
    ) -> Option<f64> {
        self.pricing
            .load()
            .cost(model, tokens_in, tokens_out, cache_create, cache_read)
    }

    pub fn update_pricing(&self, table: PricingTable) {
        // Replace wholesale — the live table is authoritative. The bare-wire-id
        // vs dated/prefixed-id gap that the old bundled-wins merge papered over
        // is now handled at lookup time (`PricingTable::lookup` canonicalizes),
        // so stale bundled prices never override fresh relay data.
        self.pricing.store(Arc::new(table));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kyris_core::pricing::ModelPricing;
    use std::collections::HashMap;

    fn calc_with_cache_model() -> CostCalculator {
        let mut models = HashMap::new();
        models.insert(
            "test-model".to_string(),
            ModelPricing {
                provider: "test".to_string(),
                input_per_million: 10.0,
                output_per_million: 30.0,
                cache_create_per_million: Some(12.5),
                cache_read_per_million: Some(1.0),
            },
        );
        models.insert(
            "no-cache-model".to_string(),
            ModelPricing {
                provider: "test".to_string(),
                input_per_million: 5.0,
                output_per_million: 15.0,
                cache_create_per_million: None,
                cache_read_per_million: None,
            },
        );
        let table = PricingTable {
            version: "test".to_string(),
            models,
        };
        CostCalculator::from_table(table)
    }

    #[test]
    fn testCostCalculatorBundledPricing() {
        let calc = CostCalculator::from_table(PricingTable::bundled());
        let cost = calc.calculate("gpt-4o", 1_000_000, 500_000, None, None);
        assert!(cost.is_some());
        assert!(cost.unwrap() > 0.0);
    }

    #[test]
    fn testCostCalculatorUnknownModel() {
        let calc = CostCalculator::from_table(PricingTable::bundled());
        assert!(
            calc.calculate("nonexistent", 100, 100, None, None)
                .is_none()
        );
    }

    #[test]
    fn testCostCalculatorUpdatePricing() {
        let calc = CostCalculator::from_table(PricingTable::bundled());
        let mut table = PricingTable::bundled();
        table.version = "v99.0.0".to_string();
        calc.update_pricing(table);
        assert_eq!(calc.pricing.load().version, "v99.0.0");
    }

    #[test]
    fn testRefreshResolvesBareWireIdViaCanonicalMatch() {
        // The relay-fetched table (from litellm) catalogs Anthropic models as
        // dated/prefixed variants, missing the bare wire id `claude` sends. With
        // the bundled-wins merge gone, the bare id still prices — `lookup`
        // canonicalizes on a miss — so a refresh can't leave `cost_usd: null`,
        // and stale bundled prices never override the fresh relay table.
        let calc = CostCalculator::from_table(PricingTable::bundled());
        let mut sparse = PricingTable {
            version: "litellm-2026".to_string(),
            models: std::collections::HashMap::new(),
        };
        // A relay table that has only the dated variant.
        sparse.models.insert(
            "claude-opus-4-7-20260416".to_string(),
            kyris_core::pricing::ModelPricing {
                provider: "anthropic".to_string(),
                input_per_million: 15.0,
                output_per_million: 75.0,
                cache_create_per_million: None,
                cache_read_per_million: None,
            },
        );
        calc.update_pricing(sparse);
        let active = calc.pricing.load();
        // Wholesale replace: only the relay's keys are present (no bundled bleed).
        assert!(active.models.contains_key("claude-opus-4-7-20260416"));
        assert!(!active.models.contains_key("claude-opus-4-7"));
        // ...yet the bare wire id still prices, via canonical lookup.
        assert!(
            calc.calculate("claude-opus-4-7", 1_000, 500, None, None)
                .unwrap()
                > 0.0,
            "bare wire id must price against the dated relay entry"
        );
    }

    #[test]
    fn testCostWithCacheCreateOnly() {
        let calc = calc_with_cache_model();
        let cost = calc
            .calculate("test-model", 1_000_000, 0, Some(500_000), None)
            .unwrap();
        let expected = 10.0 + 0.0 + (500_000.0 / 1_000_000.0) * 12.5;
        assert!((cost - expected).abs() < 0.001);
    }

    #[test]
    fn testCostWithCacheReadOnly() {
        let calc = calc_with_cache_model();
        let cost = calc
            .calculate("test-model", 1_000_000, 0, None, Some(200_000))
            .unwrap();
        let expected = 10.0 + 0.0 + (200_000.0 / 1_000_000.0) * 1.0;
        assert!((cost - expected).abs() < 0.001);
    }

    #[test]
    fn testCostWithBothCacheParams() {
        let calc = calc_with_cache_model();
        let cost = calc
            .calculate(
                "test-model",
                1_000_000,
                500_000,
                Some(300_000),
                Some(100_000),
            )
            .unwrap();
        let expected =
            10.0 + 15.0 + (300_000.0 / 1_000_000.0) * 12.5 + (100_000.0 / 1_000_000.0) * 1.0;
        assert!((cost - expected).abs() < 0.001);
    }

    #[test]
    fn testCostCacheParamsIgnoredWhenModelHasNoRates() {
        let calc = calc_with_cache_model();
        let with_cache = calc
            .calculate("no-cache-model", 1_000_000, 0, Some(500_000), Some(200_000))
            .unwrap();
        let without_cache = calc
            .calculate("no-cache-model", 1_000_000, 0, None, None)
            .unwrap();
        assert!((with_cache - without_cache).abs() < 0.001);
    }
}
