// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PricingTable {
    pub version: String,
    #[serde(default)]
    pub models: HashMap<String, ModelPricing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ModelPricing {
    pub provider: String,
    pub input_per_million: f64,
    pub output_per_million: f64,
    #[serde(default)]
    pub cache_create_per_million: Option<f64>,
    #[serde(default)]
    pub cache_read_per_million: Option<f64>,
}

impl PricingTable {
    /// Find the pricing for `model`, tolerating the id-shape gap between what
    /// agents send (bare wire ids, e.g. `claude-opus-4-7`) and how a
    /// litellm-derived table catalogs the same model (provider-prefixed and/or
    /// date-suffixed, e.g. `anthropic/claude-opus-4-7-20260416`). Exact match
    /// first; on a miss, compare canonical forms. Returns `None` only when no
    /// entry matches even canonically — a genuine "no price" the caller surfaces.
    #[must_use]
    pub fn lookup(&self, model: &str) -> Option<&ModelPricing> {
        if let Some(pricing) = self.models.get(model) {
            return Some(pricing);
        }
        let target = canonical_model_id(model);
        self.models
            .iter()
            .find(|(key, _)| canonical_model_id(key) == target)
            .map(|(_, pricing)| pricing)
    }

    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn cost(
        &self,
        model: &str,
        tokens_in: i64,
        tokens_out: i64,
        cache_create: Option<i64>,
        cache_read: Option<i64>,
    ) -> Option<f64> {
        let pricing = self.lookup(model)?;
        let mut total = (tokens_in as f64 / 1_000_000.0) * pricing.input_per_million
            + (tokens_out as f64 / 1_000_000.0) * pricing.output_per_million;

        if let (Some(create), Some(rate)) = (cache_create, pricing.cache_create_per_million) {
            total += (create as f64 / 1_000_000.0) * rate;
        }
        if let (Some(read), Some(rate)) = (cache_read, pricing.cache_read_per_million) {
            total += (read as f64 / 1_000_000.0) * rate;
        }

        Some(total)
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn bundled() -> Self {
        serde_saphyr::from_str(include_str!("../../config/pricing.yaml"))
            .expect("bundled pricing.yaml must be valid")
    }
}

/// Reduce a model id to a canonical form for cross-shape matching: drop any
/// `provider/` prefix and any trailing `-YYYYMMDD` date snapshot. Deliberately
/// conservative — it does NOT touch version dots (so `gemini-2.5-pro` survives)
/// and only strips an 8-digit trailing segment, so it can't collapse two
/// genuinely different models together.
#[must_use]
pub fn canonical_model_id(id: &str) -> &str {
    let no_prefix = id.rsplit('/').next().unwrap_or(id);
    if let Some((base, tail)) = no_prefix.rsplit_once('-')
        && tail.len() == 8
        && tail.bytes().all(|b| b.is_ascii_digit())
    {
        return base;
    }
    no_prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_table() -> PricingTable {
        let mut models = HashMap::new();
        models.insert(
            "claude-4-opus".to_string(),
            ModelPricing {
                provider: "anthropic".to_string(),
                input_per_million: 15.0,
                output_per_million: 75.0,
                cache_create_per_million: Some(18.75),
                cache_read_per_million: Some(1.50),
            },
        );
        models.insert(
            "gpt-4o".to_string(),
            ModelPricing {
                provider: "openai".to_string(),
                input_per_million: 2.50,
                output_per_million: 10.0,
                cache_create_per_million: None,
                cache_read_per_million: None,
            },
        );
        PricingTable {
            version: "v0.1.0".to_string(),
            models,
        }
    }

    #[test]
    fn testCostCalculation() {
        let table = test_table();
        let cost = table.cost("claude-4-opus", 1_000_000, 500_000, None, None);
        assert!(cost.is_some());
        let c = cost.unwrap();
        let expected = 15.0 + 37.5;
        assert!((c - expected).abs() < 0.001);
    }

    #[test]
    fn testCostWithCache() {
        let table = test_table();
        let cost = table.cost("claude-4-opus", 1_000_000, 0, Some(500_000), Some(200_000));
        let c = cost.unwrap();
        let expected =
            15.0 + 0.0 + (500_000.0 / 1_000_000.0) * 18.75 + (200_000.0 / 1_000_000.0) * 1.50;
        assert!((c - expected).abs() < 0.001);
    }

    #[test]
    fn testCostUnknownModel() {
        let table = test_table();
        assert!(table.cost("nonexistent", 100, 100, None, None).is_none());
    }

    #[test]
    fn testCanonicalModelId() {
        // Provider prefix stripped.
        assert_eq!(
            canonical_model_id("anthropic/claude-opus-4-7"),
            "claude-opus-4-7"
        );
        // Trailing 8-digit date stripped.
        assert_eq!(
            canonical_model_id("claude-opus-4-7-20260416"),
            "claude-opus-4-7"
        );
        // Both at once.
        assert_eq!(
            canonical_model_id("anthropic/claude-opus-4-7-20260416"),
            "claude-opus-4-7"
        );
        // Version dots and non-date trailing segments are preserved.
        assert_eq!(canonical_model_id("gemini-2.5-pro"), "gemini-2.5-pro");
        assert_eq!(canonical_model_id("claude-opus-4-7"), "claude-opus-4-7");
    }

    #[test]
    fn testLookupMatchesDatedAndPrefixedKeys() {
        // The table catalogs the litellm-shaped key; the agent sends the bare id.
        let mut models = HashMap::new();
        models.insert(
            "anthropic/claude-opus-4-7-20260416".to_string(),
            ModelPricing {
                provider: "anthropic".to_string(),
                input_per_million: 15.0,
                output_per_million: 75.0,
                cache_create_per_million: None,
                cache_read_per_million: None,
            },
        );
        let table = PricingTable {
            version: "v".to_string(),
            models,
        };
        // Bare wire id resolves to the dated/prefixed entry via canonical match.
        assert!(table.lookup("claude-opus-4-7").is_some());
        assert!(
            table
                .cost("claude-opus-4-7", 1_000_000, 0, None, None)
                .is_some()
        );
        // A genuinely different model still misses.
        assert!(table.lookup("claude-sonnet-4-6").is_none());
    }

    #[test]
    fn testCostZeroTokens() {
        let table = test_table();
        let cost = table.cost("gpt-4o", 0, 0, None, None).unwrap();
        assert!((cost).abs() < 0.001);
    }

    #[test]
    fn testPricingTableRoundTrip() {
        let table = test_table();
        let json = serde_json::to_string(&table).unwrap();
        let parsed: PricingTable = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "v0.1.0");
        assert_eq!(parsed.models.len(), 2);
    }

    #[test]
    fn testBundledHasCurrentAnthropicModelIds() {
        // CostCalculator looks up models by exact string match against the wire
        // id `claude` sends (e.g. `claude-opus-4-7`). Earlier entries used the
        // legacy `claude-4-{opus,sonnet,haiku}` keys which never matched, so
        // every Claude Code record had `cost_usd: null`. Guard against losing
        // the current ids.
        let bundled = PricingTable::bundled();
        for model in [
            "claude-opus-4-7",
            "claude-sonnet-4-6",
            "claude-haiku-4-5-20251001",
        ] {
            assert!(
                bundled.models.contains_key(model),
                "bundled pricing missing wire model id `{model}`"
            );
        }
        // And the lookup actually returns a non-zero cost for plausible tokens.
        let cost = bundled
            .cost("claude-opus-4-7", 1_000, 500, None, None)
            .expect("priced");
        assert!(cost > 0.0, "claude-opus-4-7 priced 1k/500 -> {cost}");
    }
}
