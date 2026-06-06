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

    /// The bundled pricing table — the runtime fallback when the live `LiteLLM`
    /// feed is unreachable. The snapshot is fetched from `LiteLLM` **at build
    /// time** (see `build.rs`) and baked into the binary, then run through the
    /// same [`transform_litellm`] the relay uses at runtime — so the bundled
    /// table is real `LiteLLM` data, not a hand-maintained list, and there is one
    /// transform, not two.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn bundled() -> Self {
        transform_litellm(include_str!(concat!(
            env!("OUT_DIR"),
            "/litellm_bundled.json"
        )))
        .expect("bundled LiteLLM snapshot (fetched at build time) must transform")
    }
}

/// Transform the `LiteLLM` `model_prices_and_context_window.json` schema into a
/// [`PricingTable`]. Pure (no I/O): the relay's runtime fetch and the
/// build-time bundled snapshot both call this, so the `LiteLLM` field mapping
/// (`input_cost_per_token`/`output_cost_per_token`/`litellm_provider`/the
/// `sample_spec` skip key) lives in exactly one place. `LiteLLM` quotes costs
/// per token; we store per million. A provider-prefixed key (`gemini/x`) also
/// gets an unprefixed alias (`x`) so agent-sent bare ids resolve.
///
/// # Errors
/// Returns `Err` if the JSON does not parse or yields no priced models.
pub fn transform_litellm(raw_json: &str) -> Result<PricingTable, String> {
    let raw: HashMap<String, serde_json::Value> =
        serde_json::from_str(raw_json).map_err(|e| format!("pricing JSON parse failed: {e}"))?;

    let mut models = HashMap::new();
    for (key, value) in &raw {
        if key.starts_with("sample_spec") || !value.is_object() {
            continue;
        }
        let input_cost = value
            .get("input_cost_per_token")
            .and_then(serde_json::Value::as_f64);
        let output_cost = value
            .get("output_cost_per_token")
            .and_then(serde_json::Value::as_f64);
        let (Some(input), Some(output)) = (input_cost, output_cost) else {
            continue;
        };
        let provider = value
            .get("litellm_provider")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let cache_create = value
            .get("cache_creation_input_token_cost")
            .and_then(serde_json::Value::as_f64)
            .map(|v| v * 1_000_000.0);
        let cache_read = value
            .get("cache_read_input_token_cost")
            .and_then(serde_json::Value::as_f64)
            .map(|v| v * 1_000_000.0);

        let pricing = ModelPricing {
            provider,
            input_per_million: input * 1_000_000.0,
            output_per_million: output * 1_000_000.0,
            cache_create_per_million: cache_create,
            cache_read_per_million: cache_read,
        };
        models.insert(key.clone(), pricing.clone());

        if let Some(unprefixed) = key.split('/').nth(1)
            && !models.contains_key(unprefixed)
        {
            models.insert(unprefixed.to_string(), pricing);
        }
    }

    if models.is_empty() {
        return Err("no models with pricing found in source".to_string());
    }

    Ok(PricingTable {
        version: chrono::Utc::now().to_rfc3339(),
        models,
    })
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
    fn testBundledIsLiveLitellmSnapshot() {
        // bundled() is the LiteLLM feed fetched at build time (build.rs) →
        // transform_litellm. So it must look like the real feed: hundreds of
        // models, and a priced Anthropic Claude resolvable via lookup() (the
        // canonical path agents actually hit — guards the legacy-key bug where
        // `claude-4-opus` never matched the wire id and every record priced
        // null).
        let bundled = PricingTable::bundled();
        assert!(
            bundled.models.len() > 100,
            "bundled snapshot looks too small ({}) — build-time LiteLLM fetch/transform broken?",
            bundled.models.len()
        );
        let claude = bundled
            .models
            .iter()
            .find(|(key, p)| key.contains("claude") && p.provider == "anthropic")
            .map(|(key, _)| key.clone())
            .expect("bundled snapshot has no anthropic claude model");
        let cost = bundled
            .cost(&claude, 1_000, 500, None, None)
            .expect("priced");
        assert!(cost > 0.0, "{claude} priced 1k/500 -> {cost}");
    }

    // --- LiteLLM interface (transform) tests ----------------------------------
    // These exercise the real `transform_litellm` against LiteLLM-shaped
    // fixtures, offline. They are the contract for the relay's runtime fetch AND
    // the build-time bundled snapshot (both call this one function).

    #[test]
    fn testTransformMapsLitellmFieldsToPerMillion() {
        let table = transform_litellm(
            r#"{
                "claude-4-opus": {
                    "input_cost_per_token": 0.000015,
                    "output_cost_per_token": 0.000075,
                    "litellm_provider": "anthropic",
                    "cache_creation_input_token_cost": 0.00001875,
                    "cache_read_input_token_cost": 0.0000015
                }
            }"#,
        )
        .expect("valid litellm entry");
        let m = &table.models["claude-4-opus"];
        assert!((m.input_per_million - 15.0).abs() < 0.001);
        assert!((m.output_per_million - 75.0).abs() < 0.001);
        assert!((m.cache_create_per_million.unwrap() - 18.75).abs() < 0.001);
        assert!((m.cache_read_per_million.unwrap() - 1.5).abs() < 0.001);
        assert_eq!(m.provider, "anthropic");
    }

    #[test]
    fn testTransformSkipsSampleSpecAndUncostedEntries() {
        // `sample_spec` is LiteLLM's schema doc row; `dall-e-3` has no token
        // costs. Both must be dropped; only the costed chat model survives.
        let table = transform_litellm(
            r#"{
                "sample_spec": {"input_cost_per_token": 0.01, "output_cost_per_token": 0.01},
                "dall-e-3": {"litellm_provider": "openai"},
                "gpt-4o": {
                    "input_cost_per_token": 0.0000025,
                    "output_cost_per_token": 0.00001,
                    "litellm_provider": "openai"
                }
            }"#,
        )
        .expect("one costed model");
        assert!(!table.models.contains_key("sample_spec"));
        assert!(!table.models.contains_key("dall-e-3"));
        assert!(table.models.contains_key("gpt-4o"));
    }

    #[test]
    fn testTransformAliasesProviderPrefixedKey() {
        let table = transform_litellm(
            r#"{
                "gemini/gemini-2.5-pro": {
                    "input_cost_per_token": 0.00000125,
                    "output_cost_per_token": 0.00001,
                    "litellm_provider": "gemini"
                }
            }"#,
        )
        .unwrap();
        assert!(table.models.contains_key("gemini/gemini-2.5-pro"));
        assert!(
            table.models.contains_key("gemini-2.5-pro"),
            "prefixed key should also get an unprefixed alias"
        );
    }

    #[test]
    fn testTransformKeepsEmbeddingWithZeroOutput() {
        // Embedding models cost for input tokens but emit none → output rate 0.
        // The entry has both cost fields, so it is kept (non-negative, not skipped).
        let table = transform_litellm(
            r#"{
                "text-embedding-3-small": {
                    "input_cost_per_token": 0.00000002,
                    "output_cost_per_token": 0.0,
                    "litellm_provider": "openai"
                }
            }"#,
        )
        .unwrap();
        let m = &table.models["text-embedding-3-small"];
        assert!(m.input_per_million > 0.0);
        assert!((m.output_per_million).abs() < f64::EPSILON);
    }

    #[test]
    fn testTransformErrorsOnNoPricedModels() {
        assert!(transform_litellm(r#"{"dall-e-3": {"litellm_provider": "openai"}}"#).is_err());
        assert!(transform_litellm("not json").is_err());
    }
}
