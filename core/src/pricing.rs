// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingTable {
    pub version: String,
    #[serde(default)]
    pub models: HashMap<String, ModelPricing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let pricing = self.models.get(model)?;
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
}
