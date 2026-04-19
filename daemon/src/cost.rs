// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;

use arc_swap::ArcSwap;
use kyris_core::pricing::PricingTable;

pub struct CostCalculator {
    pricing: Arc<ArcSwap<PricingTable>>,
}

impl CostCalculator {
    pub fn new() -> Self {
        Self {
            pricing: Arc::new(ArcSwap::from_pointee(PricingTable::bundled())),
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
        self.pricing.store(Arc::new(table));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testCostCalculatorBundledPricing() {
        let calc = CostCalculator::new();
        let cost = calc.calculate("gpt-4o", 1_000_000, 500_000, None, None);
        assert!(cost.is_some());
        assert!(cost.unwrap() > 0.0);
    }

    #[test]
    fn testCostCalculatorUnknownModel() {
        let calc = CostCalculator::new();
        assert!(
            calc.calculate("nonexistent", 100, 100, None, None)
                .is_none()
        );
    }

    #[test]
    fn testCostCalculatorUpdatePricing() {
        let calc = CostCalculator::new();
        let mut table = PricingTable::bundled();
        table.version = "v99.0.0".to_string();
        calc.update_pricing(table);
        assert_eq!(calc.pricing.load().version, "v99.0.0");
    }
}
