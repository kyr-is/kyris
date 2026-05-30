// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;
use std::time::Duration;

use kyris_core::pricing::PricingTable;

use crate::server::AppState;

pub async fn run_pricing_fetch(state: Arc<AppState>) {
    let config = state.config.load();
    // Pricing is public reference data — gated on a configured relay, NOT on
    // enrollment. A dev who never enrolls still gets live pricing from the
    // relay's public `/api/v1/pricing`.
    let relay_base = config.relay.url.trim_end_matches('/').to_string();
    if relay_base.is_empty() {
        tracing::warn!(
            "no `relay.url` configured: live pricing disabled, using last cached/bundled table"
        );
        return;
    }

    let fetch_interval_hours = config.pricing.fetch_interval_hours;
    let client = reqwest::Client::new();
    let pricing_url = format!("{relay_base}/api/v1/pricing");

    if let Some(table) = fetch_pricing(&client, &pricing_url).await {
        tracing::info!(version = %table.version, "loaded pricing table from relay");
        cache_table(&table);
        state.cost_calculator.update_pricing(table);
    }

    let mut interval = tokio::time::interval(Duration::from_secs(fetch_interval_hours * 3600));
    interval.tick().await;

    loop {
        interval.tick().await;
        if let Some(table) = fetch_pricing(&client, &pricing_url).await {
            tracing::info!(version = %table.version, "updated pricing table from relay");
            cache_table(&table);
            state.cost_calculator.update_pricing(table);
        }
    }
}

/// Persist the freshest table so a restart (or an offline daemon) starts from
/// the last table actually seen rather than the release-stale bundled one.
fn cache_table(table: &PricingTable) {
    if let Err(e) = kyris_core::pricing_cache::store(table) {
        tracing::warn!(error = %e, "failed to write pricing cache");
    }
}

async fn fetch_pricing(client: &reqwest::Client, url: &str) -> Option<PricingTable> {
    match client
        .get(url)
        .timeout(Duration::from_secs(30))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(body) => match serde_saphyr::from_str::<PricingTable>(&body) {
                Ok(table) => Some(table),
                Err(e) => {
                    tracing::warn!(error = %e, "failed to parse pricing response");
                    None
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "failed to read pricing response body");
                None
            }
        },
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), "pricing fetch returned non-success");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "pricing fetch failed");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testParseBundledPricing() {
        let table = PricingTable::bundled();
        assert!(!table.version.is_empty());
        assert!(!table.models.is_empty());
    }
}
