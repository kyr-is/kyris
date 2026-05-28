// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;
use std::time::Duration;

use kyris_core::pricing::PricingTable;

use crate::server::AppState;

pub async fn run_pricing_fetch(state: Arc<AppState>) {
    let config = state.config.load();
    let relay_url = config.sync.relay_url.clone();
    if relay_url.is_empty() {
        tracing::debug!("no relay_url configured, skipping pricing fetch");
        return;
    }

    let fetch_interval_hours = config.pricing.fetch_interval_hours;
    let client = reqwest::Client::new();
    // The relay serves pricing at `/api/v1/pricing`; an earlier bare `/api/pricing`
    // here 404'd against every real relay (the bundled table was the silent fallback).
    let pricing_url = format!("{}/api/v1/pricing", relay_url.trim_end_matches('/'));

    if let Some(table) = fetch_pricing(&client, &pricing_url).await {
        tracing::info!(version = %table.version, "loaded pricing table from relay");
        state.cost_calculator.update_pricing(table);
    }

    let mut interval = tokio::time::interval(Duration::from_secs(fetch_interval_hours * 3600));
    interval.tick().await;

    loop {
        interval.tick().await;
        if let Some(table) = fetch_pricing(&client, &pricing_url).await {
            tracing::info!(version = %table.version, "updated pricing table from relay");
            state.cost_calculator.update_pricing(table);
        }
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
