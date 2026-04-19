// SPDX-License-Identifier: Apache-2.0
pub mod anthropic;
pub mod google;
pub mod openai;

use std::sync::Arc;

use axum::Router;
use axum::http::HeaderMap;

use crate::server::AppState;

pub fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-kyris-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(anthropic::routes(state.clone()))
        .merge(openai::routes(state.clone()))
        .merge(google::routes(state.clone()))
        .merge(models_route(state))
}

fn models_route(state: Arc<AppState>) -> Router {
    use axum::routing::get;

    Router::new().route("/v1/models", get(list_models).with_state(state))
}

async fn list_models(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> axum::Json<serde_json::Value> {
    let config = state.config.load();
    let mut models = Vec::new();

    for provider in &config.providers {
        for model in &provider.models {
            models.push(serde_json::json!({
                "id": model,
                "object": "model",
                "owned_by": provider.name,
            }));
        }
    }

    axum::Json(serde_json::json!({
        "object": "list",
        "data": models,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn testExtractSessionIdPresent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-kyris-session-id",
            HeaderValue::from_static("sess-abc-123"),
        );
        assert_eq!(
            extract_session_id(&headers),
            Some("sess-abc-123".to_string())
        );
    }

    #[test]
    fn testExtractSessionIdMissing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_session_id(&headers), None);
    }

    #[test]
    fn testExtractSessionIdEmpty() {
        let mut headers = HeaderMap::new();
        headers.insert("x-kyris-session-id", HeaderValue::from_static(""));
        assert_eq!(extract_session_id(&headers), Some(String::new()));
    }
}
