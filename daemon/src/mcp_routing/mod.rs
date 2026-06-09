// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! HTTP MCP routing. Proxies Streamable HTTP MCP transport (POST, GET,
//! DELETE) on `/mcp/{server}` and `/mcp/{server}/{path}` to configured
//! upstream MCP servers.
//! POST tools/call requests are policy-checked via `AgentPact`; all other
//! requests are forwarded directly. SSE responses are streamed as received.
pub mod policy;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
};
use bytes::Bytes;
use futures_util::StreamExt;
use kyris_core::agentpact::ToolAnnotations;

use crate::server::AppState;

#[derive(Default, Clone)]
pub struct AnnotationCache(Arc<std::sync::RwLock<HashMap<(String, String), ToolAnnotations>>>);

impl AnnotationCache {
    pub fn lookup(&self, server: &str, tool: &str) -> ToolAnnotations {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(server.to_string(), tool.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn update_from_response(&self, server: &str, body: &[u8]) {
        let Ok(tools) = serde_json::from_slice::<serde_json::Value>(body) else {
            return;
        };
        let Some(tool_array) = tools
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
        else {
            return;
        };
        let mut cache = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for tool in tool_array {
            if let Some(name) = tool.get("name").and_then(|n| n.as_str()) {
                let annotations = tool.get("annotations").cloned().unwrap_or_default();
                cache.insert(
                    (server.to_string(), name.to_string()),
                    ToolAnnotations {
                        read_only_hint: annotations
                            .get("readOnlyHint")
                            .and_then(serde_json::Value::as_bool),
                        destructive_hint: annotations
                            .get("destructiveHint")
                            .and_then(serde_json::Value::as_bool),
                    },
                );
            }
        }
    }

    pub fn clear_server(&self, server: &str) {
        self.0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(s, _), _| s != server);
    }
}

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP_HEADERS
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h))
}

fn forward_request_headers(
    mut builder: reqwest::RequestBuilder,
    headers: &HeaderMap,
) -> reqwest::RequestBuilder {
    for (key, value) in headers {
        let name = key.as_str();
        if is_hop_by_hop(name)
            || name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("x-working-dir")
        {
            continue;
        }
        builder = builder.header(key, value);
    }
    builder
}

fn is_sse_response(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream"))
}

fn build_upstream_response(
    status: StatusCode,
    upstream_headers: &reqwest::header::HeaderMap,
    body: Body,
) -> Result<Response, StatusCode> {
    let mut builder = Response::builder().status(status);
    for (key, value) in upstream_headers {
        let name = key.as_str();
        if is_hop_by_hop(name)
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        builder = builder.header(key, value);
    }
    builder.body(body).map_err(|e| {
        tracing::error!(error = %e, "failed to build MCP upstream response");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

fn resolve_server<'a>(
    config: &'a kyris_core::config::KyrisdConfig,
    server_name: &str,
) -> Result<&'a kyris_core::config::McpServerConfig, StatusCode> {
    if !config.mcp.enabled {
        return Err(StatusCode::NOT_FOUND);
    }
    config
        .mcp
        .servers
        .iter()
        .find(|s| s.name == server_name)
        .ok_or(StatusCode::NOT_FOUND)
}

fn get_mcp_client(state: &AppState, server_name: &str) -> reqwest::Client {
    state
        .provider_clients
        .load()
        .get(&format!("mcp_{server_name}"))
        .cloned()
        .unwrap_or_else(|| state.default_provider_client.clone())
}

pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/mcp/{server}",
            post(handle_mcp_root_post)
                .get(handle_mcp_root_get)
                .delete(handle_mcp_root_delete),
        )
        .route(
            "/mcp/{server}/{*path}",
            post(handle_mcp_post)
                .get(handle_mcp_get)
                .delete(handle_mcp_delete),
        )
        .with_state(state)
}

async fn handle_mcp_root_post(
    State(state): State<Arc<AppState>>,
    Path(server_name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    forward_mcp_post(state, server_name, String::new(), headers, body).await
}

async fn handle_mcp_post(
    State(state): State<Arc<AppState>>,
    Path((server_name, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    forward_mcp_post(state, server_name, path, headers, body).await
}

async fn forward_mcp_post(
    state: Arc<AppState>,
    server_name: String,
    path: String,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let config = state.config.load();
    let server = resolve_server(&config, &server_name)?;

    // Per-request working_dir from X-Working-Dir header takes precedence
    // over static config so agents can scope policy to the current project
    // without requiring a fixed server config entry.
    let working_dir_header = headers
        .get("x-working-dir")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.trim().is_empty());
    let working_dir_config = server
        .working_dir
        .as_deref()
        .filter(|dir| !dir.trim().is_empty());
    let working_dir = working_dir_header.or(working_dir_config);

    if policy::is_tools_call_request(&path, &body) && working_dir.is_none() {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "error": "mcp_working_dir_required",
                    "detail": format!(
                        "MCP server '{server_name}' requires either the X-Working-Dir request \
                         header or mcp.servers[].working_dir in kyrisd.yaml for tools/call \
                         policy evaluation."
                    )
                })
                .to_string(),
            ))
            .map_err(|e| {
                tracing::error!(error = %e, server = %server_name, "failed to build MCP working_dir_required response");
                StatusCode::INTERNAL_SERVER_ERROR
            });
    }

    let tool_name = policy::extract_tool_name(&path, &body);
    let mcp_operation = extract_json_rpc_method(&body);
    let annotations = tool_name
        .as_deref()
        .map(|t| state.mcp_annotation_cache.lookup(&server_name, t))
        .unwrap_or_default();
    let socket_timeout = Duration::from_millis(config.mcp.socket_timeout_ms);
    let decision = policy::check_permission(
        &server_name,
        &path,
        &body,
        working_dir,
        mcp_operation.as_deref(),
        &annotations,
        socket_timeout,
    )
    .await;

    match decision {
        policy::PolicyDecision::Deny(reason) => {
            let status = if reason == "agentpact_unavailable" {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::FORBIDDEN
            };
            let body = if reason == "agentpact_unavailable" {
                serde_json::json!({
                    "error": "agentpact_unavailable",
                    "detail": "AgentPact daemon is unreachable. MCP governance cannot be evaluated."
                })
            } else {
                serde_json::json!({"error": reason})
            };
            tracing::warn!(
                server = %server_name,
                path = %path,
                reason = %reason,
                "mcp request denied by policy"
            );
            return Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .map_err(|e| {
                    tracing::error!(error = %e, server = %server_name, "failed to build MCP policy-deny response");
                    StatusCode::INTERNAL_SERVER_ERROR
                });
        }
        policy::PolicyDecision::Ask {
            approval_id,
            approval_token,
            allow_always,
        } => {
            let pending_timeout = config.mcp.pending_timeout_seconds;
            let tool_display = tool_name.as_deref().unwrap_or("unknown tool");

            crate::notify::mcp_pending_toast(tool_display);

            let rx = state.pending.hold(
                approval_id.clone(),
                approval_token,
                server_name.clone(),
                tool_name,
                None,
                "kyris-mcp".to_string(),
                allow_always,
            );

            let pending = state.pending.clone();
            let timeout_id = approval_id.clone();
            let timeout_handle = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(pending_timeout)).await;
                pending.timeout(&timeout_id);
            });

            let resolution = rx.await;
            timeout_handle.abort();

            match resolution {
                Ok(r) if r.approved => {
                    tracing::info!(id = %approval_id, "mcp request approved");
                }
                Ok(_) => {
                    tracing::info!(id = %approval_id, "mcp request denied by user");
                    return Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({"error": "denied by user"}).to_string(),
                        ))
                        .map_err(|e| {
                            tracing::error!(error = %e, server = %server_name, "failed to build MCP denied-by-user response");
                            StatusCode::INTERNAL_SERVER_ERROR
                        });
                }
                Err(_) => {
                    tracing::info!(id = %approval_id, "mcp request timed out or cancelled");
                    return Response::builder()
                        .status(StatusCode::REQUEST_TIMEOUT)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({"error": "request timed out"}).to_string(),
                        ))
                        .map_err(|e| {
                            tracing::error!(error = %e, server = %server_name, "failed to build MCP request-timeout response");
                            StatusCode::INTERNAL_SERVER_ERROR
                        });
                }
            }
        }
        policy::PolicyDecision::Allow => {}
    }

    let client = get_mcp_client(&state, &server_name);
    let upstream_url = upstream_url(&server.upstream, &path);

    let req = forward_request_headers(client.post(&upstream_url).body(body.to_vec()), &headers);
    let response = req.send().await.map_err(|e| {
        tracing::error!(error = %e, server = %server_name, "mcp upstream POST failed");
        StatusCode::BAD_GATEWAY
    })?;

    let status = response.status();
    let resp_headers = response.headers().clone();

    if is_sse_response(&resp_headers) {
        let stream = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(std::io::Error::other));
        return build_upstream_response(status, &resp_headers, Body::from_stream(stream));
    }

    let resp_body = response
        .bytes()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, server = %server_name, "failed to read MCP upstream POST response body");
            StatusCode::BAD_GATEWAY
        })?;

    if is_tools_list_request(&path, &body) {
        state
            .mcp_annotation_cache
            .update_from_response(&server_name, &resp_body);
    }

    build_upstream_response(status, &resp_headers, Body::from(resp_body))
}

async fn handle_mcp_root_get(
    State(state): State<Arc<AppState>>,
    Path(server_name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    forward_mcp_get(state, server_name, String::new(), headers).await
}

async fn handle_mcp_get(
    State(state): State<Arc<AppState>>,
    Path((server_name, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    forward_mcp_get(state, server_name, path, headers).await
}

async fn forward_mcp_get(
    state: Arc<AppState>,
    server_name: String,
    path: String,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let config = state.config.load();
    let server = resolve_server(&config, &server_name)?;

    let client = get_mcp_client(&state, &server_name);
    let upstream_url = upstream_url(&server.upstream, &path);

    let req = forward_request_headers(client.get(&upstream_url), &headers);
    let response = req.send().await.map_err(|e| {
        tracing::error!(error = %e, server = %server_name, "mcp upstream GET failed");
        StatusCode::BAD_GATEWAY
    })?;

    let status = response.status();
    let resp_headers = response.headers().clone();

    if is_sse_response(&resp_headers) {
        let stream = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(std::io::Error::other));
        return build_upstream_response(status, &resp_headers, Body::from_stream(stream));
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, server = %server_name, "failed to read MCP upstream GET response body");
            StatusCode::BAD_GATEWAY
        })?;
    build_upstream_response(status, &resp_headers, Body::from(body))
}

async fn handle_mcp_root_delete(
    State(state): State<Arc<AppState>>,
    Path(server_name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    forward_mcp_delete(state, server_name, String::new(), headers).await
}

async fn handle_mcp_delete(
    State(state): State<Arc<AppState>>,
    Path((server_name, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    forward_mcp_delete(state, server_name, path, headers).await
}

async fn forward_mcp_delete(
    state: Arc<AppState>,
    server_name: String,
    path: String,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let config = state.config.load();
    let server = resolve_server(&config, &server_name)?;

    let client = get_mcp_client(&state, &server_name);
    let upstream_url = upstream_url(&server.upstream, &path);

    let req = forward_request_headers(client.delete(&upstream_url), &headers);
    let response = req.send().await.map_err(|e| {
        tracing::error!(error = %e, server = %server_name, "mcp upstream DELETE failed");
        StatusCode::BAD_GATEWAY
    })?;

    let status = response.status();
    let resp_headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, server = %server_name, "failed to read MCP upstream DELETE response body");
            StatusCode::BAD_GATEWAY
        })?;
    build_upstream_response(status, &resp_headers, Body::from(body))
}

fn upstream_url(upstream: &str, path: &str) -> String {
    let base = upstream.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{path}")
    }
}

fn extract_json_rpc_method(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("method")?.as_str().map(String::from))
}

fn is_tools_list_request(path: &str, body: &[u8]) -> bool {
    path.contains("tools/list")
        || serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("method")?.as_str().map(String::from))
            .is_some_and(|m| m == "tools/list")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

    use arc_swap::ArcSwap;
    use axum::{Router, extract::State, http::HeaderMap, response::IntoResponse, routing::post};
    use bytes::Bytes;
    use kyris_core::config::{KyrisdConfig, McpServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tokio::sync::{mpsc, oneshot};

    use crate::{
        circuit_breaker::CircuitBreaker, cost::CostCalculator, metering::StatsEvent,
        pending::PendingStore, server::AppState, storage::DuckDbWriter,
    };

    static MCP_ROUTE_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteAllowsAndForwardsToolsCall() {
        let _guard = lock_mcp_route_tests();
        let upstream_recorded = Arc::new(Mutex::new(None));
        let upstream = Router::new()
            .route("/tools/call", post(record_upstream_request))
            .with_state(upstream_recorded.clone());
        let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

        let sock_dir = tempfile::tempdir().unwrap();
        let sock_path = sock_dir.path().join("agentpact.sock");
        let daemon_recorded = Arc::new(Mutex::new(None));
        let daemon_handle = spawn_agentpact_stub(
            &sock_path,
            serde_json::json!({"code": "PACT_OK"}),
            daemon_recorded.clone(),
        );
        policy::set_test_agentpact_socket(Some(sock_path.clone()));

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = true;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: upstream_url.clone(),
            working_dir: Some("/tmp/project".to_string()),
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "README.md"}}
        });

        let response = reqwest::Client::new()
            .post(format!("{router_url}/mcp/remote/tools/call"))
            .header("content-type", "application/json")
            .body(request_body.to_string())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let response_json: serde_json::Value = response.json().await.unwrap();
        assert_eq!(response_json["result"]["ok"], true);

        let policy_request = daemon_recorded.lock().unwrap().clone().unwrap();
        assert_eq!(policy_request["method"], "permission.request");
        assert_eq!(policy_request["action"], "call");
        assert_eq!(policy_request["detail"], "read_file");
        assert_eq!(policy_request["context"]["mcp_server"], "remote");
        assert_eq!(policy_request["context"]["working_dir"], "/tmp/project");
        assert_eq!(policy_request["context"]["mcp_operation"], "tools/call");

        let upstream_request = upstream_recorded.lock().unwrap().clone().unwrap();
        let forwarded: serde_json::Value = serde_json::from_slice(&upstream_request.body).unwrap();
        assert_eq!(forwarded["method"], "tools/call");
        assert_eq!(forwarded["params"]["name"], "read_file");

        policy::set_test_agentpact_socket(None);
        let _ = router_shutdown.send(());
        let _ = upstream_shutdown.send(());
        router_handle.await.unwrap();
        upstream_handle.await.unwrap();
        daemon_handle.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRootRouteAllowsAndForwardsToolsCall() {
        let _guard = lock_mcp_route_tests();
        let upstream_recorded = Arc::new(Mutex::new(None));
        let upstream = Router::new()
            .route("/", post(record_upstream_request))
            .with_state(upstream_recorded.clone());
        let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

        let sock_dir = tempfile::tempdir().unwrap();
        let sock_path = sock_dir.path().join("agentpact.sock");
        let daemon_recorded = Arc::new(Mutex::new(None));
        let daemon_handle = spawn_agentpact_stub(
            &sock_path,
            serde_json::json!({"code": "PACT_OK"}),
            daemon_recorded.clone(),
        );
        policy::set_test_agentpact_socket(Some(sock_path.clone()));

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = true;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: upstream_url.clone(),
            working_dir: Some("/tmp/project".to_string()),
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "README.md"}}
        });

        let response = reqwest::Client::new()
            .post(format!("{router_url}/mcp/remote"))
            .header("content-type", "application/json")
            .body(request_body.to_string())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let response_json: serde_json::Value = response.json().await.unwrap();
        assert_eq!(response_json["result"]["ok"], true);

        let policy_request = daemon_recorded.lock().unwrap().clone().unwrap();
        assert_eq!(policy_request["method"], "permission.request");
        assert_eq!(policy_request["detail"], "read_file");
        assert_eq!(policy_request["context"]["mcp_server"], "remote");
        assert_eq!(policy_request["context"]["working_dir"], "/tmp/project");
        assert_eq!(policy_request["context"]["mcp_operation"], "tools/call");

        let upstream_request = upstream_recorded.lock().unwrap().clone().unwrap();
        let forwarded: serde_json::Value = serde_json::from_slice(&upstream_request.body).unwrap();
        assert_eq!(forwarded["method"], "tools/call");
        assert_eq!(forwarded["params"]["name"], "read_file");

        policy::set_test_agentpact_socket(None);
        let _ = router_shutdown.send(());
        let _ = upstream_shutdown.send(());
        router_handle.await.unwrap();
        upstream_handle.await.unwrap();
        daemon_handle.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteReturnsForbiddenWhenPolicyDenies() {
        let _guard = lock_mcp_route_tests();
        let sock_dir = tempfile::tempdir().unwrap();
        let sock_path = sock_dir.path().join("agentpact.sock");
        let daemon_recorded = Arc::new(Mutex::new(None));
        let daemon_handle = spawn_agentpact_stub(
            &sock_path,
            serde_json::json!({"code": "PACT_DENIED", "reason": "blocked by policy"}),
            daemon_recorded.clone(),
        );
        policy::set_test_agentpact_socket(Some(sock_path.clone()));

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = true;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: "http://127.0.0.1:1".to_string(),
            working_dir: Some("/tmp/project".to_string()),
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "README.md"}}
        });

        let response = reqwest::Client::new()
            .post(format!("{router_url}/mcp/remote/tools/call"))
            .header("content-type", "application/json")
            .body(request_body.to_string())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response_json: serde_json::Value = response.json().await.unwrap();
        assert_eq!(response_json["error"], "blocked by policy");

        let policy_request = daemon_recorded.lock().unwrap().clone().unwrap();
        assert_eq!(policy_request["detail"], "read_file");
        assert_eq!(policy_request["context"]["mcp_server"], "remote");

        policy::set_test_agentpact_socket(None);
        let _ = router_shutdown.send(());
        router_handle.await.unwrap();
        daemon_handle.await.unwrap();
    }

    #[derive(Clone, Debug)]
    struct RecordedRequest {
        body: Vec<u8>,
    }

    async fn record_upstream_request(
        State(recorded): State<Arc<Mutex<Option<RecordedRequest>>>>,
        _headers: HeaderMap,
        body: Bytes,
    ) -> impl IntoResponse {
        *recorded.lock().unwrap() = Some(RecordedRequest {
            body: body.to_vec(),
        });

        (
            StatusCode::OK,
            [("content-type", "application/json")],
            serde_json::json!({"jsonrpc": "2.0", "result": {"ok": true}}).to_string(),
        )
    }

    fn make_test_state(config: KyrisdConfig, temp_root: &std::path::Path) -> Arc<AppState> {
        let (stats_tx, _stats_rx) = mpsc::channel::<StatsEvent>(8);
        Arc::new(AppState {
            config: Arc::new(ArcSwap::from_pointee(config)),
            circuit_breaker: Arc::new(CircuitBreaker::new()),
            cost_calculator: CostCalculator::new(),
            stats_tx,
            db: Arc::new(DuckDbWriter::open(&temp_root.join("kyrisd.duckdb"))),
            provider_clients: ArcSwap::from_pointee(HashMap::new()),
            default_provider_client: crate::server::build_default_provider_client(),
            pending: Arc::new(PendingStore::new()),
            agentpact_socket: None,
            mcp_annotation_cache: AnnotationCache::default(),
        })
    }

    async fn spawn_test_server(
        app: Router,
    ) -> (String, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });
        (address, shutdown_tx, handle)
    }

    fn spawn_agentpact_stub(
        sock_path: &std::path::Path,
        response: serde_json::Value,
        recorded: Arc<Mutex<Option<serde_json::Value>>>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(sock_path).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let read = stream.read(&mut buf).await.unwrap();
            buf.truncate(read);
            *recorded.lock().unwrap() = Some(serde_json::from_slice(&buf).unwrap());
            stream
                .write_all(response.to_string().as_bytes())
                .await
                .unwrap();
        })
    }

    fn lock_mcp_route_tests() -> MutexGuard<'static, ()> {
        MCP_ROUTE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteReturnsNotFoundWhenDisabled() {
        let _guard = lock_mcp_route_tests();
        policy::set_test_agentpact_socket(None);

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = false;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: "http://127.0.0.1:1".to_string(),
            working_dir: None,
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let response = reqwest::Client::new()
            .post(format!("{router_url}/mcp/remote/tools/call"))
            .header("content-type", "application/json")
            .body(r#"{"method":"tools/call","params":{"name":"read_file"}}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let _ = response.bytes().await.unwrap();

        let _ = router_shutdown.send(());
        router_handle.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteReturnsNotFoundForUnknownServer() {
        let _guard = lock_mcp_route_tests();
        let sock_dir = tempfile::tempdir().unwrap();
        let sock_path = sock_dir.path().join("agentpact.sock");
        policy::set_test_agentpact_socket(Some(sock_path.clone()));

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = true;
        config.mcp.servers = vec![McpServerConfig {
            name: "known".to_string(),
            upstream: "http://127.0.0.1:1".to_string(),
            working_dir: None,
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let response = reqwest::Client::new()
            .post(format!("{router_url}/mcp/unknown-server/tools/call"))
            .header("content-type", "application/json")
            .body(r#"{"method":"tools/call","params":{"name":"read_file"}}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let _ = response.bytes().await.unwrap();

        policy::set_test_agentpact_socket(None);
        let _ = router_shutdown.send(());
        router_handle.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteAskTimesOutAndReturns408() {
        let _guard = lock_mcp_route_tests();
        let sock_dir = tempfile::tempdir().unwrap();
        let sock_path = sock_dir.path().join("agentpact.sock");
        let daemon_recorded = Arc::new(Mutex::new(None));
        let daemon_handle = spawn_agentpact_stub(
            &sock_path,
            serde_json::json!({"code": "PACT_ASK", "approval_id": "req-timeout", "approval_token": "apt-timeout"}),
            daemon_recorded,
        );
        policy::set_test_agentpact_socket(Some(sock_path.clone()));

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = true;
        config.mcp.pending_timeout_seconds = 1;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: "http://127.0.0.1:1".to_string(),
            working_dir: Some("/tmp/project".to_string()),
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let response = reqwest::Client::new()
            .post(format!("{router_url}/mcp/remote/tools/call"))
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dangerous_tool"}}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["error"], "request timed out");

        policy::set_test_agentpact_socket(None);
        let _ = router_shutdown.send(());
        router_handle.await.unwrap();
        daemon_handle.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteReturnsBadRequestWithoutWorkingDir() {
        let _guard = lock_mcp_route_tests();
        policy::set_test_agentpact_socket(None);

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = true;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: "http://127.0.0.1:1".to_string(),
            working_dir: None,
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let response = reqwest::Client::new()
            .post(format!("{router_url}/mcp/remote/tools/call"))
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json().await.unwrap();
        let detail = body["detail"].as_str().unwrap();
        assert!(
            detail.contains("X-Working-Dir") && detail.contains("mcp.servers"),
            "expected error to mention both header and config, got: {detail}"
        );

        let _ = router_shutdown.send(());
        router_handle.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteAcceptsWorkingDirFromHeader() {
        let _guard = lock_mcp_route_tests();
        let sock_dir = tempfile::tempdir().unwrap();
        let sock_path = sock_dir.path().join("agentpact.sock");
        let daemon_recorded = Arc::new(Mutex::new(None));
        let daemon_handle = spawn_agentpact_stub(
            &sock_path,
            serde_json::json!({"code": "PACT_OK"}),
            daemon_recorded.clone(),
        );
        policy::set_test_agentpact_socket(Some(sock_path.clone()));

        // Server has no static working_dir — relies on X-Working-Dir header.
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = true;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: "http://127.0.0.1:1".to_string(),
            working_dir: None,
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        // With X-Working-Dir header, should NOT get 400.
        let response = reqwest::Client::new()
            .post(format!("{router_url}/mcp/remote/tools/call"))
            .header("content-type", "application/json")
            .header("x-working-dir", "/home/user/project")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}"#)
            .send()
            .await
            .unwrap();

        assert_ne!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "X-Working-Dir header should satisfy working_dir requirement"
        );

        // Verify the agentpactd received a permission request (policy was evaluated).
        let recorded = daemon_recorded.lock().unwrap().clone();
        assert!(
            recorded.is_some(),
            "agentpactd should have received a permission request"
        );
        let req = recorded.unwrap();
        assert_eq!(
            req["context"]["working_dir"].as_str(),
            Some("/home/user/project"),
            "working_dir from header should reach agentpactd"
        );

        let _ = response.bytes().await.unwrap();

        policy::set_test_agentpact_socket(None);
        let _ = router_shutdown.send(());
        router_handle.await.unwrap();
        daemon_handle.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteHeaderOverridesStaticWorkingDir() {
        let _guard = lock_mcp_route_tests();
        let sock_dir = tempfile::tempdir().unwrap();
        let sock_path = sock_dir.path().join("agentpact.sock");
        let daemon_recorded = Arc::new(Mutex::new(None));
        let daemon_handle = spawn_agentpact_stub(
            &sock_path,
            serde_json::json!({"code": "PACT_OK"}),
            daemon_recorded.clone(),
        );
        policy::set_test_agentpact_socket(Some(sock_path.clone()));

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = true;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: "http://127.0.0.1:1".to_string(),
            working_dir: Some("/static/config/dir".to_string()),
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let response = reqwest::Client::new()
            .post(format!("{router_url}/mcp/remote/tools/call"))
            .header("content-type", "application/json")
            .header("x-working-dir", "/dynamic/per-request/dir")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}"#)
            .send()
            .await
            .unwrap();

        let _ = response.bytes().await.unwrap();

        let recorded = daemon_recorded.lock().unwrap().clone();
        assert!(recorded.is_some());
        let req = recorded.unwrap();
        assert_eq!(
            req["context"]["working_dir"].as_str(),
            Some("/dynamic/per-request/dir"),
            "header working_dir should take precedence over static config"
        );

        policy::set_test_agentpact_socket(None);
        let _ = router_shutdown.send(());
        router_handle.await.unwrap();
        daemon_handle.await.unwrap();
    }

    #[derive(Clone, Debug)]
    struct RecordedHeaders {
        headers: Vec<(String, String)>,
    }

    async fn record_upstream_get(
        State(recorded): State<Arc<Mutex<Option<RecordedHeaders>>>>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        let h: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        *recorded.lock().unwrap() = Some(RecordedHeaders { headers: h });
        (
            StatusCode::OK,
            [("content-type", "application/json")],
            r#"{"ok":true}"#,
        )
    }

    async fn sse_upstream_post(
        State(recorded): State<Arc<Mutex<Option<RecordedRequest>>>>,
        _headers: HeaderMap,
        body: Bytes,
    ) -> impl IntoResponse {
        *recorded.lock().unwrap() = Some(RecordedRequest {
            body: body.to_vec(),
        });
        (
            StatusCode::OK,
            [("content-type", "text/event-stream")],
            "data: {\"chunk\":1}\n\ndata: {\"chunk\":2}\n\n",
        )
    }

    async fn record_upstream_delete(
        State(recorded): State<Arc<Mutex<Option<RecordedHeaders>>>>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        let h: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        *recorded.lock().unwrap() = Some(RecordedHeaders { headers: h });
        (StatusCode::OK, [("content-type", "application/json")], "{}")
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteForwardsGetRequest() {
        let _guard = lock_mcp_route_tests();
        policy::set_test_agentpact_socket(None);

        let upstream_recorded = Arc::new(Mutex::new(None::<RecordedHeaders>));
        let upstream = Router::new()
            .route("/sse", axum::routing::get(record_upstream_get))
            .with_state(upstream_recorded.clone());
        let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = true;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: upstream_url.clone(),
            working_dir: None,
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let response = reqwest::Client::new()
            .get(format!("{router_url}/mcp/remote/sse"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_text = response.text().await.unwrap();
        assert_eq!(body_text, r#"{"ok":true}"#);
        assert!(upstream_recorded.lock().unwrap().is_some());

        let _ = router_shutdown.send(());
        let _ = upstream_shutdown.send(());
        router_handle.await.unwrap();
        upstream_handle.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteForwardsDeleteRequest() {
        let _guard = lock_mcp_route_tests();
        policy::set_test_agentpact_socket(None);

        let upstream_recorded = Arc::new(Mutex::new(None::<RecordedHeaders>));
        let upstream = Router::new()
            .route(
                "/session/abc",
                axum::routing::delete(record_upstream_delete),
            )
            .with_state(upstream_recorded.clone());
        let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = true;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: upstream_url.clone(),
            working_dir: None,
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let response = reqwest::Client::new()
            .delete(format!("{router_url}/mcp/remote/session/abc"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(upstream_recorded.lock().unwrap().is_some());

        let _ = router_shutdown.send(());
        let _ = upstream_shutdown.send(());
        router_handle.await.unwrap();
        upstream_handle.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteStreamsSSEResponse() {
        let _guard = lock_mcp_route_tests();
        let upstream_recorded = Arc::new(Mutex::new(None));
        let upstream = Router::new()
            .route("/tools/call", axum::routing::post(sse_upstream_post))
            .with_state(upstream_recorded.clone());
        let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

        let sock_dir = tempfile::tempdir().unwrap();
        let sock_path = sock_dir.path().join("agentpact.sock");
        let daemon_recorded = Arc::new(Mutex::new(None));
        let daemon_handle = spawn_agentpact_stub(
            &sock_path,
            serde_json::json!({"code": "PACT_OK"}),
            daemon_recorded,
        );
        policy::set_test_agentpact_socket(Some(sock_path.clone()));

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = true;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: upstream_url.clone(),
            working_dir: Some("/tmp/project".to_string()),
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "stream_tool", "arguments": {}}
        });

        let response = reqwest::Client::new()
            .post(format!("{router_url}/mcp/remote/tools/call"))
            .header("content-type", "application/json")
            .body(request_body.to_string())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            content_type.starts_with("text/event-stream"),
            "expected text/event-stream, got: {content_type}"
        );
        let body_text = response.text().await.unwrap();
        assert!(body_text.contains("\"chunk\":1"));
        assert!(body_text.contains("\"chunk\":2"));

        policy::set_test_agentpact_socket(None);
        let _ = router_shutdown.send(());
        let _ = upstream_shutdown.send(());
        router_handle.await.unwrap();
        upstream_handle.await.unwrap();
        daemon_handle.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteForwardsHeaders() {
        let _guard = lock_mcp_route_tests();
        policy::set_test_agentpact_socket(None);

        let upstream_recorded = Arc::new(Mutex::new(None::<RecordedHeaders>));
        let upstream = Router::new().route(
            "/ping",
            axum::routing::get({
                let recorded = upstream_recorded.clone();
                move |headers: HeaderMap| {
                    let recorded = recorded.clone();
                    async move {
                        let h: Vec<(String, String)> = headers
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect();
                        *recorded.lock().unwrap() = Some(RecordedHeaders { headers: h });
                        (
                            StatusCode::OK,
                            [
                                ("content-type", "application/json"),
                                ("mcp-session-id", "sess-upstream-abc"),
                            ],
                            r#"{"ok":true}"#,
                        )
                    }
                }
            }),
        );
        let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = true;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: upstream_url.clone(),
            working_dir: None,
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let response = reqwest::Client::new()
            .get(format!("{router_url}/mcp/remote/ping"))
            .header("mcp-session-id", "sess-client-123")
            .header("last-event-id", "evt-42")
            .header("accept", "text/event-stream")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let upstream_headers = upstream_recorded.lock().unwrap().clone().unwrap().headers;
        let has_header = |name: &str| -> Option<String> {
            upstream_headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };

        assert_eq!(
            has_header("mcp-session-id"),
            Some("sess-client-123".to_string()),
        );
        assert_eq!(has_header("last-event-id"), Some("evt-42".to_string()));
        assert_eq!(has_header("accept"), Some("text/event-stream".to_string()),);
        assert!(
            has_header("host").is_none() || has_header("host").unwrap().contains("127.0.0.1"),
            "host should not be the client's original host"
        );

        let resp_session = response
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(resp_session, "sess-upstream-abc");

        let _ = router_shutdown.send(());
        let _ = upstream_shutdown.send(());
        router_handle.await.unwrap();
        upstream_handle.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteGetReturnsNotFoundWhenDisabled() {
        let _guard = lock_mcp_route_tests();
        policy::set_test_agentpact_socket(None);

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = false;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: "http://127.0.0.1:1".to_string(),
            working_dir: None,
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let response = reqwest::Client::new()
            .get(format!("{router_url}/mcp/remote/sse"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let _ = response.bytes().await.unwrap();

        let _ = router_shutdown.send(());
        router_handle.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn testMcpRouteDeleteReturnsNotFoundWhenDisabled() {
        let _guard = lock_mcp_route_tests();
        policy::set_test_agentpact_socket(None);

        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.mcp.enabled = false;
        config.mcp.servers = vec![McpServerConfig {
            name: "remote".to_string(),
            upstream: "http://127.0.0.1:1".to_string(),
            working_dir: None,
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let response = reqwest::Client::new()
            .delete(format!("{router_url}/mcp/remote/session/abc"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let _ = response.bytes().await.unwrap();

        let _ = router_shutdown.send(());
        router_handle.await.unwrap();
    }
}
