// SPDX-License-Identifier: Apache-2.0
//! HTTP MCP routing. Proxies `POST /mcp/{server}/{path}` to configured
//! upstream MCP servers, applying policy checks before forwarding. Server
//! names and upstream URLs are resolved from the daemon config.
pub mod policy;

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

use crate::server::AppState;

pub fn routes(state: Arc<AppState>) -> Router {
    Router::new().route("/mcp/{server}/{*path}", post(handle_mcp).with_state(state))
}

async fn handle_mcp(
    State(state): State<Arc<AppState>>,
    Path((server_name, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let config = state.config.load();

    if !config.mcp.enabled {
        return Err(StatusCode::NOT_FOUND);
    }

    let server = config
        .mcp
        .servers
        .iter()
        .find(|s| s.name == server_name)
        .ok_or(StatusCode::NOT_FOUND)?;

    let working_dir = headers
        .get("x-working-dir")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if policy::is_tools_call_request(&path, &body) && working_dir.is_none() {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"error": "X-Working-Dir header required for tools/call"})
                    .to_string(),
            ))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }

    let tool_name = policy::extract_tool_name(&path, &body);
    let socket_timeout = Duration::from_millis(config.mcp.socket_timeout_ms);
    let decision = policy::check_permission(
        &server_name,
        &path,
        &body,
        working_dir.as_deref(),
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
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
        }
        policy::PolicyDecision::Ask {
            approval_id,
            approval_token,
        } => {
            let pending_timeout = config.mcp.pending_timeout_seconds;
            let tool_display = tool_name.as_deref().unwrap_or("unknown tool");

            crate::notify::mcp_pending_toast(tool_display);

            let rx = state.pending.hold(
                approval_id.clone(),
                approval_token,
                server_name.clone(),
                tool_name,
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
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
                }
                Err(_) => {
                    tracing::info!(id = %approval_id, "mcp request timed out or cancelled");
                    return Response::builder()
                        .status(StatusCode::REQUEST_TIMEOUT)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({"error": "request timed out"}).to_string(),
                        ))
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        }
        policy::PolicyDecision::Allow => {}
    }

    let clients = state.provider_clients.load();
    let client = clients
        .get(&format!("mcp_{server_name}"))
        .cloned()
        .unwrap_or_else(reqwest::Client::new);
    let upstream_url = format!("{}/{}", server.upstream, path);

    let response = client
        .post(&upstream_url)
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, server = %server_name, "mcp upstream failed");
            StatusCode::BAD_GATEWAY
        })?;

    let status = response.status();
    let resp_body = response
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(resp_body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
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
            .header("x-working-dir", "/tmp/project")
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
            .header("x-working-dir", "/tmp/project")
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
            pending: Arc::new(PendingStore::new()),
            agentpact_socket: None,
        })
    }

    async fn spawn_test_server(
        app: Router,
    ) -> (String, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
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
        }];

        let temp_dir = tempfile::tempdir().unwrap();
        let state = make_test_state(config, temp_dir.path());
        let app = routes(state);
        let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

        let response = reqwest::Client::new()
            .post(format!("{router_url}/mcp/remote/tools/call"))
            .header("content-type", "application/json")
            .header("x-working-dir", "/tmp/project")
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
}
