// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Kyris daemon (`kyrisd`). Reverse-proxy for LLM provider APIs with
//! token metering, cost tracking, circuit breaking, and streaming relay.
//! Also routes MCP tool calls through policy and syncs events to the
//! relay. `DuckDB`-backed local storage; config hot-reloaded via `ArcSwap`.
#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]
#![cfg_attr(test, allow(non_snake_case))]

pub mod adapter;
pub mod auth;
pub mod circuit_breaker;
pub mod config;
pub mod cost;
pub mod fail_open_log;
pub mod mcp_routing;
pub mod metering;
pub mod notify;
pub mod pending;
pub mod pricing_fetch;
pub mod reconcile_watcher;
pub mod server;
pub mod storage;
pub mod streaming;
pub mod sync;
pub mod tray;
