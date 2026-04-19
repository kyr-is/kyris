// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(
    dead_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::needless_pass_by_value,
    clippy::too_many_lines
)]
#![cfg_attr(test, allow(non_snake_case))]

pub mod adapter;
pub mod auth;
pub mod circuit_breaker;
pub mod config;
pub mod cost;
pub mod mcp_routing;
pub mod metering;
pub mod notify;
pub mod pending;
pub mod platform;
pub mod pricing_fetch;
pub mod server;
pub mod storage;
pub mod streaming;
pub mod sync;
pub mod trace_attach;
pub mod tray;
