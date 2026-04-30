// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Pure schema and serialization types shared across the kyris workspace.
//! No I/O, no runtime, no filesystem — just structs, enums, and serde
//! derives. Every crate in the workspace depends on this one.
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(test, allow(non_snake_case))]

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod config;
pub mod event;
pub mod pricing;
pub mod record;
pub mod schema;
pub mod sync;
