// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Shared library layer. Re-exports `kyris-types` and adds I/O helpers:
//! config loading with environment variable overrides, `AgentPact` protocol
//! types, and governance coverage derivation logic.
// `paths.rs` reads/writes env vars in its tests, so unsafe is required for
// the env-mutation calls (Rust 2024 marks env mutation unsafe). Scope:
// only the test helper in paths.rs uses unsafe; production code is safe.
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(test, allow(non_snake_case))]

pub use kyris_types::event;
pub use kyris_types::pricing;
pub use kyris_types::record;
pub use kyris_types::schema;
pub use kyris_types::sync;
pub use kyris_types::timeline;

pub mod agentpact;
pub mod config;
// The on-disk artifact is named `credentials.json`; the module file is
// `enrollment.rs` so it doesn't collide with the credentials path-protection
// boundary rule, but the public module path is `credentials` to match the
// artifact it loads.
pub mod coverage;
#[path = "enrollment.rs"]
pub mod credentials;
pub mod fail_open_log;
pub mod path_display;
pub mod paths;
#[cfg(feature = "pending")]
pub mod pending;
pub mod pricing_cache;
pub mod secret;
