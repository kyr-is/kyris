// SPDX-License-Identifier: Apache-2.0
//! Shared library layer. Re-exports `kyris-types` and adds I/O helpers:
//! config loading with environment variable overrides, `AgentPact` protocol
//! types, and governance coverage derivation logic.
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(test, allow(non_snake_case))]

pub use kyris_types::event;
pub use kyris_types::pricing;
pub use kyris_types::record;
pub use kyris_types::schema;
pub use kyris_types::sync;

pub mod agentpact;
pub mod config;
pub mod coverage;
