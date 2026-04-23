// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(test, allow(non_snake_case))]

pub mod config;
pub mod event;
pub mod pricing;
pub mod record;
pub mod schema;
pub mod sync;
