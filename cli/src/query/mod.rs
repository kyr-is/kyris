// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Time-series queries against the local `DuckDB` event store. Subcommands
//! for timeline views, event replay, usage statistics, and raw history.
pub mod history;
pub mod replay;
pub mod stats;
pub mod timeline;
