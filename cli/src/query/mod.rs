// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Time-series query commands. These are thin **renderers**: kyrisd owns the
//! event↔record join (it holds the gateway records and reads agentpact's event
//! log), so each command asks kyrisd's operator API for finished
//! `TimelineEntry` / `TimelineStats` data and formats it for the terminal —
//! the CLI never opens the `DuckDB` file (so kyrisd's exclusive lock is a
//! non-issue) and never reads the event log directly.
pub mod approvals;
pub mod history;
pub mod render;
pub mod replay;
pub mod stats;
pub mod timeline;
pub mod trace;
