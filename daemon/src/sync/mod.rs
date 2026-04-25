// SPDX-License-Identifier: Apache-2.0
//! Relay synchronization. Pushes local events and gateway records to the
//! remote relay in batches, using a cursor to track progress. Daemon state
//! (enrollment, machine token) is synced separately from the event stream.
pub mod daemon_sync;
pub mod event_sync;
pub mod scope;
