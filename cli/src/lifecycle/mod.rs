// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Daemon and system lifecycle management: install/uninstall binaries and
//! launchd services, enroll with the relay, and check for updates.
pub mod enroll;
pub mod install;
pub mod log;
pub mod release;
pub mod run_state;
pub mod uninstall;
pub mod update;
pub mod verify;
