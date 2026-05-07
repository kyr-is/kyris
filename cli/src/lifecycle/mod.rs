// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Daemon and system lifecycle management: install/uninstall binaries and
//! launchd services, enroll with the relay, check for updates, and
//! start/stop/restart `kyrisd`.
pub mod daemon_cmd;
pub mod enroll;
pub mod install;
pub mod release;
pub mod uninstall;
pub mod update;
pub mod verify;
