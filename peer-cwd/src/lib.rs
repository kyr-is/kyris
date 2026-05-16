// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(test, allow(non_snake_case))]
//! Resolve the current working directory of the process that owns a localhost
//! TCP connection. Used to obtain `working_dir` for non-conformant agents that
//! route LLM traffic through `kyrisd` without sending `x-kyris-trace-token`.
//!
//! The OS tracks which PID owns every TCP socket. This crate queries that
//! mapping while the connection is still open, then reads the process's CWD.
//! Platform-specific: macOS uses `libproc`, Linux reads `/proc`.

use std::net::SocketAddr;

/// Hard deadline for the PID scan loop. On a busy macOS machine the full
/// `pids_by_type` + per-PID `listpidinfo` pass can take several hundred
/// milliseconds if there are thousands of processes. Since `working_dir` is
/// best-effort attribution, returning `None` after this limit is preferable to
/// holding a blocking-pool thread indefinitely.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const PID_SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);

/// Resolve the CWD of the process owning the peer side of a localhost TCP
/// connection. Returns `None` if the platform is unsupported, the peer PID
/// cannot be determined, or the CWD cannot be read.
pub fn resolve(peer_addr: SocketAddr) -> Option<String> {
    let peer_port = peer_addr.port();
    let pid = find_pid_for_local_port(peer_port)?;
    read_cwd(pid)
}

// ---------------------------------------------------------------------------
// macOS implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn find_pid_for_local_port(port: u16) -> Option<i32> {
    let deadline = std::time::Instant::now() + PID_SCAN_TIMEOUT;
    find_pid_for_local_port_with_deadline(port, deadline)
}

/// Inner implementation that accepts an explicit deadline so tests can inject
/// an already-expired deadline to verify the short-circuit path.
#[cfg(target_os = "macos")]
fn find_pid_for_local_port_with_deadline(port: u16, deadline: std::time::Instant) -> Option<i32> {
    use libproc::libproc::file_info::{ListFDs, ProcFDType, pidfdinfo};
    use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
    use libproc::libproc::proc_pid::listpidinfo;
    use libproc::processes::{ProcFilter, pids_by_type};

    let pids = pids_by_type(ProcFilter::All).ok()?;
    for pid in pids {
        // Bail out if we have exceeded the hard deadline. `working_dir` is
        // best-effort; returning None is preferable to blocking indefinitely.
        if std::time::Instant::now() >= deadline {
            return None;
        }
        let pid_i32 = match i32::try_from(pid) {
            Ok(p) if p > 0 => p,
            _ => continue,
        };
        let fds = match listpidinfo::<ListFDs>(pid_i32, 256) {
            Ok(fds) => fds,
            Err(_) => continue,
        };
        for fd in fds {
            if !matches!(ProcFDType::from(fd.proc_fdtype), ProcFDType::Socket) {
                continue;
            }
            let socket_info = match pidfdinfo::<SocketFDInfo>(pid_i32, fd.proc_fd) {
                Ok(info) => info,
                Err(_) => continue,
            };
            if !matches!(
                SocketInfoKind::from(socket_info.psi.soi_kind),
                SocketInfoKind::Tcp
            ) {
                continue;
            }
            // Safety: soi_proto is a union; accessing pri_tcp is valid after confirming soi_kind is Tcp.
            let tcp = unsafe { socket_info.psi.soi_proto.pri_tcp };
            let raw_port = tcp.tcpsi_ini.insi_lport;
            let local_port = ((raw_port >> 8) & 0x00FF | (raw_port << 8) & 0xFF00) as u16;
            if local_port == port {
                return Some(pid_i32);
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn read_cwd(pid: i32) -> Option<String> {
    libproc::libproc::proc_pid::pidcwd(pid)
        .ok()
        .and_then(|p| p.to_str().map(String::from))
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn find_pid_for_local_port(port: u16) -> Option<i32> {
    let inode = find_tcp_inode(port)?;
    let deadline = std::time::Instant::now() + PID_SCAN_TIMEOUT;
    find_pid_for_inode(inode, deadline)
}

#[cfg(target_os = "linux")]
fn find_tcp_inode(port: u16) -> Option<u64> {
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in contents.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            if let Some(port_hex) = fields[1].split(':').nth(1) {
                if let Ok(p) = u16::from_str_radix(port_hex, 16) {
                    if p == port {
                        return fields[9].parse::<u64>().ok();
                    }
                }
            }
        }
    }
    None
}

/// Inner implementation that accepts an explicit deadline so tests can inject
/// an already-expired deadline to verify the short-circuit path.
#[cfg(target_os = "linux")]
fn find_pid_for_inode(target_inode: u64, deadline: std::time::Instant) -> Option<i32> {
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        if std::time::Instant::now() >= deadline {
            return None;
        }
        let name = entry.file_name();
        let pid: i32 = match name.to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let fd_entries = match std::fs::read_dir(&fd_dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for fd_entry in fd_entries.flatten() {
            let link = match std::fs::read_link(fd_entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let link_str = link.to_string_lossy();
            if let Some(inode_str) = link_str
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
            {
                if let Ok(inode) = inode_str.parse::<u64>() {
                    if inode == target_inode {
                        return Some(pid);
                    }
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_cwd(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .and_then(|p| p.to_str().map(String::from))
}

// ---------------------------------------------------------------------------
// Unsupported platforms
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn find_pid_for_local_port(_port: u16) -> Option<i32> {
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_cwd(_pid: i32) -> Option<String> {
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testResolveReturnsNoneForBogusPort() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(resolve(addr).is_none());
    }

    /// Verifies the hard timeout constant is in a sensible range.
    /// Too short risks missing the target on a loaded system; too long blocks
    /// the thread pool thread pointlessly.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn testPidScanTimeoutIsReasonable() {
        assert!(
            PID_SCAN_TIMEOUT >= std::time::Duration::from_millis(50),
            "timeout too short: {:?}",
            PID_SCAN_TIMEOUT
        );
        assert!(
            PID_SCAN_TIMEOUT <= std::time::Duration::from_millis(500),
            "timeout too long: {:?}",
            PID_SCAN_TIMEOUT
        );
    }

    /// Passing an already-expired deadline must return None immediately without
    /// scanning any PIDs. This exercises the short-circuit branch directly.
    #[cfg(target_os = "macos")]
    #[test]
    fn testMacosDeadlineAlreadyExpiredReturnsNone() {
        // Use a deadline in the past — the very first iteration must bail out.
        let expired = std::time::Instant::now() - std::time::Duration::from_secs(1);
        let result = find_pid_for_local_port_with_deadline(12345, expired);
        assert!(result.is_none());
    }

    /// Passing an already-expired deadline must return None immediately without
    /// iterating /proc.
    #[cfg(target_os = "linux")]
    #[test]
    fn testLinuxDeadlineAlreadyExpiredReturnsNone() {
        let expired = std::time::Instant::now() - std::time::Duration::from_secs(1);
        // inode 0 cannot match any real socket; the deadline check fires first.
        let result = find_pid_for_inode(0, expired);
        assert!(result.is_none());
    }

    /// End-to-end: resolving a port that nobody owns must complete within twice
    /// the timeout — not hang indefinitely.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn testResolveCompletesWithinBoundedTimeForBogusPort() {
        let limit = PID_SCAN_TIMEOUT * 2;
        let start = std::time::Instant::now();
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = resolve(addr);
        let elapsed = start.elapsed();
        assert!(result.is_none());
        assert!(
            elapsed <= limit,
            "resolve took {:?}, expected at most {:?}",
            elapsed,
            limit
        );
    }
}
