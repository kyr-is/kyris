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

/// Resolve the CWD of the process owning the peer side of a localhost TCP
/// connection. Returns `None` if the platform is unsupported, the peer PID
/// cannot be determined, or the CWD cannot be read.
pub fn resolve(peer_addr: SocketAddr) -> Option<String> {
    let peer_port = peer_addr.port();
    let pid = find_pid_for_local_port(peer_port)?;
    read_cwd(pid)
}

#[cfg(target_os = "macos")]
fn find_pid_for_local_port(port: u16) -> Option<i32> {
    use libproc::libproc::file_info::{ListFDs, ProcFDType, pidfdinfo};
    use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
    use libproc::libproc::proc_pid::listpidinfo;
    use libproc::processes::{ProcFilter, pids_by_type};

    let pids = pids_by_type(ProcFilter::All).ok()?;
    for pid in pids {
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

#[cfg(target_os = "linux")]
fn find_pid_for_local_port(port: u16) -> Option<i32> {
    let inode = find_tcp_inode(port)?;
    find_pid_for_inode(inode)
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

#[cfg(target_os = "linux")]
fn find_pid_for_inode(target_inode: u64) -> Option<i32> {
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
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

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn find_pid_for_local_port(_port: u16) -> Option<i32> {
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_cwd(_pid: i32) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testResolveReturnsNoneForBogusPort() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(resolve(addr).is_none());
    }
}
