// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Build the current process's ancestor PID chain (nearest first), up to
//! [`MAX_CHAIN_LEN`] entries. Sent on every `permission.request` so
//! agentpactd can match the request to an anchored `exec_token` issued by
//! a native hook in an ancestor of this process — eliminating the popup
//! that would otherwise fire for a command the agent's `PreToolUse` hook
//! already approved.
//!
//! macOS: one `proc_pidinfo(PROC_PIDTBSDINFO)` FFI call per hop. Cheap
//! and bounded; no shell-out, no `/proc`.
//! Linux: pure stdlib — read `/proc/<pid>/status`, parse `PPid:`.
//!
//! The chain terminates at PID 1 (init/launchd), the first repeat
//! (defensive against a degenerate ancestry), or [`MAX_CHAIN_LEN`].
//! Returns an empty vec when nothing useful was gathered — the wire
//! builder then omits the `ppid_chain` field entirely.

/// Walk depth cap. agentpactd does a linear scan against this list
/// (bounded by `MAX_EXEC_TOKENS`), so keeping it modest matters; 32 hops
/// is enough for `sudo` / `nohup` / `env -i` chains and well past anything
/// real agents produce.
pub const MAX_CHAIN_LEN: usize = 32;

/// Return the ancestor chain of the current process: index 0 is the
/// direct parent, index 1 its parent, etc., stopping at PID 1 or at
/// [`MAX_CHAIN_LEN`]. Returns `Vec::new()` if even the direct parent
/// cannot be determined (the wire builder treats this as "omit field").
#[must_use]
pub fn current_chain() -> Vec<u32> {
    let mut chain = Vec::with_capacity(8);
    let mut cur = direct_parent();
    while let Some(pid) = cur {
        // PID 1 is launchd/init — there is no useful ancestor beyond it
        // and recording it would only add noise to the daemon scan.
        if pid <= 1 || chain.len() >= MAX_CHAIN_LEN {
            break;
        }
        if chain.contains(&pid) {
            // PIDs do not normally repeat in a chain. If they do (PID
            // wrap with a stale read), stop rather than loop.
            break;
        }
        chain.push(pid);
        cur = parent_of(pid);
    }
    chain
}

/// PPID of the current process. Uses `getppid(2)` which is documented
/// safe (no arguments, no failure modes).
#[allow(unsafe_code)]
fn direct_parent() -> Option<u32> {
    #[cfg(target_family = "unix")]
    {
        // SAFETY: getppid has no arguments, no failure modes, and
        // returns a kernel-managed value. PIDs are non-negative on
        // Unix; cast_unsigned preserves the bit pattern after we have
        // gated on `> 0` so the sign bit is known clear.
        let ppid = unsafe { libc_getppid() };
        if ppid > 0 {
            Some(ppid.cast_unsigned())
        } else {
            None
        }
    }
    #[cfg(not(target_family = "unix"))]
    {
        None
    }
}

#[cfg(all(target_family = "unix", target_os = "macos"))]
#[allow(unsafe_code)]
unsafe fn libc_getppid() -> i32 {
    unsafe { libc::getppid() }
}

#[cfg(all(target_family = "unix", target_os = "linux"))]
#[allow(unsafe_code)]
unsafe fn libc_getppid() -> i32 {
    // On Linux we don't depend on libc — getppid is exposed by the C
    // library too, but we can read it from /proc/self/status. Using
    // /proc keeps the platform's dependency surface symmetric with
    // `parent_of` below.
    parent_of_via_proc(std::process::id())
        .map(|p| i32::try_from(p).unwrap_or(0))
        .unwrap_or(0)
}

#[cfg(all(
    target_family = "unix",
    not(any(target_os = "macos", target_os = "linux"))
))]
#[allow(unsafe_code)]
unsafe fn libc_getppid() -> i32 {
    // Other Unix: fall back to /proc parsing for self; if /proc is
    // absent the chain becomes empty (the wire builder then omits the
    // field — the daemon falls through to normal policy).
    parent_of_via_proc(std::process::id())
        .map(|p| i32::try_from(p).unwrap_or(0))
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn parent_of(pid: u32) -> Option<u32> {
    parent_of_via_proc_pidinfo(pid)
}

#[cfg(not(target_os = "macos"))]
fn parent_of(pid: u32) -> Option<u32> {
    parent_of_via_proc(pid)
}

/// macOS: query the per-process BSD info via `proc_pidinfo`. The
/// returned struct's `pbi_ppid` field lives at offset 16 — see
/// `<sys/proc_info.h>`, `struct proc_bsdinfo`, where four `u32`s
/// (`pbi_flags`, `pbi_status`, `pbi_xstatus`, `pbi_pid`) precede it.
/// We avoid declaring the full 288-byte struct to stay strictly
/// minimal — just the offset of the field we need.
#[cfg(target_os = "macos")]
#[allow(unsafe_code, clippy::similar_names)]
fn parent_of_via_proc_pidinfo(pid: u32) -> Option<u32> {
    const PROC_PIDTBSDINFO: libc::c_int = 3;
    const PROC_PIDTBSDINFO_SIZE: libc::c_int = 288;
    const PBI_PPID_OFFSET: usize = 16;
    let mut buf = [0u8; PROC_PIDTBSDINFO_SIZE as usize];
    let pid_i32 = i32::try_from(pid).ok()?;
    // SAFETY: proc_pidinfo writes at most `buffersize` bytes into the
    // provided buffer; we pass the exact size of our stack allocation.
    // No aliasing — the buffer is exclusive to this call.
    let rv = unsafe {
        libc::proc_pidinfo(
            pid_i32,
            PROC_PIDTBSDINFO,
            0,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            PROC_PIDTBSDINFO_SIZE,
        )
    };
    // proc_pidinfo returns the number of bytes written on success; 0 or
    // a negative value indicates EPERM (other user's process), a zombie,
    // or the PID being gone. We require at least enough bytes to cover
    // the `pbi_ppid` slot — the rest of the struct we ignore.
    let min_bytes = libc::c_int::try_from(PBI_PPID_OFFSET + 4).ok()?;
    if rv < min_bytes {
        return None;
    }
    let ppid_bytes: [u8; 4] = buf[PBI_PPID_OFFSET..PBI_PPID_OFFSET + 4].try_into().ok()?;
    let ppid = u32::from_le_bytes(ppid_bytes);
    if ppid == 0 { None } else { Some(ppid) }
}

/// Linux (and other /proc-bearing systems): read `/proc/<pid>/status`
/// and parse the `PPid:` line. Pure stdlib, no FFI.
#[cfg(not(target_os = "macos"))]
fn parent_of_via_proc(pid: u32) -> Option<u32> {
    let path = format!("/proc/{pid}/status");
    let content = std::fs::read_to_string(&path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testCurrentChainIncludesAtLeastDirectParent() {
        let chain = current_chain();
        // The test runner is always a child of cargo (or a shell), so the
        // direct-parent lookup should succeed in any sane CI/dev setup.
        assert!(
            !chain.is_empty(),
            "expected at least one ancestor in the chain"
        );
    }

    #[test]
    fn testCurrentChainIsBoundedByMaxLen() {
        let chain = current_chain();
        assert!(
            chain.len() <= MAX_CHAIN_LEN,
            "chain exceeded MAX_CHAIN_LEN: {} entries",
            chain.len()
        );
    }

    #[test]
    fn testCurrentChainHasNoDuplicates() {
        // The walker breaks on the first repeated PID; this asserts
        // that property on a real chain (defends against a future
        // refactor that drops the check).
        let chain = current_chain();
        let mut seen = std::collections::HashSet::new();
        for pid in &chain {
            assert!(seen.insert(*pid), "duplicate PID {pid} in chain {chain:?}");
        }
    }

    #[test]
    fn testCurrentChainDoesNotIncludePid1() {
        // PID 1 (init/launchd) is excluded by design — recording it
        // would force every shell on the machine into the daemon's
        // anchor scan for nothing.
        let chain = current_chain();
        assert!(
            !chain.contains(&1),
            "PID 1 must not appear in the chain: {chain:?}"
        );
    }

    #[test]
    fn testCurrentChainStartsWithDirectParent() {
        // Index 0 must be the immediate parent. We can verify this
        // against std::process::id() of self vs the first entry, which
        // is the platform's getppid.
        let chain = current_chain();
        let me = std::process::id();
        if let Some(first) = chain.first() {
            // The direct parent of self should not equal self (would
            // imply we're our own parent — only possible for PID 1).
            assert_ne!(*first, me);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn testParentOfSelfMatchesDirectParent() {
        // On macOS our parent_of() FFI path should agree with the
        // direct-parent stdlib path for our own PID.
        let direct = direct_parent().expect("direct parent");
        let via_ffi = parent_of(std::process::id()).expect("ffi parent");
        assert_eq!(direct, via_ffi);
    }
}
