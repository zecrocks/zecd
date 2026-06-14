//! Process and memory hardening against *passive* secret disclosure - the threat where the
//! wallet seed leaks into a core dump, a swap file, or another process reading this one's
//! memory (`/proc/<pid>/mem`, `ptrace`), rather than via code execution inside zecd.
//!
//! Three best-effort, Linux-focused mitigations (each a no-op with a warning if the platform
//! or the process's privileges don't allow it - a wallet must keep serving, not refuse to
//! start, if a hardening syscall is denied):
//!
//! - **No core dumps** (`RLIMIT_CORE = 0`): a core dump of a crashed zecd would contain the
//!   in-memory seed. Disabled unless `ZECD_ALLOW_CORE_DUMPS=1` (a debugging escape hatch).
//! - **Non-dumpable** (`PR_SET_DUMPABLE = 0`, Linux): also blocks `ptrace` attach and
//!   `/proc/<pid>/mem` reads by other non-root processes, and re-asserts no-core-dump.
//! - **`mlock` of the seed** ([`lock_secret`]): pins the page(s) holding the decrypted seed
//!   into RAM so they are never written to swap. Applied per seed buffer in `SeedKeeper`
//!   (targeted rather than `mlockall`, which would have to fit the whole RSS - proving keys
//!   included - under `RLIMIT_MEMLOCK` and typically fails in containers).
//!
//! Honest limits: this defends passive capture, not an attacker with code execution inside
//! zecd (who can read the seed directly, or - for a KMS wallet - just call Decrypt). And the
//! `mlock` is targeted at the seed buffer; transient key copies made deeper in librustzcash
//! during derivation/proving are not individually locked (raising `RLIMIT_MEMLOCK` and using
//! an encrypted swap device covers that residue).

use tracing::{info, warn};

/// Environment variable that opts out of the core-dump / non-dumpable hardening (for
/// debugging a crash). `mlock` of the seed is unaffected.
pub const ALLOW_CORE_DUMPS_ENV: &str = "ZECD_ALLOW_CORE_DUMPS";

/// Apply the process-wide hardening once at startup (before any secret is decrypted). Safe to
/// call from every subcommand; best-effort, so failures are logged and never fatal.
pub fn harden_process() {
    if std::env::var_os(ALLOW_CORE_DUMPS_ENV).is_some() {
        info!("{ALLOW_CORE_DUMPS_ENV} set; leaving core dumps and ptrace enabled");
        return;
    }
    disable_core_dumps();
    set_non_dumpable();
}

#[cfg(unix)]
fn disable_core_dumps() {
    // RLIMIT_CORE = 0: the kernel writes no core file for this process or its children.
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit` reads one valid `rlimit` for a known resource id; no aliasing.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if rc == 0 {
        info!("core dumps disabled (RLIMIT_CORE=0)");
    } else {
        warn!(
            "could not disable core dumps: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(all(unix, target_os = "linux"))]
fn set_non_dumpable() {
    // PR_SET_DUMPABLE=0: no core dump, and (the point) other non-root processes can't ptrace
    // this one or read /proc/<pid>/mem to scrape the seed.
    // SAFETY: a plain prctl with constant scalar args and no pointers.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc == 0 {
        info!(
            "process marked non-dumpable (PR_SET_DUMPABLE=0): no ptrace / /proc/pid/mem scraping"
        );
    } else {
        warn!(
            "could not mark process non-dumpable: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn set_non_dumpable() {
    // PR_SET_DUMPABLE is Linux-specific; RLIMIT_CORE above already covers core dumps elsewhere.
}

#[cfg(not(unix))]
fn disable_core_dumps() {
    warn!("core-dump hardening is not implemented on this platform");
}

#[cfg(not(unix))]
fn set_non_dumpable() {}

/// Pin a secret's bytes into RAM so they are never swapped to disk. Returns whether the lock
/// succeeded - pass that flag back to [`unlock_secret`] so the `munlock` accounting is
/// symmetric. Best-effort: a denied `mlock` (e.g. an unprivileged container with
/// `RLIMIT_MEMLOCK=0`) warns once and leaves the secret usable but swappable.
#[cfg(unix)]
#[must_use]
pub fn lock_secret(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    // SAFETY: `bytes` is a live slice; `mlock` only pins the pages spanning it and does not
    // retain the pointer past the call.
    let rc = unsafe { libc::mlock(bytes.as_ptr() as *const libc::c_void, bytes.len()) };
    if rc == 0 {
        true
    } else {
        warn!(
            "could not mlock the wallet seed (it may be swappable): {}; \
             raise RLIMIT_MEMLOCK to fix",
            std::io::Error::last_os_error()
        );
        false
    }
}

/// Release a lock taken by [`lock_secret`]. Call only when `locked` is `true`, while the
/// bytes are still mapped (before they are freed).
#[cfg(unix)]
pub fn unlock_secret(bytes: &[u8], locked: bool) {
    if locked && !bytes.is_empty() {
        // SAFETY: same contract as `lock_secret`; the slice is still valid here.
        unsafe {
            libc::munlock(bytes.as_ptr() as *const libc::c_void, bytes.len());
        }
    }
}

#[cfg(not(unix))]
#[must_use]
pub fn lock_secret(_bytes: &[u8]) -> bool {
    false
}

#[cfg(not(unix))]
pub fn unlock_secret(_bytes: &[u8], _locked: bool) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_process_is_idempotent_and_infallible() {
        // Best-effort: calling it (twice) must never panic, regardless of platform/privilege.
        harden_process();
        harden_process();
    }

    #[cfg(unix)]
    #[test]
    fn lock_unlock_roundtrip() {
        let secret = vec![0x42u8; 64];
        let locked = lock_secret(&secret);
        // Whether the lock succeeds depends on RLIMIT_MEMLOCK (often 0 in CI sandboxes), so we
        // only require that the call is well-behaved and unlock mirrors it without panicking.
        unlock_secret(&secret, locked);

        // An empty secret never locks.
        assert!(!lock_secret(&[]));
    }
}
