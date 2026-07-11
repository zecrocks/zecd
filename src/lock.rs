//! Single-instance guard for the data directory.
//!
//! Two zecd processes writing one data directory would both open the same `WalletDb` files and
//! step on each other's writes (the single-writer-actor invariant only serializes writers
//! *within* one process). To prevent that, every datadir-*writing* entry point - the daemon
//! ([`crate::daemon::run`]) and `zecd init` ([`crate::init::run`]) - takes an exclusive advisory
//! lock on `<datadir>/.lock` first and holds it for as long as it owns the datadir (the process
//! lifetime for the daemon). This mirrors zallet's `lock_datadir` (and zcashd before it): the
//! lockfile is an empty marker, the OS advisory file lock is the real mutex, and a second writer
//! finds the lock already held and refuses to start.
//!
//! Two commands are deliberately *not* locked, because neither writes the datadir:
//! - `rpcauth` - a pure credential generator that never touches the datadir (dispatched before
//!   config is even resolved).
//! - `export-ufvk` - reads the wallet DB read-only (short-lived connection, WAL), so it is safe
//!   to run while the daemon holds the datadir; locking it would needlessly refuse a UFVK export
//!   from a live wallet.
//!
//! # Limitation: the lock is host-local
//!
//! The advisory file lock is enforced by the *local* kernel, so it only guards against a second
//! zecd on the **same host**. It does **not** span hosts: on a network filesystem (NFS, SMB, a
//! Kubernetes `ReadWriteMany` volume) mounted by two machines, each host's kernel grants the lock
//! independently, so two zecd on different hosts sharing one datadir would both believe they hold
//! it and then corrupt the wallet DB with concurrent SQLite writers. **The data directory must
//! therefore be host-local** - a local disk, or a volume mounted so exactly one node can write it
//! (Kubernetes `ReadWriteOnce`) - and must never be shared read-write across hosts. There is no
//! cross-host guard today; a host-independent lease (in the DB, or an external lock service) would
//! be required for a shared-storage deployment and is out of scope. As a diagnostic aid the
//! lockfile records the holder's `hostname:pid`, so an operator investigating suspected corruption
//! can see which host last wrote a datadir. This is a breadcrumb, not enforcement: because the
//! lock doesn't conflict across hosts, a second host would overwrite the stamp, not be refused.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context as _};

/// Acquire the exclusive lock on `<datadir>/.lock`, returning a guard that releases it when
/// dropped. Hold the guard for as long as the datadir is in use (the process lifetime).
///
/// The data directory is created if it does not yet exist: `zecd init` can run before any datadir
/// has been laid down, and the lockfile's parent must exist before it can be created.
///
/// Returns an error if the lock is already held by another process (the "already running" case),
/// or on an I/O failure creating/reading the lockfile.
///
/// NB the lock is **host-local** - see the module docs. It does not protect a datadir shared
/// read-write across hosts (a network volume); that datadir must be host-local.
pub fn lock_datadir(datadir: &Path) -> anyhow::Result<fmutex::Guard<'static>> {
    // `init` may be the first thing ever run against this datadir, so make sure it (and thus the
    // lockfile's parent) exists before creating the lockfile.
    fs::create_dir_all(datadir)
        .with_context(|| format!("creating data directory {}", datadir.display()))?;

    let lockfile = datadir.join(".lock");
    // Ensure the lockfile exists before we try to lock it (the advisory OS lock on it is what
    // actually enforces single-instance access). Create-if-absent *without* truncating: a failed
    // lock attempt must not clobber the current holder's diagnostic stamp.
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&lockfile)
        .with_context(|| format!("creating lockfile {}", lockfile.display()))?;

    let guard = fmutex::try_lock_exclusive_path(&lockfile)
        .with_context(|| format!("reading lockfile {}", lockfile.display()))?
        .ok_or_else(|| {
            anyhow!(
                "Cannot lock data directory {}. Another zecd is already running on this host; \
                 the lock clears when it exits, so just retry (no lockfile to delete). \
                 Note the lock is host-local: it does NOT protect a datadir shared across hosts \
                 (e.g. a network/ReadWriteMany volume) - keep the datadir host-local.",
                datadir.display()
            )
        })?;

    // We own the lock: record a best-effort diagnostic stamp so an operator can see which host/pid
    // holds (or last held) this datadir. This does NOT enforce anything across hosts - the advisory
    // lock is host-local (see the module docs) - it is purely a breadcrumb for diagnosing suspected
    // shared-datadir corruption. Written on a separate fd, which does not disturb the lock the
    // guard holds; a write failure is ignored (the lock, not the stamp, is what matters).
    let stamp = format!("{}:{}\n", hostname(), std::process::id());
    let _ = fs::write(&lockfile, stamp);

    Ok(guard)
}

/// Best-effort local hostname for the lockfile diagnostic stamp; `"unknown"` if it can't be read.
fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: `gethostname` writes at most `buf.len()` bytes into `buf` and NUL-terminates when
    // there is room. We pass the real buffer length and read back only up to the first NUL.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return "unknown".to_string();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let name = String::from_utf8_lossy(&buf[..end]).into_owned();
    if name.is_empty() {
        "unknown".to_string()
    } else {
        name
    }
}

#[cfg(test)]
mod tests {
    use super::lock_datadir;

    #[test]
    fn second_lock_on_same_datadir_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let guard = lock_datadir(dir.path()).expect("first lock succeeds");

        // A second attempt while the first guard is held must be refused with the
        // "already running" message (advisory locks conflict across distinct file descriptions,
        // even within the same process).
        let err = lock_datadir(dir.path()).expect_err("second lock must be refused");
        let msg = err.to_string();
        assert!(msg.contains("already running"), "{msg}");
        assert!(
            msg.contains(&dir.path().display().to_string()),
            "the error names the datadir: {msg}"
        );

        // Releasing the first guard frees the lock so it can be re-acquired (clean restart).
        drop(guard);
        let _reacquired =
            lock_datadir(dir.path()).expect("lock is free after the guard is dropped");
    }

    #[test]
    fn lock_records_a_hostname_pid_diagnostic_stamp() {
        // The lockfile carries a best-effort `hostname:pid` breadcrumb for diagnosing suspected
        // shared-datadir corruption. It is diagnostic only - the host-local advisory
        // lock, not this stamp, is what enforces single-instance access.
        let dir = tempfile::tempdir().unwrap();
        let _guard = lock_datadir(dir.path()).expect("lock succeeds");

        let contents = std::fs::read_to_string(dir.path().join(".lock")).expect("read lockfile");
        let stamp = contents.trim();
        let (host, pid) = stamp
            .rsplit_once(':')
            .unwrap_or_else(|| panic!("stamp should be hostname:pid, got {stamp:?}"));
        assert!(!host.is_empty(), "hostname part is present: {stamp:?}");
        assert_eq!(
            pid.parse::<u32>().ok(),
            Some(std::process::id()),
            "the stamp records this process's pid: {stamp:?}"
        );
    }

    #[test]
    fn lock_creates_the_datadir_if_missing() {
        // `zecd init` can run before the datadir exists; locking must create it.
        let parent = tempfile::tempdir().unwrap();
        let datadir = parent.path().join("not-created-yet");
        assert!(!datadir.exists());

        let _guard = lock_datadir(&datadir).expect("lock creates the datadir");
        assert!(datadir.join(".lock").exists(), "the lockfile was created");
    }
}
