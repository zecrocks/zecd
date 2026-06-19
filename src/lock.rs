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
pub fn lock_datadir(datadir: &Path) -> anyhow::Result<fmutex::Guard<'static>> {
    // `init` may be the first thing ever run against this datadir, so make sure it (and thus the
    // lockfile's parent) exists before creating the lockfile.
    fs::create_dir_all(datadir)
        .with_context(|| format!("creating data directory {}", datadir.display()))?;

    let lockfile = datadir.join(".lock");
    // Ensure the lockfile exists on disk before we try to lock it (an empty marker; the advisory
    // OS lock on it is what actually enforces single-instance access).
    let _ = fs::File::create(&lockfile)
        .with_context(|| format!("creating lockfile {}", lockfile.display()))?;

    fmutex::try_lock_exclusive_path(&lockfile)
        .with_context(|| format!("reading lockfile {}", lockfile.display()))?
        .ok_or_else(|| {
            anyhow!(
                "Cannot lock data directory {}. Another zecd is already running; \
                 the lock clears when it exits, so just retry (no lockfile to delete).",
                datadir.display()
            )
        })
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
    fn lock_creates_the_datadir_if_missing() {
        // `zecd init` can run before the datadir exists; locking must create it.
        let parent = tempfile::tempdir().unwrap();
        let datadir = parent.path().join("not-created-yet");
        assert!(!datadir.exists());

        let _guard = lock_datadir(&datadir).expect("lock creates the datadir");
        assert!(datadir.join(".lock").exists(), "the lockfile was created");
    }
}
