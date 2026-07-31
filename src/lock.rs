use crate::diagnostic::{CodeKey, Failure, Result};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open, openat};
use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

pub(crate) fn acquire_lock(
    run_lock: &OwnedFd,
    lock_dir: &Path,
    lock_name: &OsStr,
) -> Result<OwnedFd> {
    // the directory comes from the caller so a failure names the file it failed
    // on, which is not always the default one.
    let label = lock_dir.join(lock_name);
    let lock = openat(
        run_lock,
        lock_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|errno| {
        Failure::syscall(
            CodeKey::InvalidManifest,
            label.to_string_lossy(),
            "openat-lock",
            errno,
        )
    })?;
    flock(&lock, FlockOperation::LockExclusive).map_err(|errno| {
        Failure::syscall(
            CodeKey::InvalidManifest,
            label.to_string_lossy(),
            "flock",
            errno,
        )
    })?;
    Ok(lock)
}

pub(crate) const DEFAULT_LOCK_DIR: &str = "/run/lock";

// the lock directory is a seam so crash cases can be exercised without a boot.
// nothing in the module set passes it, so the unit and the activation script
// are byte-unchanged and it never becomes a host-visible option.
pub(crate) fn open_host_lock(lock_name: &OsStr, lock_dir: &Path) -> Result<OwnedFd> {
    let mut components = Path::new(lock_name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(Failure::new(
            CodeKey::InvalidManifest,
            lock_name.to_string_lossy(),
            "lock name must be one normal path component",
        ));
    }
    let run_lock = open(
        lock_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| {
        Failure::syscall(
            CodeKey::InvalidManifest,
            lock_dir.to_string_lossy(),
            "open-run-lock",
            errno,
        )
    })?;
    acquire_lock(&run_lock, lock_dir, lock_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::serialize_failure;
    use crate::manifest::DiagnosticCodes;
    use rustix::io::Errno;
    use std::env;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestLockRoot(PathBuf);

    impl TestLockRoot {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "furnish-lock-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated lock directory");
            Self(path)
        }

        fn open(&self) -> OwnedFd {
            open(
                &self.0,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .expect("open isolated lock directory")
        }
    }

    impl Drop for TestLockRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove isolated lock directory");
        }
    }

    #[test]
    fn absent_lock_file_is_created_and_locked() {
        let root = TestLockRoot::new();
        let lock_name = OsStr::new("furnish-test.lock");
        let _lock = acquire_lock(&root.open(), &root.0, lock_name).expect("acquire fresh lock");
        assert!(root.0.join(lock_name).is_file());
    }
    #[test]
    fn lock_symlink_is_refused_without_following_it() {
        let root = TestLockRoot::new();
        let lock_name = OsStr::new("furnish-test.lock");
        symlink("elsewhere", root.0.join(lock_name)).expect("plant lock symlink");
        let failure =
            acquire_lock(&root.open(), &root.0, lock_name).expect_err("refuse lock symlink");
        assert_eq!(
            failure.cause.as_ref().map(|cause| cause.operation),
            Some("openat-lock")
        );
        assert_eq!(
            failure.cause.as_ref().map(|cause| cause.errno),
            Some(Errno::LOOP.raw_os_error())
        );
        let codes = DiagnosticCodes {
            invalid_manifest: "runtime/invalid-manifest".to_owned(),
            ..DiagnosticCodes::default()
        };
        let encoded = serialize_failure(&codes, &failure, None).expect("serialize diagnostic");
        let diagnostic: serde_json::Value =
            serde_json::from_str(&encoded).expect("decode diagnostic");
        assert_eq!(diagnostic["code"], "runtime/invalid-manifest");
        assert_eq!(diagnostic["cause"]["operation"], "openat-lock");
        assert_eq!(diagnostic["cause"]["errno"], Errno::LOOP.raw_os_error());
    }
    #[test]
    fn concurrent_lock_acquisition_serializes() {
        let root = TestLockRoot::new();
        let lock_name = OsString::from("furnish-test.lock");
        let first = acquire_lock(&root.open(), &root.0, &lock_name).expect("acquire first lock");
        let lock_root = root.0.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let directory = open(
                &lock_root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .expect("open lock directory for waiter");
            started_tx.send(()).expect("signal waiter start");
            let _lock =
                acquire_lock(&directory, &lock_root, &lock_name).expect("acquire second lock");
            acquired_tx.send(()).expect("signal waiter acquisition");
        });
        started_rx.recv().expect("waiter started");
        assert!(
            acquired_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
        drop(first);
        acquired_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("waiter acquired after release");
        waiter.join().expect("waiter completed");
    }
}
