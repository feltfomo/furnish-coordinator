use crate::diagnostic::{CodeKey, Failure, Result};
use rustix::fs::{AtFlags, unlinkat};
use rustix::io::Errno;
use std::ffi::OsStr;

#[cfg(test)]
thread_local! {
    pub(crate) static FAIL_VERIFIED_DISPLACED_CLEANUP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(crate) fn remove_unpublished_stage<Fd: std::os::fd::AsFd>(
    parent: Fd,
    stage: &OsStr,
    destination: &str,
) -> Result<()> {
    match unlinkat(parent, stage, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(errno) => Err(Failure::syscall(
            CodeKey::StagingVerification,
            destination,
            "unlinkat-unpublished-stage",
            errno,
        )),
    }
}

pub(crate) fn cleanup_unpublished_after_failure<Fd: std::os::fd::AsFd>(
    parent: Fd,
    stage: &OsStr,
    destination: &str,
    mut failure: Failure,
) -> Failure {
    if let Err(cleanup) = remove_unpublished_stage(parent, stage, destination) {
        failure.cleanup_warning = Some(Box::new(cleanup));
    }
    failure
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DisplacedCleanup {
    VerifiedOwned,
    PolicyDisplaced,
}

pub(crate) fn discard_displaced_under_policy<Fd: std::os::fd::AsFd>(
    parent: Fd,
    stage: &OsStr,
    destination: &str,
) -> Result<()> {
    unlinkat(parent, stage, AtFlags::empty()).map_err(|errno| {
        Failure::syscall(
            CodeKey::FinalVerification,
            destination,
            "unlinkat-policy-displaced",
            errno,
        )
    })
}

pub(crate) fn remove_verified_displaced<Fd: std::os::fd::AsFd>(
    parent: Fd,
    stage: &OsStr,
    destination: &str,
) -> Result<()> {
    #[cfg(test)]
    if FAIL_VERIFIED_DISPLACED_CLEANUP.with(|fault| fault.replace(false)) {
        return Err(Failure::syscall(
            CodeKey::FinalVerification,
            destination,
            "unlinkat-verified-displaced",
            Errno::IO,
        ));
    }
    unlinkat(parent, stage, AtFlags::empty()).map_err(|errno| {
        Failure::syscall(
            CodeKey::FinalVerification,
            destination,
            "unlinkat-verified-displaced",
            errno,
        )
    })
}

#[cfg(test)]
mod cleanup_tests {
    use super::remove_unpublished_stage;
    use rustix::fs::{Mode, OFlags, open};
    use std::ffi::OsStr;
    use std::path::PathBuf;

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "furnish-fs-cleanup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn unpublished_cleanup_accepts_only_absence() {
        let path = directory();
        let parent = open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        remove_unpublished_stage(&parent, OsStr::new("missing"), "/dest").unwrap();
        std::fs::create_dir(path.join("directory")).unwrap();
        let failure = remove_unpublished_stage(&parent, OsStr::new("directory"), "/dest")
            .expect_err("directory unlink must be real");
        assert_eq!(
            failure.cause.as_ref().map(|cause| cause.operation),
            Some("unlinkat-unpublished-stage")
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
