use super::{
    CodeKey, Entry, Failure, Result, cleanup_unpublished_after_failure, profile_for,
    remove_unpublished_stage, run_executor, symlink_target,
};
use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::path::Path;

pub(super) fn stage_symlink(
    setpriv: &Path,
    parent: &OwnedFd,
    stage: &OsStr,
    entry: &Entry,
    expected: &OsStr,
) -> Result<()> {
    let destination = &entry.filesystem_identity.destination;
    remove_unpublished_stage(parent, stage, destination)?;
    let profile = profile_for(
        &entry.executor.identity,
        entry.executor.protocol_version,
        entry.representation,
    )
    .ok_or_else(|| {
        Failure::new(
            CodeKey::UnsupportedExecutor,
            destination,
            "no qualified executor for this entry",
        )
    })?;
    run_executor(
        setpriv,
        parent,
        stage,
        &entry.retained_artifact_target,
        &entry.authority,
        profile,
    )?;
    let staged = symlink_target(parent, stage).map_err(|errno| {
        Failure::syscall(
            CodeKey::StagingVerification,
            destination,
            "readlinkat-staging",
            errno,
        )
    })?;
    if staged.target() != Some(expected) {
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::new(
                CodeKey::StagingVerification,
                destination,
                "native executor produced an unexpected staging object",
            ),
        ));
    }
    Ok(())
}
