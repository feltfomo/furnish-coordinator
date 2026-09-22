use super::observe::{
    hash_regular, observe_kind, symlink_target, verify_writable_destination, verify_writable_hash,
};
use super::stage::{
    DisplacedCleanup, cleanup_unpublished_after_failure, discard_displaced_under_policy,
    remove_verified_displaced,
};
use crate::diagnostic::{CodeKey, Context, Failure, Result};
use crate::fault::{fault_point, reverse_exchange_restore_fault};
use rustix::fs::{RenameFlags, fsync, renameat_with};
use std::ffi::OsStr;
use std::os::fd::OwnedFd;

// a bare exchange, for the recovery paths that are putting things back. the
// stage holds the bytes being restored there, so unlinking it on failure would
// destroy the very thing the restore exists to preserve. publication uses
// rename_or_clean instead.
pub(crate) fn exchange_names(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    key: CodeKey,
    operation: &'static str,
) -> Result<()> {
    renameat_with(parent, stage, parent, name, RenameFlags::EXCHANGE).at(
        key,
        destination,
        operation,
    )
}

// the rename is the publication, and a rename that fails on the way in always
// leaves a stage nothing else will come back for, so every publishing route
// shares both the attempt and the cleanup instead of each one remembering to
// unlink. the code key is the caller's, because the same failed rename means
// "lost a race" on the apply paths and "refused the transfer" on the
// representation change.
pub(crate) fn rename_or_clean(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    flags: RenameFlags,
    key: CodeKey,
    operation: &'static str,
) -> Result<()> {
    renameat_with(parent, stage, parent, name, flags).map_err(|errno| {
        cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::syscall(key, destination, operation, errno),
        )
    })
}

// a name that is occupied when the pre-publication check runs is something
// outside furnish arriving mid-flight, not a destination to replace.
fn refuse_occupied_name(parent: &OwnedFd, stage: &OsStr, destination: &str) -> Failure {
    cleanup_unpublished_after_failure(
        parent,
        stage,
        destination,
        Failure::new(
            CodeKey::PublishRace,
            destination,
            "destination appeared before atomic publish; refusing replacement",
        ),
    )
}

// the rename returning is not the end of publication; the parent directory
// entry reaching disk is. the two fault points stay either side of the sync so
// a crash test can still land in the window between them.
fn commit_to_disk(parent: &OwnedFd, destination: &str) -> Result<()> {
    fault_point("published");
    sync_parent(parent, destination)?;
    fault_point("published-synced");
    Ok(())
}

pub(crate) fn publish_new(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    expected: &OsStr,
) -> Result<()> {
    if symlink_target(parent, name)
        .at(CodeKey::PublishRace, destination, "fstatat-before-publish")?
        .exists()
    {
        return Err(refuse_occupied_name(parent, stage, destination));
    }
    rename_or_clean(
        parent,
        name,
        stage,
        destination,
        RenameFlags::NOREPLACE,
        CodeKey::PublishRace,
        "renameat2-noreplace-publish",
    )?;
    commit_to_disk(parent, destination)?;

    let final_target = symlink_target(parent, name).at(
        CodeKey::FinalVerification,
        destination,
        "readlinkat-final",
    )?;
    if final_target.target() != Some(expected) {
        return Err(Failure::new(
            CodeKey::FinalVerification,
            destination,
            "published destination failed exact-target verification",
        ));
    }
    Ok(())
}

pub(crate) fn publish_exchange(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    expected: &OsStr,
    recorded: &OsStr,
) -> Result<()> {
    rename_or_clean(
        parent,
        name,
        stage,
        destination,
        RenameFlags::EXCHANGE,
        CodeKey::PublishRace,
        "renameat2-exchange-publish",
    )?;
    fault_point("exchange-published");

    let published = symlink_target(parent, name).at(
        CodeKey::RepairVerification,
        destination,
        "readlinkat-published",
    )?;
    let displaced = symlink_target(parent, stage).at(
        CodeKey::RepairVerification,
        destination,
        "readlinkat-displaced",
    )?;
    if published.target() != Some(expected) || displaced.target() != Some(recorded) {
        return Err(Failure::new(
            CodeKey::RepairVerification,
            destination,
            "post-exchange verification did not observe the recorded link on both sides",
        ));
    }

    remove_verified_displaced(parent, stage, destination)?;
    commit_to_disk(parent, destination)
}

pub(crate) fn sync_parent(parent: &OwnedFd, destination: &str) -> Result<()> {
    fsync(parent).at(CodeKey::FinalVerification, destination, "fsync-parent")
}

pub(crate) fn rollback_exchange(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    prior_hash: &str,
    intended_hash: &str,
) -> Result<()> {
    const RESTORE: &str = "renameat2-exchange-restore-pending";
    reverse_exchange_restore_fault().at(CodeKey::PendingRecovery, destination, RESTORE)?;
    renameat_with(parent, stage, parent, name, RenameFlags::EXCHANGE).at(
        CodeKey::PendingRecovery,
        destination,
        RESTORE,
    )?;
    sync_parent(parent, destination)?;
    verify_writable_hash(
        parent,
        name,
        destination,
        prior_hash,
        "read-restored-destination",
    )?;
    verify_writable_hash(
        parent,
        stage,
        destination,
        intended_hash,
        "read-restored-stage",
    )?;
    Ok(())
}

pub(crate) fn publish_writable_new(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    intended_hash: &str,
) -> Result<()> {
    fault_point("stage-synced");
    if observe_kind(parent, name, destination)?.is_some() {
        return Err(refuse_occupied_name(parent, stage, destination));
    }
    rename_or_clean(
        parent,
        name,
        stage,
        destination,
        RenameFlags::NOREPLACE,
        CodeKey::PublishRace,
        "renameat2-noreplace-publish",
    )?;
    commit_to_disk(parent, destination)?;
    verify_writable_destination(parent, name, destination, intended_hash)?;
    fault_point("verified");
    Ok(())
}

pub(crate) fn publish_writable_exchange(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    expected_displaced: &str,
    intended_hash: &str,
    cleanup: DisplacedCleanup,
) -> Result<()> {
    fault_point("stage-synced");
    rename_or_clean(
        parent,
        name,
        stage,
        destination,
        RenameFlags::EXCHANGE,
        CodeKey::PublishRace,
        "renameat2-exchange-publish",
    )?;
    fault_point("exchange-published");
    // the displaced hash must equal the pre-publication witness.
    let displaced_hash = hash_regular(
        parent,
        stage,
        destination,
        CodeKey::PublishRace,
        "read-displaced",
    )?;
    if displaced_hash != expected_displaced {
        rollback_exchange(
            parent,
            name,
            stage,
            destination,
            &displaced_hash,
            intended_hash,
        )?;
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::new(
                CodeKey::PublishRace,
                destination,
                "destination changed between observation and publication; exchange reversed",
            ),
        ));
    }
    match cleanup {
        DisplacedCleanup::VerifiedOwned => remove_verified_displaced(parent, stage, destination)?,
        DisplacedCleanup::PolicyDisplaced => {
            discard_displaced_under_policy(parent, stage, destination)?;
        }
    }
    commit_to_disk(parent, destination)?;
    verify_writable_destination(parent, name, destination, intended_hash)?;
    fault_point("verified");
    Ok(())
}
