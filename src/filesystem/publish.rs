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
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::new(
                CodeKey::PublishRace,
                destination,
                "destination appeared before atomic publish; refusing replacement",
            ),
        ));
    }

    if let Err(errno) = renameat_with(parent, stage, parent, name, RenameFlags::NOREPLACE) {
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::syscall(
                CodeKey::PublishRace,
                destination,
                "renameat2-noreplace-publish",
                errno,
            ),
        ));
    }

    fault_point("published");
    sync_parent(parent, destination)?;
    fault_point("published-synced");

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
    if let Err(errno) = renameat_with(parent, stage, parent, name, RenameFlags::EXCHANGE) {
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::syscall(
                CodeKey::PublishRace,
                destination,
                "renameat2-exchange-publish",
                errno,
            ),
        ));
    }
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
    fault_point("published");
    sync_parent(parent, destination)?;
    fault_point("published-synced");
    Ok(())
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
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::new(
                CodeKey::PublishRace,
                destination,
                "destination appeared before atomic publish; refusing replacement",
            ),
        ));
    }
    if let Err(errno) = renameat_with(parent, stage, parent, name, RenameFlags::NOREPLACE) {
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::syscall(
                CodeKey::PublishRace,
                destination,
                "renameat2-noreplace-publish",
                errno,
            ),
        ));
    }
    fault_point("published");
    sync_parent(parent, destination)?;
    fault_point("published-synced");
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
    if let Err(errno) = renameat_with(parent, stage, parent, name, RenameFlags::EXCHANGE) {
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::syscall(
                CodeKey::PublishRace,
                destination,
                "renameat2-exchange-publish",
                errno,
            ),
        ));
    }
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
    fault_point("published");
    sync_parent(parent, destination)?;
    fault_point("published-synced");
    verify_writable_destination(parent, name, destination, intended_hash)?;
    fault_point("verified");
    Ok(())
}
