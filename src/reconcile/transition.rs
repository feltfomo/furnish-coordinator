use super::{
    AppliedOperation, CodeKey, Entry, Failure, LedgerRecord, LedgerState, PendingIntent, Result,
    RunIdentity, TransitionPair, WRITABLE_REPRESENTATION, cleanup_unpublished_after_failure,
    exchange_names, fault_point, hash_regular, hash_source, owned_record, pending_record,
    remove_unpublished_stage, sha256_hex, stage_name, stage_symlink, stage_writable,
    symlink_target, sync_parent, verify_writable_destination,
};
use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::path::Path;

// transfer between representations. post-write verification completes before
// the ledger representation changes, in both directions.
pub(super) fn transition_representation(
    entry: &Entry,
    setpriv: &Path,
    index: usize,
    ledger: &mut LedgerState,
    identity: &RunIdentity,
    record: &LedgerRecord,
    parent: &OwnedFd,
    name: &OsStr,
) -> Result<()> {
    let canonical = &entry.filesystem_identity.canonical;
    let destination = &entry.filesystem_identity.destination;
    let from = record.representation;
    let to = entry.representation;
    let pair = TransitionPair::try_from((from, to)).map_err(|error| {
        Failure::new(CodeKey::TransitionRefused, destination, error.to_string())
    })?;
    let stage = stage_name(index);
    let recorded = OsStr::new(&record.applied_artifact_target);

    if to == WRITABLE_REPRESENTATION {
        // only sound when the current symlink is exactly the recorded one.
        let observed = symlink_target(&parent, &name).map_err(|errno| {
            Failure::syscall(
                CodeKey::TransitionRefused,
                destination,
                "readlinkat-transition",
                errno,
            )
        })?;
        if observed.target() != Some(recorded) {
            return Err(Failure::new(
                CodeKey::TransitionRefused,
                destination,
                "refusing to transfer a destination that is not the link recorded as furnish-owned",
            ));
        }
        let intended = hash_source(&entry.retained_artifact_target, destination)?;
        fault_point("pre-pending");
        let mut pending = pending_record(
            identity,
            entry,
            PendingIntent::Transition(pair),
            record.owned(),
            &stage,
            &intended,
        );
        pending.applied_artifact_target = record.applied_artifact_target.clone();
        ledger.commit(canonical, pending)?;
        fault_point("pending-committed");
        stage_writable(setpriv, &parent, &stage, entry, &intended)?;
        fault_point("stage-synced");
        if let Err(failure) = exchange_names(
            &parent,
            name,
            &stage,
            destination,
            CodeKey::TransitionRefused,
            "renameat2-exchange-transition",
        ) {
            return Err(cleanup_unpublished_after_failure(
                &parent,
                &stage,
                destination,
                failure,
            ));
        }
        fault_point("exchange-published");
        sync_parent(&parent, destination)?;
        verify_writable_destination(&parent, &name, destination, &intended)?;
        fault_point("verified");
        remove_unpublished_stage(&parent, &stage, destination)?;
        ledger.commit(
            canonical,
            owned_record(
                identity,
                entry,
                AppliedOperation::Update,
                record.owned(),
                &intended,
            ),
        )?;
        return Ok(());
    }

    // writable to symlink is automatic only when the destination still equals
    // its baseline. an edited file is never silently converted away.
    let Some(baseline) = record.baseline_hash.clone() else {
        return Err(Failure::new(
            CodeKey::TransitionRefused,
            destination,
            "refusing to transfer a writable destination with no recorded baseline",
        ));
    };
    let observed_hash = hash_regular(
        &parent,
        &name,
        destination,
        CodeKey::TransitionRefused,
        "read-writable-transition",
    )?;
    if observed_hash != baseline {
        return Err(Failure::new(
            CodeKey::TransitionRefused,
            destination,
            "refusing to transfer a writable destination that no longer matches its baseline",
        ));
    }
    let expected = OsStr::new(&entry.retained_artifact_target);
    fault_point("pre-pending");
    let pending = pending_record(
        identity,
        entry,
        PendingIntent::Transition(pair),
        record.owned(),
        &stage,
        &sha256_hex(entry.retained_artifact_target.as_bytes()),
    );
    ledger.commit(canonical, pending)?;
    fault_point("pending-committed");
    stage_symlink(setpriv, &parent, &stage, entry, expected)?;
    fault_point("stage-synced");
    if let Err(failure) = exchange_names(
        &parent,
        name,
        &stage,
        destination,
        CodeKey::TransitionRefused,
        "renameat2-exchange-transition",
    ) {
        return Err(cleanup_unpublished_after_failure(
            &parent,
            &stage,
            destination,
            failure,
        ));
    }
    fault_point("exchange-published");
    sync_parent(&parent, destination)?;
    let published = symlink_target(&parent, &name).map_err(|errno| {
        Failure::syscall(
            CodeKey::TransitionRefused,
            destination,
            "readlinkat-transition-published",
            errno,
        )
    })?;
    if published.target() != Some(expected) {
        return Err(Failure::new(
            CodeKey::TransitionRefused,
            destination,
            "post-transfer verification did not observe the intended link",
        ));
    }
    fault_point("verified");
    // the displaced object is the pristine regular file, proven equal to its
    // baseline above, so removing it destroys no work.
    remove_unpublished_stage(&parent, &stage, destination)?;
    let owned = owned_record(
        identity,
        entry,
        AppliedOperation::Update,
        record.owned(),
        &sha256_hex(entry.retained_artifact_target.as_bytes()),
    );
    ledger.commit(canonical, owned)?;
    Ok(())
}
