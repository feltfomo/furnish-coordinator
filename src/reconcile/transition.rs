use super::{
    AppliedOperation, CodeKey, Context, Entry, Failure, LedgerRecord, LedgerState, OpenDestination,
    PendingIntent, Publication, Result, RunIdentity, TransitionPair, WRITABLE_REPRESENTATION,
    fault_point, hash_regular, hash_source, remove_unpublished_stage, rename_or_clean, stage_name,
    stage_symlink, stage_writable, symlink_target, sync_parent, verify_writable_destination,
    witness,
};
use rustix::fs::RenameFlags;
use std::ffi::OsStr;
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
    open: &OpenDestination<'_>,
) -> Result<()> {
    let parent = &open.parent;
    let name = open.name.as_os_str();
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
        let observed = symlink_target(parent, name).at(
            CodeKey::TransitionRefused,
            destination,
            "readlinkat-transition",
        )?;
        if observed.target() != Some(recorded) {
            return Err(Failure::new(
                CodeKey::TransitionRefused,
                destination,
                "refusing to transfer a destination that is not the link recorded as furnish-owned",
            ));
        }
        let intended = hash_source(entry.target.path(), destination)?;
        return Publication {
            entry,
            identity,
            intent: PendingIntent::Transition(pair),
            applied_by: AppliedOperation::Update,
            prior: record.owned(),
            stage: &stage,
            witness: &intended,
            pending_artifact_target: Some(&record.applied_artifact_target),
        }
        .run(ledger, || {
            stage_writable(setpriv, parent, &stage, entry, &intended)?;
            fault_point("stage-synced");
            rename_or_clean(
                parent,
                name,
                &stage,
                destination,
                RenameFlags::EXCHANGE,
                CodeKey::TransitionRefused,
                "renameat2-exchange-transition",
            )?;
            fault_point("exchange-published");
            sync_parent(parent, destination)?;
            verify_writable_destination(parent, name, destination, &intended)?;
            fault_point("verified");
            remove_unpublished_stage(parent, &stage, destination)
        });
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
        parent,
        name,
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
    let expected = OsStr::new(entry.target.path());
    let intended = witness(entry.target.path().as_bytes());
    Publication {
        entry,
        identity,
        intent: PendingIntent::Transition(pair),
        applied_by: AppliedOperation::Update,
        prior: record.owned(),
        stage: &stage,
        witness: &intended,
        pending_artifact_target: None,
    }
    .run(ledger, || {
        stage_symlink(setpriv, parent, &stage, entry, expected)?;
        fault_point("stage-synced");
        rename_or_clean(
            parent,
            name,
            &stage,
            destination,
            RenameFlags::EXCHANGE,
            CodeKey::TransitionRefused,
            "renameat2-exchange-transition",
        )?;
        fault_point("exchange-published");
        sync_parent(parent, destination)?;
        let published = symlink_target(parent, name).at(
            CodeKey::TransitionRefused,
            destination,
            "readlinkat-transition-published",
        )?;
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
        remove_unpublished_stage(parent, &stage, destination)
    })
}
