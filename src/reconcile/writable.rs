use super::{
    AppliedOperation, CodeKey, ConflictPolicy, DisplacedCleanup, Entry, Failure, LedgerRecord,
    LedgerState, OpenDestination, PendingIntent, REGULAR_MODE, ReconcileContext, RecordStatus,
    Result, RunIdentity, WRITABLE_FILE_MODE, baseline_for, carry_applied_state,
    cleanup_unpublished_after_failure, fault_point, hash_regular, observe_kind, observe_mode,
    owned_record, pending_record, profile_for, publish_writable_exchange, publish_writable_new,
    remove_unpublished_stage, run_executor, sha256_hex, stage_name, verify_writable_destination,
};
use std::ffi::OsStr;
use std::fs;
use std::os::fd::OwnedFd;
use std::path::Path;

pub(super) fn hash_source(source: &str, destination: &str) -> Result<String> {
    let bytes = fs::read(source).map_err(|error| {
        Failure::io(
            CodeKey::UnresolvableDesiredTarget,
            destination,
            "read-source-artifact",
            &error,
        )
    })?;
    Ok(sha256_hex(&bytes))
}

// the coordinator re-derives the staged content itself rather than trusting the
// executor's exit status, so an executor that succeeded while producing the
// wrong bytes cannot reach a destination.
pub(super) fn stage_writable(
    setpriv: &Path,
    parent: &OwnedFd,
    stage: &OsStr,
    entry: &Entry,
    intended_hash: &str,
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
    fault_point("stage-written");
    if observe_kind(parent, stage, destination)? != Some(REGULAR_MODE) {
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
    let staged_hash = hash_regular(
        parent,
        stage,
        destination,
        CodeKey::StagingVerification,
        "read-staging",
    )?;
    if staged_hash != intended_hash {
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::new(
                CodeKey::StagingVerification,
                destination,
                "staged content does not hash to the intended source content",
            ),
        ));
    }
    let mode = observe_mode(parent, stage, destination)?;
    if mode != WRITABLE_FILE_MODE {
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::new(
                CodeKey::StagingVerification,
                destination,
                format!("staged file mode is {mode:04o}; expected {WRITABLE_FILE_MODE:04o}"),
            ),
        ));
    }
    Ok(())
}

// Row three and source-wins share one pending-record bracket after the caller
// selects publication.
pub(super) struct WritableUpdate<'a> {
    pub(super) entry: &'a Entry,
    pub(super) index: usize,
    pub(super) record: &'a LedgerRecord,
    pub(super) destination: &'a OpenDestination<'a>,
    pub(super) expected_displaced: &'a str,
    pub(super) intended: &'a str,
}

pub(super) fn publish_writable_update(
    context: &mut ReconcileContext<'_>,
    update: WritableUpdate<'_>,
) -> Result<()> {
    let WritableUpdate {
        entry,
        index,
        record,
        destination: open,
        expected_displaced,
        intended,
    } = update;
    let setpriv = context.setpriv;
    let ledger = &mut context.ledger;
    let identity = context.identity;
    let parent = &open.parent;
    let name = open.name.as_os_str();
    let canonical = &entry.filesystem_identity.canonical;
    let destination = &entry.filesystem_identity.destination;
    let stage = stage_name(index);
    fault_point("pre-pending");
    ledger.commit(
        canonical,
        pending_record(
            identity,
            entry,
            PendingIntent::Apply(AppliedOperation::Update),
            record.owned(),
            &stage,
            intended,
        ),
    )?;
    fault_point("pending-committed");
    stage_writable(setpriv, parent, &stage, entry, intended)?;
    publish_writable_exchange(
        parent,
        name,
        &stage,
        destination,
        expected_displaced,
        intended,
        if entry.on_conflict == ConflictPolicy::SourceWins
            && record.baseline_hash.as_deref() != Some(expected_displaced)
        {
            DisplacedCleanup::PolicyDisplaced
        } else {
            DisplacedCleanup::VerifiedOwned
        },
    )?;
    ledger.commit(
        canonical,
        owned_record(
            identity,
            entry,
            AppliedOperation::Update,
            record.owned(),
            intended,
        ),
    )?;
    Ok(())
}

// first ownership of an absent destination, the self-heal for an owned one that
// has gone missing, and the convergence for a destination that already equals
// the source while the recorded baseline does not. divergent content is refused
// rather than reconciled.
pub(super) fn reconcile_writable_entry(
    entry: &Entry,
    setpriv: &Path,
    index: usize,
    ledger: &mut LedgerState,
    identity: &RunIdentity,
    open: &OpenDestination<'_>,
) -> Result<()> {
    let canonical = open.canonical();
    let destination = open.destination();
    let parent = &open.parent;
    let name = open.name.as_os_str();
    let intended = hash_source(&entry.retained_artifact_target, destination)?;
    let record = ledger.record(canonical).cloned();
    let observed = observe_kind(&parent, &name, destination)?;

    match (observed, record) {
        // first ownership, and the self-heal for an owned destination that has
        // gone missing. both publish into an absent name; they differ only in
        // what the record says about how it was decided.
        (None, prior) => {
            let applied_by = if prior.is_some() {
                AppliedOperation::Repair
            } else {
                AppliedOperation::New
            };
            let stage = stage_name(index);
            fault_point("pre-pending");
            ledger.commit(
                canonical,
                pending_record(
                    identity,
                    entry,
                    PendingIntent::Apply(applied_by),
                    prior.as_ref().and_then(LedgerRecord::owned),
                    &stage,
                    &intended,
                ),
            )?;
            fault_point("pending-committed");
            stage_writable(setpriv, &parent, &stage, entry, &intended)?;
            publish_writable_new(&parent, &name, &stage, destination, &intended)?;
            ledger.commit(
                canonical,
                owned_record(
                    identity,
                    entry,
                    applied_by,
                    prior.as_ref().and_then(LedgerRecord::owned),
                    &intended,
                ),
            )?;
            Ok(())
        }
        // refused by default even when the content already equals the source.
        // equality is not adoption proof.
        (Some(_), None) => Err(Failure::new(
            CodeKey::ConflictingDestination,
            destination,
            "refusing to take ownership of a pre-existing destination: applied state records no furnish ownership of it",
        )),
        (Some(kind), Some(record)) => {
            if kind != REGULAR_MODE {
                return Err(Failure::new(
                    CodeKey::ConflictingDestination,
                    destination,
                    "refusing a destination that is not a regular file",
                ));
            }
            let observed_hash = hash_regular(
                &parent,
                &name,
                destination,
                CodeKey::ContentVerification,
                "read-destination",
            )?;
            let Some(baseline) = record.baseline_hash.as_deref() else {
                // absence of a baseline is not a diverged baseline. a record
                // that cannot say what furnish last wrote cannot authorise
                // overwriting whatever is there now, whichever policy the
                // declaration carries, so this refuses in the same register
                // the transition path already refuses in.
                return Err(Failure::new(
                    CodeKey::ConflictingDestination,
                    destination,
                    "refusing to reconcile a writable destination with no recorded baseline",
                ));
            };
            let d_eq_s = observed_hash == intended;
            let d_eq_b = observed_hash == baseline;
            let s_eq_b = baseline == intended.as_str();

            if d_eq_s {
                if s_eq_b {
                    // row one. nothing to publish, but the record is refreshed
                    // so that when this last reconciled has a live answer here
                    // and not only on the symlink steady-state path.
                    let mut refreshed = identity.record(
                        entry,
                        RecordStatus::Owned {
                            applied_by: record
                                .owned()
                                .map_or(AppliedOperation::Update, |owned| owned.applied_by),
                            unresolved_retirement: None,
                        },
                    );
                    carry_applied_state(&record, &mut refreshed);
                    ledger.commit(canonical, refreshed)?;
                    return Ok(());
                }
                // row five. the crash window after the destination was
                // replaced and before the baseline was committed, so the
                // representation is verified and the baseline advances under
                // the applied_by this record already carries rather than
                // being reported as a conflict.
                verify_writable_destination(&parent, &name, destination, &intended)?;
                ledger.commit(
                    canonical,
                    owned_record(
                        identity,
                        entry,
                        record
                            .owned()
                            .map_or(AppliedOperation::Update, |owned| owned.applied_by),
                        record.owned(),
                        &intended,
                    ),
                )?;
                return Ok(());
            }

            if s_eq_b {
                // row two. the source has not changed but the destination has,
                // so a user edited the file after furnish wrote it. the edit
                // is preserved and no reload is triggered.
                let mut refreshed = identity.record(
                    entry,
                    RecordStatus::Owned {
                        applied_by: record
                            .owned()
                            .map_or(AppliedOperation::Update, |owned| owned.applied_by),
                        unresolved_retirement: None,
                    },
                );
                carry_applied_state(&record, &mut refreshed);
                ledger.commit(canonical, refreshed)?;
                return Ok(());
            }

            if d_eq_b {
                // row three. the source changed and the destination is still
                // exactly what furnish last wrote, so the new version goes in
                // through the exchange route. the bytes it will displace are
                // the ones just measured, which is what the recheck expects.
                return {
                    let mut context = ReconcileContext::new(setpriv, ledger, identity);
                    publish_writable_update(
                        &mut context,
                        WritableUpdate {
                            entry,
                            index,
                            record: &record,
                            destination: open,
                            expected_displaced: &observed_hash,
                            intended: &intended,
                        },
                    )
                };
            }

            // row four. the destination and the source have both moved off the
            // baseline, so nothing here is derivable from the hashes and the
            // declaration's policy is the only thing left to decide it.
            match entry.on_conflict {
                ConflictPolicy::Error => Err(Failure::conflict(
                    destination,
                    Some(baseline),
                    &intended,
                    &observed_hash,
                )),
                ConflictPolicy::SourceWins => {
                    let mut context = ReconcileContext::new(setpriv, ledger, identity);
                    publish_writable_update(
                        &mut context,
                        WritableUpdate {
                            entry,
                            index,
                            record: &record,
                            destination: open,
                            expected_displaced: &observed_hash,
                            intended: &intended,
                        },
                    )
                }
                ConflictPolicy::RuntimeWins => {
                    // the destination stays as it is and the baseline advances
                    // to the source that was refused, so a later run sees a
                    // settled decision instead of the same conflict again. the
                    // witness moves with it because every writable owned
                    // record in this file keeps the two equal.
                    let mut refreshed = identity.record(
                        entry,
                        RecordStatus::Owned {
                            applied_by: record
                                .owned()
                                .map_or(AppliedOperation::Update, |owned| owned.applied_by),
                            unresolved_retirement: None,
                        },
                    );
                    carry_applied_state(&record, &mut refreshed);
                    refreshed.baseline_hash = baseline_for(entry.representation, &intended);
                    refreshed.intended_witness_hash = Some(intended.clone());
                    ledger.commit(canonical, refreshed)?;
                    Ok(())
                }
            }
        }
    }
}
