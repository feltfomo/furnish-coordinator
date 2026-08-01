use super::{
    AppliedOperation, CodeKey, ConflictPolicy, Entry, Failure, LedgerRecord, LedgerState,
    NATIVE_REPRESENTATION, OpenDestination, PendingIntent, REGULAR_MODE, ReconcileContext,
    RecordStatus, Representation, Result, RunIdentity, SYMLINK_MODE, TransitionPair,
    WRITABLE_REPRESENTATION, baseline_for, cleanup_unpublished_after_failure,
    discard_displaced_under_policy, exchange_names, hash_regular, observe_kind, open_parent,
    owned_record, remove_unpublished_stage, remove_verified_displaced, rollback_exchange,
    sha256_hex, symlink_target, sync_parent, verify_writable_destination, verify_writable_hash,
};
use std::ffi::{OsStr, OsString};
use std::path::Path;

pub(super) fn representation_of_kind(kind: u32) -> Option<Representation> {
    match kind {
        SYMLINK_MODE => Some(NATIVE_REPRESENTATION),
        REGULAR_MODE => Some(WRITABLE_REPRESENTATION),
        _ => None,
    }
}

// recovery promotes a pending record only when the destination proves the
// intended publication landed. otherwise it restores an exact prior-owned
// snapshot when the prior representation is still present. a legacy record
// that proves neither direction preserves every transaction name and fails.
pub(super) fn recover_pending(
    entry: &Entry,
    ledger: &mut LedgerState,
    identity: &RunIdentity,
) -> Result<()> {
    let canonical = &entry.filesystem_identity.canonical;
    let destination = &entry.filesystem_identity.destination;
    let Some(record) = ledger.record(canonical).cloned() else {
        return Ok(());
    };
    if !record.is_pending() {
        return Ok(());
    }

    let (parent, name) = open_parent(destination, &record.managed_root)?;
    let stage = record.stage_name().map(OsString::from);
    let observed = observe_kind(&parent, &name, destination)?;
    let artifact_matches = record.applied_artifact_target == entry.retained_artifact_target;

    if let Some(PendingIntent::Transition(pair)) = record.pending_intent() {
        let open = OpenDestination {
            parent,
            name,
            identity: &entry.filesystem_identity,
        };
        let mut context = ReconcileContext::new(Path::new(""), ledger, identity);
        return recover_transition(
            &mut context,
            TransitionRecovery {
                entry,
                record: &record,
                destination: &open,
                observed,
                stage,
                pair,
            },
        );
    }

    let authored = match observed {
        None => false,
        Some(kind) if representation_of_kind(kind) != Some(record.representation) => false,
        Some(kind) if kind == REGULAR_MODE => {
            match (&record.intended_witness_hash, artifact_matches) {
                (Some(intended), true) => {
                    &hash_regular(
                        &parent,
                        &name,
                        destination,
                        CodeKey::PendingRecovery,
                        "read-pending-recovery",
                    )? == intended
                }
                _ => false,
            }
        }
        Some(_) => {
            let target = symlink_target(&parent, &name).map_err(|errno| {
                Failure::syscall(
                    CodeKey::PendingRecovery,
                    destination,
                    "readlinkat-pending-recovery",
                    errno,
                )
            })?;
            artifact_matches && target.target() == Some(OsStr::new(&record.applied_artifact_target))
        }
    };

    if authored {
        // converted to owned at the source this record was pending for, not at
        // the current one. a stale pending record converges to owned-at-old-S
        // and the ordinary path then takes it forward, both steps recorded.
        let mut owned = record.clone();
        let Some(PendingIntent::Apply(applied_by)) = record.pending_intent() else {
            return Err(Failure::new(
                CodeKey::PendingRecovery,
                destination,
                "pending apply recovery requires an apply intent; both transaction names are preserved",
            ));
        };
        owned.status = RecordStatus::Owned {
            applied_by,
            unresolved_retirement: None,
        };
        owned.baseline_hash = record
            .intended_witness_hash
            .as_deref()
            .and_then(|witness| baseline_for(record.representation, witness));
        owned.applied_operation_generation = record.applied_operation_generation.saturating_add(1);
        // an exchange publish displaces the old destination to the stage name
        // instead of consuming it, so recovery proves the displaced side from
        // the exact prior snapshot before removing it.
        if let Some(stage) = stage.as_deref() {
            match observe_kind(&parent, stage, destination)? {
                None => {}
                Some(REGULAR_MODE) => {
                    let displaced_hash = hash_regular(
                        &parent,
                        stage,
                        destination,
                        CodeKey::PendingRecovery,
                        "read-displaced-pending",
                    )?;
                    if record.baseline_hash.as_deref() != Some(displaced_hash.as_str())
                        && entry.on_conflict != ConflictPolicy::SourceWins
                    {
                        let Some(intended) = record.intended_witness_hash.as_deref() else {
                            return Err(Failure::new(
                                CodeKey::PendingRecovery,
                                destination,
                                "pending writable transaction carries no intended witness",
                            ));
                        };
                        rollback_exchange(
                            &parent,
                            name.as_os_str(),
                            stage,
                            destination,
                            &displaced_hash,
                            intended,
                        )?;
                        let Some(prior) = record.prior_owned() else {
                            return Err(Failure::new(
                                CodeKey::PendingRecovery,
                                destination,
                                "writable rollback completed but no prior owned snapshot exists",
                            ));
                        };
                        ledger.commit(canonical, prior.restore())?;
                        return Err(cleanup_unpublished_after_failure(
                            &parent,
                            stage,
                            destination,
                            Failure::new(
                                CodeKey::PendingRecovery,
                                destination,
                                "destination was edited while a writable update was publishing; the edited content was restored and the update was not recorded",
                            ),
                        ));
                    }
                    if entry.on_conflict == ConflictPolicy::SourceWins
                        && record.baseline_hash.as_deref() != Some(displaced_hash.as_str())
                    {
                        discard_displaced_under_policy(&parent, stage, destination)?;
                    } else {
                        remove_verified_displaced(&parent, stage, destination)?;
                    }
                }
                Some(SYMLINK_MODE) => {
                    let Some(prior) = record.prior_owned() else {
                        return Err(Failure::new(
                            CodeKey::PendingRecovery,
                            destination,
                            "displaced symlink has no prior owned snapshot; both names are preserved",
                        ));
                    };
                    if prior.representation != NATIVE_REPRESENTATION {
                        return Err(Failure::new(
                            CodeKey::PendingRecovery,
                            destination,
                            "displaced symlink does not match the prior representation; both names are preserved",
                        ));
                    }
                    let displaced = symlink_target(&parent, stage).map_err(|errno| {
                        Failure::syscall(
                            CodeKey::PendingRecovery,
                            destination,
                            "readlinkat-displaced-pending",
                            errno,
                        )
                    })?;
                    if displaced.target() != Some(OsStr::new(&prior.applied_artifact_target)) {
                        return Err(Failure::new(
                            CodeKey::PendingRecovery,
                            destination,
                            "displaced symlink does not match prior ownership; both names are preserved",
                        ));
                    }
                    remove_verified_displaced(&parent, stage, destination)?;
                }
                Some(_) => {
                    return Err(Failure::new(
                        CodeKey::PendingRecovery,
                        destination,
                        "displaced transaction side has an unowned representation; both names are preserved",
                    ));
                }
            }
        }
        ledger.commit(canonical, owned)?;
        return Ok(());
    }

    if let Some(prior) = record.prior_owned() {
        let prior_kind = observed.and_then(representation_of_kind);
        if prior_kind != Some(prior.representation) {
            return Err(Failure::new(
                CodeKey::PendingRecovery,
                destination,
                "pending transaction is neither forward-complete nor at its prior owned representation; both names are preserved",
            ));
        }
        if prior.representation == NATIVE_REPRESENTATION {
            let target = symlink_target(&parent, &name).map_err(|errno| {
                Failure::syscall(
                    CodeKey::PendingRecovery,
                    destination,
                    "readlinkat-prior-owned",
                    errno,
                )
            })?;
            if target.target() != Some(OsStr::new(&prior.applied_artifact_target)) {
                return Err(Failure::new(
                    CodeKey::PendingRecovery,
                    destination,
                    "pending transaction does not match its prior owned symlink; both names are preserved",
                ));
            }
        } else if prior.representation == WRITABLE_REPRESENTATION {
            let Some(baseline) = prior.baseline_hash.as_deref() else {
                return Err(Failure::new(
                    CodeKey::PendingRecovery,
                    destination,
                    "prior writable ownership carries no baseline; both names are preserved",
                ));
            };
            verify_writable_hash(&parent, &name, destination, baseline, "read-prior-owned")?;
        }
        if let Some(stage) = stage.as_deref()
            && observe_kind(&parent, stage, destination)?.is_some()
        {
            let Some(intended) = record.intended_witness_hash.as_deref() else {
                return Err(Failure::new(
                    CodeKey::PendingRecovery,
                    destination,
                    "pending transaction carries no intended witness; both names are preserved",
                ));
            };
            if record.representation == WRITABLE_REPRESENTATION {
                verify_writable_hash(
                    &parent,
                    stage,
                    destination,
                    intended,
                    "read-unpublished-pending",
                )?;
            }
            remove_unpublished_stage(&parent, stage, destination)?;
        }
        ledger.commit(canonical, prior.restore())?;
        return Ok(());
    }

    if observed.is_none() {
        if let Some(stage) = stage.as_deref()
            && observe_kind(&parent, stage, destination)?.is_some()
        {
            let Some(intended) = record.intended_witness_hash.as_deref() else {
                return Err(Failure::new(
                    CodeKey::PendingRecovery,
                    destination,
                    "pending acquisition carries no intended witness; the stage is preserved",
                ));
            };
            if record.representation == WRITABLE_REPRESENTATION {
                verify_writable_hash(
                    &parent,
                    stage,
                    destination,
                    intended,
                    "read-unpublished-acquisition",
                )?;
            }
            remove_unpublished_stage(&parent, stage, destination)?;
        }
        ledger.retire(canonical)?;
        return Ok(());
    }

    Err(Failure::new(
        CodeKey::PendingRecovery,
        destination,
        "pending transaction has no prior owned snapshot and cannot converge backward; both names are preserved",
    ))
}

// recovery for a crash between the exchange and the ledger advancing. the
// destination already holds the new representation and the displaced object
// sits at the stage name; for a writable source that displaced object may hold
// edited user bytes, so it is never unlinked without being hashed against the
// baseline first.
pub(super) struct TransitionRecovery<'a> {
    pub(super) entry: &'a Entry,
    pub(super) record: &'a LedgerRecord,
    pub(super) destination: &'a OpenDestination<'a>,
    pub(super) observed: Option<u32>,
    pub(super) stage: Option<OsString>,
    pub(super) pair: TransitionPair,
}

pub(super) fn recover_transition(
    context: &mut ReconcileContext<'_>,
    recovery: TransitionRecovery<'_>,
) -> Result<()> {
    let TransitionRecovery {
        entry,
        record,
        destination: open,
        observed,
        stage,
        pair,
    } = recovery;
    let ledger = &mut context.ledger;
    let identity = context.identity;
    let parent = &open.parent;
    let name = open.name.as_os_str();
    let canonical = &entry.filesystem_identity.canonical;
    let destination = &entry.filesystem_identity.destination;
    let target_representation = pair.target();
    let source_representation = pair.source();
    let observed_representation = observed.and_then(representation_of_kind);
    let stage = stage.ok_or_else(|| {
        Failure::new(
            CodeKey::TransitionRefused,
            destination,
            "pending transition record carries no staging name",
        )
    })?;

    // the exchange never happened, so the destination must still prove the
    // exact prior-owned representation before its staged scratch is removed.
    if observed_representation == Some(source_representation) {
        let Some(prior) = record.prior_owned() else {
            return Err(Failure::new(
                CodeKey::TransitionRefused,
                destination,
                "pending transition has no prior owned snapshot; both names are preserved",
            ));
        };
        if prior.representation != source_representation {
            return Err(Failure::new(
                CodeKey::TransitionRefused,
                destination,
                "pending transition prior snapshot names a different representation; both names are preserved",
            ));
        }
        if source_representation == WRITABLE_REPRESENTATION {
            let Some(baseline) = prior.baseline_hash.as_deref() else {
                return Err(Failure::new(
                    CodeKey::TransitionRefused,
                    destination,
                    "prior writable ownership carries no baseline; both names are preserved",
                ));
            };
            verify_writable_hash(
                parent,
                name,
                destination,
                baseline,
                "read-prior-owned-transition",
            )?;
        } else {
            let target = symlink_target(parent, name).map_err(|errno| {
                Failure::syscall(
                    CodeKey::TransitionRefused,
                    destination,
                    "readlinkat-prior-owned-transition",
                    errno,
                )
            })?;
            if target.target() != Some(OsStr::new(&prior.applied_artifact_target)) {
                return Err(Failure::new(
                    CodeKey::TransitionRefused,
                    destination,
                    "destination does not match prior symlink ownership; both names are preserved",
                ));
            }
        }
        if observe_kind(parent, &stage, destination)?.is_some() {
            if target_representation == WRITABLE_REPRESENTATION {
                let Some(intended) = record.intended_witness_hash.as_deref() else {
                    return Err(Failure::new(
                        CodeKey::TransitionRefused,
                        destination,
                        "pending transition carries no intended witness; both names are preserved",
                    ));
                };
                verify_writable_hash(
                    parent,
                    &stage,
                    destination,
                    intended,
                    "read-unpublished-transition",
                )?;
            } else {
                let target = symlink_target(parent, &stage).map_err(|errno| {
                    Failure::syscall(
                        CodeKey::TransitionRefused,
                        destination,
                        "readlinkat-unpublished-transition",
                        errno,
                    )
                })?;
                if target.target() != Some(OsStr::new(&record.applied_artifact_target)) {
                    return Err(Failure::new(
                        CodeKey::TransitionRefused,
                        destination,
                        "staged transition does not match its intended symlink; both names are preserved",
                    ));
                }
            }
            remove_unpublished_stage(parent, &stage, destination)?;
        }
        ledger.commit(canonical, prior.restore())?;
        return Ok(());
    }

    if observed_representation != Some(target_representation) {
        return Err(Failure::new(
            CodeKey::TransitionRefused,
            destination,
            "destination is neither side of the pending transition; refusing",
        ));
    }

    // forward, so both the new destination and the displaced prior side are
    // proved before the displaced object is removed.
    if target_representation == WRITABLE_REPRESENTATION {
        let Some(intended) = record.intended_witness_hash.clone() else {
            return Err(Failure::new(
                CodeKey::TransitionRefused,
                destination,
                "pending transition record carries no intended content hash",
            ));
        };
        let Some(prior) = record.prior_owned() else {
            return Err(Failure::new(
                CodeKey::TransitionRefused,
                destination,
                "completed transition has no prior owned snapshot; both names are preserved",
            ));
        };
        verify_writable_destination(parent, name, destination, &intended)?;
        let displaced = symlink_target(parent, &stage).map_err(|errno| {
            Failure::syscall(
                CodeKey::TransitionRefused,
                destination,
                "readlinkat-displaced-transition",
                errno,
            )
        })?;
        if displaced.target() != Some(OsStr::new(&prior.applied_artifact_target)) {
            return Err(Failure::new(
                CodeKey::TransitionRefused,
                destination,
                "displaced transition side does not match prior symlink ownership; both names are preserved",
            ));
        }
        remove_verified_displaced(parent, &stage, destination)?;
        let prior = prior.restore();
        ledger.commit(
            canonical,
            owned_record(
                identity,
                entry,
                AppliedOperation::Update,
                prior.owned(),
                &intended,
            ),
        )?;
        return Ok(());
    }

    // forward into symlink. the displaced regular file must match the exact
    // prior snapshot or be restored and retained as user-edited data.
    let Some(prior) = record.prior_owned() else {
        return Err(Failure::new(
            CodeKey::TransitionRefused,
            destination,
            "completed transition has no prior owned snapshot; both names are preserved",
        ));
    };
    let displaced_hash = hash_regular(
        parent,
        &stage,
        destination,
        CodeKey::TransitionRefused,
        "read-displaced-writable",
    )?;
    let pristine = prior.baseline_hash.as_deref() == Some(displaced_hash.as_str());
    if !pristine {
        exchange_names(
            parent,
            name,
            &stage,
            destination,
            CodeKey::TransitionRefused,
            "renameat2-exchange-restore",
        )?;
        sync_parent(parent, destination)?;
        verify_writable_hash(
            parent,
            name,
            destination,
            &displaced_hash,
            "read-restored-transition-destination",
        )?;
        let restored_stage = symlink_target(parent, &stage).map_err(|errno| {
            Failure::syscall(
                CodeKey::TransitionRefused,
                destination,
                "readlinkat-restored-transition-stage",
                errno,
            )
        })?;
        if restored_stage.target() != Some(OsStr::new(&record.applied_artifact_target)) {
            return Err(Failure::new(
                CodeKey::TransitionRefused,
                destination,
                "restored transition stage does not match the intended symlink; both names are preserved",
            ));
        }
        ledger.commit(canonical, prior.restore())?;
        return Err(cleanup_unpublished_after_failure(
            parent,
            &stage,
            destination,
            Failure::new(
                CodeKey::TransitionRefused,
                destination,
                "refusing to retire a writable destination that no longer matches its baseline; edited content was restored",
            ),
        ));
    }
    remove_verified_displaced(parent, &stage, destination)?;
    let prior = prior.restore();
    let owned = owned_record(
        identity,
        entry,
        AppliedOperation::Update,
        prior.owned(),
        &sha256_hex(entry.retained_artifact_target.as_bytes()),
    );
    ledger.commit(canonical, owned)?;
    Ok(())
}
