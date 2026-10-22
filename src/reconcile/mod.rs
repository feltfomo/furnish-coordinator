mod context;
mod plan;
mod publication;
mod recovery;
mod resolve;
mod retirement;
mod symlink;
mod transition;
mod writable;

use context::{OpenDestination, ReconcileContext, run_executor, stage_name};
use plan::report;
use publication::Publication;
use recovery::recover_pending;
pub(crate) use resolve::{Resolution, resolve_retirement};
use retirement::{RetireOutcome, retire_record};
use symlink::{SymlinkAction, stage_symlink, symlink_action, symlink_refusal};
use transition::transition_representation;
use writable::{
    NO_BASELINE, NOT_RECORDED, NOT_REGULAR, WritableAction, hash_source, read_source,
    reconcile_writable_entry, stage_writable, unreadable_baseline, writable_action,
};

use crate::diagnostic::{
    CodeKey, Context, DiagnosticFormat, EXIT_CONFLICT, EXIT_USAGE, Failure, Result, emit_bootstrap,
    emit_failure, emit_warning,
};
use crate::fault::fault_point;
use crate::filesystem::{
    DestinationObservation, DisplacedCleanup, ParentMode, REGULAR_MODE, SYMLINK_MODE,
    WRITABLE_FILE_MODE, cleanup_unpublished_after_failure, discard_displaced_under_policy,
    exchange_names, hash_regular, observe_kind, observe_mode, open_parent, publish_exchange,
    publish_new, publish_writable_exchange, publish_writable_new, read_regular,
    remove_unpublished_stage, remove_verified_displaced, rename_or_clean, rollback_exchange,
    symlink_target, sync_parent, verify_writable_destination, verify_writable_hash, walk_parent,
};
use crate::hash::{algorithm_of, matches as hash_matches, witness};
use crate::identity::RunIdentity;
use crate::ledger::{
    AppliedOperation, LedgerRecord, LedgerState, OwnedRecord, PendingIntent, RecordStatus,
    Representation, TransitionPair, UnresolvedRetirement, baseline_for, owned_record,
    pending_record, refreshed_record,
};
use crate::lock::open_host_lock;
use crate::manifest::{
    Authority, ConflictPolicy, DiagnosticCodes, Entry, ExecutorProfile, FilesystemIdentity,
    Manifest, NATIVE_REPRESENTATION, WRITABLE_REPRESENTATION, decode_manifest, profile_for,
    validate_manifest,
};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::ExitCode;

pub(super) fn reconcile_entry(
    entry: &Entry,
    setpriv: &Path,
    index: usize,
    ledger: &mut LedgerState,
    identity: &RunIdentity,
) -> Result<()> {
    let destination = &entry.filesystem_identity.destination;
    let canonical = &entry.filesystem_identity.canonical;

    // the one walk for this entry, and the only one allowed to create. it runs
    // ahead of recovery because recovery resolves the parent too, so a
    // destination whose directory nothing else creates has to be reachable
    // before any branch reads it. every branch below is handed this descriptor
    // rather than repeating the walk.
    let open = {
        let context = ReconcileContext::new(setpriv, ledger, identity);
        context.open(entry)?
    };
    let name = open.name.as_os_str();

    // recovery runs before the ordinary path and only ever converts pending to
    // owned. the two are never fused, so a stale pending record converges to
    // owned at the source it was pending for and is then carried forward. it
    // resolves the parent from the record's own managed root, which is not
    // always the entry's, so it keeps its own refusing walk.
    recover_pending(entry, ledger, identity)?;

    if let Some(record) = ledger.record(canonical).cloned()
        && record.is_owned()
        && record.representation != entry.representation
    {
        return transition_representation(entry, setpriv, index, ledger, identity, &record, &open);
    }

    if entry.representation == WRITABLE_REPRESENTATION {
        return reconcile_writable_entry(entry, setpriv, index, ledger, identity, &open);
    }

    let expected = OsStr::new(entry.target.path());

    let observed = symlink_target(&open.parent, name).at(
        CodeKey::ConflictingDestination,
        destination,
        "fstatat-destination",
    )?;

    let record = ledger.record(canonical).cloned();

    match (symlink_action(&observed, expected, record.as_ref()), record) {
        (SymlinkAction::Publish { repair }, prior) => {
            let stage = stage_name(index);
            let intended = witness(entry.target.path().as_bytes());
            let applied_by = if repair {
                AppliedOperation::Repair
            } else {
                AppliedOperation::New
            };
            Publication {
                entry,
                identity,
                intent: PendingIntent::Apply(applied_by),
                applied_by,
                prior: prior.as_ref().and_then(LedgerRecord::owned),
                stage: &stage,
                witness: &intended,
                pending_artifact_target: None,
            }
            .run(ledger, || {
                stage_symlink(setpriv, &open.parent, &stage, entry, expected)?;
                fault_point("stage-synced");
                publish_new(&open.parent, name, &stage, destination, expected)?;
                fault_point("verified");
                Ok(())
            })
        }
        (SymlinkAction::Settle, prior) => {
            // nothing was published, so the branch that produced this target is
            // carried forward rather than restated as a decision this run made,
            // and so is everything else the applied state already recorded.
            if let Some(prior) = prior {
                ledger.note(canonical, refreshed_record(identity, entry, &prior));
            }
            Ok(())
        }
        (SymlinkAction::Exchange, Some(record)) => {
            let recorded = OsStr::new(&record.applied_artifact_target);

            let applied_by = entry
                .target
                .replacement_operation(&open.parent, name, destination)?;

            let stage = stage_name(index);
            let intended = witness(entry.target.path().as_bytes());
            Publication {
                entry,
                identity,
                intent: PendingIntent::Apply(applied_by),
                applied_by,
                prior: record.owned(),
                stage: &stage,
                witness: &intended,
                pending_artifact_target: None,
            }
            .run(ledger, || {
                stage_symlink(setpriv, &open.parent, &stage, entry, expected)?;
                fault_point("stage-synced");
                publish_exchange(&open.parent, name, &stage, destination, expected, recorded)?;
                fault_point("verified");
                Ok(())
            })
        }
        // the exchange is the only branch selected from a record, so what is
        // left refuses, and the refusal reads the record to say why.
        (_, record) => Err(symlink_refusal(destination, &observed, record.as_ref())),
    }
}

// emitting the diagnostic and choosing the status for a refusal are the same
// decision, so every verb makes it in one place.
pub(super) fn refused(
    codes: &DiagnosticCodes,
    failure: &Failure,
    format: DiagnosticFormat,
) -> ExitCode {
    emit_failure(codes, failure, None, format);
    ExitCode::from(failure.key.exit_code())
}

// the manifest, the host lock, and applied state, in the one order every verb
// needs them. the read-only verbs take the same lock the apply path takes, so
// a report is never a torn read of a ledger another run is rewriting.
struct Session {
    manifest: Manifest,
    _lock: OwnedFd,
    ledger: LedgerState,
}

fn open_session(
    manifest_path: &Path,
    lock_name: &OsStr,
    state_dir: &Path,
    lock_dir: &Path,
    format: DiagnosticFormat,
) -> std::result::Result<Session, ExitCode> {
    let bootstrap = |message: String| {
        emit_bootstrap(&message, &manifest_path.to_string_lossy(), format);
        // the manifest is what the caller handed us, so an unreadable or
        // undecodable one is a usage problem rather than a refusal about
        // anything on this host.
        ExitCode::from(EXIT_USAGE)
    };
    let bytes = fs::read(manifest_path)
        .map_err(|error| bootstrap(format!("cannot read manifest: {error}")))?;
    let decoded = decode_manifest(&bytes)
        .map_err(|error| bootstrap(format!("cannot decode manifest: {error}")))?;
    let declared_codes = decoded.diagnostic_codes().clone();
    let manifest =
        validate_manifest(decoded).map_err(|failure| refused(&declared_codes, &failure, format))?;
    let codes = &manifest.diagnostic_contract.codes;
    let _ = (
        manifest.schema_version,
        manifest.diagnostic_contract.schema_version,
    );
    let lock = match open_host_lock(lock_name, lock_dir) {
        Ok(lock) => lock,
        Err(failure) => return Err(refused(codes, &failure, format)),
    };
    // applied state is read under the host lock, so no other run can be
    // deciding ownership against a copy of it.
    let ledger = match LedgerState::load(state_dir) {
        Ok(ledger) => ledger,
        Err(failure) => return Err(refused(codes, &failure, format)),
    };
    Ok(Session {
        manifest,
        _lock: lock,
        ledger,
    })
}

// the read-only verb. it holds the lock and the loaded ledger and writes
// neither.
pub(crate) fn status(
    manifest_path: &Path,
    lock_name: &OsStr,
    state_dir: &Path,
    lock_dir: &Path,
    format: DiagnosticFormat,
) -> ExitCode {
    match open_session(manifest_path, lock_name, state_dir, lock_dir, format) {
        Ok(session) => report(&session.manifest, &session.ledger, format),
        Err(status) => status,
    }
}

pub(crate) fn reconcile(
    manifest_path: &Path,
    lock_name: &OsStr,
    setpriv: &Path,
    state_dir: &Path,
    lock_dir: &Path,
    dry_run: bool,
    format: DiagnosticFormat,
) -> ExitCode {
    let session = match open_session(manifest_path, lock_name, state_dir, lock_dir, format) {
        Ok(session) => session,
        Err(status) => return status,
    };
    let Session {
        manifest,
        _lock,
        mut ledger,
    } = session;

    // a dry run stops here, before anything has been noted, so the flush
    // below is never reached and nothing it would have written exists.
    if dry_run {
        return report(&manifest, &ledger, format);
    }

    let identity = RunIdentity::observe();
    let outcome = apply_desired(&manifest, setpriv, &mut ledger, &identity, format);
    // the deferred changes become durable on the way out whichever way the run
    // ends, so a refused run leaves exactly the applied state an eager run
    // would have left. only a crash can lose them, and only observations are
    // ever deferred.
    if let Err(failure) = ledger.flush() {
        return refused(&manifest.diagnostic_contract.codes, &failure, format);
    }
    outcome
}

fn apply_desired(
    manifest: &Manifest,
    setpriv: &Path,
    ledger: &mut LedgerState,
    identity: &RunIdentity,
    format: DiagnosticFormat,
) -> ExitCode {
    let codes = &manifest.diagnostic_contract.codes;
    for (index, entry) in manifest.entries.iter().enumerate() {
        let _ = (
            entry.schema_version,
            entry.cleanup_strategy.as_str(),
            entry.self_heal_strategy.as_str(),
            entry.filesystem_identity.namespace.as_str(),
        );
        if let Err(failure) = reconcile_entry(entry, setpriv, index, ledger, identity) {
            emit_failure(codes, &failure, Some(&entry.provenance), format);
            return ExitCode::from(failure.key.exit_code());
        }
    }

    // a manifest with no entries is a real desired set, not a no-op. this is the
    // only place a record is ever removed.
    let desired: BTreeSet<&str> = manifest
        .entries
        .iter()
        .map(|entry| entry.filesystem_identity.canonical.as_str())
        .collect();
    for (canonical, record) in ledger.recorded() {
        if desired.contains(canonical.as_str()) {
            continue;
        }
        match retire_record(&record) {
            Ok(RetireOutcome::Removed) => ledger.forget(&canonical),
            // the record is the point, since it is what stops the file becoming
            // an unexplained orphan, so ownership is preserved rather than
            // dropped and the prune is refused rather than the activation.
            Ok(RetireOutcome::Unresolved(unresolved)) => {
                let failure = Failure::new(
                    CodeKey::UnresolvedRetirement,
                    &record.destination,
                    format!(
                        "retirement is blocked: {}; the file and its ownership record are preserved",
                        unresolved.reason
                    ),
                );
                emit_warning(codes, &failure, None, format);
                let mut kept = record.clone();
                kept.set_unresolved_retirement(Some(unresolved));
                ledger.note(&canonical, kept);
            }
            Err(failure) => return refused(codes, &failure, format),
        }
    }
    ExitCode::SUCCESS
}
#[cfg(test)]
mod tests;
