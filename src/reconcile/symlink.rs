use super::{
    CodeKey, Context, DestinationObservation, Entry, Failure, LedgerRecord, Result,
    cleanup_unpublished_after_failure, profile_for, remove_unpublished_stage, run_executor,
    symlink_target,
};
use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::path::Path;

// the whole symlink branch selection, once, as a function of what is on disk
// and what applied state records. reconcile acts on it and the read-only
// report prints it, so a dry run cannot describe a decision a real run would
// not make.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SymlinkAction {
    // the name is free. a record already existing makes this the self-heal
    // rather than first ownership.
    Publish { repair: bool },
    // the link already points at the desired target, so nothing is published
    // and the record is only re-stated under this run.
    Settle,
    // recorded as furnish-owned and still pointing at the recorded target, so
    // the desired target goes in through the exchange.
    Exchange,
    RefuseNotRecorded,
    RefuseForeign,
}

pub(super) fn symlink_action(
    observed: &DestinationObservation,
    expected: &OsStr,
    record: Option<&LedgerRecord>,
) -> SymlinkAction {
    if !observed.exists() {
        return SymlinkAction::Publish {
            repair: record.is_some(),
        };
    }
    // ownership is never inferred from a matching target, because a
    // destination furnish never published is indistinguishable from one it
    // did. a host whose link predates the ledger stays unrecorded here and
    // acquires from absence instead.
    if observed.target() == Some(expected) {
        return SymlinkAction::Settle;
    }
    let Some(record) = record else {
        return SymlinkAction::RefuseNotRecorded;
    };
    // exact match against the RECORD, not against the desired target. read
    // against desired this condition could never be satisfied by any
    // repairable state, because a destination already equal to desired needs
    // no repair.
    if observed.target() == Some(OsStr::new(&record.applied_artifact_target)) {
        SymlinkAction::Exchange
    } else {
        SymlinkAction::RefuseForeign
    }
}

// the text for the two actions that refuse, in one place, so the report and
// the apply path decline for the same stated reason. a record is present
// exactly when the refusal is about a target furnish does not recognise.
pub(super) fn symlink_refusal(
    destination: &str,
    observed: &DestinationObservation,
    record: Option<&LedgerRecord>,
) -> Failure {
    let label = observed.label();
    let message = match record {
        Some(record) => format!(
            "refusing to replace {label}: it is not the target recorded as furnish-owned ({})",
            record.applied_artifact_target
        ),
        None => format!(
            "refusing to replace {label}: applied state records no furnish ownership of this destination"
        ),
    };
    Failure::new(CodeKey::ConflictingDestination, destination, message)
}

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
        entry.target.path(),
        &entry.authority,
        profile,
    )?;
    let staged = symlink_target(parent, stage).at(
        CodeKey::StagingVerification,
        destination,
        "readlinkat-staging",
    )?;
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
