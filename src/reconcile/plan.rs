use super::{
    CodeKey, Context, DiagnosticFormat, EXIT_CONFLICT, Entry, Failure, LedgerRecord, LedgerState,
    Manifest, NO_BASELINE, NOT_RECORDED, NOT_REGULAR, REGULAR_MODE, Result, SymlinkAction,
    WRITABLE_REPRESENTATION, WritableAction, algorithm_of, emit_warning, hash_matches,
    observe_kind, open_parent, read_regular, read_source, symlink_action, symlink_refusal,
    symlink_target, unreadable_baseline, witness, writable_action,
};
use rustix::io::Errno;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::process::ExitCode;

// what a run would do to one destination. every verdict here comes out of the
// same decision core the apply path calls, so the report cannot name a
// decision a real run would not reach.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict {
    // the destination already holds what the declaration asks for. a run would
    // still re-state the ownership record, which is bookkeeping about the past
    // rather than a change to this host.
    Settled,
    Change(&'static str),
}

impl Verdict {
    fn word(self) -> &'static str {
        match self {
            Self::Settled => "settled",
            Self::Change(word) => word,
        }
    }
}

// a parent component a run would create reads as NOENT from the refusing
// walk. that is a publication waiting to happen, not a traversal refusal, and
// telling them apart is what keeps the report usable on a host furnish has
// never touched.
fn missing_parent(failure: &Failure) -> bool {
    matches!(failure.key, CodeKey::ParentTraversal)
        && failure
            .cause
            .as_ref()
            .is_some_and(|cause| cause.errno == Errno::NOENT.raw_os_error())
}

pub(super) fn report(
    manifest: &Manifest,
    ledger: &LedgerState,
    format: DiagnosticFormat,
) -> ExitCode {
    let codes = &manifest.diagnostic_contract.codes;
    let mut drifted = false;
    let mut refusal = None;
    for entry in &manifest.entries {
        let destination = &entry.filesystem_identity.destination;
        match plan_entry(entry, ledger) {
            Ok(verdict) => {
                drifted |= verdict != Verdict::Settled;
                println!("{}\t{destination}", verdict.word());
            }
            Err(failure) => {
                // a report does not stop at the first refusal, because the
                // point of asking is to see every destination at once. the
                // diagnostics are warnings for the same reason: nothing here
                // failed, the run that would follow is what would fail.
                println!("refused\t{destination}");
                emit_warning(codes, &failure, Some(&entry.provenance), format);
                refusal = refusal.or(Some(failure.key));
            }
        }
    }
    drifted |= report_retirements(manifest, ledger);
    match refusal {
        Some(key) => ExitCode::from(key.exit_code()),
        // drift is not a failure of the report, but an activation script that
        // asks whether this host matches its declaration needs an answer it
        // can branch on without reading stdout.
        None if drifted => ExitCode::from(EXIT_CONFLICT),
        None => ExitCode::SUCCESS,
    }
}

// the retirement pass, described rather than run. a record whose retirement is
// already blocked is reported as blocked, because rerunning the coordinator
// will not clear it; only the release or discard verb will.
fn report_retirements(manifest: &Manifest, ledger: &LedgerState) -> bool {
    let desired: BTreeSet<&str> = manifest
        .entries
        .iter()
        .map(|entry| entry.filesystem_identity.canonical.as_str())
        .collect();
    let mut drifted = false;
    for (canonical, record) in ledger.recorded() {
        if desired.contains(canonical.as_str()) {
            continue;
        }
        drifted = true;
        let word = if record.unresolved_retirement().is_some() {
            "blocked"
        } else {
            "retire"
        };
        println!("{word}\t{}", record.destination);
    }
    drifted
}

fn plan_entry(entry: &Entry, ledger: &LedgerState) -> Result<Verdict> {
    let destination = &entry.filesystem_identity.destination;
    let record = ledger.record(&entry.filesystem_identity.canonical);

    // recovery is the only thing that reads a pending record, and recovery
    // writes, so the report stops at naming it. which way it would resolve
    // depends on what recovery finds, and finding out is not a read.
    if record.is_some_and(LedgerRecord::is_pending) {
        return Ok(Verdict::Change("recover"));
    }

    // the refusing walk, because describing a run must not leave a directory
    // behind.
    let (parent, name) = match open_parent(destination, &entry.managed_root) {
        Ok(opened) => opened,
        Err(failure) if missing_parent(&failure) => return Ok(Verdict::Change("publish")),
        Err(failure) => return Err(failure),
    };
    let name = name.as_os_str();

    if record
        .is_some_and(|record| record.is_owned() && record.representation != entry.representation)
    {
        return Ok(Verdict::Change("transition"));
    }

    if entry.representation == WRITABLE_REPRESENTATION {
        return plan_writable(entry, record, &parent, name);
    }

    let observed = symlink_target(&parent, name).at(
        CodeKey::ConflictingDestination,
        destination,
        "fstatat-destination",
    )?;
    let expected = OsStr::new(entry.target.path());
    match symlink_action(&observed, expected, record) {
        SymlinkAction::Publish { repair: false } => Ok(Verdict::Change("publish")),
        SymlinkAction::Publish { repair: true } => Ok(Verdict::Change("repair")),
        SymlinkAction::Settle => Ok(Verdict::Settled),
        SymlinkAction::Exchange => {
            entry.target.check_replacement(destination)?;
            Ok(Verdict::Change("republish"))
        }
        SymlinkAction::RefuseForeign | SymlinkAction::RefuseNotRecorded => {
            Err(symlink_refusal(destination, &observed, record))
        }
    }
}

fn plan_writable(
    entry: &Entry,
    record: Option<&LedgerRecord>,
    parent: &OwnedFd,
    name: &OsStr,
) -> Result<Verdict> {
    let destination = &entry.filesystem_identity.destination;
    let source_bytes = read_source(entry.target.path(), destination)?;
    let observed = observe_kind(parent, name, destination)?;
    let (Some(kind), Some(record)) = (observed, record) else {
        return match (observed, record) {
            (None, prior) => Ok(Verdict::Change(if prior.is_some() {
                "repair"
            } else {
                "publish"
            })),
            _ => Err(Failure::new(
                CodeKey::ConflictingDestination,
                destination,
                NOT_RECORDED,
            )),
        };
    };
    if kind != REGULAR_MODE {
        return Err(Failure::new(
            CodeKey::ConflictingDestination,
            destination,
            NOT_REGULAR,
        ));
    }
    let destination_bytes = read_regular(
        parent,
        name,
        destination,
        CodeKey::ContentVerification,
        "read-destination",
    )?;
    let Some(baseline) = record.baseline_hash.as_deref() else {
        return Err(Failure::new(
            CodeKey::ConflictingDestination,
            destination,
            NO_BASELINE,
        ));
    };
    if algorithm_of(baseline).is_none() {
        return Err(unreadable_baseline(destination, baseline));
    }
    match writable_action(
        destination_bytes == source_bytes,
        hash_matches(baseline, &destination_bytes),
        hash_matches(baseline, &source_bytes),
        entry.on_conflict,
    ) {
        // both of these leave the bytes on disk exactly as they are. the
        // second one only advances the record over a crash window.
        WritableAction::Settle | WritableAction::VerifyAndAdvance => Ok(Verdict::Settled),
        WritableAction::Exchange { .. } => Ok(Verdict::Change("replace")),
        WritableAction::RefuseConflict => Err(Failure::conflict(
            destination,
            Some(baseline),
            &witness(&source_bytes),
            &witness(&destination_bytes),
        )),
    }
}

// the report is only worth having if it agrees with the apply path, and it
// agrees by construction: every branch above returns what one of the two
// decision cores returned. these pin the mapping from a core's answer to the
// word printed, which is the only part the report decides on its own.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ConflictPolicy;

    #[test]
    fn every_writable_row_maps_to_a_word_the_apply_path_would_earn() {
        let cases = [
            (true, true, true, ConflictPolicy::Error, "settled"),
            (true, false, false, ConflictPolicy::Error, "settled"),
            (false, false, true, ConflictPolicy::Error, "settled"),
            (false, true, false, ConflictPolicy::Error, "replace"),
            (false, false, false, ConflictPolicy::SourceWins, "replace"),
            (false, false, false, ConflictPolicy::RuntimeWins, "settled"),
        ];
        for (d_eq_s, d_eq_b, s_eq_b, policy, word) in cases {
            let verdict = match writable_action(d_eq_s, d_eq_b, s_eq_b, policy) {
                WritableAction::Settle | WritableAction::VerifyAndAdvance => Verdict::Settled,
                WritableAction::Exchange { .. } => Verdict::Change("replace"),
                WritableAction::RefuseConflict => panic!("unexpected refusal"),
            };
            assert_eq!(verdict.word(), word, "{d_eq_s} {d_eq_b} {s_eq_b}");
        }
        assert_eq!(
            writable_action(false, false, false, ConflictPolicy::Error),
            WritableAction::RefuseConflict
        );
    }

    #[test]
    fn a_missing_parent_component_is_told_apart_from_a_traversal_refusal() {
        assert!(missing_parent(&Failure::syscall(
            CodeKey::ParentTraversal,
            "/home/user/.config/app/file",
            "openat-parent-component",
            Errno::NOENT,
        )));
        assert!(!missing_parent(&Failure::syscall(
            CodeKey::ParentTraversal,
            "/home/user/.config/app/file",
            "openat-parent-component",
            Errno::LOOP,
        )));
        assert!(!missing_parent(&Failure::new(
            CodeKey::InvalidDestination,
            "/home/user/.config/app/file",
            "destination must be an absolute descendant of managedRoot",
        )));
    }
}
