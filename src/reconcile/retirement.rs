use super::{
    CodeKey, DestinationObservation, Failure, LedgerRecord, REGULAR_MODE, Result,
    UnresolvedRetirement, WRITABLE_REPRESENTATION, hash_regular, observe_kind, open_parent,
    symlink_target,
};
use rustix::fs::{AtFlags, unlinkat};
use std::ffi::OsStr;

#[derive(Debug)]
pub(super) enum RetireOutcome {
    Removed,
    // edited data is never deleted to satisfy cleanup, so the file stays,
    // ownership stays to explain it, and what is blocked is the retirement.
    Unresolved(UnresolvedRetirement),
}

// retirement is the destructive direction, so it runs on the same ownership
// conditions as the two publishing branches, plus one more, that no desired entry
// claims this destination any more. anything that is not a link furnish can still
// prove it published is left exactly where it is.
pub(super) fn retire_record(record: &LedgerRecord) -> Result<RetireOutcome> {
    let destination = &record.destination;
    if record.is_pending() {
        return Err(Failure::new(
            CodeKey::PendingRecovery,
            destination,
            "refusing to retire a pending transaction without its declaration; both transaction names are preserved",
        ));
    }
    let (parent, name) = open_parent(destination, &record.managed_root)?;

    if record.representation == WRITABLE_REPRESENTATION {
        let observed = observe_kind(&parent, &name, destination)?;
        return match observed {
            None => Ok(RetireOutcome::Removed),
            Some(kind) if kind == REGULAR_MODE => {
                let observed_hash = hash_regular(
                    &parent,
                    &name,
                    destination,
                    CodeKey::UnresolvedRetirement,
                    "read-retire-writable",
                )?;
                if record.baseline_hash.as_deref() == Some(observed_hash.as_str()) {
                    // pristine, so the destination is exactly what furnish put
                    // there and removing it destroys nothing.
                    unlinkat(&parent, name.as_os_str(), AtFlags::empty()).map_err(|errno| {
                        Failure::syscall(
                            CodeKey::ExecutorFailed,
                            destination,
                            "unlinkat-retire",
                            errno,
                        )
                    })?;
                    Ok(RetireOutcome::Removed)
                } else {
                    Ok(RetireOutcome::Unresolved(UnresolvedRetirement {
                        reason: "writable destination no longer matches its baseline".to_owned(),
                        observed_hash: Some(observed_hash),
                        baseline_hash: record.baseline_hash.clone(),
                    }))
                }
            }
            Some(_) => Err(Failure::new(
                CodeKey::ConflictingDestination,
                destination,
                "refusing to retire a destination that is no longer the regular file recorded as furnish-owned",
            )),
        };
    }

    let observed = symlink_target(&parent, &name).map_err(|errno| {
        Failure::syscall(
            CodeKey::ConflictingDestination,
            destination,
            "fstatat-retire",
            errno,
        )
    })?;
    let recorded = OsStr::new(&record.applied_artifact_target);
    match observed {
        // already gone. there is nothing to unlink, and the record is the only
        // thing left to remove.
        DestinationObservation::Missing => Ok(RetireOutcome::Removed),
        DestinationObservation::Symlink(actual) if actual == recorded => {
            unlinkat(&parent, name.as_os_str(), AtFlags::empty()).map_err(|errno| {
                Failure::syscall(
                    CodeKey::ExecutorFailed,
                    destination,
                    "unlinkat-retire",
                    errno,
                )
            })?;
            Ok(RetireOutcome::Removed)
        }
        _ => Err(Failure::new(
            CodeKey::ConflictingDestination,
            destination,
            "refusing to retire a destination that is no longer the link recorded as furnish-owned",
        )),
    }
}
