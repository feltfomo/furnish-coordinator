use super::{
    CodeKey, Context, Failure, LedgerState, Manifest, Result, Session, hash_matches, open_parent,
    open_session, read_regular, refused,
};
use rustix::fs::{AtFlags, unlinkat};
use std::ffi::OsStr;
use std::path::Path;
use std::process::ExitCode;

// the only exit from an unresolved retirement. a writable destination that was
// undeclared while holding runtime edits keeps both its file and its ownership
// record, which is the right default and the wrong permanent state: nothing in
// the reconcile loop can clear it, because the loop only ever sees a
// destination that is declared or one that is not. redeclaring resolves it.
// these two are how an operator says the other thing.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Resolution {
    // drop the record and leave the file. the destination becomes foreign,
    // which is what it already is in substance, and a later declaration of it
    // will refuse rather than adopt.
    Release,
    // drop both. the runtime edits are the thing being destroyed, so this is
    // the only operation in the crate that discards work nothing else holds a
    // copy of, and that is why it refuses every record except a marked one.
    Discard,
}

impl Resolution {
    fn verb(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Discard => "discard",
        }
    }
}

pub(crate) fn resolve_retirement(
    resolution: Resolution,
    destination: &str,
    manifest_path: &Path,
    lock_name: &OsStr,
    state_dir: &Path,
    lock_dir: &Path,
    format: super::DiagnosticFormat,
) -> ExitCode {
    // the diagnostic contract is manifest-supplied, so these verbs take the
    // manifest for its registry even though the destination they act on is by
    // definition not declared in it. they take the same host lock the apply
    // path takes, so this cannot drop a record while a run is deciding
    // ownership against it.
    let session = match open_session(manifest_path, lock_name, state_dir, lock_dir, format) {
        Ok(session) => session,
        Err(status) => return status,
    };
    let Session {
        manifest,
        _lock,
        mut ledger,
    } = session;
    let declared = manifest_declares(&manifest);
    match apply_resolution(resolution, destination, &declared, &mut ledger)
        .and_then(|()| ledger.flush())
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => refused(&manifest.diagnostic_contract.codes, &failure, format),
    }
}

fn manifest_declares(manifest: &Manifest) -> Vec<String> {
    manifest
        .entries
        .iter()
        .map(|entry| entry.filesystem_identity.destination.clone())
        .collect()
}

fn apply_resolution(
    resolution: Resolution,
    destination: &str,
    declared: &[String],
    ledger: &mut LedgerState,
) -> Result<()> {
    let verb = resolution.verb();
    // a declared destination is one the reconcile loop still owns and will
    // keep republishing, so resolving its retirement would be resolving a
    // retirement that is not happening.
    if declared.iter().any(|value| value == destination) {
        return Err(Failure::new(
            CodeKey::ConflictingDestination,
            destination,
            format!(
                "refusing to {verb} a destination the manifest still declares; remove the declaration first"
            ),
        ));
    }

    let mut found = ledger
        .recorded()
        .into_iter()
        .filter(|(_, record)| record.destination == destination);
    let Some((canonical, record)) = found.next() else {
        return Err(Failure::new(
            CodeKey::ConflictingDestination,
            destination,
            format!("refusing to {verb} a destination that applied state records no ownership of"),
        ));
    };
    // two namespaces recording the same path is not something a valid manifest
    // can produce, so it means the ledger holds history this cannot pick
    // between, and picking would drop the wrong one.
    if found.next().is_some() {
        return Err(Failure::new(
            CodeKey::LedgerInvalid,
            destination,
            format!(
                "refusing to {verb} a destination recorded under more than one canonical identity"
            ),
        ));
    }

    // the marker is the authorization. without it this would be a way to drop
    // ownership of a live destination, or to delete a file, without the
    // coordinator ever having decided that retirement was blocked.
    let Some(unresolved) = record.unresolved_retirement() else {
        return Err(Failure::new(
            CodeKey::ConflictingDestination,
            destination,
            format!(
                "refusing to {verb} a destination that carries no unresolved retirement; only a blocked retirement can be resolved"
            ),
        ));
    };

    if matches!(resolution, Resolution::Release) {
        // the file is untouched, so there is nothing to verify about it. the
        // record is the only thing being dropped.
        ledger.forget(&canonical);
        return Ok(());
    }

    // discard destroys the edits, so the bytes on disk are re-read and checked
    // against the marker before anything is unlinked. if the destination moved
    // again since the marker was written, the operator is authorizing the
    // destruction of content they have not seen.
    let (parent, name) = open_parent(destination, &record.managed_root)?;
    let current = read_regular(
        &parent,
        name.as_os_str(),
        destination,
        CodeKey::ContentVerification,
        "read-discard-destination",
    )?;
    let observed = unresolved.observed_hash.as_deref().ok_or_else(|| {
        Failure::new(
            CodeKey::LedgerInvalid,
            destination,
            "unresolved retirement records no observed hash; refusing to discard content it cannot describe",
        )
    })?;
    if !hash_matches(observed, &current) {
        return Err(Failure::new(
            CodeKey::ContentVerification,
            destination,
            "destination has changed since the retirement was blocked; refusing to discard content that was never reported",
        ));
    }
    unlinkat(&parent, name.as_os_str(), AtFlags::empty()).at(
        CodeKey::ExecutorFailed,
        destination,
        "unlinkat-discard",
    )?;
    ledger.forget(&canonical);
    Ok(())
}
