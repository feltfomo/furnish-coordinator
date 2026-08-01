use super::{
    Authority, Entry, ExecutorProfile, FilesystemIdentity, LedgerState, ParentMode, Result,
    RunIdentity, walk_parent,
};
use crate::executor;
use std::ffi::{OsStr, OsString};
use std::os::fd::OwnedFd;
use std::path::Path;

pub(super) struct ReconcileContext<'a> {
    pub(super) setpriv: &'a Path,
    pub(super) ledger: &'a mut LedgerState,
    pub(super) identity: &'a RunIdentity,
}

impl<'a> ReconcileContext<'a> {
    pub(super) fn new(
        setpriv: &'a Path,
        ledger: &'a mut LedgerState,
        identity: &'a RunIdentity,
    ) -> Self {
        Self {
            setpriv,
            ledger,
            identity,
        }
    }

    pub(super) fn open<'entry>(&self, entry: &'entry Entry) -> Result<OpenDestination<'entry>> {
        let (parent, name) = walk_parent(
            &entry.filesystem_identity.destination,
            &entry.managed_root,
            &ParentMode::Create {
                setpriv: self.setpriv,
                authority: &entry.authority,
            },
        )?;
        Ok(OpenDestination {
            parent,
            name,
            identity: &entry.filesystem_identity,
        })
    }
}

pub(super) struct OpenDestination<'a> {
    pub(super) parent: OwnedFd,
    pub(super) name: OsString,
    pub(super) identity: &'a FilesystemIdentity,
}

impl OpenDestination<'_> {
    pub(super) fn destination(&self) -> &str {
        &self.identity.destination
    }

    pub(super) fn canonical(&self) -> &str {
        &self.identity.canonical
    }
}

pub(super) fn stage_name(index: usize) -> OsString {
    OsString::from(format!(".furnish.{}.{}.stage", std::process::id(), index))
}

pub(super) fn run_executor(
    setpriv: &Path,
    parent: &OwnedFd,
    stage: &OsStr,
    target: &str,
    authority: &Authority,
    profile: &ExecutorProfile,
) -> Result<()> {
    executor::launch(
        setpriv,
        parent,
        stage,
        Some(OsStr::new(target)),
        target,
        authority,
        profile.worker_kind,
    )
}
