use crate::diagnostic::{CodeKey, Context, Failure, Result};
use crate::ledger::{AppliedOperation, Representation};
use rustix::fs::{AtFlags, statat};
use rustix::io::Errno;
use serde::Deserialize;
use std::ffi::OsStr;
use std::os::fd::OwnedFd;

#[derive(Debug, Deserialize)]
#[serde(
    tag = "kind",
    content = "path",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(crate) enum Target {
    Retained(String),
    External(String),
}

impl Target {
    pub(crate) fn path(&self) -> &str {
        match self {
            Self::Retained(path) | Self::External(path) => path,
        }
    }

    pub(crate) fn validate(&self, representation: Representation, destination: &str) -> Result<()> {
        if let Self::External(path) = self {
            let normalized = path.starts_with('/')
                && path != "/"
                && path[1..]
                    .split('/')
                    .all(|part| !matches!(part, "" | "." | ".."))
                && !path.contains('\0');
            if representation != Representation::Symlink || !normalized || path == destination {
                return Err(Failure::new(
                    CodeKey::InvalidManifest,
                    destination,
                    "external targets require a symlink to a normalized absolute path distinct from its destination",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn replacement_operation(
        &self,
        parent: &OwnedFd,
        name: &OsStr,
        destination: &str,
    ) -> Result<AppliedOperation> {
        if matches!(self, Self::External(_)) {
            return Ok(AppliedOperation::Update);
        }
        let operation = match statat(parent, name, AtFlags::empty()) {
            Err(Errno::NOENT) => AppliedOperation::Repair,
            other => {
                other.at(
                    CodeKey::ConflictingDestination,
                    destination,
                    "fstatat-recorded-target",
                )?;
                AppliedOperation::Update
            }
        };
        self.check_replacement(destination)?;
        Ok(operation)
    }

    pub(crate) fn check_replacement(&self, destination: &str) -> Result<()> {
        // External paths may appear after activation. Retained artifacts must
        // still resolve before an owned link is exchanged toward them.
        if let Self::Retained(path) = self {
            std::fs::metadata(path).at(
                CodeKey::UnresolvableDesiredTarget,
                destination,
                "stat-desired-target",
            )?;
        }
        Ok(())
    }
}
