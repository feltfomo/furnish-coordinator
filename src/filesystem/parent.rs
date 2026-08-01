use crate::diagnostic::{CodeKey, Failure, Result};
use crate::executor::{self, WorkerProgram};
use crate::manifest::Authority;
use rustix::fs::{Mode, OFlags, open, openat};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

// creating a directory under a user's home is the user's write, so it goes
// through the same setpriv door a staged artifact does. the name handed over is
// a single component and the worker does no walking of its own.
fn run_directory_executor(
    setpriv: &Path,
    parent: &OwnedFd,
    name: &OsStr,
    destination: &str,
    authority: &Authority,
) -> Result<()> {
    executor::launch(
        setpriv,
        parent,
        name,
        None,
        destination,
        authority,
        WorkerProgram::Directory,
    )
}

pub(crate) enum ParentMode<'a> {
    Refuse,
    Create {
        setpriv: &'a Path,
        authority: &'a Authority,
    },
}

// the no-create walk. every caller that must not create keeps this one.
pub(crate) fn open_parent(destination: &str, managed_root: &str) -> Result<(OwnedFd, OsString)> {
    walk_parent(destination, managed_root, &ParentMode::Refuse)
}

pub(crate) fn walk_parent(
    destination: &str,
    managed_root: &str,
    mode: &ParentMode<'_>,
) -> Result<(OwnedFd, OsString)> {
    let destination_path = Path::new(destination);
    let managed_root_path = Path::new(managed_root);
    if !destination_path.is_absolute()
        || !managed_root_path.is_absolute()
        || destination_path == managed_root_path
        || !destination_path.starts_with(managed_root_path)
    {
        return Err(Failure::new(
            CodeKey::InvalidDestination,
            destination,
            "destination must be an absolute descendant of managedRoot",
        ));
    }
    let name = destination_path
        .file_name()
        .ok_or_else(|| {
            Failure::new(
                CodeKey::InvalidDestination,
                destination,
                "destination has no final component",
            )
        })?
        .to_os_string();
    let parent = destination_path.parent().ok_or_else(|| {
        Failure::new(
            CodeKey::InvalidDestination,
            destination,
            "destination has no parent",
        )
    })?;

    let mut current = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|errno| Failure::syscall(CodeKey::ParentTraversal, destination, "open-root", errno))?;

    // components at and above the managed root cannot be created.
    let boundary = managed_root_path.components().count();
    let mut depth = 0;
    for component in parent.components() {
        depth += 1;
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                current =
                    open_parent_component(&current, part, destination, mode, depth > boundary)?;
            }
            _ => {
                return Err(Failure::new(
                    CodeKey::InvalidDestination,
                    destination,
                    "destination contains a non-normal path component",
                ));
            }
        }
    }
    Ok((current, name))
}

fn open_parent_component(
    parent: &OwnedFd,
    part: &OsStr,
    destination: &str,
    mode: &ParentMode<'_>,
    creatable: bool,
) -> Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW;
    let refusal = |errno: Errno| {
        Failure::syscall(
            CodeKey::ParentTraversal,
            destination,
            "openat-parent-component",
            errno,
        )
    };
    match openat(parent, part, flags, Mode::empty()) {
        Ok(opened) => Ok(opened),
        Err(Errno::NOENT) => match mode {
            ParentMode::Create { setpriv, authority } if creatable => {
                run_directory_executor(setpriv, parent, part, destination, authority)?;
                openat(parent, part, flags, Mode::empty()).map_err(|errno| {
                    Failure::syscall(
                        CodeKey::ParentTraversal,
                        destination,
                        "openat-created-parent-component",
                        errno,
                    )
                })
            }
            _ => Err(refusal(Errno::NOENT)),
        },
        Err(errno) => Err(refusal(errno)),
    }
}
