use super::{FILE_TYPE_MASK, REGULAR_MODE, SYMLINK_MODE, WRITABLE_FILE_MODE};
use crate::diagnostic::{CodeKey, Failure, Result};
use crate::hash::sha256_hex;
use rustix::fs::{AtFlags, Mode, OFlags, openat, readlinkat, statat};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DestinationObservation {
    Missing,
    Symlink(OsString),
    Regular,
    Directory,
    Fifo,
    Socket,
    CharacterDevice,
    BlockDevice,
    Unknown { raw_file_type: u32 },
}

impl DestinationObservation {
    pub(crate) fn exists(&self) -> bool {
        !matches!(self, Self::Missing)
    }
    pub(crate) fn target(&self) -> Option<&OsStr> {
        match self {
            Self::Symlink(target) => Some(target),
            _ => None,
        }
    }
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Missing => "missing destination".to_owned(),
            Self::Symlink(target) => format!("symlink to {}", target.to_string_lossy()),
            Self::Regular => "regular file".to_owned(),
            Self::Directory => "directory".to_owned(),
            Self::Fifo => "fifo".to_owned(),
            Self::Socket => "socket".to_owned(),
            Self::CharacterDevice => "character device".to_owned(),
            Self::BlockDevice => "block device".to_owned(),
            Self::Unknown { .. } => "unknown filesystem object".to_owned(),
        }
    }
}

pub(crate) fn symlink_target<Fd: std::os::fd::AsFd>(
    dir: Fd,
    name: &OsStr,
) -> std::result::Result<DestinationObservation, Errno> {
    match statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            let raw_file_type = stat.st_mode & FILE_TYPE_MASK;
            let observation = match raw_file_type {
                SYMLINK_MODE => {
                    let target = readlinkat(dir, name, Vec::new())?;
                    DestinationObservation::Symlink(OsString::from_vec(target.into_bytes()))
                }
                REGULAR_MODE => DestinationObservation::Regular,
                0o040000 => DestinationObservation::Directory,
                0o010000 => DestinationObservation::Fifo,
                0o140000 => DestinationObservation::Socket,
                0o020000 => DestinationObservation::CharacterDevice,
                0o060000 => DestinationObservation::BlockDevice,
                raw_file_type => DestinationObservation::Unknown { raw_file_type },
            };
            Ok(observation)
        }
        Err(Errno::NOENT) => Ok(DestinationObservation::Missing),
        Err(errno) => Err(errno),
    }
}

pub(crate) fn observe_kind(
    parent: &OwnedFd,
    name: &OsStr,
    destination: &str,
) -> Result<Option<u32>> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(stat.st_mode & FILE_TYPE_MASK)),
        Err(Errno::NOENT) => Ok(None),
        Err(errno) => Err(Failure::syscall(
            CodeKey::ConflictingDestination,
            destination,
            "fstatat-destination-kind",
            errno,
        )),
    }
}

pub(crate) fn observe_mode(parent: &OwnedFd, name: &OsStr, destination: &str) -> Result<u32> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(stat.st_mode & 0o7777),
        Err(errno) => Err(Failure::syscall(
            CodeKey::ConflictingDestination,
            destination,
            "fstatat-destination-mode",
            errno,
        )),
    }
}

fn read_regular(
    parent: &OwnedFd,
    name: &OsStr,
    destination: &str,
    key: CodeKey,
    operation: &'static str,
) -> Result<Vec<u8>> {
    let opened = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|errno| Failure::syscall(key, destination, operation, errno))?;
    let mut file = fs::File::from(opened);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| Failure::io(key, destination, operation, &error))?;
    Ok(bytes)
}

pub(crate) fn hash_regular(
    parent: &OwnedFd,
    name: &OsStr,
    destination: &str,
    key: CodeKey,
    operation: &'static str,
) -> Result<String> {
    Ok(sha256_hex(&read_regular(
        parent,
        name,
        destination,
        key,
        operation,
    )?))
}

pub(crate) fn verify_writable_hash(
    parent: &OwnedFd,
    name: &OsStr,
    destination: &str,
    expected: &str,
    operation: &'static str,
) -> Result<()> {
    if observe_kind(parent, name, destination)? != Some(REGULAR_MODE) {
        return Err(Failure::new(
            CodeKey::PendingRecovery,
            destination,
            "transaction side is not the recorded regular file",
        ));
    }
    let observed = hash_regular(
        parent,
        name,
        destination,
        CodeKey::PendingRecovery,
        operation,
    )?;
    if observed != expected {
        return Err(Failure::new(
            CodeKey::PendingRecovery,
            destination,
            "transaction side does not match its recorded witness",
        ));
    }
    Ok(())
}

pub(crate) fn verify_writable_destination(
    parent: &OwnedFd,
    name: &OsStr,
    destination: &str,
    intended_hash: &str,
) -> Result<()> {
    if observe_kind(parent, name, destination)? != Some(REGULAR_MODE) {
        return Err(Failure::new(
            CodeKey::FinalVerification,
            destination,
            "published destination is not a regular file",
        ));
    }
    let observed = hash_regular(
        parent,
        name,
        destination,
        CodeKey::ContentVerification,
        "read-published",
    )?;
    if observed != intended_hash {
        return Err(Failure::new(
            CodeKey::ContentVerification,
            destination,
            "published destination failed exact-content verification",
        ));
    }
    let mode = observe_mode(parent, name, destination)?;
    if mode != WRITABLE_FILE_MODE {
        return Err(Failure::new(
            CodeKey::FinalVerification,
            destination,
            format!("published file mode is {mode:04o}; expected {WRITABLE_FILE_MODE:04o}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod observation_tests {
    use super::{DestinationObservation, symlink_target};
    use rustix::fs::{Mode, OFlags, open};
    use std::ffi::{OsStr, OsString};
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "furnish-fs-observation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn destination_observation_is_exhaustive_without_a_sentinel() {
        let path = directory();
        let parent = open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        assert_eq!(
            symlink_target(&parent, OsStr::new("missing")).unwrap(),
            DestinationObservation::Missing
        );
        std::fs::write(path.join("file"), b"x").unwrap();
        assert_eq!(
            symlink_target(&parent, OsStr::new("file")).unwrap(),
            DestinationObservation::Regular
        );
        std::fs::create_dir(path.join("dir")).unwrap();
        assert_eq!(
            symlink_target(&parent, OsStr::new("dir")).unwrap(),
            DestinationObservation::Directory
        );
        symlink("target", path.join("link")).unwrap();
        assert_eq!(
            symlink_target(&parent, OsStr::new("link")).unwrap(),
            DestinationObservation::Symlink(OsString::from("target"))
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
