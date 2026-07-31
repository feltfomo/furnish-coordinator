use super::*;

// non-directory refuses in both modes for the same reason.
pub(super) enum ParentMode<'a> {
    Refuse,
    Create {
        setpriv: &'a Path,
        authority: &'a Authority,
    },
}

// the no-create walk. every caller that must not create keeps this one.
pub(super) fn open_parent(destination: &str, managed_root: &str) -> Result<(OwnedFd, OsString)> {
    walk_parent(destination, managed_root, &ParentMode::Refuse)
}

pub(super) fn walk_parent(
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

    // Components at and above the managed root cannot be created.
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

pub(super) fn open_parent_component(
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

#[derive(Debug, Eq, PartialEq)]
pub(super) enum DestinationObservation {
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
    pub(super) fn exists(&self) -> bool {
        !matches!(self, Self::Missing)
    }
    pub(super) fn target(&self) -> Option<&OsStr> {
        match self {
            Self::Symlink(target) => Some(target),
            _ => None,
        }
    }
    pub(super) fn label(&self) -> String {
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

pub(super) fn symlink_target<Fd: std::os::fd::AsFd>(
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

pub(super) fn remove_unpublished_stage<Fd: std::os::fd::AsFd>(
    parent: Fd,
    stage: &OsStr,
    destination: &str,
) -> Result<()> {
    match unlinkat(parent, stage, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(errno) => Err(Failure::syscall(
            CodeKey::StagingVerification,
            destination,
            "unlinkat-unpublished-stage",
            errno,
        )),
    }
}

pub(super) fn cleanup_unpublished_after_failure<Fd: std::os::fd::AsFd>(
    parent: Fd,
    stage: &OsStr,
    destination: &str,
    mut failure: Failure,
) -> Failure {
    if let Err(cleanup) = remove_unpublished_stage(parent, stage, destination) {
        failure.cleanup_warning = Some(Box::new(cleanup));
    }
    failure
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DisplacedCleanup {
    VerifiedOwned,
    PolicyDisplaced,
}

pub(super) fn discard_displaced_under_policy<Fd: std::os::fd::AsFd>(
    parent: Fd,
    stage: &OsStr,
    destination: &str,
) -> Result<()> {
    unlinkat(parent, stage, AtFlags::empty()).map_err(|errno| {
        Failure::syscall(
            CodeKey::FinalVerification,
            destination,
            "unlinkat-policy-displaced",
            errno,
        )
    })
}

pub(super) fn remove_verified_displaced<Fd: std::os::fd::AsFd>(
    parent: Fd,
    stage: &OsStr,
    destination: &str,
) -> Result<()> {
    #[cfg(test)]
    if FAIL_VERIFIED_DISPLACED_CLEANUP.with(|fault| fault.replace(false)) {
        return Err(Failure::syscall(
            CodeKey::FinalVerification,
            destination,
            "unlinkat-verified-displaced",
            Errno::IO,
        ));
    }
    unlinkat(parent, stage, AtFlags::empty()).map_err(|errno| {
        Failure::syscall(
            CodeKey::FinalVerification,
            destination,
            "unlinkat-verified-displaced",
            errno,
        )
    })
}

pub(super) fn exchange_names(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    key: CodeKey,
    operation: &'static str,
) -> Result<()> {
    renameat_with(parent, stage, parent, name, RenameFlags::EXCHANGE)
        .map_err(|errno| Failure::syscall(key, destination, operation, errno))
}

pub(super) fn publish_new(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    expected: &OsStr,
) -> Result<()> {
    if symlink_target(parent, name)
        .map_err(|errno| {
            Failure::syscall(
                CodeKey::PublishRace,
                destination,
                "fstatat-before-publish",
                errno,
            )
        })?
        .exists()
    {
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::new(
                CodeKey::PublishRace,
                destination,
                "destination appeared before atomic publish; refusing replacement",
            ),
        ));
    }

    if let Err(errno) = renameat_with(parent, stage, parent, name, RenameFlags::NOREPLACE) {
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::syscall(
                CodeKey::PublishRace,
                destination,
                "renameat2-noreplace-publish",
                errno,
            ),
        ));
    }

    fault_point("published");
    sync_parent(parent, destination)?;
    fault_point("published-synced");

    let final_target = symlink_target(parent, name).map_err(|errno| {
        Failure::syscall(
            CodeKey::FinalVerification,
            destination,
            "readlinkat-final",
            errno,
        )
    })?;
    if final_target.target() != Some(expected) {
        return Err(Failure::new(
            CodeKey::FinalVerification,
            destination,
            "published destination failed exact-target verification",
        ));
    }
    Ok(())
}

pub(super) fn publish_exchange(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    expected: &OsStr,
    recorded: &OsStr,
) -> Result<()> {
    if let Err(errno) = renameat_with(parent, stage, parent, name, RenameFlags::EXCHANGE) {
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::syscall(
                CodeKey::PublishRace,
                destination,
                "renameat2-exchange-publish",
                errno,
            ),
        ));
    }
    fault_point("exchange-published");

    // Both exchange sides must match their recorded targets.
    let published = symlink_target(parent, name).map_err(|errno| {
        Failure::syscall(
            CodeKey::RepairVerification,
            destination,
            "readlinkat-published",
            errno,
        )
    })?;
    let displaced = symlink_target(parent, stage).map_err(|errno| {
        Failure::syscall(
            CodeKey::RepairVerification,
            destination,
            "readlinkat-displaced",
            errno,
        )
    })?;
    if published.target() != Some(expected) || displaced.target() != Some(recorded) {
        return Err(Failure::new(
            CodeKey::RepairVerification,
            destination,
            "post-exchange verification did not observe the recorded link on both sides",
        ));
    }

    remove_verified_displaced(parent, stage, destination)?;
    fault_point("published");
    sync_parent(parent, destination)?;
    fault_point("published-synced");
    Ok(())
}

pub(super) fn observe_kind(
    parent: &OwnedFd,
    name: &OsStr,
    destination: &str,
) -> Result<Option<u32>> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(stat.st_mode as u32 & FILE_TYPE_MASK)),
        Err(Errno::NOENT) => Ok(None),
        Err(errno) => Err(Failure::syscall(
            CodeKey::ConflictingDestination,
            destination,
            "fstatat-destination-kind",
            errno,
        )),
    }
}

pub(super) fn observe_mode(parent: &OwnedFd, name: &OsStr, destination: &str) -> Result<u32> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(stat.st_mode as u32 & 0o7777),
        Err(errno) => Err(Failure::syscall(
            CodeKey::ConflictingDestination,
            destination,
            "fstatat-destination-mode",
            errno,
        )),
    }
}

pub(super) fn read_regular(
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

pub(super) fn hash_regular(
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

pub(super) fn sync_parent(parent: &OwnedFd, destination: &str) -> Result<()> {
    fsync(parent).map_err(|errno| {
        Failure::syscall(
            CodeKey::FinalVerification,
            destination,
            "fsync-parent",
            errno,
        )
    })
}

pub(super) fn verify_writable_hash(
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

pub(super) fn rollback_exchange(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    prior_hash: &str,
    intended_hash: &str,
) -> Result<()> {
    reverse_exchange_restore_fault().map_err(|errno| {
        Failure::syscall(
            CodeKey::PendingRecovery,
            destination,
            "renameat2-exchange-restore-pending",
            errno,
        )
    })?;
    renameat_with(parent, stage, parent, name, RenameFlags::EXCHANGE).map_err(|errno| {
        Failure::syscall(
            CodeKey::PendingRecovery,
            destination,
            "renameat2-exchange-restore-pending",
            errno,
        )
    })?;
    sync_parent(parent, destination)?;
    verify_writable_hash(
        parent,
        name,
        destination,
        prior_hash,
        "read-restored-destination",
    )?;
    verify_writable_hash(
        parent,
        stage,
        destination,
        intended_hash,
        "read-restored-stage",
    )?;
    Ok(())
}

pub(super) fn publish_writable_new(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    intended_hash: &str,
) -> Result<()> {
    fault_point("stage-synced");
    if observe_kind(parent, name, destination)?.is_some() {
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::new(
                CodeKey::PublishRace,
                destination,
                "destination appeared before atomic publish; refusing replacement",
            ),
        ));
    }
    if let Err(errno) = renameat_with(parent, stage, parent, name, RenameFlags::NOREPLACE) {
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::syscall(
                CodeKey::PublishRace,
                destination,
                "renameat2-noreplace-publish",
                errno,
            ),
        ));
    }
    fault_point("published");
    sync_parent(parent, destination)?;
    fault_point("published-synced");
    verify_writable_destination(parent, name, destination, intended_hash)?;
    fault_point("verified");
    Ok(())
}

pub(super) fn publish_writable_exchange(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    expected_displaced: &str,
    intended_hash: &str,
    cleanup: DisplacedCleanup,
) -> Result<()> {
    fault_point("stage-synced");
    if let Err(errno) = renameat_with(parent, stage, parent, name, RenameFlags::EXCHANGE) {
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::syscall(
                CodeKey::PublishRace,
                destination,
                "renameat2-exchange-publish",
                errno,
            ),
        ));
    }
    fault_point("exchange-published");
    // The displaced hash must equal the pre-publication witness.
    let displaced_hash = hash_regular(
        parent,
        stage,
        destination,
        CodeKey::PublishRace,
        "read-displaced",
    )?;
    if displaced_hash != expected_displaced {
        rollback_exchange(
            parent,
            name,
            stage,
            destination,
            &displaced_hash,
            intended_hash,
        )?;
        return Err(cleanup_unpublished_after_failure(
            parent,
            stage,
            destination,
            Failure::new(
                CodeKey::PublishRace,
                destination,
                "destination changed between observation and publication; exchange reversed",
            ),
        ));
    }
    match cleanup {
        DisplacedCleanup::VerifiedOwned => remove_verified_displaced(parent, stage, destination)?,
        DisplacedCleanup::PolicyDisplaced => {
            discard_displaced_under_policy(parent, stage, destination)?;
        }
    }
    fault_point("published");
    sync_parent(parent, destination)?;
    fault_point("published-synced");
    verify_writable_destination(parent, name, destination, intended_hash)?;
    fault_point("verified");
    Ok(())
}

#[cfg(test)]
mod sp3_tests {
    use super::*;
    use std::os::unix::fs::symlink;

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

    #[test]
    fn unpublished_cleanup_accepts_only_absence() {
        let path = directory();
        let parent = open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        remove_unpublished_stage(&parent, OsStr::new("missing"), "/dest").unwrap();
        std::fs::create_dir(path.join("directory")).unwrap();
        let failure = remove_unpublished_stage(&parent, OsStr::new("directory"), "/dest")
            .expect_err("directory unlink must be real");
        assert_eq!(
            failure.cause.as_ref().map(|cause| cause.operation),
            Some("unlinkat-unpublished-stage")
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
