use crate::lock::DEFAULT_LOCK_DIR;
use crate::manifest::{EXECUTOR_PROFILES, ExecutorProfile, WRITABLE_REPRESENTATION};
use crate::{WRITABLE_FILE_MODE, reconcile};
use rustix::fs::{Mode, OFlags, mkdirat, open, openat, symlinkat};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

// creating a parent is not an executor. it presents no representation, owns no
// destination and is never recorded, so it stays out of the table a manifest
// entry is qualified against and lives in a worker-only one that main scans
// second. what the worker does is chosen by which table matched, never by a
// representation.
pub(crate) struct WorkerAction {
    pub(crate) subcommand: &'static str,
}

pub(crate) const DIRECTORY_ACTION: WorkerAction = WorkerAction {
    subcommand: "create-native-directory",
};

pub(crate) const WORKER_ACTIONS: [&WorkerAction; 1] = [&DIRECTORY_ACTION];

// one mode for a created parent, asserted rather than requested, because
// mkdirat is masked by the umask of whichever authority created it.
pub(crate) const DIRECTORY_MODE: u32 = 0o755;

pub(crate) fn worker_action_for(subcommand: &str) -> Option<&'static WorkerAction> {
    WORKER_ACTIONS
        .iter()
        .copied()
        .find(|action| action.subcommand == subcommand)
}
pub(crate) fn worker(args: &[OsString], profile: &ExecutorProfile) -> ExitCode {
    let mut parent_fd = None;
    let mut name = None;
    let mut value = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].to_string_lossy().as_ref() {
            "--parent-fd" if index + 1 < args.len() => {
                parent_fd = args[index + 1].to_string_lossy().parse::<i32>().ok();
                index += 2;
            }
            "--name" if index + 1 < args.len() => {
                name = Some(args[index + 1].clone());
                index += 2;
            }
            flag if flag == profile.worker_value_flag && index + 1 < args.len() => {
                value = Some(args[index + 1].clone());
                index += 2;
            }
            _ => return ExitCode::FAILURE,
        }
    }
    let (Some(parent_fd), Some(name), Some(value)) = (parent_fd, name, value) else {
        return ExitCode::FAILURE;
    };
    let inherited = PathBuf::from(format!("/proc/self/fd/{parent_fd}"));
    let parent = match open(
        &inherited,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    ) {
        Ok(parent) => parent,
        Err(_) => return ExitCode::FAILURE,
    };
    if profile.representation == WRITABLE_REPRESENTATION {
        return stage_writable_content(&parent, &name, Path::new(&value));
    }
    match symlinkat(&value, &parent, &name) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

// the worker half of parent creation. a name that is anything other than one
// ordinary component is refused before a syscall runs, on the same reasoning the
// lock name is guarded. an existing directory is success and is left untouched;
// only a component this call actually created has its mode asserted.
pub(crate) fn create_directory_component(args: &[OsString]) -> ExitCode {
    let mut parent_fd = None;
    let mut name = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].to_string_lossy().as_ref() {
            "--parent-fd" if index + 1 < args.len() => {
                parent_fd = args[index + 1].to_string_lossy().parse::<i32>().ok();
                index += 2;
            }
            "--name" if index + 1 < args.len() => {
                name = Some(args[index + 1].clone());
                index += 2;
            }
            _ => return ExitCode::FAILURE,
        }
    }
    let (Some(parent_fd), Some(name)) = (parent_fd, name) else {
        return ExitCode::FAILURE;
    };
    if !is_single_component(&name) {
        return ExitCode::FAILURE;
    }
    let inherited = PathBuf::from(format!("/proc/self/fd/{parent_fd}"));
    let parent = match open(
        &inherited,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    ) {
        Ok(parent) => parent,
        Err(_) => return ExitCode::FAILURE,
    };
    match mkdirat(&parent, &name, Mode::from_bits_truncate(DIRECTORY_MODE)) {
        Ok(()) => {}
        // somebody else got there first, which is the same end state and is not a
        // failure. it is also not permission to touch what they made.
        Err(Errno::EXIST) => return ExitCode::SUCCESS,
        Err(_) => return ExitCode::FAILURE,
    }
    let created = match openat(
        &parent,
        &name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(created) => created,
        Err(_) => return ExitCode::FAILURE,
    };
    let path = format!("/proc/self/fd/{}", created.as_raw_fd());
    if fs::set_permissions(&path, fs::Permissions::from_mode(DIRECTORY_MODE)).is_err() {
        return ExitCode::FAILURE;
    }
    // the request is not the guarantee, so the mode is read back off the
    // descriptor that was just created rather than trusted.
    match fs::metadata(&path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.permissions().mode() & 0o7777 != DIRECTORY_MODE {
                return ExitCode::FAILURE;
            }
        }
        Err(_) => return ExitCode::FAILURE,
    }
    ExitCode::SUCCESS
}

pub(crate) fn is_single_component(name: &OsStr) -> bool {
    let path = Path::new(name);
    let mut components = path.components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

// the bytes are written and durable before the coordinator is told anything
// succeeded, so a crash after the executor returns can never leave a stage the
// coordinator would mistake for complete.
pub(crate) fn stage_writable_content(parent: &OwnedFd, name: &OsStr, source: &Path) -> ExitCode {
    let bytes = match fs::read(source) {
        Ok(bytes) => bytes,
        Err(_) => return ExitCode::FAILURE,
    };
    let staged = match openat(
        parent,
        name,
        OFlags::CREATE | OFlags::WRONLY | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_bits_truncate(WRITABLE_FILE_MODE),
    ) {
        Ok(fd) => fd,
        Err(_) => return ExitCode::FAILURE,
    };
    let mut file = fs::File::from(staged);
    if file.write_all(&bytes).is_err() {
        return ExitCode::FAILURE;
    }
    // the mode is asserted rather than assumed, because O_CREAT is subject to
    // the umask of whichever authority the executor is running under.
    if fs::set_permissions(
        format!("/proc/self/fd/{}", file.as_raw_fd()),
        fs::Permissions::from_mode(WRITABLE_FILE_MODE),
    )
    .is_err()
    {
        return ExitCode::FAILURE;
    }
    if file.sync_all().is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

pub(crate) fn option(args: &[OsString], flag: &str) -> Option<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == OsStr::new(flag))
        .map(|pair| PathBuf::from(&pair[1]))
}
pub(crate) fn run(args: &[OsString]) -> ExitCode {
    match args.first().and_then(|value| value.to_str()) {
        Some("reconcile") => {
            let Some(manifest) = option(&args[1..], "--manifest") else {
                return ExitCode::FAILURE;
            };
            let Some(lock_name) = option(&args[1..], "--lock-name") else {
                return ExitCode::FAILURE;
            };
            let Some(setpriv) = option(&args[1..], "--setpriv") else {
                return ExitCode::FAILURE;
            };
            let Some(state_dir) = option(&args[1..], "--state-dir") else {
                return ExitCode::FAILURE;
            };
            let lock_dir =
                option(&args[1..], "--lock-dir").unwrap_or_else(|| PathBuf::from(DEFAULT_LOCK_DIR));
            reconcile(
                &manifest,
                lock_name.as_os_str(),
                &setpriv,
                &state_dir,
                &lock_dir,
            )
        }
        Some(subcommand) => {
            match EXECUTOR_PROFILES
                .iter()
                .find(|profile| profile.worker_subcommand == subcommand)
            {
                Some(profile) => worker(&args[1..], profile),
                None => match worker_action_for(subcommand) {
                    Some(_) => create_directory_component(&args[1..]),
                    None => ExitCode::FAILURE,
                },
            }
        }
        _ => ExitCode::FAILURE,
    }
}
