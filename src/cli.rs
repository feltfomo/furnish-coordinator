use crate::executor::{self, WorkerCommand, WorkerKind, WorkerProgram};
use crate::filesystem::WRITABLE_FILE_MODE;
use crate::lock::DEFAULT_LOCK_DIR;
use crate::reconcile::reconcile;
use rustix::fs::{Mode, OFlags, mkdirat, open, openat, symlinkat};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

pub(crate) const DIRECTORY_MODE: u32 = 0o755;

#[derive(Debug)]
pub(crate) enum Command {
    Reconcile {
        manifest: PathBuf,
        lock_name: OsString,
        setpriv: PathBuf,
        state_dir: PathBuf,
        lock_dir: PathBuf,
    },
    Worker(WorkerCommand),
}

impl Command {
    // main already removed argv[0]. parsing begins at the subcommand and never
    // discards another argument.
    pub(crate) fn parse(args: &[OsString]) -> Option<Self> {
        let subcommand = args.first()?.to_str()?;
        if subcommand == "reconcile" {
            return Self::parse_reconcile(&args[1..]);
        }
        let program = WorkerProgram::from_subcommand(subcommand)?;
        Self::parse_worker(program, &args[1..]).map(Self::Worker)
    }

    // this permissive grammar is compatibility. overlapping pairs preserve
    // first-occurrence wins, unknown options and flag strings used as values.
    fn parse_reconcile(args: &[OsString]) -> Option<Self> {
        Some(Self::Reconcile {
            manifest: option(args, "--manifest")?,
            lock_name: option(args, "--lock-name")?.into_os_string(),
            setpriv: option(args, "--setpriv")?,
            state_dir: option(args, "--state-dir")?,
            lock_dir: option(args, "--lock-dir").unwrap_or_else(|| PathBuf::from(DEFAULT_LOCK_DIR)),
        })
    }

    fn parse_worker(program: WorkerProgram, args: &[OsString]) -> Option<WorkerCommand> {
        let mut parent_fd = None;
        let mut name = None;
        let mut value = None;
        let mut index = 0;
        while index < args.len() {
            let flag = args[index].to_str()?;
            let argument = args.get(index + 1)?;
            match flag {
                "--parent-fd" if parent_fd.is_none() => {
                    parent_fd = argument.to_string_lossy().parse::<i32>().ok();
                }
                "--name" if name.is_none() => name = Some(argument.clone()),
                _ if program.value_flag() == Some(flag) && value.is_none() => {
                    value = Some(argument.clone());
                }
                _ => return None,
            }
            index += 2;
        }
        let kind = match program {
            WorkerProgram::Symlink => WorkerKind::Symlink { target: value? },
            WorkerProgram::Writable => WorkerKind::Writable { source: value? },
            WorkerProgram::Directory => WorkerKind::Directory,
        };
        Some(WorkerCommand {
            kind,
            parent_fd: parent_fd?,
            name: name?,
        })
    }
}

fn option(args: &[OsString], flag: &str) -> Option<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == OsStr::new(flag))
        .map(|pair| PathBuf::from(&pair[1]))
}

pub(crate) fn run(args: &[OsString]) -> ExitCode {
    match Command::parse(args) {
        Some(Command::Reconcile {
            manifest,
            lock_name,
            setpriv,
            state_dir,
            lock_dir,
        }) => reconcile(&manifest, &lock_name, &setpriv, &state_dir, &lock_dir),
        Some(Command::Worker(command)) => run_worker(command),
        None => ExitCode::FAILURE,
    }
}

fn run_worker(command: WorkerCommand) -> ExitCode {
    if !is_single_component(&command.name) {
        return ExitCode::FAILURE;
    }
    let inherited = PathBuf::from(format!("/proc/self/fd/{}", command.parent_fd));
    // the coordinator intentionally hands the parent descriptor through exec.
    let parent = match open(
        &inherited,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    ) {
        Ok(parent) => parent,
        Err(errno) => return executor::worker_failure("open-worker-parent", errno.raw_os_error()),
    };
    match command.kind {
        WorkerKind::Symlink { target } => match symlinkat(&target, &parent, &command.name) {
            Ok(()) => ExitCode::SUCCESS,
            Err(errno) => executor::worker_failure("symlinkat-stage", errno.raw_os_error()),
        },
        WorkerKind::Writable { source } => {
            stage_writable_content(&parent, &command.name, Path::new(&source))
        }
        WorkerKind::Directory => create_directory_component_parsed(&parent, &command.name),
    }
}

fn create_directory_component_parsed(parent: &OwnedFd, name: &OsStr) -> ExitCode {
    match mkdirat(parent, name, Mode::from_bits_truncate(DIRECTORY_MODE)) {
        Ok(()) => {}
        Err(Errno::EXIST) => return ExitCode::SUCCESS,
        Err(errno) => {
            return executor::worker_failure("mkdirat-parent-component", errno.raw_os_error());
        }
    }
    let created = match openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(created) => created,
        Err(errno) => {
            return executor::worker_failure(
                "openat-created-parent-component",
                errno.raw_os_error(),
            );
        }
    };
    let path = format!("/proc/self/fd/{}", created.as_raw_fd());
    if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(DIRECTORY_MODE)) {
        return executor::worker_failure(
            "chmod-created-parent-component",
            executor::io_errno(&error),
        );
    }
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return executor::worker_failure(
                "stat-created-parent-component",
                executor::io_errno(&error),
            );
        }
    };
    if !metadata.is_dir() || metadata.permissions().mode() & 0o7777 != DIRECTORY_MODE {
        return executor::worker_failure(
            "verify-created-parent-component",
            Errno::IO.raw_os_error(),
        );
    }
    ExitCode::SUCCESS
}

fn is_single_component(name: &OsStr) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn stage_writable_content(parent: &OwnedFd, name: &OsStr, source: &Path) -> ExitCode {
    let bytes = match fs::read(source) {
        Ok(bytes) => bytes,
        Err(error) => {
            return executor::worker_failure("read-worker-source", executor::io_errno(&error));
        }
    };
    let staged = match openat(
        parent,
        name,
        OFlags::CREATE | OFlags::WRONLY | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_bits_truncate(WRITABLE_FILE_MODE),
    ) {
        Ok(fd) => fd,
        Err(errno) => {
            return executor::worker_failure("openat-worker-stage", errno.raw_os_error());
        }
    };
    let mut file = fs::File::from(staged);
    if let Err(error) = file.write_all(&bytes) {
        return executor::worker_failure("write-worker-stage", executor::io_errno(&error));
    }
    if let Err(error) = fs::set_permissions(
        format!("/proc/self/fd/{}", file.as_raw_fd()),
        fs::Permissions::from_mode(WRITABLE_FILE_MODE),
    ) {
        return executor::worker_failure("chmod-worker-stage", executor::io_errno(&error));
    }
    if let Err(error) = file.sync_all() {
        return executor::worker_failure("fsync-worker-stage", executor::io_errno(&error));
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parser_does_not_skip_the_subcommand() {
        assert!(matches!(
            Command::parse(&args(&[
                "reconcile",
                "--manifest",
                "m",
                "--lock-name",
                "l",
                "--setpriv",
                "s",
                "--state-dir",
                "d"
            ])),
            Some(Command::Reconcile { .. })
        ));
    }

    #[test]
    fn permissive_parser_keeps_first_occurrence_and_unknowns() {
        let parsed = Command::parse(&args(&[
            "reconcile",
            "--bogus",
            "q",
            "--manifest",
            "m",
            "--lock-name",
            "l",
            "--setpriv",
            "first",
            "--setpriv",
            "second",
            "--state-dir",
            "d",
        ]));
        let Some(Command::Reconcile { setpriv, .. }) = parsed else {
            panic!("reconcile")
        };
        assert_eq!(setpriv, PathBuf::from("first"));
    }

    #[test]
    fn permissive_parser_keeps_a_flag_string_as_the_preceding_value() {
        let parsed = Command::parse(&args(&[
            "reconcile",
            "--manifest",
            "m",
            "--lock-name",
            "l",
            "--setpriv",
            "--state-dir",
            "/w",
        ]));
        let Some(Command::Reconcile {
            setpriv, state_dir, ..
        }) = parsed
        else {
            panic!("reconcile")
        };
        assert_eq!(setpriv, PathBuf::from("--state-dir"));
        assert_eq!(state_dir, PathBuf::from("/w"));
    }
}
