use crate::diagnostic::{Cause, CodeKey, Failure, Result};
use crate::manifest::Authority;
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use std::env;
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

const EVIDENCE_ENV: &str = "FURNISH_WORKER_EVIDENCE";
const EVIDENCE_LIMIT: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerKind {
    Symlink,
    Writable,
    Directory,
}

impl WorkerKind {
    pub(crate) fn from_subcommand(value: &str) -> Option<Self> {
        match value {
            "stage-native-symlink" => Some(Self::Symlink),
            "stage-native-writable" => Some(Self::Writable),
            "create-native-directory" => Some(Self::Directory),
            _ => None,
        }
    }

    pub(crate) const fn subcommand(self) -> &'static str {
        match self {
            Self::Symlink => "stage-native-symlink",
            Self::Writable => "stage-native-writable",
            Self::Directory => "create-native-directory",
        }
    }

    pub(crate) const fn value_flag(self) -> Option<&'static str> {
        match self {
            Self::Symlink => Some("--target"),
            Self::Writable => Some("--source"),
            Self::Directory => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct WorkerCommand {
    pub(crate) kind: WorkerKind,
    pub(crate) parent_fd: i32,
    pub(crate) name: OsString,
    pub(crate) value: Option<OsString>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    operation: String,
    errno: i32,
}

pub(crate) fn worker_failure(operation: &'static str, errno: i32) -> ExitCode {
    if env::var_os(EVIDENCE_ENV).is_some() {
        let evidence = Evidence {
            operation: operation.to_owned(),
            errno,
        };
        if let Ok(line) = serde_json::to_string(&evidence) {
            eprintln!("{line}");
        }
    }
    ExitCode::FAILURE
}

fn known_operation(value: &str) -> Option<&'static str> {
    match value {
        "open-worker-parent" => Some("open-worker-parent"),
        "symlinkat-stage" => Some("symlinkat-stage"),
        "read-worker-source" => Some("read-worker-source"),
        "openat-worker-stage" => Some("openat-worker-stage"),
        "write-worker-stage" => Some("write-worker-stage"),
        "chmod-worker-stage" => Some("chmod-worker-stage"),
        "fsync-worker-stage" => Some("fsync-worker-stage"),
        "mkdirat-parent-component" => Some("mkdirat-parent-component"),
        "openat-created-parent-component" => Some("openat-created-parent-component"),
        "chmod-created-parent-component" => Some("chmod-created-parent-component"),
        "stat-created-parent-component" => Some("stat-created-parent-component"),
        "verify-created-parent-component" => Some("verify-created-parent-component"),
        _ => None,
    }
}

fn parse_evidence(bytes: &[u8]) -> Option<Cause<'static>> {
    if bytes.is_empty() || bytes.len() > EVIDENCE_LIMIT {
        return None;
    }
    let evidence: Evidence = serde_json::from_slice(bytes).ok()?;
    Some(Cause {
        operation: known_operation(&evidence.operation)?,
        errno: evidence.errno,
    })
}

pub(crate) fn launch(
    setpriv: &Path,
    parent: &OwnedFd,
    name: &OsStr,
    value: Option<&OsStr>,
    target: &str,
    authority: &Authority,
    kind: WorkerKind,
) -> Result<()> {
    let executable = env::current_exe().map_err(|error| {
        Failure::new(
            CodeKey::ExecutorFailed,
            target,
            format!("cannot resolve coordinator executable: {error}"),
        )
    })?;
    let mut command = if authority.scope == "user" {
        let mut command = Command::new(setpriv);
        command
            .arg("--reuid")
            .arg(&authority.identity)
            .arg("--regid")
            .arg(&authority.identity)
            .arg("--init-groups")
            .arg("--")
            .arg(&executable);
        command
    } else {
        Command::new(&executable)
    };
    command
        .arg(kind.subcommand())
        .arg("--parent-fd")
        .arg(parent.as_raw_fd().to_string())
        .arg("--name")
        .arg(name)
        .env(EVIDENCE_ENV, "1")
        .stderr(Stdio::piped());
    if let (Some(flag), Some(value)) = (kind.value_flag(), value) {
        command.arg(flag).arg(value);
    }
    let directory = kind == WorkerKind::Directory;
    let output = command.output().map_err(|error| {
        Failure::new(
            CodeKey::ExecutorFailed,
            target,
            if directory {
                format!("failed to launch parent creation: {error}")
            } else {
                format!("failed to launch native executor: {error}")
            },
        )
    })?;
    if output.status.success() {
        return Ok(());
    }
    let mut failure = Failure::new(
        CodeKey::ExecutorFailed,
        target,
        if directory {
            format!("parent creation exited with {}", output.status)
        } else {
            format!("native executor exited with {}", output.status)
        },
    );
    failure.cause = parse_evidence(&output.stderr);
    Err(failure)
}

pub(crate) fn io_errno(error: &std::io::Error) -> i32 {
    error.raw_os_error().unwrap_or(Errno::IO.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_is_bounded_and_strict() {
        let cause = parse_evidence(br#"{"operation":"open-worker-parent","errno":9}"#)
            .expect("valid evidence");
        assert_eq!(cause.operation, "open-worker-parent");
        assert_eq!(cause.errno, 9);
        assert!(parse_evidence(br#"{"operation":"unknown","errno":9}"#).is_none());
        assert!(
            parse_evidence(br#"{"operation":"open-worker-parent","errno":9,"extra":1}"#).is_none()
        );
        assert!(parse_evidence(&vec![b'x'; EVIDENCE_LIMIT + 1]).is_none());
    }
}

#[cfg(test)]
mod inherited_fd_tests {
    use super::*;
    use rustix::fs::{Mode, OFlags, open};

    #[test]
    fn parent_descriptor_crosses_exec_only_without_cloexec() {
        let inherited = open("/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        let inherited_status = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("test -d /proc/self/fd/{}", inherited.as_raw_fd()))
            .status()
            .unwrap();
        assert!(inherited_status.success());

        let closed = open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let closed_status = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("test ! -e /proc/self/fd/{}", closed.as_raw_fd()))
            .status()
            .unwrap();
        assert!(closed_status.success());
    }
}
