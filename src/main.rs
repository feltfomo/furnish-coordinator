use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, RenameFlags, flock, open, openat, readlinkat,
    renameat_with, statat, symlinkat, unlinkat,
};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};

const MANIFEST_SCHEMA_VERSION: u64 = 1;
const DIAGNOSTIC_SCHEMA_VERSION: u64 = 1;
const NATIVE_EXECUTOR_IDENTITY: &str = "furnish/native-symlink";
const NATIVE_EXECUTOR_PROTOCOL: u64 = 1;
const NATIVE_REPRESENTATION: &str = "symlink";
const SYMLINK_MODE: u32 = 0o120000;
const FILE_TYPE_MASK: u32 = 0o170000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u64,
    diagnostic_contract: DiagnosticContract,
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticContract {
    schema_version: u64,
    codes: DiagnosticCodes,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticCodes {
    invalid_manifest: String,
    unsupported_executor: String,
    invalid_destination: String,
    parent_traversal: String,
    conflicting_destination: String,
    executor_failed: String,
    staging_verification: String,
    publish_race: String,
    final_verification: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    schema_version: u64,
    filesystem_identity: FilesystemIdentity,
    authority: Authority,
    managed_root: String,
    representation: String,
    retained_artifact_target: String,
    executor: Executor,
    cleanup_strategy: String,
    self_heal_strategy: String,
    provenance: Provenance,
}

#[derive(Debug, Deserialize)]
struct FilesystemIdentity {
    namespace: String,
    destination: String,
    canonical: String,
}

#[derive(Debug, Deserialize)]
struct Authority {
    scope: String,
    identity: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Executor {
    identity: String,
    protocol_version: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct Provenance {
    declaration: String,
    source: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Diagnostic<'a> {
    schema_version: u64,
    severity: &'static str,
    code: &'a str,
    message: &'a str,
    primary: Primary<'a>,
    provenance: Option<&'a Provenance>,
    cause: Option<Cause<'a>>,
}

#[derive(Debug, Serialize)]
struct Primary<'a> {
    label: &'a str,
}

#[derive(Debug, Serialize)]
struct Cause<'a> {
    operation: &'a str,
    errno: i32,
}

#[derive(Clone, Copy, Debug)]
enum CodeKey {
    InvalidManifest,
    UnsupportedExecutor,
    InvalidDestination,
    ParentTraversal,
    ConflictingDestination,
    ExecutorFailed,
    StagingVerification,
    PublishRace,
    FinalVerification,
}

#[derive(Debug)]
struct Failure {
    key: CodeKey,
    message: String,
    label: String,
    operation: Option<&'static str>,
    errno: Option<i32>,
}

type Result<T> = std::result::Result<T, Failure>;

impl Failure {
    fn new(key: CodeKey, label: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            key,
            message: message.into(),
            label: label.into(),
            operation: None,
            errno: None,
        }
    }

    fn syscall(
        key: CodeKey,
        label: impl Into<String>,
        operation: &'static str,
        errno: Errno,
    ) -> Self {
        Self {
            key,
            message: format!("{operation} failed"),
            label: label.into(),
            operation: Some(operation),
            errno: Some(errno.raw_os_error()),
        }
    }
}

fn code<'a>(codes: &'a DiagnosticCodes, key: CodeKey) -> &'a str {
    match key {
        CodeKey::InvalidManifest => &codes.invalid_manifest,
        CodeKey::UnsupportedExecutor => &codes.unsupported_executor,
        CodeKey::InvalidDestination => &codes.invalid_destination,
        CodeKey::ParentTraversal => &codes.parent_traversal,
        CodeKey::ConflictingDestination => &codes.conflicting_destination,
        CodeKey::ExecutorFailed => &codes.executor_failed,
        CodeKey::StagingVerification => &codes.staging_verification,
        CodeKey::PublishRace => &codes.publish_race,
        CodeKey::FinalVerification => &codes.final_verification,
    }
}

fn serialize_failure(
    codes: &DiagnosticCodes,
    failure: &Failure,
    provenance: Option<&Provenance>,
) -> serde_json::Result<String> {
    serde_json::to_string(&Diagnostic {
        schema_version: DIAGNOSTIC_SCHEMA_VERSION,
        severity: "error",
        code: code(codes, failure.key),
        message: &failure.message,
        primary: Primary {
            label: &failure.label,
        },
        provenance,
        cause: failure
            .operation
            .zip(failure.errno)
            .map(|(operation, errno)| Cause { operation, errno }),
    })
}

fn emit_failure(codes: &DiagnosticCodes, failure: &Failure, provenance: Option<&Provenance>) {
    match serialize_failure(codes, failure, provenance) {
        Ok(line) => eprintln!("{line}"),
        Err(_) => eprintln!("furnish: failed to serialize runtime diagnostic"),
    }
}

fn validate_manifest(manifest: &Manifest) -> Result<()> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(Failure::new(
            CodeKey::InvalidManifest,
            "manifest",
            format!(
                "manifest schema {} is unsupported; expected {}",
                manifest.schema_version, MANIFEST_SCHEMA_VERSION
            ),
        ));
    }
    if manifest.diagnostic_contract.schema_version != DIAGNOSTIC_SCHEMA_VERSION {
        return Err(Failure::new(
            CodeKey::InvalidManifest,
            "diagnostic contract",
            format!(
                "diagnostic schema {} is unsupported; expected {}",
                manifest.diagnostic_contract.schema_version, DIAGNOSTIC_SCHEMA_VERSION
            ),
        ));
    }
    for entry in &manifest.entries {
        if entry.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(Failure::new(
                CodeKey::InvalidManifest,
                &entry.filesystem_identity.canonical,
                "entry schema does not match the manifest schema",
            ));
        }
        if entry.executor.identity != NATIVE_EXECUTOR_IDENTITY
            || entry.executor.protocol_version != NATIVE_EXECUTOR_PROTOCOL
            || entry.representation != NATIVE_REPRESENTATION
        {
            return Err(Failure::new(
                CodeKey::UnsupportedExecutor,
                &entry.filesystem_identity.canonical,
                format!(
                    "unsupported executor tuple ({}, {}, {})",
                    entry.executor.identity, entry.executor.protocol_version, entry.representation
                ),
            ));
        }
        if entry.cleanup_strategy != "exact-symlink-target"
            || entry.self_heal_strategy != "exact-symlink-target"
        {
            return Err(Failure::new(
                CodeKey::InvalidManifest,
                &entry.filesystem_identity.canonical,
                "native symlink reconciliation requires exact-symlink-target lifecycle strategies",
            ));
        }
        if entry.authority.scope != "user" && entry.authority.scope != "system" {
            return Err(Failure::new(
                CodeKey::InvalidManifest,
                &entry.filesystem_identity.canonical,
                "authority scope must be user or system",
            ));
        }
        let expected = format!(
            "{}:{}",
            entry.filesystem_identity.namespace, entry.filesystem_identity.destination
        );
        if entry.filesystem_identity.canonical != expected {
            return Err(Failure::new(
                CodeKey::InvalidManifest,
                &entry.filesystem_identity.canonical,
                "filesystem identity is not canonical",
            ));
        }
    }
    Ok(())
}

fn open_parent(destination: &str, managed_root: &str) -> Result<(OwnedFd, OsString)> {
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

    for component in parent.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                current = openat(
                    &current,
                    part,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|errno| {
                    Failure::syscall(
                        CodeKey::ParentTraversal,
                        destination,
                        "openat-parent-component",
                        errno,
                    )
                })?;
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

fn symlink_target<Fd: std::os::fd::AsFd>(
    dir: Fd,
    name: &OsStr,
) -> std::result::Result<Option<OsString>, Errno> {
    match statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            if stat.st_mode & FILE_TYPE_MASK != SYMLINK_MODE {
                return Ok(Some(OsString::new()));
            }
            let target = readlinkat(dir, name, Vec::new())?;
            Ok(Some(OsString::from_vec(target.into_bytes())))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(errno) => Err(errno),
    }
}

fn remove_stage<Fd: std::os::fd::AsFd>(parent: Fd, stage: &OsStr) {
    let _ = unlinkat(parent, stage, AtFlags::empty());
}

fn stage_name(index: usize) -> OsString {
    OsString::from(format!(".furnish.{}.{}.stage", std::process::id(), index))
}

fn run_executor(
    setpriv: &Path,
    parent: &OwnedFd,
    stage: &OsStr,
    target: &str,
    authority: &Authority,
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
    let status = command
        .arg("stage-native-symlink")
        .arg("--parent-fd")
        .arg(parent.as_raw_fd().to_string())
        .arg("--name")
        .arg(stage)
        .arg("--target")
        .arg(target)
        .status()
        .map_err(|error| {
            Failure::new(
                CodeKey::ExecutorFailed,
                target,
                format!("failed to launch native executor: {error}"),
            )
        })?;
    if !status.success() {
        return Err(Failure::new(
            CodeKey::ExecutorFailed,
            target,
            format!("native executor exited with {status}"),
        ));
    }
    Ok(())
}

fn reconcile_entry(entry: &Entry, setpriv: &Path, index: usize) -> Result<()> {
    let destination = &entry.filesystem_identity.destination;
    let expected = OsStr::new(&entry.retained_artifact_target);
    let (parent, name) = open_parent(destination, &entry.managed_root)?;

    match symlink_target(&parent, &name).map_err(|errno| {
        Failure::syscall(
            CodeKey::ConflictingDestination,
            destination,
            "fstatat-destination",
            errno,
        )
    })? {
        None => {}
        Some(actual) if actual == expected => return Ok(()),
        Some(actual) => {
            let observed = if actual.is_empty() {
                "non-symlink filesystem object".to_owned()
            } else {
                format!("symlink to {}", actual.to_string_lossy())
            };
            return Err(Failure::new(
                CodeKey::ConflictingDestination,
                destination,
                format!("refusing to replace {observed}"),
            ));
        }
    }

    let stage = stage_name(index);
    remove_stage(&parent, &stage);
    run_executor(
        setpriv,
        &parent,
        &stage,
        &entry.retained_artifact_target,
        &entry.authority,
    )?;

    let staged = symlink_target(&parent, &stage).map_err(|errno| {
        Failure::syscall(
            CodeKey::StagingVerification,
            destination,
            "readlinkat-staging",
            errno,
        )
    })?;
    if staged.as_deref() != Some(expected) {
        remove_stage(&parent, &stage);
        return Err(Failure::new(
            CodeKey::StagingVerification,
            destination,
            "native executor produced an unexpected staging object",
        ));
    }

    if symlink_target(&parent, &name)
        .map_err(|errno| {
            Failure::syscall(
                CodeKey::PublishRace,
                destination,
                "fstatat-before-publish",
                errno,
            )
        })?
        .is_some()
    {
        remove_stage(&parent, &stage);
        return Err(Failure::new(
            CodeKey::PublishRace,
            destination,
            "destination appeared before atomic publish; refusing replacement",
        ));
    }

    if let Err(errno) = renameat_with(&parent, &stage, &parent, &name, RenameFlags::NOREPLACE) {
        remove_stage(&parent, &stage);
        return Err(Failure::syscall(
            CodeKey::PublishRace,
            destination,
            "renameat2-noreplace-publish",
            errno,
        ));
    }

    let final_target = symlink_target(&parent, &name).map_err(|errno| {
        Failure::syscall(
            CodeKey::FinalVerification,
            destination,
            "readlinkat-final",
            errno,
        )
    })?;
    if final_target.as_deref() != Some(expected) {
        return Err(Failure::new(
            CodeKey::FinalVerification,
            destination,
            "published destination failed exact-target verification",
        ));
    }
    Ok(())
}

fn acquire_lock(run_lock: &OwnedFd, lock_name: &OsStr) -> Result<OwnedFd> {
    let label = Path::new("/run/lock").join(lock_name);
    let lock = openat(
        run_lock,
        lock_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|errno| {
        Failure::syscall(
            CodeKey::InvalidManifest,
            label.to_string_lossy(),
            "openat-lock",
            errno,
        )
    })?;
    flock(&lock, FlockOperation::LockExclusive).map_err(|errno| {
        Failure::syscall(
            CodeKey::InvalidManifest,
            label.to_string_lossy(),
            "flock",
            errno,
        )
    })?;
    Ok(lock)
}

fn open_host_lock(lock_name: &OsStr) -> Result<OwnedFd> {
    let mut components = Path::new(lock_name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(Failure::new(
            CodeKey::InvalidManifest,
            lock_name.to_string_lossy(),
            "lock name must be one normal path component",
        ));
    }
    let run_lock = open(
        "/run/lock",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| {
        Failure::syscall(
            CodeKey::InvalidManifest,
            "/run/lock",
            "open-run-lock",
            errno,
        )
    })?;
    acquire_lock(&run_lock, lock_name)
}

fn reconcile(manifest_path: &Path, lock_name: &OsStr, setpriv: &Path) -> ExitCode {
    let bytes = match fs::read(manifest_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "schemaVersion": DIAGNOSTIC_SCHEMA_VERSION,
                    "severity": "error",
                    "code": "furnish/runtime-bootstrap",
                    "message": format!("cannot read manifest: {error}"),
                    "primary": {"label": manifest_path}
                })
            );
            return ExitCode::FAILURE;
        }
    };
    let manifest: Manifest = match serde_json::from_slice(&bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "schemaVersion": DIAGNOSTIC_SCHEMA_VERSION,
                    "severity": "error",
                    "code": "furnish/runtime-bootstrap",
                    "message": format!("cannot decode manifest: {error}"),
                    "primary": {"label": manifest_path}
                })
            );
            return ExitCode::FAILURE;
        }
    };
    if let Err(failure) = validate_manifest(&manifest) {
        emit_failure(&manifest.diagnostic_contract.codes, &failure, None);
        return ExitCode::FAILURE;
    }

    let _lock = match open_host_lock(lock_name) {
        Ok(lock) => lock,
        Err(failure) => {
            emit_failure(&manifest.diagnostic_contract.codes, &failure, None);
            return ExitCode::FAILURE;
        }
    };

    for (index, entry) in manifest.entries.iter().enumerate() {
        if let Err(failure) = reconcile_entry(entry, setpriv, index) {
            emit_failure(
                &manifest.diagnostic_contract.codes,
                &failure,
                Some(&entry.provenance),
            );
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn worker(args: &[OsString]) -> ExitCode {
    let mut parent_fd = None;
    let mut name = None;
    let mut target = None;
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
            "--target" if index + 1 < args.len() => {
                target = Some(args[index + 1].clone());
                index += 2;
            }
            _ => return ExitCode::FAILURE,
        }
    }
    let (Some(parent_fd), Some(name), Some(target)) = (parent_fd, name, target) else {
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
    match symlinkat(&target, &parent, &name) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

fn option(args: &[OsString], flag: &str) -> Option<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == OsStr::new(flag))
        .map(|pair| PathBuf::from(&pair[1]))
}

fn main() -> ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
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
            reconcile(&manifest, lock_name.as_os_str(), &setpriv)
        }
        Some("stage-native-symlink") => worker(&args[1..]),
        _ => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestLockRoot(PathBuf);

    impl TestLockRoot {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "furnish-lock-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated lock directory");
            Self(path)
        }

        fn open(&self) -> OwnedFd {
            open(
                &self.0,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .expect("open isolated lock directory")
        }
    }

    impl Drop for TestLockRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove isolated lock directory");
        }
    }

    #[test]
    fn stage_names_are_hidden_and_process_scoped() {
        let name = stage_name(7);
        let rendered = name.to_string_lossy();
        assert!(rendered.starts_with(".furnish."));
        assert!(rendered.ends_with(".7.stage"));
    }

    #[test]
    fn native_tuple_is_exact() {
        assert_eq!(NATIVE_EXECUTOR_IDENTITY, "furnish/native-symlink");
        assert_eq!(NATIVE_EXECUTOR_PROTOCOL, 1);
        assert_eq!(NATIVE_REPRESENTATION, "symlink");
    }

    #[test]
    fn absent_lock_file_is_created_and_locked() {
        let root = TestLockRoot::new();
        let lock_name = OsStr::new("furnish-test.lock");
        let _lock = acquire_lock(&root.open(), lock_name).expect("acquire fresh lock");
        assert!(root.0.join(lock_name).is_file());
    }

    #[test]
    fn lock_symlink_is_refused_without_following_it() {
        let root = TestLockRoot::new();
        let lock_name = OsStr::new("furnish-test.lock");
        symlink("elsewhere", root.0.join(lock_name)).expect("plant lock symlink");
        let failure = acquire_lock(&root.open(), lock_name).expect_err("refuse lock symlink");
        assert_eq!(failure.operation, Some("openat-lock"));
        assert_eq!(failure.errno, Some(Errno::LOOP.raw_os_error()));
        let codes = DiagnosticCodes {
            invalid_manifest: "runtime/invalid-manifest".to_owned(),
            ..DiagnosticCodes::default()
        };
        let encoded = serialize_failure(&codes, &failure, None).expect("serialize diagnostic");
        let diagnostic: serde_json::Value =
            serde_json::from_str(&encoded).expect("decode diagnostic");
        assert_eq!(diagnostic["code"], "runtime/invalid-manifest");
        assert_eq!(diagnostic["cause"]["operation"], "openat-lock");
        assert_eq!(diagnostic["cause"]["errno"], Errno::LOOP.raw_os_error());
    }

    #[test]
    fn concurrent_lock_acquisition_serializes() {
        let root = TestLockRoot::new();
        let lock_name = OsString::from("furnish-test.lock");
        let first = acquire_lock(&root.open(), &lock_name).expect("acquire first lock");
        let lock_root = root.0.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let directory = open(
                lock_root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .expect("open lock directory for waiter");
            started_tx.send(()).expect("signal waiter start");
            let _lock = acquire_lock(&directory, &lock_name).expect("acquire second lock");
            acquired_tx.send(()).expect("signal waiter acquisition");
        });
        started_rx.recv().expect("waiter started");
        assert!(
            acquired_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
        drop(first);
        acquired_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("waiter acquired after release");
        waiter.join().expect("waiter completed");
    }

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let base = fs::canonicalize(env::temp_dir()).expect("canonicalize temp dir");
            let path = base.join(format!(
                "furnish-entry-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated entry directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample_entry(managed_root: &str, destination: &str, target: &str) -> Entry {
        Entry {
            schema_version: MANIFEST_SCHEMA_VERSION,
            filesystem_identity: FilesystemIdentity {
                namespace: "test".to_owned(),
                destination: destination.to_owned(),
                canonical: format!("test:{destination}"),
            },
            authority: Authority {
                scope: "system".to_owned(),
                identity: "test/system".to_owned(),
            },
            managed_root: managed_root.to_owned(),
            representation: NATIVE_REPRESENTATION.to_owned(),
            retained_artifact_target: target.to_owned(),
            executor: Executor {
                identity: NATIVE_EXECUTOR_IDENTITY.to_owned(),
                protocol_version: NATIVE_EXECUTOR_PROTOCOL,
            },
            cleanup_strategy: "exact-symlink-target".to_owned(),
            self_heal_strategy: "exact-symlink-target".to_owned(),
            provenance: Provenance {
                declaration: "unit-test".to_owned(),
                source: "coordinator/src/main.rs".to_owned(),
            },
        }
    }

    #[test]
    fn reconcile_entry_is_noop_on_exact_existing_symlink() {
        let dir = TestDir::new();
        let destination = dir.path().join("value");
        let target = "/desired/target";
        symlink(target, &destination).expect("plant exact symlink");
        let before = fs::symlink_metadata(&destination).expect("stat before");
        let entry = sample_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            target,
        );
        reconcile_entry(&entry, Path::new("/nonexistent/setpriv"), 0)
            .expect("exact target is a no-op");
        let after = fs::symlink_metadata(&destination).expect("stat after");
        assert_eq!(fs::read_link(&destination).unwrap(), PathBuf::from(target));
        assert_eq!(before.ino(), after.ino());
    }

    #[test]
    fn reconcile_entry_refuses_foreign_symlink() {
        let dir = TestDir::new();
        let destination = dir.path().join("value");
        symlink("/wrong/target", &destination).expect("plant foreign symlink");
        let entry = sample_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            "/desired/target",
        );
        let failure = reconcile_entry(&entry, Path::new("/nonexistent/setpriv"), 0)
            .expect_err("refuse foreign symlink");
        assert!(matches!(failure.key, CodeKey::ConflictingDestination));
        assert_eq!(
            fs::read_link(&destination).unwrap(),
            PathBuf::from("/wrong/target")
        );
    }

    #[test]
    fn reconcile_entry_refuses_foreign_regular_file() {
        let dir = TestDir::new();
        let destination = dir.path().join("value");
        fs::write(&destination, b"foreign").expect("plant foreign file");
        let entry = sample_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            "/desired/target",
        );
        let failure = reconcile_entry(&entry, Path::new("/nonexistent/setpriv"), 0)
            .expect_err("refuse foreign regular file");
        assert!(matches!(failure.key, CodeKey::ConflictingDestination));
        assert!(destination.is_file());
    }

    #[test]
    fn reconcile_entry_refuses_foreign_directory() {
        let dir = TestDir::new();
        let destination = dir.path().join("value");
        fs::create_dir(&destination).expect("plant foreign directory");
        let entry = sample_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            "/desired/target",
        );
        let failure = reconcile_entry(&entry, Path::new("/nonexistent/setpriv"), 0)
            .expect_err("refuse foreign directory");
        assert!(matches!(failure.key, CodeKey::ConflictingDestination));
        assert!(destination.is_dir());
    }

    #[test]
    fn open_parent_refuses_destination_outside_managed_root() {
        let dir = TestDir::new();
        let managed_root = dir.path().join("managed");
        fs::create_dir(&managed_root).expect("create managed root");
        let destination = dir.path().join("outside");
        let failure = open_parent(
            destination.to_str().unwrap(),
            managed_root.to_str().unwrap(),
        )
        .expect_err("refuse non-descendant destination");
        assert!(matches!(failure.key, CodeKey::InvalidDestination));
    }

    #[test]
    fn open_parent_refuses_symlinked_path_component() {
        let dir = TestDir::new();
        let real = dir.path().join("real");
        fs::create_dir(&real).expect("create real directory");
        let link = dir.path().join("link");
        symlink(&real, &link).expect("plant symlinked component");
        let destination = link.join("value");
        let failure = open_parent(destination.to_str().unwrap(), link.to_str().unwrap())
            .expect_err("refuse symlinked path component");
        assert!(matches!(failure.key, CodeKey::ParentTraversal));
        assert_eq!(failure.operation, Some("openat-parent-component"));
        // Directory components are opened O_DIRECTORY|O_NOFOLLOW, so a symlinked
        // component is refused with ENOTDIR (the unfollowed symlink is not a
        // directory); ELOOP only applies to the O_NOFOLLOW-without-O_DIRECTORY
        // lock-file open. Either way the symlink is refused without being followed.
        assert_eq!(failure.errno, Some(Errno::NOTDIR.raw_os_error()));
    }
}
