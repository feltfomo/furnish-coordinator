use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, RenameFlags, flock, fsync, open, openat, readlinkat,
    renameat_with, statat, symlinkat, unlinkat,
};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};

const MANIFEST_SCHEMA_VERSION: u64 = 1;
const DIAGNOSTIC_SCHEMA_VERSION: u64 = 1;
const NATIVE_EXECUTOR_IDENTITY: &str = "furnish/native-symlink";
const NATIVE_EXECUTOR_PROTOCOL: u64 = 1;
const NATIVE_REPRESENTATION: &str = "symlink";
const SYMLINK_MODE: u32 = 0o120000;
const FILE_TYPE_MASK: u32 = 0o170000;
const LEDGER_SCHEMA_VERSION: u64 = 1;
const LEDGER_FILE_NAME: &str = "applied-state.json";
const LEDGER_STAGE_PREFIX: &str = ".applied-state";

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
    ledger_unreadable: String,
    ledger_invalid: String,
    ledger_write_failed: String,
    repair_verification: String,
    unresolvable_desired_target: String,
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
    LedgerUnreadable,
    LedgerInvalid,
    LedgerWriteFailed,
    RepairVerification,
    UnresolvableDesiredTarget,
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

    fn io(
        key: CodeKey,
        label: impl Into<String>,
        operation: &'static str,
        error: &io::Error,
    ) -> Self {
        Self {
            key,
            message: format!("{operation} failed: {error}"),
            label: label.into(),
            operation: Some(operation),
            errno: error.raw_os_error(),
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
        CodeKey::LedgerUnreadable => &codes.ledger_unreadable,
        CodeKey::LedgerInvalid => &codes.ledger_invalid,
        CodeKey::LedgerWriteFailed => &codes.ledger_write_failed,
        CodeKey::RepairVerification => &codes.repair_verification,
        CodeKey::UnresolvableDesiredTarget => &codes.unresolvable_desired_target,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReloadEvidence {
    invocation_id: Option<String>,
    monotonic_seconds: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LedgerRecord {
    destination: String,
    applied_artifact_target: String,
    // Retirement has to prove the destination sits beneath a managed root, and
    // by the time an entry is retired the declaration that named that root is
    // gone. The record is the only place left to read it from.
    managed_root: String,
    // Which branch published the target above: new, update, or repair. A record
    // that cannot say how it was decided is not evidence of a decision.
    applied_by: String,
    applied_generation: Option<String>,
    last_successful_reload: ReloadEvidence,
    reload_action_identity: Option<String>,
    boot_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Ledger {
    schema_version: u64,
    records: BTreeMap<String, LedgerRecord>,
}

// Two runs can produce byte-identical values, so values alone cannot say which
// run produced a record. The invocation ID and the monotonic reading are what
// make a record evidence of a specific reconciliation rather than an assertion
// about a target.
#[derive(Debug)]
struct RunIdentity {
    invocation_id: Option<String>,
    monotonic_seconds: f64,
    boot_id: Option<String>,
    system_generation: Option<String>,
}

impl RunIdentity {
    fn observe() -> Self {
        Self {
            invocation_id: env::var("INVOCATION_ID")
                .ok()
                .filter(|value| !value.is_empty()),
            monotonic_seconds: fs::read_to_string("/proc/uptime")
                .ok()
                .and_then(|value| {
                    value
                        .split_whitespace()
                        .next()
                        .and_then(|first| first.parse::<f64>().ok())
                })
                .unwrap_or(0.0),
            // Diagnostic only. A boot ID says which boot wrote the record; it is
            // never consulted when deciding ownership, because a record that
            // stopped counting after a reboot would be useless to a ledger whose
            // entire purpose is surviving one.
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .map(|value| value.trim().to_owned()),
            system_generation: fs::read_link("/run/current-system")
                .ok()
                .map(|path| path.to_string_lossy().into_owned()),
        }
    }

    fn record(&self, entry: &Entry, applied_by: &str) -> LedgerRecord {
        LedgerRecord {
            destination: entry.filesystem_identity.destination.clone(),
            applied_artifact_target: entry.retained_artifact_target.clone(),
            managed_root: entry.managed_root.clone(),
            applied_by: applied_by.to_owned(),
            applied_generation: self.system_generation.clone(),
            last_successful_reload: ReloadEvidence {
                invocation_id: self.invocation_id.clone(),
                monotonic_seconds: self.monotonic_seconds,
            },
            // Reload actions do not exist yet. The field is written null rather
            // than omitted so a later reader can tell "no reload was requested"
            // apart from "this record predates reload actions".
            reload_action_identity: None,
            boot_id: self.boot_id.clone(),
        }
    }
}

struct LedgerState {
    directory: PathBuf,
    path: PathBuf,
    document: Ledger,
}

impl LedgerState {
    fn load(directory: &Path) -> Result<Self> {
        let label = directory.to_string_lossy().into_owned();
        if let Err(error) = fs::create_dir_all(directory) {
            return Err(Failure::io(
                CodeKey::LedgerUnreadable,
                &label,
                "create-state-directory",
                &error,
            ));
        }
        // Writability is the privilege here: anything that can write this file
        // can claim ownership of a destination. Readability is not, and keeping
        // it readable lets the unprivileged harness verify that the record
        // survived a root wipe without being handed root to look.
        if let Err(error) = fs::set_permissions(directory, fs::Permissions::from_mode(0o755)) {
            return Err(Failure::io(
                CodeKey::LedgerUnreadable,
                &label,
                "chmod-state-directory",
                &error,
            ));
        }
        // Asserted rather than assumed. A mode that is 0755 because it was chosen
        // is a decision; a mode that is 0755 because of this host's umask is an
        // accident that will silently be something else on the next host.
        match fs::metadata(directory) {
            Ok(metadata) => {
                let mode = metadata.permissions().mode() & 0o7777;
                if mode != 0o755 {
                    return Err(Failure::new(
                        CodeKey::LedgerUnreadable,
                        &label,
                        format!("state directory mode is {mode:04o}; expected 0755"),
                    ));
                }
            }
            Err(error) => {
                return Err(Failure::io(
                    CodeKey::LedgerUnreadable,
                    &label,
                    "stat-state-directory",
                    &error,
                ));
            }
        }
        let path = directory.join(LEDGER_FILE_NAME);
        let document = match fs::read(&path) {
            Ok(bytes) => {
                let parsed: Ledger = serde_json::from_slice(&bytes).map_err(|error| {
                    Failure::new(
                        CodeKey::LedgerInvalid,
                        path.to_string_lossy(),
                        format!("cannot decode applied state: {error}"),
                    )
                })?;
                if parsed.schema_version != LEDGER_SCHEMA_VERSION {
                    return Err(Failure::new(
                        CodeKey::LedgerInvalid,
                        path.to_string_lossy(),
                        format!(
                            "applied-state schema {} is unsupported; expected {}",
                            parsed.schema_version, LEDGER_SCHEMA_VERSION
                        ),
                    ));
                }
                parsed
            }
            // An absent ledger is a cold start, not a clean bill of health: it
            // proves nothing was recorded, so nothing is owned, so nothing is
            // repairable until acquisition-from-absence records something.
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ledger {
                schema_version: LEDGER_SCHEMA_VERSION,
                records: BTreeMap::new(),
            },
            Err(error) => {
                return Err(Failure::io(
                    CodeKey::LedgerUnreadable,
                    path.to_string_lossy(),
                    "read-applied-state",
                    &error,
                ));
            }
        };
        Ok(Self {
            directory: directory.to_path_buf(),
            path,
            document,
        })
    }

    fn record(&self, canonical: &str) -> Option<&LedgerRecord> {
        self.document.records.get(canonical)
    }

    fn recorded(&self) -> Vec<(String, LedgerRecord)> {
        self.document
            .records
            .iter()
            .map(|(canonical, record)| (canonical.clone(), record.clone()))
            .collect()
    }

    fn retire(&mut self, canonical: &str) -> Result<()> {
        self.document.records.remove(canonical);
        self.write()
    }

    fn commit(&mut self, canonical: &str, record: LedgerRecord) -> Result<()> {
        self.document.records.insert(canonical.to_owned(), record);
        self.write()
    }

    fn write(&self) -> Result<()> {
        let label = self.path.to_string_lossy().into_owned();
        let encoded = serde_json::to_vec(&self.document).map_err(|error| {
            Failure::new(
                CodeKey::LedgerWriteFailed,
                &label,
                format!("cannot encode applied state: {error}"),
            )
        })?;
        // Staged beside the ledger rather than in a temporary directory: a
        // rename across filesystems is not atomic, and EXDEV here would mean
        // publishing evidence by copy.
        let stage = self.directory.join(format!(
            "{LEDGER_STAGE_PREFIX}.{}.stage",
            std::process::id()
        ));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&stage)
            .map_err(|error| {
                Failure::io(
                    CodeKey::LedgerWriteFailed,
                    &label,
                    "open-applied-state-stage",
                    &error,
                )
            })?;
        // OpenOptions::mode is masked by the ambient umask, so the mode above is
        // a request, not a guarantee. Set it explicitly and assert it: the record
        // has to be readable by the unprivileged verifier on every host, not only
        // on hosts whose umask happens to be 022.
        if let Err(error) = fs::set_permissions(&stage, fs::Permissions::from_mode(0o644)) {
            let _ = fs::remove_file(&stage);
            return Err(Failure::io(
                CodeKey::LedgerWriteFailed,
                &label,
                "chmod-applied-state-stage",
                &error,
            ));
        }
        match fs::metadata(&stage) {
            Ok(metadata) => {
                let mode = metadata.permissions().mode() & 0o7777;
                if mode != 0o644 {
                    let _ = fs::remove_file(&stage);
                    return Err(Failure::new(
                        CodeKey::LedgerWriteFailed,
                        &label,
                        format!("applied state mode is {mode:04o}; expected 0644"),
                    ));
                }
            }
            Err(error) => {
                let _ = fs::remove_file(&stage);
                return Err(Failure::io(
                    CodeKey::LedgerWriteFailed,
                    &label,
                    "stat-applied-state-stage",
                    &error,
                ));
            }
        }
        if let Err(error) = file.write_all(&encoded) {
            let _ = fs::remove_file(&stage);
            return Err(Failure::io(
                CodeKey::LedgerWriteFailed,
                &label,
                "write-applied-state-stage",
                &error,
            ));
        }
        // Contents durable before the name is published, so a crash can lose the
        // update but cannot expose a truncated one under the real name.
        if let Err(error) = file.sync_all() {
            let _ = fs::remove_file(&stage);
            return Err(Failure::io(
                CodeKey::LedgerWriteFailed,
                &label,
                "fsync-applied-state-stage",
                &error,
            ));
        }
        drop(file);
        if let Err(error) = fs::rename(&stage, &self.path) {
            let _ = fs::remove_file(&stage);
            return Err(Failure::io(
                CodeKey::LedgerWriteFailed,
                &label,
                "rename-applied-state",
                &error,
            ));
        }
        let directory = open(
            &self.directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| {
            Failure::syscall(
                CodeKey::LedgerWriteFailed,
                &label,
                "open-state-directory",
                errno,
            )
        })?;
        // The bytes were synced; this syncs the name. Without it the rename can
        // be lost across a power cut and the ledger reverts to a state that
        // disagrees with the symlink already on disk.
        fsync(&directory).map_err(|errno| {
            Failure::syscall(
                CodeKey::LedgerWriteFailed,
                &label,
                "fsync-state-directory",
                errno,
            )
        })?;
        Ok(())
    }
}

fn stage_symlink(
    setpriv: &Path,
    parent: &OwnedFd,
    stage: &OsStr,
    entry: &Entry,
    expected: &OsStr,
) -> Result<()> {
    let destination = &entry.filesystem_identity.destination;
    remove_stage(parent, stage);
    run_executor(
        setpriv,
        parent,
        stage,
        &entry.retained_artifact_target,
        &entry.authority,
    )?;
    let staged = symlink_target(parent, stage).map_err(|errno| {
        Failure::syscall(
            CodeKey::StagingVerification,
            destination,
            "readlinkat-staging",
            errno,
        )
    })?;
    if staged.as_deref() != Some(expected) {
        remove_stage(parent, stage);
        return Err(Failure::new(
            CodeKey::StagingVerification,
            destination,
            "native executor produced an unexpected staging object",
        ));
    }
    Ok(())
}

fn publish_new(
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
        .is_some()
    {
        remove_stage(parent, stage);
        return Err(Failure::new(
            CodeKey::PublishRace,
            destination,
            "destination appeared before atomic publish; refusing replacement",
        ));
    }

    if let Err(errno) = renameat_with(parent, stage, parent, name, RenameFlags::NOREPLACE) {
        remove_stage(parent, stage);
        return Err(Failure::syscall(
            CodeKey::PublishRace,
            destination,
            "renameat2-noreplace-publish",
            errno,
        ));
    }

    let final_target = symlink_target(parent, name).map_err(|errno| {
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

// Both owned branches land here, and neither is reachable without a LedgerRecord
// in hand. The recorded target is a parameter rather than something re-read here
// so that the thing being exchanged away has to have been proven, not assumed, by
// the caller.
fn publish_exchange(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    expected: &OsStr,
    recorded: &OsStr,
) -> Result<()> {
    if let Err(errno) = renameat_with(parent, stage, parent, name, RenameFlags::EXCHANGE) {
        remove_stage(parent, stage);
        // ENOENT means the destination we proved ownership of is no longer the
        // thing on disk. The proof is stale, so the next reconcile decides again
        // from observation. Falling back to a create here would be publishing on
        // evidence already known to be out of date.
        return Err(Failure::syscall(
            CodeKey::PublishRace,
            destination,
            "renameat2-exchange-publish",
            errno,
        ));
    }

    // Both sides, because an exchange that put the right link at the destination
    // while displacing something we did not identify is not a repair we can
    // account for.
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
    if published.as_deref() != Some(expected) || displaced.as_deref() != Some(recorded) {
        return Err(Failure::new(
            CodeKey::RepairVerification,
            destination,
            "post-exchange verification did not observe the recorded link on both sides",
        ));
    }

    // Only the displaced symlink is unlinked. Under repair it pointed at a target
    // that was already reaped; under update it points at one that is still live
    // and still referenced by the generation that declared it. Unlinking a
    // symlink never touches its pointee, so neither case destroys anything.
    remove_stage(parent, stage);
    Ok(())
}

// Retirement is the destructive direction, so it runs on exactly the same five
// ownership conditions as the two publishing branches, plus one more: no desired
// entry claims this destination any more. Anything that is not a link furnish
// can still prove it published is left exactly where it is.
fn retire_record(record: &LedgerRecord) -> Result<()> {
    let destination = &record.destination;
    let (parent, name) = open_parent(destination, &record.managed_root)?;
    let observed = symlink_target(&parent, &name).map_err(|errno| {
        Failure::syscall(
            CodeKey::ConflictingDestination,
            destination,
            "fstatat-retire",
            errno,
        )
    })?;
    let recorded = OsStr::new(&record.applied_artifact_target);
    match observed {
        // Already gone. There is nothing to unlink, and the record is the only
        // thing left to remove.
        None => Ok(()),
        Some(actual) if !actual.is_empty() && actual == recorded => {
            unlinkat(&parent, name.as_os_str(), AtFlags::empty()).map_err(|errno| {
                Failure::syscall(
                    CodeKey::ExecutorFailed,
                    destination,
                    "unlinkat-retire",
                    errno,
                )
            })?;
            Ok(())
        }
        Some(_) => Err(Failure::new(
            CodeKey::ConflictingDestination,
            destination,
            "refusing to retire a destination that is no longer the link recorded as furnish-owned",
        )),
    }
}

fn reconcile_entry(
    entry: &Entry,
    setpriv: &Path,
    index: usize,
    ledger: &mut LedgerState,
    identity: &RunIdentity,
) -> Result<()> {
    let destination = &entry.filesystem_identity.destination;
    let canonical = &entry.filesystem_identity.canonical;
    let expected = OsStr::new(&entry.retained_artifact_target);
    let (parent, name) = open_parent(destination, &entry.managed_root)?;

    let observed = symlink_target(&parent, &name).map_err(|errno| {
        Failure::syscall(
            CodeKey::ConflictingDestination,
            destination,
            "fstatat-destination",
            errno,
        )
    })?;

    match observed {
        None => {
            let stage = stage_name(index);
            stage_symlink(setpriv, &parent, &stage, entry, expected)?;
            publish_new(&parent, &name, &stage, destination, expected)?;
            ledger.commit(canonical, identity.record(entry, "new"))?;
            Ok(())
        }
        Some(actual) if actual == expected => {
            // Ownership is never inferred from a matching target: a destination
            // furnish never published is indistinguishable from one it did. A
            // host whose link predates the ledger stays unrecorded here and
            // acquires from absence instead.
            // Nothing was published, so the branch that produced this target is
            // carried forward rather than restated as a decision this run made.
            if let Some(applied_by) = ledger
                .record(canonical)
                .map(|prior| prior.applied_by.clone())
            {
                ledger.commit(canonical, identity.record(entry, &applied_by))?;
            }
            Ok(())
        }
        Some(actual) => {
            let observed_label = if actual.is_empty() {
                "non-symlink filesystem object".to_owned()
            } else {
                format!("symlink to {}", actual.to_string_lossy())
            };
            let Some(record) = ledger.record(canonical).cloned() else {
                return Err(Failure::new(
                    CodeKey::ConflictingDestination,
                    destination,
                    format!(
                        "refusing to replace {observed_label}: applied state records no furnish ownership of this destination"
                    ),
                ));
            };
            let recorded = OsStr::new(&record.applied_artifact_target);
            // Exact match against the RECORD, not against the desired target.
            // Read against desired this condition could never be satisfied by
            // any repairable state, because a destination already equal to
            // desired needs no repair.
            if actual.is_empty() || actual != recorded {
                return Err(Failure::new(
                    CodeKey::ConflictingDestination,
                    destination,
                    format!(
                        "refusing to replace {observed_label}: it is not the target recorded as furnish-owned ({})",
                        record.applied_artifact_target
                    ),
                ));
            }

            // Conditions 1 through 5 hold, so the destination is provably ours
            // and the only question left is which owned branch this is. Both
            // publish to desired through the same exchange; they differ in what
            // they mean. A resolving recorded target says the declaration moved,
            // which is a fact about the config. A reaped one says the store
            // object furnish published is gone, which is a fact about the world.
            //
            // Resolution is only ever tested against a target furnish published
            // itself, which is always a store path on an already-mounted
            // filesystem. Applied to a foreign target this test would be a race:
            // a link into a late-mounting filesystem reads unresolvable at boot
            // and resolvable at switch, and the coordinator runs at both.
            let applied_by = match statat(&parent, &name, AtFlags::empty()) {
                // What we published is still live.
                Ok(_) => "update",
                // What we published was reaped.
                Err(Errno::NOENT) => "repair",
                Err(errno) => {
                    return Err(Failure::syscall(
                        CodeKey::ConflictingDestination,
                        destination,
                        "fstatat-recorded-target",
                        errno,
                    ));
                }
            };

            // Republishing toward a target that is not there would manufacture
            // the exact breakage being repaired.
            if let Err(error) = fs::metadata(&entry.retained_artifact_target) {
                return Err(Failure::io(
                    CodeKey::UnresolvableDesiredTarget,
                    destination,
                    "stat-desired-target",
                    &error,
                ));
            }

            let stage = stage_name(index);
            stage_symlink(setpriv, &parent, &stage, entry, expected)?;
            publish_exchange(&parent, &name, &stage, destination, expected, recorded)?;
            ledger.commit(canonical, identity.record(entry, applied_by))?;
            Ok(())
        }
    }
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

fn reconcile(
    manifest_path: &Path,
    lock_name: &OsStr,
    setpriv: &Path,
    state_dir: &Path,
) -> ExitCode {
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

    // Applied state is read under the host lock, so no other reconcile can be
    // deciding ownership against a copy of it.
    let mut ledger = match LedgerState::load(state_dir) {
        Ok(ledger) => ledger,
        Err(failure) => {
            emit_failure(&manifest.diagnostic_contract.codes, &failure, None);
            return ExitCode::FAILURE;
        }
    };
    let identity = RunIdentity::observe();

    for (index, entry) in manifest.entries.iter().enumerate() {
        if let Err(failure) = reconcile_entry(entry, setpriv, index, &mut ledger, &identity) {
            emit_failure(
                &manifest.diagnostic_contract.codes,
                &failure,
                Some(&entry.provenance),
            );
            return ExitCode::FAILURE;
        }
    }

    // A manifest with no entries is a real desired set, not a no-op. This is the
    // only place a record is ever removed.
    let desired: BTreeSet<&str> = manifest
        .entries
        .iter()
        .map(|entry| entry.filesystem_identity.canonical.as_str())
        .collect();
    for (canonical, record) in ledger.recorded() {
        if desired.contains(canonical.as_str()) {
            continue;
        }
        if let Err(failure) = retire_record(&record) {
            emit_failure(&manifest.diagnostic_contract.codes, &failure, None);
            return ExitCode::FAILURE;
        }
        if let Err(failure) = ledger.retire(&canonical) {
            emit_failure(&manifest.diagnostic_contract.codes, &failure, None);
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
            let Some(state_dir) = option(&args[1..], "--state-dir") else {
                return ExitCode::FAILURE;
            };
            reconcile(&manifest, lock_name.as_os_str(), &setpriv, &state_dir)
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

    fn test_ledger(dir: &TestDir) -> LedgerState {
        LedgerState::load(&dir.path().join("state")).expect("initialize applied state")
    }

    fn record_ownership(ledger: &mut LedgerState, entry: &Entry, target: &str) {
        let identity = RunIdentity::observe();
        let mut record = identity.record(entry, "new");
        record.applied_artifact_target = target.to_owned();
        ledger
            .commit(&entry.filesystem_identity.canonical, record)
            .expect("record ownership");
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
        let mut ledger = test_ledger(&dir);
        let identity = RunIdentity::observe();
        reconcile_entry(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &identity,
        )
        .expect("exact target is a no-op");
        // No adoption: a matching target furnish never published stays
        // unrecorded, so it stays unrepairable rather than becoming owned by
        // having been looked at.
        assert!(
            ledger
                .record(&entry.filesystem_identity.canonical)
                .is_none()
        );
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
        let mut ledger = test_ledger(&dir);
        let identity = RunIdentity::observe();
        let failure = reconcile_entry(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &identity,
        )
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
        let mut ledger = test_ledger(&dir);
        let identity = RunIdentity::observe();
        let failure = reconcile_entry(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &identity,
        )
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
        let mut ledger = test_ledger(&dir);
        let identity = RunIdentity::observe();
        let failure = reconcile_entry(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &identity,
        )
        .expect_err("refuse foreign directory");
        assert!(matches!(failure.key, CodeKey::ConflictingDestination));
        assert!(destination.is_dir());
    }

    #[test]
    fn applied_state_round_trips_through_the_ledger_file() {
        let dir = TestDir::new();
        let entry = sample_entry("/managed", "/managed/value", "/desired/target");
        let mut ledger = test_ledger(&dir);
        record_ownership(&mut ledger, &entry, "/desired/target");
        let reloaded = LedgerState::load(&dir.path().join("state")).expect("reload applied state");
        let record = reloaded
            .record(&entry.filesystem_identity.canonical)
            .expect("record survives a reload");
        assert_eq!(record.applied_artifact_target, "/desired/target");
        assert_eq!(record.destination, "/managed/value");
        assert_eq!(record.applied_by, "new");
        assert_eq!(record.managed_root, "/managed");
        assert!(record.reload_action_identity.is_none());
    }

    #[test]
    fn unrecorded_dangling_destination_is_refused() {
        let dir = TestDir::new();
        let destination = dir.path().join("value");
        symlink("/nonexistent/reaped", &destination).expect("plant dangling symlink");
        let entry = sample_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            "/desired/target",
        );
        let mut ledger = test_ledger(&dir);
        let identity = RunIdentity::observe();
        let failure = reconcile_entry(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &identity,
        )
        .expect_err("refuse repair without applied state");
        assert!(matches!(failure.key, CodeKey::ConflictingDestination));
        assert_eq!(
            fs::read_link(&destination).unwrap(),
            PathBuf::from("/nonexistent/reaped")
        );
    }

    #[test]
    fn dangling_destination_that_does_not_match_the_record_is_refused() {
        // Drift to a dead target: the link points somewhere furnish never
        // published, and the pointee happens to be missing. Non-resolution alone
        // does not make it ours.
        let dir = TestDir::new();
        let destination = dir.path().join("value");
        symlink("/nonexistent/manufactured", &destination).expect("plant dangling drift");
        let entry = sample_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            "/desired/target",
        );
        let mut ledger = test_ledger(&dir);
        record_ownership(&mut ledger, &entry, "/nonexistent/reaped");
        let identity = RunIdentity::observe();
        let failure = reconcile_entry(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &identity,
        )
        .expect_err("refuse drift that does not match the record");
        assert!(matches!(failure.key, CodeKey::ConflictingDestination));
        assert_eq!(
            fs::read_link(&destination).unwrap(),
            PathBuf::from("/nonexistent/manufactured")
        );
    }

    #[test]
    fn recorded_target_that_still_resolves_takes_the_owned_update_branch() {
        // Staging cannot run inside the test process, so the branch is proven by
        // how far it gets: reaching the executor at all means the predicate
        // admitted it instead of refusing. Authority is switched to user scope so
        // the launch fails on the nonexistent setpriv rather than re-executing the
        // test binary.
        let dir = TestDir::new();
        let recorded = dir.path().join("recorded-target");
        fs::write(&recorded, b"live").expect("create live recorded target");
        let desired = dir.path().join("desired-target");
        fs::write(&desired, b"desired").expect("create live desired target");
        let destination = dir.path().join("value");
        symlink(&recorded, &destination).expect("plant link to live recorded target");
        let mut entry = sample_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            desired.to_str().unwrap(),
        );
        entry.authority.scope = "user".to_owned();
        let mut ledger = test_ledger(&dir);
        record_ownership(&mut ledger, &entry, recorded.to_str().unwrap());
        let identity = RunIdentity::observe();
        let failure = reconcile_entry(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &identity,
        )
        .expect_err("staging cannot run inside the test process");
        assert!(matches!(failure.key, CodeKey::ExecutorFailed));
        assert_eq!(fs::read_link(&destination).unwrap(), recorded);
    }

    #[test]
    fn owned_update_refuses_an_unresolvable_desired_target() {
        // Desired resolution is checked before anything is staged. Republishing
        // toward a target that is not there would manufacture exactly the
        // breakage the repair branch exists to undo.
        let dir = TestDir::new();
        let recorded = dir.path().join("recorded-target");
        fs::write(&recorded, b"live").expect("create live recorded target");
        let destination = dir.path().join("value");
        symlink(&recorded, &destination).expect("plant link to live recorded target");
        let entry = sample_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            "/nonexistent/desired",
        );
        let mut ledger = test_ledger(&dir);
        record_ownership(&mut ledger, &entry, recorded.to_str().unwrap());
        let identity = RunIdentity::observe();
        let failure = reconcile_entry(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &identity,
        )
        .expect_err("desired target must resolve");
        assert!(matches!(failure.key, CodeKey::UnresolvableDesiredTarget));
        assert_eq!(fs::read_link(&destination).unwrap(), recorded);
    }

    #[test]
    fn applied_state_is_written_with_an_explicitly_chosen_mode() {
        let dir = TestDir::new();
        let entry = sample_entry("/managed", "/managed/value", "/desired/target");
        let mut ledger = test_ledger(&dir);
        record_ownership(&mut ledger, &entry, "/desired/target");
        let state = dir.path().join("state");
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        assert_eq!(
            fs::metadata(state.join(LEDGER_FILE_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
    }

    #[test]
    fn undeclared_owned_destination_is_retired() {
        let dir = TestDir::new();
        let target = dir.path().join("target");
        fs::write(&target, b"live").expect("create live target");
        let destination = dir.path().join("value");
        symlink(&target, &destination).expect("plant owned symlink");
        let entry = sample_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            target.to_str().unwrap(),
        );
        let identity = RunIdentity::observe();
        let record = identity.record(&entry, "new");
        retire_record(&record).expect("retire owned link");
        assert!(fs::symlink_metadata(&destination).is_err());
        // Retirement removes what furnish published, never what it pointed at.
        assert!(target.is_file());
    }

    #[test]
    fn retirement_refuses_a_destination_that_stopped_matching_its_record() {
        let dir = TestDir::new();
        let destination = dir.path().join("value");
        symlink("/somewhere/else", &destination).expect("plant replaced symlink");
        let entry = sample_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            "/desired/target",
        );
        let identity = RunIdentity::observe();
        let record = identity.record(&entry, "new");
        let failure = retire_record(&record)
            .expect_err("refuse to retire a destination that is no longer ours");
        assert!(matches!(failure.key, CodeKey::ConflictingDestination));
        assert_eq!(
            fs::read_link(&destination).unwrap(),
            PathBuf::from("/somewhere/else")
        );
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
