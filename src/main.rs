use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, RenameFlags, flock, fsync, mkdirat, open, openat,
    readlinkat, renameat_with, statat, symlinkat, unlinkat,
};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};

const MANIFEST_SCHEMA_VERSION: u64 = 2;
const DIAGNOSTIC_SCHEMA_VERSION: u64 = 1;
const NATIVE_EXECUTOR_IDENTITY: &str = "furnish/native-symlink";
const NATIVE_EXECUTOR_PROTOCOL: u64 = 1;
const NATIVE_REPRESENTATION: &str = "symlink";
const NATIVE_WRITABLE_IDENTITY: &str = "furnish/native-writable";
const NATIVE_WRITABLE_PROTOCOL: u64 = 1;
const WRITABLE_REPRESENTATION: &str = "writable";
const SYMLINK_MODE: u32 = 0o120000;
const REGULAR_MODE: u32 = 0o100000;
const FILE_TYPE_MASK: u32 = 0o170000;
// one mode for both authority scopes. a mode that varies by scope is the
// deferred permissions feature arriving early under another name.
const WRITABLE_FILE_MODE: u32 = 0o644;
const LEDGER_SCHEMA_VERSION: u64 = 2;
const LEDGER_FILE_NAME: &str = "applied-state.json";
const LEDGER_ROLLBACK_FILE_NAME: &str = "applied-state.v1.json";
const STATE_PENDING: &str = "pending";
const STATE_OWNED: &str = "owned";

// qualification is a table lookup, not a chain of name comparisons. nothing in
// the protocol asks whether an executor is the native one; it asks whether the
// tuple it presents appears here.
struct ExecutorProfile {
    identity: &'static str,
    protocol_version: u64,
    representation: &'static str,
    lifecycle_strategy: &'static str,
    worker_subcommand: &'static str,
    worker_value_flag: &'static str,
}

const EXECUTOR_PROFILES: [ExecutorProfile; 2] = [
    ExecutorProfile {
        identity: NATIVE_EXECUTOR_IDENTITY,
        protocol_version: NATIVE_EXECUTOR_PROTOCOL,
        representation: NATIVE_REPRESENTATION,
        lifecycle_strategy: "exact-symlink-target",
        worker_subcommand: "stage-native-symlink",
        worker_value_flag: "--target",
    },
    ExecutorProfile {
        identity: NATIVE_WRITABLE_IDENTITY,
        protocol_version: NATIVE_WRITABLE_PROTOCOL,
        representation: WRITABLE_REPRESENTATION,
        lifecycle_strategy: "exact-source-content",
        worker_subcommand: "stage-native-writable",
        worker_value_flag: "--source",
    },
];

// creating a parent is not an executor. it presents no representation, owns no
// destination and is never recorded, so it stays out of the table a manifest
// entry is qualified against and lives in a worker-only one that main scans
// second. what the worker does is chosen by which table matched, never by a
// representation.
struct WorkerAction {
    subcommand: &'static str,
}

const DIRECTORY_ACTION: WorkerAction = WorkerAction {
    subcommand: "create-native-directory",
};

const WORKER_ACTIONS: [&WorkerAction; 1] = [&DIRECTORY_ACTION];

// one mode for a created parent, asserted rather than requested, because
// mkdirat is masked by the umask of whichever authority created it.
const DIRECTORY_MODE: u32 = 0o755;

fn worker_action_for(subcommand: &str) -> Option<&'static WorkerAction> {
    WORKER_ACTIONS
        .iter()
        .copied()
        .find(|action| action.subcommand == subcommand)
}

// transfer is generic over representation pairs; the gate is the set of pairs
// that actually exist today.
const TRANSITION_PAIRS: [(&str, &str); 2] = [
    (NATIVE_REPRESENTATION, WRITABLE_REPRESENTATION),
    (WRITABLE_REPRESENTATION, NATIVE_REPRESENTATION),
];

fn profile_for(
    identity: &str,
    protocol_version: u64,
    representation: &str,
) -> Option<&'static ExecutorProfile> {
    EXECUTOR_PROFILES.iter().find(|profile| {
        profile.identity == identity
            && profile.protocol_version == protocol_version
            && profile.representation == representation
    })
}

fn transition_is_gated(from: &str, to: &str) -> bool {
    TRANSITION_PAIRS
        .iter()
        .any(|(source, target)| *source == from && *target == to)
}
const LEDGER_STAGE_PREFIX: &str = ".applied-state";

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_hex(bytes: &[u8]) -> String {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut padded = bytes.to_vec();
    let bit_length = (bytes.len() as u64).wrapping_mul(8);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (index, word) in chunk.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    state.iter().map(|word| format!("{word:08x}")).collect()
}

// a real process death, not a simulated error return, so recovery is exercised
// against the same state a power loss would leave. compiled out entirely unless
// the feature is on, so the shipped binary cannot reach it.
#[cfg(feature = "fault-injection")]
fn fault_point(name: &str) {
    if env::var("FURNISH_FAULT_POINT").ok().as_deref() == Some(name) {
        std::process::abort();
    }
}

#[cfg(not(feature = "fault-injection"))]
#[inline(always)]
fn fault_point(_name: &str) {}

fn default_state() -> String {
    STATE_OWNED.to_owned()
}

fn default_representation() -> String {
    NATIVE_REPRESENTATION.to_owned()
}

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
    content_verification: String,
    transition_refused: String,
    unresolved_retirement: String,
    pending_recovery: String,
}

// how a destination that diverged from its baseline gets resolved. the choice
// travels with the entry rather than with the run, and it has no default here,
// so a manifest written before the choice existed fails to deserialize instead
// of reconciling under a guess about what its author wanted.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ConflictPolicy {
    Error,
    SourceWins,
    RuntimeWins,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    schema_version: u64,
    filesystem_identity: FilesystemIdentity,
    authority: Authority,
    managed_root: String,
    on_conflict: ConflictPolicy,
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
    severity: &'a str,
    code: &'a str,
    message: &'a str,
    primary: Primary<'a>,
    provenance: Option<&'a Provenance>,
    cause: Option<Cause<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed: Option<ObservedHashes<'a>>,
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

// b, s, and d are the three hashes reported when onConflict is error. they
// travel in the diagnostic so a reader can reconstruct what the coordinator
// saw without re-reading either the manifest or the destination.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ObservedHashes<'a> {
    baseline: Option<&'a str>,
    source: &'a str,
    destination: &'a str,
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
    ContentVerification,
    TransitionRefused,
    UnresolvedRetirement,
    PendingRecovery,
}

#[derive(Debug)]
struct Failure {
    key: CodeKey,
    message: String,
    label: String,
    operation: Option<&'static str>,
    errno: Option<i32>,
    // set only on conflict diagnostics; carries b, s, d so the caller does
    // not have to thread them through a separate code path.
    observed: Option<(Option<String>, String, String)>,
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
            observed: None,
        }
    }

    fn conflict(
        label: impl Into<String>,
        baseline: Option<&str>,
        source: &str,
        destination: &str,
    ) -> Self {
        Self {
            key: CodeKey::ConflictingDestination,
            message: "destination and source have both diverged from the baseline and this declaration's policy is to refuse".to_owned(),
            label: label.into(),
            operation: None,
            errno: None,
            observed: Some((
                baseline.map(str::to_owned),
                source.to_owned(),
                destination.to_owned(),
            )),
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
            observed: None,
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
            observed: None,
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
        CodeKey::ContentVerification => &codes.content_verification,
        CodeKey::TransitionRefused => &codes.transition_refused,
        CodeKey::UnresolvedRetirement => &codes.unresolved_retirement,
        CodeKey::PendingRecovery => &codes.pending_recovery,
    }
}

fn serialize_failure(
    codes: &DiagnosticCodes,
    failure: &Failure,
    provenance: Option<&Provenance>,
) -> serde_json::Result<String> {
    serialize_diagnostic(codes, failure, provenance, "error")
}

fn serialize_diagnostic(
    codes: &DiagnosticCodes,
    failure: &Failure,
    provenance: Option<&Provenance>,
    severity: &str,
) -> serde_json::Result<String> {
    serde_json::to_string(&Diagnostic {
        schema_version: DIAGNOSTIC_SCHEMA_VERSION,
        severity,
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
        observed: failure.observed.as_ref().map(|(b, s, d)| ObservedHashes {
            baseline: b.as_deref(),
            source: s,
            destination: d,
        }),
    })
}

fn emit_failure(codes: &DiagnosticCodes, failure: &Failure, provenance: Option<&Provenance>) {
    match serialize_failure(codes, failure, provenance) {
        Ok(line) => eprintln!("{line}"),
        Err(_) => eprintln!("furnish: failed to serialize runtime diagnostic"),
    }
}

// loud but not fatal. what an unresolved retirement blocks is the retirement,
// not the activation around it, so this path reports and continues rather than
// returning a Failure.
fn emit_warning(codes: &DiagnosticCodes, failure: &Failure, provenance: Option<&Provenance>) {
    match serialize_diagnostic(codes, failure, provenance, "warning") {
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
        let Some(profile) = profile_for(
            &entry.executor.identity,
            entry.executor.protocol_version,
            &entry.representation,
        ) else {
            return Err(Failure::new(
                CodeKey::UnsupportedExecutor,
                &entry.filesystem_identity.canonical,
                format!(
                    "unsupported executor tuple ({}, {}, {})",
                    entry.executor.identity, entry.executor.protocol_version, entry.representation
                ),
            ));
        };
        if entry.cleanup_strategy != profile.lifecycle_strategy
            || entry.self_heal_strategy != profile.lifecycle_strategy
        {
            return Err(Failure::new(
                CodeKey::InvalidManifest,
                &entry.filesystem_identity.canonical,
                format!(
                    "{} reconciliation requires {} lifecycle strategies",
                    entry.representation, profile.lifecycle_strategy
                ),
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

// how the walk treats a parent component that is not there. the traversal is
// identical either way, so a component that exists as a symlink or as a
// non-directory refuses in both modes for the same reason.
enum ParentMode<'a> {
    Refuse,
    Create {
        setpriv: &'a Path,
        authority: &'a Authority,
    },
}

// the no-create walk. every caller that must not create keeps this one.
fn open_parent(destination: &str, managed_root: &str) -> Result<(OwnedFd, OsString)> {
    walk_parent(destination, managed_root, &ParentMode::Refuse)
}

fn walk_parent(
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

    // creation is bounded by the managed root, so the components at and above it
    // are traversed and never made. the bound is counted on the walk itself
    // rather than matched on the string, because the walk is where a component is
    // opened and so is the only place the bound can hold.
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

// one component of the walk. a component that is absent below the managed root
// is delegated to the authority that will own it and then reopened through this
// same refusing openat, so a symlink that appears in the gap loses to the reopen
// rather than to a check that ran before it. an existing component is opened and
// never touched, because its mode and ownership are somebody else's.
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
    profile: &ExecutorProfile,
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
        .arg(profile.worker_subcommand)
        .arg("--parent-fd")
        .arg(parent.as_raw_fd().to_string())
        .arg("--name")
        .arg(stage)
        .arg(profile.worker_value_flag)
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
    let executable = env::current_exe().map_err(|error| {
        Failure::new(
            CodeKey::ExecutorFailed,
            destination,
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
        .arg(DIRECTORY_ACTION.subcommand)
        .arg("--parent-fd")
        .arg(parent.as_raw_fd().to_string())
        .arg("--name")
        .arg(name)
        .status()
        .map_err(|error| {
            Failure::new(
                CodeKey::ExecutorFailed,
                destination,
                format!("failed to launch parent creation: {error}"),
            )
        })?;
    if !status.success() {
        return Err(Failure::new(
            CodeKey::ExecutorFailed,
            destination,
            format!("parent creation exited with {status}"),
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
    // retirement has to prove the destination sits beneath a managed root, and
    // by the time an entry is retired the declaration that named that root is
    // gone. the record is the only place left to read it from.
    managed_root: String,
    // which branch published the target above, one of new, update, or repair. a
    // record that cannot say how it was decided is not evidence of a decision.
    applied_by: String,
    applied_generation: Option<String>,
    last_successful_reload: ReloadEvidence,
    reload_action_identity: Option<String>,
    boot_id: Option<String>,
    // everything below is v2. the defaults describe what a v1 record could only
    // have been, since writable did not exist and pending state was never
    // written, so every v1 record is an owned symlink as a matter of what the
    // code could produce rather than an assumption about the data.
    #[serde(default = "default_state")]
    state: String,
    #[serde(default = "default_representation")]
    representation: String,
    // only a representation that keeps bytes at the destination can drift under
    // the user, so a symlink record carries no baseline. a path that writes one
    // for a symlink is writing a claim it cannot check. under runtime-wins the
    // baseline is the source that was refused rather than bytes that were ever
    // written here, so read it as the last source this record was reconciled
    // against and not as a copy of what sits at the destination.
    #[serde(default)]
    baseline_hash: Option<String>,
    // what this record intended to put at the destination. its meaning is fixed
    // by `representation` and by nothing else. on a writable record it hashes
    // the file's CONTENT, on a symlink record it hashes the target PATH STRING
    // the link must point at. the two readings are never interchangeable, so
    // neither is ever derived from the other. only the writable reading is read
    // back to prove authorship; symlink authorship compares the target string
    // itself, so on a symlink record this field is written and never consulted.
    // a branch that converges backward sets the representation, so it restates
    // this field to the reading that representation demands rather than carrying
    // forward the one the pending record held.
    #[serde(default)]
    intended_witness_hash: Option<String>,
    #[serde(default)]
    applied_operation_generation: u64,
    // recovery has to find the displaced object by name, and a writable file
    // displaced by a transition or by an update to its source may hold edited
    // bytes.
    #[serde(default)]
    stage_name: Option<String>,
    #[serde(default)]
    unresolved_retirement: Option<UnresolvedRetirement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct UnresolvedRetirement {
    reason: String,
    observed_hash: Option<String>,
    baseline_hash: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Ledger {
    schema_version: u64,
    records: BTreeMap<String, LedgerRecord>,
}

// two runs can produce byte-identical values, so values alone cannot say which
// run produced a record. the invocation ID and the monotonic reading are what
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
            // diagnostic only. a boot ID says which boot wrote the record; it is
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
            state: STATE_OWNED.to_owned(),
            representation: entry.representation.clone(),
            baseline_hash: None,
            intended_witness_hash: None,
            applied_operation_generation: 0,
            stage_name: None,
            unresolved_retirement: None,
            applied_generation: self.system_generation.clone(),
            last_successful_reload: ReloadEvidence {
                invocation_id: self.invocation_id.clone(),
                monotonic_seconds: self.monotonic_seconds,
            },
            // reload actions do not exist yet. the field is written null rather
            // than omitted so a later reader can tell "no reload was requested"
            // apart from "this record predates reload actions".
            reload_action_identity: None,
            boot_id: self.boot_id.clone(),
        }
    }
}

#[derive(Debug)]
struct LedgerState {
    directory: PathBuf,
    path: PathBuf,
    document: Ledger,
}

impl LedgerState {
    fn load(directory: &Path) -> Result<Self> {
        let label = directory.to_string_lossy().into_owned();
        let path = directory.join(LEDGER_FILE_NAME);
        let existing = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(Failure::io(
                    CodeKey::LedgerUnreadable,
                    path.to_string_lossy(),
                    "read-applied-state",
                    &error,
                ));
            }
        };
        let on_disk_version = match existing.as_deref() {
            Some(bytes) => {
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Version {
                    schema_version: u64,
                }
                let version: Version = serde_json::from_slice(bytes).map_err(|error| {
                    Failure::new(
                        CodeKey::LedgerInvalid,
                        path.to_string_lossy(),
                        format!("cannot decode applied state: {error}"),
                    )
                })?;
                Some(version.schema_version)
            }
            None => None,
        };
        if let Some(version) = on_disk_version
            && version > LEDGER_SCHEMA_VERSION
        {
            return Err(Failure::new(
                CodeKey::LedgerInvalid,
                path.to_string_lossy(),
                format!(
                    "applied-state schema {version} is newer than this coordinator supports ({LEDGER_SCHEMA_VERSION}); refusing before any mutation"
                ),
            ));
        }
        if let Err(error) = fs::create_dir_all(directory) {
            return Err(Failure::io(
                CodeKey::LedgerUnreadable,
                &label,
                "create-state-directory",
                &error,
            ));
        }
        // writability is the privilege here, since anything that can write this
        // file can claim ownership of a destination. readability is not, and
        // keeping it readable lets the unprivileged harness verify that the
        // record survived a root wipe without being handed root to look.
        if let Err(error) = fs::set_permissions(directory, fs::Permissions::from_mode(0o755)) {
            return Err(Failure::io(
                CodeKey::LedgerUnreadable,
                &label,
                "chmod-state-directory",
                &error,
            ));
        }
        // asserted rather than assumed. a mode that is 0755 because it was chosen
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
        let (document, migrated) = match (existing, on_disk_version) {
            // an absent ledger is a cold start, not a clean bill of health. it
            // proves nothing was recorded, so nothing is owned, so nothing is
            // repairable until acquisition-from-absence records something.
            (None, _) => (
                Ledger {
                    schema_version: LEDGER_SCHEMA_VERSION,
                    records: BTreeMap::new(),
                },
                false,
            ),
            (Some(bytes), Some(version)) if version == LEDGER_SCHEMA_VERSION => {
                let parsed: Ledger = serde_json::from_slice(&bytes).map_err(|error| {
                    Failure::new(
                        CodeKey::LedgerInvalid,
                        path.to_string_lossy(),
                        format!("cannot decode applied state: {error}"),
                    )
                })?;
                (parsed, false)
            }
            (Some(bytes), Some(1)) => {
                // the copy is the rollback evidence, and it is written before the
                // first v2 write so a downgrade always has the exact input the
                // migration consumed.
                let rollback = directory.join(LEDGER_ROLLBACK_FILE_NAME);
                if let Err(error) = fs::write(&rollback, &bytes) {
                    return Err(Failure::io(
                        CodeKey::LedgerWriteFailed,
                        rollback.to_string_lossy(),
                        "write-applied-state-rollback",
                        &error,
                    ));
                }
                let mut parsed: Ledger = serde_json::from_slice(&bytes).map_err(|error| {
                    Failure::new(
                        CodeKey::LedgerInvalid,
                        path.to_string_lossy(),
                        format!("cannot decode applied state: {error}"),
                    )
                })?;
                for record in parsed.records.values_mut() {
                    record.state = STATE_OWNED.to_owned();
                    record.representation = NATIVE_REPRESENTATION.to_owned();
                    record.stage_name = None;
                    record.unresolved_retirement = None;
                }
                parsed.schema_version = LEDGER_SCHEMA_VERSION;
                (parsed, true)
            }
            (Some(_), Some(version)) => {
                return Err(Failure::new(
                    CodeKey::LedgerInvalid,
                    path.to_string_lossy(),
                    format!(
                        "applied-state schema {version} is unsupported; expected {LEDGER_SCHEMA_VERSION}"
                    ),
                ));
            }
            (Some(_), None) => {
                return Err(Failure::new(
                    CodeKey::LedgerInvalid,
                    path.to_string_lossy(),
                    "applied state has no schema version",
                ));
            }
        };
        let state = Self {
            directory: directory.to_path_buf(),
            path,
            document,
        };
        if migrated {
            state.write()?;
        }
        Ok(state)
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
        // staged beside the ledger rather than in a temporary directory, because
        // a rename across filesystems is not atomic and EXDEV here would mean
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
        // a request, not a guarantee. it is set explicitly and asserted, since the
        // record has to be readable by the unprivileged verifier on every host,
        // not only on hosts whose umask happens to be 022.
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
        // contents durable before the name is published, so a crash can lose the
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
        // the bytes were synced; this syncs the name. without it the rename can
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
    let profile = profile_for(
        &entry.executor.identity,
        entry.executor.protocol_version,
        &entry.representation,
    )
    .ok_or_else(|| {
        Failure::new(
            CodeKey::UnsupportedExecutor,
            destination,
            "no qualified executor for this entry",
        )
    })?;
    run_executor(
        setpriv,
        parent,
        stage,
        &entry.retained_artifact_target,
        &entry.authority,
        profile,
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

// both owned branches land here, and neither is reachable without a LedgerRecord
// in hand. the recorded target is a parameter rather than something re-read here
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
        // ENOENT means the destination proved ownership of is no longer the thing
        // on disk. the proof is stale, so the next reconcile decides again from
        // observation. falling back to a create here would be publishing on
        // evidence already known to be out of date.
        return Err(Failure::syscall(
            CodeKey::PublishRace,
            destination,
            "renameat2-exchange-publish",
            errno,
        ));
    }

    // both sides, because an exchange that put the right link at the destination
    // while displacing something unidentified is not an accountable repair.
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

    // only the displaced symlink is unlinked. under repair it pointed at a target
    // that was already reaped; under update it points at one that is still live
    // and still referenced by the generation that declared it. unlinking a
    // symlink never touches its pointee, so neither case destroys anything.
    remove_stage(parent, stage);
    Ok(())
}

// retirement is the destructive direction, so it runs on the same ownership
// conditions as the two publishing branches, plus one more, that no desired entry
// claims this destination any more. anything that is not a link furnish can still
// prove it published is left exactly where it is.
#[derive(Debug)]
enum RetireOutcome {
    Removed,
    // edited data is never deleted to satisfy cleanup, so the file stays,
    // ownership stays to explain it, and what is blocked is the retirement.
    Unresolved(UnresolvedRetirement),
}

fn retire_record(record: &LedgerRecord) -> Result<RetireOutcome> {
    let destination = &record.destination;
    let (parent, name) = open_parent(destination, &record.managed_root)?;

    if record.representation == WRITABLE_REPRESENTATION {
        let observed = observe_kind(&parent, &name, destination)?;
        return match observed {
            None => Ok(RetireOutcome::Removed),
            Some(kind) if kind == REGULAR_MODE => {
                let observed_hash = hash_regular(
                    &parent,
                    &name,
                    destination,
                    CodeKey::UnresolvedRetirement,
                    "read-retire-writable",
                )?;
                if record.baseline_hash.as_deref() == Some(observed_hash.as_str()) {
                    // pristine, so the destination is exactly what furnish put
                    // there and removing it destroys nothing.
                    unlinkat(&parent, name.as_os_str(), AtFlags::empty()).map_err(|errno| {
                        Failure::syscall(
                            CodeKey::ExecutorFailed,
                            destination,
                            "unlinkat-retire",
                            errno,
                        )
                    })?;
                    Ok(RetireOutcome::Removed)
                } else {
                    Ok(RetireOutcome::Unresolved(UnresolvedRetirement {
                        reason: "writable destination no longer matches its baseline".to_owned(),
                        observed_hash: Some(observed_hash),
                        baseline_hash: record.baseline_hash.clone(),
                    }))
                }
            }
            Some(_) => Err(Failure::new(
                CodeKey::ConflictingDestination,
                destination,
                "refusing to retire a destination that is no longer the regular file recorded as furnish-owned",
            )),
        };
    }

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
        // already gone. there is nothing to unlink, and the record is the only
        // thing left to remove.
        None => Ok(RetireOutcome::Removed),
        Some(actual) if !actual.is_empty() && actual == recorded => {
            unlinkat(&parent, name.as_os_str(), AtFlags::empty()).map_err(|errno| {
                Failure::syscall(
                    CodeKey::ExecutorFailed,
                    destination,
                    "unlinkat-retire",
                    errno,
                )
            })?;
            Ok(RetireOutcome::Removed)
        }
        Some(_) => Err(Failure::new(
            CodeKey::ConflictingDestination,
            destination,
            "refusing to retire a destination that is no longer the link recorded as furnish-owned",
        )),
    }
}

// observation is by file type, not by a link read, because writable has to tell
// a regular file from a directory or a device before it will touch anything.
fn observe_kind(parent: &OwnedFd, name: &OsStr, destination: &str) -> Result<Option<u32>> {
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

fn observe_mode(parent: &OwnedFd, name: &OsStr, destination: &str) -> Result<u32> {
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

// NOFOLLOW throughout, so a symlink at the destination is never followed and
// never written through, and reading one is refused rather than resolved.
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

fn hash_regular(
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

fn hash_source(source: &str, destination: &str) -> Result<String> {
    let bytes = fs::read(source).map_err(|error| {
        Failure::io(
            CodeKey::UnresolvableDesiredTarget,
            destination,
            "read-source-artifact",
            &error,
        )
    })?;
    Ok(sha256_hex(&bytes))
}

// the rename is only durable once the directory entry is, so the parent is
// synced before anything is verified or recorded as published.
fn sync_parent(parent: &OwnedFd, destination: &str) -> Result<()> {
    fsync(parent).map_err(|errno| {
        Failure::syscall(
            CodeKey::FinalVerification,
            destination,
            "fsync-parent",
            errno,
        )
    })
}

// nothing has been applied yet, so the prior record's applied state is carried
// across unchanged. a pending record that dropped it would make recovery
// converge to a state weaker than the one already durable. the publishing
// branch is named here and not only at the owned commit, because recovery
// promotes this record as it stands, and a record that named a branch it was
// not published by is not evidence of the decision that produced it.
fn pending_record(
    identity: &RunIdentity,
    entry: &Entry,
    applied_by: &str,
    prior: Option<&LedgerRecord>,
    stage: &OsStr,
    witness_hash: &str,
) -> LedgerRecord {
    let mut record = identity.record(entry, applied_by);
    record.state = STATE_PENDING.to_owned();
    record.intended_witness_hash = Some(witness_hash.to_owned());
    record.stage_name = Some(stage.to_string_lossy().into_owned());
    if let Some(prior) = prior {
        record.baseline_hash = prior.baseline_hash.clone();
        record.applied_operation_generation = prior.applied_operation_generation;
    }
    record
}

// every commit that carries the applied state forward after a publish goes
// through here, whatever the representation, so no path can write a record that
// carries less than the one it replaces. the operation generation counts applies
// that reached the destination, so it advances from the prior record instead of
// restarting. the one exemption is a recovery branch that converges BACKWARD to
// the state the ledger already describes, which restates that record rather than
// constructing a new one, because nothing was carried forward to count. what it
// is exempt from is advancing the generation, not the meanings of the fields, so
// a restatement that sets the representation owes the witness reading that
// representation demands.
fn owned_record(
    identity: &RunIdentity,
    entry: &Entry,
    applied_by: &str,
    prior: Option<&LedgerRecord>,
    witness_hash: &str,
) -> LedgerRecord {
    let mut record = identity.record(entry, applied_by);
    record.state = STATE_OWNED.to_owned();
    record.intended_witness_hash = Some(witness_hash.to_owned());
    record.baseline_hash = baseline_for(&entry.representation, witness_hash);
    record.applied_operation_generation = prior
        .map_or(0, |prior| prior.applied_operation_generation)
        .saturating_add(1);
    record
}

// a witness hash is a baseline only where it hashes bytes that live at the
// destination. for a symlink it hashes a path string, which is not a baseline
// and must not be stored as one.
fn baseline_for(representation: &str, witness_hash: &str) -> Option<String> {
    (representation == WRITABLE_REPRESENTATION).then(|| witness_hash.to_owned())
}

// a run that publishes nothing must not erase what an earlier run recorded,
// because these fields describe the applied state, not the invocation that
// observed it. an unresolved retirement marker is deliberately NOT among them,
// since reaching this path means the destination is declared again, and being
// declared again is what resolves it.
fn carry_applied_state(prior: &LedgerRecord, record: &mut LedgerRecord) {
    record.baseline_hash = prior.baseline_hash.clone();
    record.intended_witness_hash = prior.intended_witness_hash.clone();
    record.applied_operation_generation = prior.applied_operation_generation;
}

// the coordinator re-derives the staged content itself rather than trusting the
// executor's exit status, so an executor that succeeded while producing the
// wrong bytes cannot reach a destination.
fn stage_writable(
    setpriv: &Path,
    parent: &OwnedFd,
    stage: &OsStr,
    entry: &Entry,
    intended_hash: &str,
) -> Result<()> {
    let destination = &entry.filesystem_identity.destination;
    remove_stage(parent, stage);
    let profile = profile_for(
        &entry.executor.identity,
        entry.executor.protocol_version,
        &entry.representation,
    )
    .ok_or_else(|| {
        Failure::new(
            CodeKey::UnsupportedExecutor,
            destination,
            "no qualified executor for this entry",
        )
    })?;
    run_executor(
        setpriv,
        parent,
        stage,
        &entry.retained_artifact_target,
        &entry.authority,
        profile,
    )?;
    fault_point("stage-written");
    if observe_kind(parent, stage, destination)? != Some(REGULAR_MODE) {
        remove_stage(parent, stage);
        return Err(Failure::new(
            CodeKey::StagingVerification,
            destination,
            "native executor produced an unexpected staging object",
        ));
    }
    let staged_hash = hash_regular(
        parent,
        stage,
        destination,
        CodeKey::StagingVerification,
        "read-staging",
    )?;
    if staged_hash != intended_hash {
        remove_stage(parent, stage);
        return Err(Failure::new(
            CodeKey::StagingVerification,
            destination,
            "staged content does not hash to the intended source content",
        ));
    }
    let mode = observe_mode(parent, stage, destination)?;
    if mode != WRITABLE_FILE_MODE {
        remove_stage(parent, stage);
        return Err(Failure::new(
            CodeKey::StagingVerification,
            destination,
            format!("staged file mode is {mode:04o}; expected {WRITABLE_FILE_MODE:04o}"),
        ));
    }
    Ok(())
}

// publication into an absent name. NOREPLACE is what makes this refuse rather
// than displace, so a destination that appeared during staging is never
// overwritten and never adopted.
fn publish_writable_new(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    intended_hash: &str,
) -> Result<()> {
    fault_point("stage-synced");
    if observe_kind(parent, name, destination)?.is_some() {
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
    fault_point("published");
    sync_parent(parent, destination)?;
    fault_point("published-synced");
    verify_writable_destination(parent, name, destination, intended_hash)?;
    fault_point("verified");
    Ok(())
}

// ownership commits only after this returns. observation of the published
// object, not the executor's exit status, is what makes the claim.
fn verify_writable_destination(
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

const TRANSITION_MARKER: &str = "transition";

// materialize a new source version over an owned destination. the existing
// destination is displaced to the stage path by an atomic exchange. after the
// exchange the displaced bytes are hashed and compared to expected_displaced,
// which is what was observed before staging; if they differ, a concurrent write
// raced us and we exchange back to restore the original destination, then
// report the race without leaving either side in an intermediate state.
//
// publish_exchange, the symlink route, runs the same exchange but rechecks a
// target string, because what it guards is a representation swap. this one
// rechecks content, because what it guards is bytes a user may have edited.
fn publish_writable_exchange(
    parent: &OwnedFd,
    name: &OsStr,
    stage: &OsStr,
    destination: &str,
    expected_displaced: &str,
    intended_hash: &str,
) -> Result<()> {
    fault_point("stage-synced");
    if let Err(errno) = renameat_with(parent, stage, parent, name, RenameFlags::EXCHANGE) {
        remove_stage(parent, stage);
        return Err(Failure::syscall(
            CodeKey::PublishRace,
            destination,
            "renameat2-exchange-publish",
            errno,
        ));
    }
    fault_point("exchange-published");
    // the displaced content now sits at the stage path. hash it and compare
    // to what was observed before staging; a mismatch means a concurrent
    // writer modified the destination between our read and the exchange.
    let displaced_hash = hash_regular(
        parent,
        stage,
        destination,
        CodeKey::PublishRace,
        "read-displaced",
    )?;
    if displaced_hash != expected_displaced {
        // exchange back to restore the original destination, then remove the
        // stage. both sides return to their pre-exchange state.
        let _ = renameat_with(parent, stage, parent, name, RenameFlags::EXCHANGE);
        remove_stage(parent, stage);
        return Err(Failure::new(
            CodeKey::PublishRace,
            destination,
            "destination changed between observation and publication; exchange reversed",
        ));
    }
    // displaced content matched; the exchange is clean. remove the displaced
    // bytes from the stage path and sync the directory.
    remove_stage(parent, stage);
    fault_point("published");
    sync_parent(parent, destination)?;
    fault_point("published-synced");
    verify_writable_destination(parent, name, destination, intended_hash)?;
    fault_point("verified");
    Ok(())
}

// row three and source-wins publish identically and differ only in why they
// were reached, so the pending-record bracket is written once here instead of
// twice at the call sites. the caller has already decided that publishing is
// the right answer; this only carries it out durably.
#[allow(clippy::too_many_arguments)]
fn publish_writable_update(
    entry: &Entry,
    setpriv: &Path,
    index: usize,
    ledger: &mut LedgerState,
    identity: &RunIdentity,
    record: &LedgerRecord,
    parent: &OwnedFd,
    name: &OsStr,
    expected_displaced: &str,
    intended: &str,
) -> Result<()> {
    let canonical = &entry.filesystem_identity.canonical;
    let destination = &entry.filesystem_identity.destination;
    let stage = stage_name(index);
    fault_point("pre-pending");
    ledger.commit(
        canonical,
        pending_record(identity, entry, "update", Some(record), &stage, intended),
    )?;
    fault_point("pending-committed");
    stage_writable(setpriv, parent, &stage, entry, intended)?;
    publish_writable_exchange(
        parent,
        name,
        &stage,
        destination,
        expected_displaced,
        intended,
    )?;
    ledger.commit(
        canonical,
        owned_record(identity, entry, "update", Some(record), intended),
    )?;
    Ok(())
}

fn transition_source_of(target: &str) -> Option<&'static str> {
    TRANSITION_PAIRS
        .iter()
        .find(|(_, to)| *to == target)
        .map(|(from, _)| *from)
}

fn representation_of_kind(kind: u32) -> Option<&'static str> {
    match kind {
        SYMLINK_MODE => Some(NATIVE_REPRESENTATION),
        REGULAR_MODE => Some(WRITABLE_REPRESENTATION),
        _ => None,
    }
}

// recovery replay. a pending record authorizes recovery only when destination,
// intended source hash, and artifact identity all agree with it; anything else
// is not authorship, so the record is cleared and the ordinary path decides
// again from observation. authorship is not the end of it for a writable
// update, because the object the exchange displaced can still be sitting at the
// stage name holding a user edit, and that case is restored and refused here
// rather than promoted.
fn recover_pending(entry: &Entry, ledger: &mut LedgerState, identity: &RunIdentity) -> Result<()> {
    let canonical = &entry.filesystem_identity.canonical;
    let destination = &entry.filesystem_identity.destination;
    let Some(record) = ledger.record(canonical).cloned() else {
        return Ok(());
    };
    if record.state != STATE_PENDING {
        return Ok(());
    }

    let (parent, name) = open_parent(destination, &record.managed_root)?;
    let stage = record.stage_name.clone().map(OsString::from);
    let observed = observe_kind(&parent, &name, destination)?;
    let artifact_matches = record.applied_artifact_target == entry.retained_artifact_target;

    if record.applied_by == TRANSITION_MARKER {
        return recover_transition(
            entry, ledger, identity, &record, &parent, &name, observed, stage,
        );
    }

    let authored = match observed {
        None => false,
        Some(kind)
            if representation_of_kind(kind).as_deref() != Some(record.representation.as_str()) =>
        {
            false
        }
        Some(kind) if kind == REGULAR_MODE => {
            match (&record.intended_witness_hash, artifact_matches) {
                (Some(intended), true) => {
                    &hash_regular(
                        &parent,
                        &name,
                        destination,
                        CodeKey::PendingRecovery,
                        "read-pending-recovery",
                    )? == intended
                }
                _ => false,
            }
        }
        Some(_) => {
            let target = symlink_target(&parent, &name).map_err(|errno| {
                Failure::syscall(
                    CodeKey::PendingRecovery,
                    destination,
                    "readlinkat-pending-recovery",
                    errno,
                )
            })?;
            artifact_matches
                && target.as_deref() == Some(OsStr::new(&record.applied_artifact_target))
        }
    };

    if authored {
        // converted to owned at the source this record was pending for, not at
        // the current one. a stale pending record converges to owned-at-old-S
        // and the ordinary path then takes it forward, both steps recorded.
        let mut owned = record.clone();
        owned.state = STATE_OWNED.to_owned();
        owned.baseline_hash = record
            .intended_witness_hash
            .as_deref()
            .and_then(|witness| baseline_for(&record.representation, witness));
        owned.stage_name = None;
        owned.applied_operation_generation = record.applied_operation_generation.saturating_add(1);
        // an exchange publish displaces the old destination to the stage name
        // instead of consuming it, so a death between the exchange and the
        // cleanup arrives here with the stage still populated. those bytes can
        // be a user edit, so they are hashed against the baseline this record
        // was pending against before anything unlinks them.
        if let Some(stage) = stage.as_deref()
            && observe_kind(&parent, stage, destination)? == Some(REGULAR_MODE)
        {
            let displaced_hash = hash_regular(
                &parent,
                stage,
                destination,
                CodeKey::PendingRecovery,
                "read-displaced-pending",
            )?;
            if record.baseline_hash.as_deref() != Some(displaced_hash.as_str())
                && entry.on_conflict != ConflictPolicy::SourceWins
            {
                // not what furnish wrote, and the declaration does not
                // authorise discarding it, so the exchange is reversed and the
                // edited bytes go back to the destination the user knows.
                if let Err(errno) = renameat_with(
                    &parent,
                    stage,
                    &parent,
                    name.as_os_str(),
                    RenameFlags::EXCHANGE,
                ) {
                    return Err(Failure::syscall(
                        CodeKey::PendingRecovery,
                        destination,
                        "renameat2-exchange-restore-pending",
                        errno,
                    ));
                }
                sync_parent(&parent, destination)?;
                // what sits at the stage name now is the content this run
                // published, which is ours and holds nothing of the user's.
                remove_stage(&parent, stage);
                // backward convergence, so the owned state the ledger already
                // describes is restated rather than advanced. that leaves the
                // destination off both its baseline and the source, which is
                // exactly the state the declaration's policy exists to decide,
                // so the next run decides it there instead of here. the witness
                // is restated with it, because on a writable owned record the
                // witness is the baseline, and the one this pending record
                // carries is the source that never landed.
                let mut restored = record.clone();
                restored.state = STATE_OWNED.to_owned();
                restored.intended_witness_hash = record.baseline_hash.clone();
                restored.stage_name = None;
                ledger.commit(canonical, restored)?;
                return Err(Failure::new(
                    CodeKey::PendingRecovery,
                    destination,
                    "destination was edited while a writable update was publishing; the edited content was restored and the update was not recorded",
                ));
            }
            remove_stage(&parent, stage);
        }
        ledger.commit(canonical, owned)?;
        return Ok(());
    }

    // not ours. the staged object is content this coordinator wrote and never
    // published, so removing it destroys nothing a user could have edited.
    if observed.is_none()
        && let Some(stage) = stage.as_deref()
    {
        remove_stage(&parent, stage);
    }
    ledger.retire(canonical)?;
    Ok(())
}

// recovery for a crash between the exchange and the ledger advancing. the
// destination already holds the new representation and the displaced object
// sits at the stage name; for a writable source that displaced object may hold
// edited user bytes, so it is never unlinked without being hashed against the
// baseline first.
#[allow(clippy::too_many_arguments)]
fn recover_transition(
    entry: &Entry,
    ledger: &mut LedgerState,
    identity: &RunIdentity,
    record: &LedgerRecord,
    parent: &OwnedFd,
    name: &OsStr,
    observed: Option<u32>,
    stage: Option<OsString>,
) -> Result<()> {
    let canonical = &entry.filesystem_identity.canonical;
    let destination = &entry.filesystem_identity.destination;
    let target_representation = record.representation.clone();
    let Some(source_representation) = transition_source_of(&target_representation) else {
        return Err(Failure::new(
            CodeKey::TransitionRefused,
            destination,
            "pending transition names a representation pair that is not gated",
        ));
    };
    let observed_representation = observed.and_then(representation_of_kind);
    let stage = stage.ok_or_else(|| {
        Failure::new(
            CodeKey::TransitionRefused,
            destination,
            "pending transition record carries no staging name",
        )
    })?;

    // the exchange never happened, so the destination is still what it was and
    // this converges backward by restating the record the ledger already holds.
    if observed_representation == Some(source_representation) {
        if observe_kind(parent, &stage, destination)?.is_some() {
            remove_stage(parent, &stage);
        }
        // the witness reading is fixed by the representation, and this restates
        // the representation, so carrying the pending witness across would leave
        // a target hash on a writable record or a content hash on a symlink one.
        // a writable record's witness is its own baseline; a symlink record's is
        // the hash of the target it is recorded as pointing at, which the pending
        // record carried forward for exactly this. the baseline is derived from
        // the same representation rather than left as it stands, because a record
        // this file did not write can carry one where the schema forbids it.
        let witness = if source_representation == WRITABLE_REPRESENTATION {
            let Some(baseline) = record.baseline_hash.clone() else {
                return Err(Failure::new(
                    CodeKey::TransitionRefused,
                    destination,
                    "refusing to restate a writable destination with no recorded baseline",
                ));
            };
            baseline
        } else {
            sha256_hex(record.applied_artifact_target.as_bytes())
        };
        let mut owned = record.clone();
        owned.state = STATE_OWNED.to_owned();
        owned.representation = source_representation.to_owned();
        owned.baseline_hash = baseline_for(source_representation, &witness);
        owned.intended_witness_hash = Some(witness);
        owned.stage_name = None;
        ledger.commit(canonical, owned)?;
        return Ok(());
    }

    if observed_representation != Some(target_representation.as_str()) {
        return Err(Failure::new(
            CodeKey::TransitionRefused,
            destination,
            "destination is neither side of the pending transition; refusing",
        ));
    }

    // forward, so the destination already holds the new representation.
    if target_representation == WRITABLE_REPRESENTATION {
        let Some(intended) = record.intended_witness_hash.clone() else {
            return Err(Failure::new(
                CodeKey::TransitionRefused,
                destination,
                "pending transition record carries no intended content hash",
            ));
        };
        verify_writable_destination(parent, name, destination, &intended)?;
        remove_stage(parent, &stage);
        ledger.commit(
            canonical,
            owned_record(identity, entry, "update", Some(record), &intended),
        )?;
        return Ok(());
    }

    // forward into symlink. the displaced object is the regular file, and it is
    // the one thing here that can hold work a user cannot get back.
    let displaced_hash = hash_regular(
        parent,
        &stage,
        destination,
        CodeKey::TransitionRefused,
        "read-displaced-writable",
    )?;
    let pristine = record.baseline_hash.as_deref() == Some(displaced_hash.as_str());
    if !pristine {
        // exchange back, so the edited bytes return to the destination the user
        // knows, and the transition is refused rather than completed.
        if let Err(errno) = renameat_with(parent, &stage, parent, name, RenameFlags::EXCHANGE) {
            return Err(Failure::syscall(
                CodeKey::TransitionRefused,
                destination,
                "renameat2-exchange-restore",
                errno,
            ));
        }
        sync_parent(parent, destination)?;
        // what sits at the stage name now is the symlink this run staged, which
        // is ours and holds nothing of the user's.
        remove_stage(parent, &stage);
        // backward convergence again, so the destination is back to the writable
        // file it was and the record it already had is restated, baseline and
        // the witness that baseline is included.
        let Some(baseline) = record.baseline_hash.clone() else {
            return Err(Failure::new(
                CodeKey::TransitionRefused,
                destination,
                "refusing to restate a writable destination with no recorded baseline; edited content was restored",
            ));
        };
        let mut owned = record.clone();
        owned.state = STATE_OWNED.to_owned();
        owned.representation = WRITABLE_REPRESENTATION.to_owned();
        owned.intended_witness_hash = Some(baseline);
        owned.stage_name = None;
        ledger.commit(canonical, owned)?;
        return Err(Failure::new(
            CodeKey::TransitionRefused,
            destination,
            "refusing to retire a writable destination that no longer matches its baseline; edited content was restored",
        ));
    }
    remove_stage(parent, &stage);
    // the exchange landed, so this carries the applied state forward and takes
    // the same constructor as any other post-publish commit.
    let owned = owned_record(
        identity,
        entry,
        "update",
        Some(record),
        &sha256_hex(entry.retained_artifact_target.as_bytes()),
    );
    ledger.commit(canonical, owned)?;
    Ok(())
}

// transfer between representations. post-write verification completes before
// the ledger representation changes, in both directions.
fn transition_representation(
    entry: &Entry,
    setpriv: &Path,
    index: usize,
    ledger: &mut LedgerState,
    identity: &RunIdentity,
    record: &LedgerRecord,
    parent: &OwnedFd,
    name: &OsStr,
) -> Result<()> {
    let canonical = &entry.filesystem_identity.canonical;
    let destination = &entry.filesystem_identity.destination;
    let from = record.representation.clone();
    let to = entry.representation.clone();
    if !transition_is_gated(&from, &to) {
        return Err(Failure::new(
            CodeKey::TransitionRefused,
            destination,
            format!("no gated transfer from {from} to {to}"),
        ));
    }
    let stage = stage_name(index);
    let recorded = OsStr::new(&record.applied_artifact_target);

    if to == WRITABLE_REPRESENTATION {
        // only sound when the current symlink is exactly the recorded one.
        let observed = symlink_target(&parent, &name).map_err(|errno| {
            Failure::syscall(
                CodeKey::TransitionRefused,
                destination,
                "readlinkat-transition",
                errno,
            )
        })?;
        if observed.as_deref() != Some(recorded) {
            return Err(Failure::new(
                CodeKey::TransitionRefused,
                destination,
                "refusing to transfer a destination that is not the link recorded as furnish-owned",
            ));
        }
        let intended = hash_source(&entry.retained_artifact_target, destination)?;
        fault_point("pre-pending");
        let mut pending = pending_record(
            identity,
            entry,
            TRANSITION_MARKER,
            Some(record),
            &stage,
            &intended,
        );
        pending.representation = WRITABLE_REPRESENTATION.to_owned();
        pending.applied_artifact_target = record.applied_artifact_target.clone();
        ledger.commit(canonical, pending)?;
        fault_point("pending-committed");
        stage_writable(setpriv, &parent, &stage, entry, &intended)?;
        fault_point("stage-synced");
        if let Err(errno) = renameat_with(&parent, &stage, &parent, name, RenameFlags::EXCHANGE) {
            remove_stage(&parent, &stage);
            return Err(Failure::syscall(
                CodeKey::TransitionRefused,
                destination,
                "renameat2-exchange-transition",
                errno,
            ));
        }
        fault_point("exchange-published");
        sync_parent(&parent, destination)?;
        verify_writable_destination(&parent, &name, destination, &intended)?;
        fault_point("verified");
        remove_stage(&parent, &stage);
        ledger.commit(
            canonical,
            owned_record(identity, entry, "update", Some(record), &intended),
        )?;
        return Ok(());
    }

    // writable to symlink is automatic only when the destination still equals
    // its baseline. an edited file is never silently converted away.
    let Some(baseline) = record.baseline_hash.clone() else {
        return Err(Failure::new(
            CodeKey::TransitionRefused,
            destination,
            "refusing to transfer a writable destination with no recorded baseline",
        ));
    };
    let observed_hash = hash_regular(
        &parent,
        &name,
        destination,
        CodeKey::TransitionRefused,
        "read-writable-transition",
    )?;
    if observed_hash != baseline {
        return Err(Failure::new(
            CodeKey::TransitionRefused,
            destination,
            "refusing to transfer a writable destination that no longer matches its baseline",
        ));
    }
    let expected = OsStr::new(&entry.retained_artifact_target);
    fault_point("pre-pending");
    let mut pending = pending_record(
        identity,
        entry,
        TRANSITION_MARKER,
        Some(record),
        &stage,
        &sha256_hex(entry.retained_artifact_target.as_bytes()),
    );
    pending.representation = NATIVE_REPRESENTATION.to_owned();
    ledger.commit(canonical, pending)?;
    fault_point("pending-committed");
    stage_symlink(setpriv, &parent, &stage, entry, expected)?;
    fault_point("stage-synced");
    if let Err(errno) = renameat_with(&parent, &stage, &parent, name, RenameFlags::EXCHANGE) {
        remove_stage(&parent, &stage);
        return Err(Failure::syscall(
            CodeKey::TransitionRefused,
            destination,
            "renameat2-exchange-transition",
            errno,
        ));
    }
    fault_point("exchange-published");
    sync_parent(&parent, destination)?;
    let published = symlink_target(&parent, &name).map_err(|errno| {
        Failure::syscall(
            CodeKey::TransitionRefused,
            destination,
            "readlinkat-transition-published",
            errno,
        )
    })?;
    if published.as_deref() != Some(expected) {
        return Err(Failure::new(
            CodeKey::TransitionRefused,
            destination,
            "post-transfer verification did not observe the intended link",
        ));
    }
    fault_point("verified");
    // the displaced object is the pristine regular file, proven equal to its
    // baseline above, so removing it destroys no work.
    remove_stage(&parent, &stage);
    let owned = owned_record(
        identity,
        entry,
        "update",
        Some(record),
        &sha256_hex(entry.retained_artifact_target.as_bytes()),
    );
    ledger.commit(canonical, owned)?;
    Ok(())
}

// first ownership of an absent destination, the self-heal for an owned one that
// has gone missing, and the convergence for a destination that already equals
// the source while the recorded baseline does not. divergent content is refused
// rather than reconciled.
fn reconcile_writable_entry(
    entry: &Entry,
    setpriv: &Path,
    index: usize,
    ledger: &mut LedgerState,
    identity: &RunIdentity,
    parent: &OwnedFd,
    name: &OsStr,
) -> Result<()> {
    let canonical = &entry.filesystem_identity.canonical;
    let destination = &entry.filesystem_identity.destination;
    let intended = hash_source(&entry.retained_artifact_target, destination)?;
    let record = ledger.record(canonical).cloned();
    let observed = observe_kind(&parent, &name, destination)?;

    match (observed, record) {
        // first ownership, and the self-heal for an owned destination that has
        // gone missing. both publish into an absent name; they differ only in
        // what the record says about how it was decided.
        (None, prior) => {
            let applied_by = if prior.is_some() { "repair" } else { "new" };
            let stage = stage_name(index);
            fault_point("pre-pending");
            ledger.commit(
                canonical,
                pending_record(
                    identity,
                    entry,
                    applied_by,
                    prior.as_ref(),
                    &stage,
                    &intended,
                ),
            )?;
            fault_point("pending-committed");
            stage_writable(setpriv, &parent, &stage, entry, &intended)?;
            publish_writable_new(&parent, &name, &stage, destination, &intended)?;
            ledger.commit(
                canonical,
                owned_record(identity, entry, applied_by, prior.as_ref(), &intended),
            )?;
            Ok(())
        }
        // refused by default even when the content already equals the source.
        // equality is not adoption proof.
        (Some(_), None) => Err(Failure::new(
            CodeKey::ConflictingDestination,
            destination,
            "refusing to take ownership of a pre-existing destination: applied state records no furnish ownership of it",
        )),
        (Some(kind), Some(record)) => {
            if kind != REGULAR_MODE {
                return Err(Failure::new(
                    CodeKey::ConflictingDestination,
                    destination,
                    "refusing a destination that is not a regular file",
                ));
            }
            let observed_hash = hash_regular(
                &parent,
                &name,
                destination,
                CodeKey::ContentVerification,
                "read-destination",
            )?;
            let Some(baseline) = record.baseline_hash.as_deref() else {
                // absence of a baseline is not a diverged baseline. a record
                // that cannot say what furnish last wrote cannot authorise
                // overwriting whatever is there now, whichever policy the
                // declaration carries, so this refuses in the same register
                // the transition path already refuses in.
                return Err(Failure::new(
                    CodeKey::ConflictingDestination,
                    destination,
                    "refusing to reconcile a writable destination with no recorded baseline",
                ));
            };
            let d_eq_s = observed_hash == intended;
            let d_eq_b = observed_hash == baseline;
            let s_eq_b = baseline == intended.as_str();

            if d_eq_s {
                if s_eq_b {
                    // row one. nothing to publish, but the record is refreshed
                    // so that when this last reconciled has a live answer here
                    // and not only on the symlink steady-state path.
                    let mut refreshed = identity.record(entry, &record.applied_by);
                    carry_applied_state(&record, &mut refreshed);
                    ledger.commit(canonical, refreshed)?;
                    return Ok(());
                }
                // row five. the crash window after the destination was
                // replaced and before the baseline was committed, so the
                // representation is verified and the baseline advances under
                // the applied_by this record already carries rather than
                // being reported as a conflict.
                verify_writable_destination(&parent, &name, destination, &intended)?;
                ledger.commit(
                    canonical,
                    owned_record(
                        identity,
                        entry,
                        &record.applied_by,
                        Some(&record),
                        &intended,
                    ),
                )?;
                return Ok(());
            }

            if s_eq_b {
                // row two. the source has not changed but the destination has,
                // so a user edited the file after furnish wrote it. the edit
                // is preserved and no reload is triggered.
                let mut refreshed = identity.record(entry, &record.applied_by);
                carry_applied_state(&record, &mut refreshed);
                ledger.commit(canonical, refreshed)?;
                return Ok(());
            }

            if d_eq_b {
                // row three. the source changed and the destination is still
                // exactly what furnish last wrote, so the new version goes in
                // through the exchange route. the bytes it will displace are
                // the ones just measured, which is what the recheck expects.
                return publish_writable_update(
                    entry,
                    setpriv,
                    index,
                    ledger,
                    identity,
                    &record,
                    &parent,
                    &name,
                    &observed_hash,
                    &intended,
                );
            }

            // row four. the destination and the source have both moved off the
            // baseline, so nothing here is derivable from the hashes and the
            // declaration's policy is the only thing left to decide it.
            match entry.on_conflict {
                ConflictPolicy::Error => Err(Failure::conflict(
                    destination,
                    Some(baseline),
                    &intended,
                    &observed_hash,
                )),
                ConflictPolicy::SourceWins => publish_writable_update(
                    entry,
                    setpriv,
                    index,
                    ledger,
                    identity,
                    &record,
                    &parent,
                    &name,
                    &observed_hash,
                    &intended,
                ),
                ConflictPolicy::RuntimeWins => {
                    // the destination stays as it is and the baseline advances
                    // to the source that was refused, so a later run sees a
                    // settled decision instead of the same conflict again. the
                    // witness moves with it because every writable owned
                    // record in this file keeps the two equal.
                    let mut refreshed = identity.record(entry, &record.applied_by);
                    carry_applied_state(&record, &mut refreshed);
                    refreshed.baseline_hash = baseline_for(&entry.representation, &intended);
                    refreshed.intended_witness_hash = Some(intended.clone());
                    ledger.commit(canonical, refreshed)?;
                    Ok(())
                }
            }
        }
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

    // the one walk for this entry, and the only one allowed to create. it runs
    // ahead of recovery because recovery resolves the parent too, so a
    // destination whose directory nothing else creates has to be reachable
    // before any branch reads it. every branch below is handed this descriptor
    // rather than repeating the walk.
    let (parent, name) = walk_parent(
        destination,
        &entry.managed_root,
        &ParentMode::Create {
            setpriv,
            authority: &entry.authority,
        },
    )?;
    let name = name.as_os_str();

    // recovery runs before the ordinary path and only ever converts pending to
    // owned. the two are never fused, so a stale pending record converges to
    // owned at the source it was pending for and is then carried forward. it
    // resolves the parent from the record's own managed root, which is not
    // always the entry's, so it keeps its own refusing walk.
    recover_pending(entry, ledger, identity)?;

    if let Some(record) = ledger.record(canonical).cloned()
        && record.state == STATE_OWNED
        && record.representation != entry.representation
    {
        return transition_representation(
            entry, setpriv, index, ledger, identity, &record, &parent, name,
        );
    }

    if entry.representation == WRITABLE_REPRESENTATION {
        return reconcile_writable_entry(entry, setpriv, index, ledger, identity, &parent, name);
    }

    let expected = OsStr::new(&entry.retained_artifact_target);

    let observed = symlink_target(&parent, name).map_err(|errno| {
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
            let intended = sha256_hex(entry.retained_artifact_target.as_bytes());
            let prior = ledger.record(canonical).cloned();
            fault_point("pre-pending");
            ledger.commit(
                canonical,
                pending_record(identity, entry, "new", prior.as_ref(), &stage, &intended),
            )?;
            fault_point("pending-committed");
            stage_symlink(setpriv, &parent, &stage, entry, expected)?;
            fault_point("stage-synced");
            publish_new(&parent, &name, &stage, destination, expected)?;
            fault_point("verified");
            ledger.commit(
                canonical,
                owned_record(identity, entry, "new", prior.as_ref(), &intended),
            )?;
            Ok(())
        }
        Some(actual) if actual == expected => {
            // ownership is never inferred from a matching target, because a
            // destination furnish never published is indistinguishable from one
            // it did. a host whose link predates the ledger stays unrecorded
            // here and acquires from absence instead.
            //
            // nothing was published, so the branch that produced this target is
            // carried forward rather than restated as a decision this run made,
            // and so is everything else the applied state already recorded.
            if let Some(prior) = ledger.record(canonical).cloned() {
                let mut refreshed = identity.record(entry, &prior.applied_by);
                carry_applied_state(&prior, &mut refreshed);
                ledger.commit(canonical, refreshed)?;
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
            // exact match against the RECORD, not against the desired target.
            // read against desired this condition could never be satisfied by
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

            // the destination is recorded as furnish-owned and the link on disk
            // still points at the recorded target, so what remains is only which
            // owned branch this is. both publish to desired through the same
            // exchange; they differ in what they mean. a resolving recorded target
            // says the declaration moved, which is a fact about the config. a
            // reaped one says the store object furnish published is gone, which is
            // a fact about the world.
            //
            // resolution is only ever tested against a target furnish published
            // itself, which is always a store path on an already-mounted
            // filesystem. applied to a foreign target this test would be a race,
            // since a link into a late-mounting filesystem reads unresolvable at
            // boot and resolvable at switch, and the coordinator runs at both.
            let applied_by = match statat(&parent, name, AtFlags::empty()) {
                // what furnish published is still live.
                Ok(_) => "update",
                // what furnish published was reaped.
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

            // republishing toward a target that is not there would manufacture
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
            let intended = sha256_hex(entry.retained_artifact_target.as_bytes());
            stage_symlink(setpriv, &parent, &stage, entry, expected)?;
            publish_exchange(&parent, &name, &stage, destination, expected, recorded)?;
            ledger.commit(
                canonical,
                owned_record(identity, entry, applied_by, Some(&record), &intended),
            )?;
            Ok(())
        }
    }
}

fn acquire_lock(run_lock: &OwnedFd, lock_dir: &Path, lock_name: &OsStr) -> Result<OwnedFd> {
    // the directory comes from the caller so a failure names the file it failed
    // on, which is not always the default one.
    let label = lock_dir.join(lock_name);
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

const DEFAULT_LOCK_DIR: &str = "/run/lock";

// the lock directory is a seam so crash cases can be exercised without a boot.
// nothing in the module set passes it, so the unit and the activation script
// are byte-unchanged and it never becomes a host-visible option.
fn open_host_lock(lock_name: &OsStr, lock_dir: &Path) -> Result<OwnedFd> {
    let mut components = Path::new(lock_name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(Failure::new(
            CodeKey::InvalidManifest,
            lock_name.to_string_lossy(),
            "lock name must be one normal path component",
        ));
    }
    let run_lock = open(
        lock_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| {
        Failure::syscall(
            CodeKey::InvalidManifest,
            lock_dir.to_string_lossy(),
            "open-run-lock",
            errno,
        )
    })?;
    acquire_lock(&run_lock, lock_dir, lock_name)
}

fn reconcile(
    manifest_path: &Path,
    lock_name: &OsStr,
    setpriv: &Path,
    state_dir: &Path,
    lock_dir: &Path,
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

    let _lock = match open_host_lock(lock_name, lock_dir) {
        Ok(lock) => lock,
        Err(failure) => {
            emit_failure(&manifest.diagnostic_contract.codes, &failure, None);
            return ExitCode::FAILURE;
        }
    };

    // applied state is read under the host lock, so no other reconcile can be
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

    // a manifest with no entries is a real desired set, not a no-op. this is the
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
        match retire_record(&record) {
            Ok(RetireOutcome::Removed) => {
                if let Err(failure) = ledger.retire(&canonical) {
                    emit_failure(&manifest.diagnostic_contract.codes, &failure, None);
                    return ExitCode::FAILURE;
                }
            }
            // the record is the point, since it is what stops the file becoming
            // an unexplained orphan, so ownership is preserved rather than
            // dropped and the prune is refused rather than the activation.
            Ok(RetireOutcome::Unresolved(unresolved)) => {
                let failure = Failure::new(
                    CodeKey::UnresolvedRetirement,
                    &record.destination,
                    format!(
                        "retirement is blocked: {}; the file and its ownership record are preserved",
                        unresolved.reason
                    ),
                );
                emit_warning(&manifest.diagnostic_contract.codes, &failure, None);
                let mut kept = record.clone();
                kept.unresolved_retirement = Some(unresolved);
                if let Err(failure) = ledger.commit(&canonical, kept) {
                    emit_failure(&manifest.diagnostic_contract.codes, &failure, None);
                    return ExitCode::FAILURE;
                }
            }
            Err(failure) => {
                emit_failure(&manifest.diagnostic_contract.codes, &failure, None);
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

fn worker(args: &[OsString], profile: &ExecutorProfile) -> ExitCode {
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
fn create_directory_component(args: &[OsString]) -> ExitCode {
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

fn is_single_component(name: &OsStr) -> bool {
    let path = Path::new(name);
    let mut components = path.components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

// the bytes are written and durable before the coordinator is told anything
// succeeded, so a crash after the executor returns can never leave a stage the
// coordinator would mistake for complete.
fn stage_writable_content(parent: &OwnedFd, name: &OsStr, source: &Path) -> ExitCode {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    // production resolves the parent once in reconcile_entry and threads it, so a
    // test that drives the writable path directly does the same walk rather than
    // a second version of it.
    fn reconcile_writable_at(
        entry: &Entry,
        setpriv: &Path,
        index: usize,
        ledger: &mut LedgerState,
        identity: &RunIdentity,
    ) -> Result<()> {
        let (parent, name) =
            open_parent(&entry.filesystem_identity.destination, &entry.managed_root)?;
        reconcile_writable_entry(
            entry,
            setpriv,
            index,
            ledger,
            identity,
            &parent,
            name.as_os_str(),
        )
    }

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

    // pinned to published vectors rather than to this implementation. every
    // other assertion here computes its expectation with the same function it
    // is checking, so a wrong compression function would be self-consistent and
    // green, and content ownership decisions ride on these digests. the third
    // vector spans two blocks, where the padding is easiest to get wrong.
    #[test]
    fn sha256_reproduces_known_answers() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
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
        let _lock = acquire_lock(&root.open(), &root.0, lock_name).expect("acquire fresh lock");
        assert!(root.0.join(lock_name).is_file());
    }

    #[test]
    fn lock_symlink_is_refused_without_following_it() {
        let root = TestLockRoot::new();
        let lock_name = OsStr::new("furnish-test.lock");
        symlink("elsewhere", root.0.join(lock_name)).expect("plant lock symlink");
        let failure =
            acquire_lock(&root.open(), &root.0, lock_name).expect_err("refuse lock symlink");
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
        let first = acquire_lock(&root.open(), &root.0, &lock_name).expect("acquire first lock");
        let lock_root = root.0.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let directory = open(
                &lock_root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .expect("open lock directory for waiter");
            started_tx.send(()).expect("signal waiter start");
            let _lock =
                acquire_lock(&directory, &lock_root, &lock_name).expect("acquire second lock");
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

        // production resolves the parent once per entry and threads it, so a
        // test that drives a publish function directly does the same walk.
        fn entry_parent(&self, name: &str) -> (OwnedFd, OsString) {
            let destination = self.0.join(name);
            open_parent(destination.to_str().unwrap(), self.0.to_str().unwrap())
                .expect("walk test entry parent")
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
            on_conflict: ConflictPolicy::Error,
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
        // no adoption, so a matching target furnish never published stays
        // unrecorded and unrepairable rather than becoming owned by having been
        // looked at.
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
        // drift to a dead target, where the link points somewhere furnish never
        // published and the pointee happens to be missing. non-resolution alone
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
        // staging cannot run inside the test process, so the branch is proven by
        // how far it gets, and reaching the executor at all means the predicate
        // admitted it instead of refusing. authority is switched to user scope so
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
        // desired resolution is checked before anything is staged. republishing
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
        // retirement removes what furnish published, never what it pointed at.
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

    // the creating walk must weaken nothing. a component that exists as a symlink
    // or as a plain file is refused exactly as it is on the no-create walk, and a
    // component missing at or above the managed root is refused rather than made.
    // the setpriv path handed in cannot be executed, so any test here that
    // reached delegation would fail on that instead of passing quietly.
    fn refusing_create_mode<'a>(authority: &'a Authority) -> ParentMode<'a> {
        ParentMode::Create {
            setpriv: Path::new("/nonexistent/setpriv"),
            authority,
        }
    }

    #[test]
    fn creating_walk_refuses_symlinked_path_component() {
        let dir = TestDir::new();
        let real = dir.path().join("real");
        fs::create_dir(&real).expect("create real directory");
        let link = dir.path().join("link");
        symlink(&real, &link).expect("plant symlinked component");
        let destination = link.join("nested").join("value");
        let entry = sample_entry(
            link.to_str().unwrap(),
            destination.to_str().unwrap(),
            "/desired/target",
        );
        let failure = walk_parent(
            destination.to_str().unwrap(),
            link.to_str().unwrap(),
            &refusing_create_mode(&entry.authority),
        )
        .expect_err("refuse symlinked path component while creating");
        assert!(matches!(failure.key, CodeKey::ParentTraversal));
        assert_eq!(failure.operation, Some("openat-parent-component"));
        assert_eq!(failure.errno, Some(Errno::NOTDIR.raw_os_error()));
        // the symlink is left as it was found and nothing was made behind it.
        assert_eq!(fs::read_link(&link).unwrap(), real);
        assert!(!real.join("nested").exists());
    }

    #[test]
    fn creating_walk_refuses_non_directory_path_component() {
        let dir = TestDir::new();
        let managed_root = dir.path().join("managed");
        fs::create_dir(&managed_root).expect("create managed root");
        let occupied = managed_root.join("occupied");
        fs::write(&occupied, b"foreign").expect("plant regular file component");
        let destination = occupied.join("value");
        let entry = sample_entry(
            managed_root.to_str().unwrap(),
            destination.to_str().unwrap(),
            "/desired/target",
        );
        let failure = walk_parent(
            destination.to_str().unwrap(),
            managed_root.to_str().unwrap(),
            &refusing_create_mode(&entry.authority),
        )
        .expect_err("refuse non-directory path component while creating");
        assert!(matches!(failure.key, CodeKey::ParentTraversal));
        assert_eq!(failure.operation, Some("openat-parent-component"));
        assert_eq!(failure.errno, Some(Errno::NOTDIR.raw_os_error()));
        // the foreign file keeps its bytes; nothing replaced it to make room.
        assert_eq!(fs::read(&occupied).unwrap(), b"foreign");
    }

    #[test]
    fn creating_walk_never_creates_at_or_above_the_managed_root() {
        let dir = TestDir::new();
        let managed_root = dir.path().join("absent-root");
        let destination = managed_root.join("value");
        let entry = sample_entry(
            managed_root.to_str().unwrap(),
            destination.to_str().unwrap(),
            "/desired/target",
        );
        let failure = walk_parent(
            destination.to_str().unwrap(),
            managed_root.to_str().unwrap(),
            &refusing_create_mode(&entry.authority),
        )
        .expect_err("refuse a managed root that does not exist");
        assert!(matches!(failure.key, CodeKey::ParentTraversal));
        assert_eq!(failure.operation, Some("openat-parent-component"));
        assert_eq!(failure.errno, Some(Errno::NOENT.raw_os_error()));
        assert!(!managed_root.exists());
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
        // directory components are opened O_DIRECTORY|O_NOFOLLOW, so a symlinked
        // component is refused with ENOTDIR (the unfollowed symlink is not a
        // directory); ELOOP only applies to the O_NOFOLLOW-without-O_DIRECTORY
        // lock-file open. either way the symlink is refused without being followed.
        assert_eq!(failure.errno, Some(Errno::NOTDIR.raw_os_error()));
    }

    // crash-boundary coverage. a unit test cannot kill the process mid-apply,
    // so each of these plants exactly the on-disk and ledger state a death at
    // that boundary leaves behind and asserts where the next run converges.
    // real process death at the same points is proven by the fault-injection
    // build in the regression harness.

    fn sample_writable_entry(managed_root: &str, destination: &str, source: &str) -> Entry {
        let mut entry = sample_entry(managed_root, destination, source);
        entry.representation = WRITABLE_REPRESENTATION.to_owned();
        entry.executor = Executor {
            identity: NATIVE_WRITABLE_IDENTITY.to_owned(),
            protocol_version: NATIVE_WRITABLE_PROTOCOL,
        };
        entry.cleanup_strategy = "exact-source-content".to_owned();
        entry.self_heal_strategy = "exact-source-content".to_owned();
        entry
    }

    fn write_source(dir: &TestDir, name: &str, contents: &str) -> String {
        let path = dir.path().join(name);
        fs::write(&path, contents).expect("write source artifact");
        path.to_str().unwrap().to_owned()
    }

    #[allow(clippy::too_many_arguments)]
    fn plant_record(
        ledger: &mut LedgerState,
        entry: &Entry,
        state: &str,
        applied_by: &str,
        representation: &str,
        target: &str,
        baseline: Option<&str>,
        intended: Option<&str>,
        stage: Option<&str>,
    ) {
        let identity = RunIdentity::observe();
        let mut record = identity.record(entry, applied_by);
        record.state = state.to_owned();
        record.representation = representation.to_owned();
        record.applied_artifact_target = target.to_owned();
        record.baseline_hash = baseline.map(str::to_owned);
        record.intended_witness_hash = intended.map(str::to_owned);
        record.stage_name = stage.map(str::to_owned);
        ledger
            .commit(&entry.filesystem_identity.canonical, record)
            .expect("plant record");
    }

    const PLANTED_GENERATION: u64 = 7;

    // the counter cannot be planted through plant_record, which starts every
    // record at zero, and a linkage proved with zero and one is a linkage between
    // two numbers that could each have come from anywhere. a nonzero prior makes
    // carrying the counter and advancing it different observations.
    fn plant_generation(ledger: &mut LedgerState, entry: &Entry, generation: u64) {
        let canonical = &entry.filesystem_identity.canonical;
        let mut record = ledger.record(canonical).expect("planted record").clone();
        record.applied_operation_generation = generation;
        ledger
            .commit(canonical, record)
            .expect("plant operation generation");
    }

    fn committed(ledger: &LedgerState, entry: &Entry) -> LedgerRecord {
        ledger
            .record(&entry.filesystem_identity.canonical)
            .expect("committed record")
            .clone()
    }

    // every route that verifies a writable destination asserts its mode as well
    // as its content, so a planted destination that skips the mode is a fixture
    // that fails for a reason the test is not about.
    fn plant_destination(dir: &TestDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, contents).expect("plant destination content");
        fs::set_permissions(&path, fs::Permissions::from_mode(WRITABLE_FILE_MODE))
            .expect("set published mode");
        path
    }

    #[test]
    fn crash_at_pre_pending_leaves_nothing_owned() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = dir.path().join("value");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let mut ledger = test_ledger(&dir);
        // nothing was recorded and nothing was written, so recovery has nothing
        // to convert and the destination is still absent.
        recover_pending(&entry, &mut ledger, &RunIdentity::observe()).expect("recovery is a no-op");
        assert!(
            ledger
                .record(&entry.filesystem_identity.canonical)
                .is_none()
        );
        assert!(!destination.exists());
    }

    #[test]
    fn crash_at_pending_committed_clears_the_record_and_keeps_the_destination_absent() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = dir.path().join("value");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let intended = sha256_hex(b"payload\n");
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_PENDING,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            None,
            Some(&intended),
            Some(".furnish.test.stage"),
        );
        recover_pending(&entry, &mut ledger, &RunIdentity::observe()).expect("recovery converges");
        // the publication never happened, so the pending record is not evidence
        // of ownership and is cleared rather than promoted.
        assert!(
            ledger
                .record(&entry.filesystem_identity.canonical)
                .is_none()
        );
        assert!(!destination.exists());
    }

    #[test]
    fn crash_at_stage_written_removes_the_orphaned_stage() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = dir.path().join("value");
        let stage = ".furnish.test.stage";
        fs::write(dir.path().join(stage), "payload\n").expect("plant staged content");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let intended = sha256_hex(b"payload\n");
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_PENDING,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            None,
            Some(&intended),
            Some(stage),
        );
        recover_pending(&entry, &mut ledger, &RunIdentity::observe()).expect("recovery converges");
        // the stage is content this coordinator wrote and never published, so
        // removing it destroys nothing a user could have edited.
        assert!(!dir.path().join(stage).exists());
        assert!(!destination.exists());
        assert!(
            ledger
                .record(&entry.filesystem_identity.canonical)
                .is_none()
        );
    }

    #[test]
    fn crash_after_publication_converts_pending_to_owned_at_the_intended_source() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = dir.path().join("value");
        fs::write(&destination, "payload\n").expect("plant published content");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let intended = sha256_hex(b"payload\n");
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_PENDING,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            None,
            Some(&intended),
            Some(".furnish.test.stage"),
        );
        recover_pending(&entry, &mut ledger, &RunIdentity::observe()).expect("recovery converges");
        let record = ledger
            .record(&entry.filesystem_identity.canonical)
            .expect("recovered record")
            .clone();
        assert_eq!(record.state, STATE_OWNED);
        assert_eq!(record.baseline_hash.as_deref(), Some(intended.as_str()));
        assert!(record.stage_name.is_none());
    }

    #[test]
    fn recovery_refuses_a_destination_the_pending_record_did_not_author() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = dir.path().join("value");
        fs::write(&destination, "somebody elses bytes\n").expect("plant foreign content");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let intended = sha256_hex(b"payload\n");
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_PENDING,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            None,
            Some(&intended),
            Some(".furnish.test.stage"),
        );
        recover_pending(&entry, &mut ledger, &RunIdentity::observe()).expect("recovery converges");
        // content that does not match the intent is not authorship, so the
        // record is cleared and the file is left exactly as found.
        assert!(
            ledger
                .record(&entry.filesystem_identity.canonical)
                .is_none()
        );
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            "somebody elses bytes\n"
        );
    }

    #[test]
    fn a_stale_pending_record_converges_to_owned_at_its_own_source_not_the_current_one() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "new payload\n");
        let destination = dir.path().join("value");
        fs::write(&destination, "old payload\n").expect("plant older publication");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let old_intended = sha256_hex(b"old payload\n");
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_PENDING,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            None,
            Some(&old_intended),
            Some(".furnish.test.stage"),
        );
        recover_pending(&entry, &mut ledger, &RunIdentity::observe()).expect("recovery converges");
        let record = ledger
            .record(&entry.filesystem_identity.canonical)
            .expect("recovered record")
            .clone();
        // recovery and reconciliation are two recorded steps, never fused, so
        // this lands at the old source and the ordinary path carries it forward.
        assert_eq!(record.state, STATE_OWNED);
        assert_eq!(record.baseline_hash.as_deref(), Some(old_intended.as_str()));
    }

    #[test]
    fn stale_baseline_is_advanced_as_recovery_and_never_reported_as_conflict() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = dir.path().join("value");
        fs::write(&destination, "payload\n").expect("plant matching destination");
        fs::set_permissions(&destination, fs::Permissions::from_mode(WRITABLE_FILE_MODE))
            .expect("set published mode");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_OWNED,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            // Opaque planted mismatch token: it names no file content and is
            // replaced when reconciliation advances the stale baseline.
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
            None,
            None,
        );
        reconcile_writable_at(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &RunIdentity::observe(),
        )
        .expect("stale baseline converges without conflict");
        let record = ledger
            .record(&entry.filesystem_identity.canonical)
            .expect("record")
            .clone();
        assert_eq!(
            record.baseline_hash.as_deref(),
            Some(sha256_hex(b"payload\n").as_str())
        );
        // the counter moves here, and moving it is not double counting. this row
        // is reachable only when the crashed run's owned commit never landed, so
        // the one advance recorded here is the one that run failed to record.
        assert_eq!(record.applied_operation_generation, 1);
    }

    #[test]
    fn writable_destination_equal_to_the_source_but_never_owned_is_refused() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = dir.path().join("value");
        fs::write(&destination, "payload\n").expect("plant identical content");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let mut ledger = test_ledger(&dir);
        let failure = reconcile_writable_at(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &RunIdentity::observe(),
        )
        .expect_err("equality is not adoption proof");
        assert!(matches!(failure.key, CodeKey::ConflictingDestination));
        assert!(
            ledger
                .record(&entry.filesystem_identity.canonical)
                .is_none()
        );
    }

    #[test]
    fn crash_at_exchange_published_completes_the_transfer_into_writable() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = dir.path().join("value");
        let stage = ".furnish.test.stage";
        // post-EXCHANGE, so the destination is the new regular file and the
        // displaced old symlink is sitting at the stage name.
        fs::write(&destination, "payload\n").expect("plant exchanged destination");
        fs::set_permissions(&destination, fs::Permissions::from_mode(WRITABLE_FILE_MODE))
            .expect("set published mode");
        symlink("/old/target", dir.path().join(stage)).expect("plant displaced symlink");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let intended = sha256_hex(b"payload\n");
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_PENDING,
            TRANSITION_MARKER,
            WRITABLE_REPRESENTATION,
            "/old/target",
            None,
            Some(&intended),
            Some(stage),
        );
        recover_pending(&entry, &mut ledger, &RunIdentity::observe())
            .expect("transition recovery converges forward");
        let record = ledger
            .record(&entry.filesystem_identity.canonical)
            .expect("record")
            .clone();
        assert_eq!(record.state, STATE_OWNED);
        assert_eq!(record.representation, WRITABLE_REPRESENTATION);
        // unlinking a symlink never touches its pointee.
        assert!(!dir.path().join(stage).exists());
    }

    #[test]
    fn crash_at_exchange_published_restores_edited_writable_and_refuses() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = dir.path().join("value");
        let stage = ".furnish.test.stage";
        // post-EXCHANGE the other way, so the destination is now the symlink and
        // the displaced regular file holds bytes the user edited.
        symlink(&source, &destination).expect("plant exchanged symlink");
        fs::write(dir.path().join(stage), "the user edited this\n")
            .expect("plant displaced edited file");
        let mut entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        entry.representation = NATIVE_REPRESENTATION.to_owned();
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_PENDING,
            TRANSITION_MARKER,
            NATIVE_REPRESENTATION,
            &source,
            Some(&sha256_hex(b"payload\n")),
            Some(&sha256_hex(source.as_bytes())),
            Some(stage),
        );
        let failure = recover_pending(&entry, &mut ledger, &RunIdentity::observe())
            .expect_err("an edited displaced file refuses the transfer");
        assert!(matches!(failure.key, CodeKey::TransitionRefused));
        // the edited bytes are back at the destination and were never unlinked.
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            "the user edited this\n"
        );
        let record = ledger
            .record(&entry.filesystem_identity.canonical)
            .expect("ownership is preserved")
            .clone();
        assert_eq!(record.representation, WRITABLE_REPRESENTATION);
    }

    #[test]
    fn crash_at_exchange_published_completes_the_transfer_into_symlink_when_pristine() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = dir.path().join("value");
        let stage = ".furnish.test.stage";
        symlink(&source, &destination).expect("plant exchanged symlink");
        fs::write(dir.path().join(stage), "payload\n").expect("plant pristine displaced file");
        let mut entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        entry.representation = NATIVE_REPRESENTATION.to_owned();
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_PENDING,
            TRANSITION_MARKER,
            NATIVE_REPRESENTATION,
            &source,
            Some(&sha256_hex(b"payload\n")),
            Some(&sha256_hex(source.as_bytes())),
            Some(stage),
        );
        recover_pending(&entry, &mut ledger, &RunIdentity::observe())
            .expect("a pristine displaced file completes the transfer");
        let record = ledger
            .record(&entry.filesystem_identity.canonical)
            .expect("record")
            .clone();
        assert_eq!(record.state, STATE_OWNED);
        assert_eq!(record.representation, NATIVE_REPRESENTATION);
        assert!(!dir.path().join(stage).exists());
    }

    #[test]
    fn writable_retirement_preserves_edited_content_and_records_it_unresolved() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = dir.path().join("value");
        fs::write(&destination, "the user edited this\n").expect("plant edited destination");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let identity = RunIdentity::observe();
        let mut record = identity.record(&entry, "new");
        record.state = STATE_OWNED.to_owned();
        record.representation = WRITABLE_REPRESENTATION.to_owned();
        record.baseline_hash = Some(sha256_hex(b"payload\n"));
        let outcome = retire_record(&record).expect("retirement is refused, not failed");
        // edited data is never deleted to satisfy cleanup, and the refusal is
        // recorded rather than thrown away.
        assert!(matches!(outcome, RetireOutcome::Unresolved(_)));
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            "the user edited this\n"
        );
    }

    #[test]
    fn writable_retirement_removes_a_pristine_destination() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = dir.path().join("value");
        fs::write(&destination, "payload\n").expect("plant pristine destination");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let identity = RunIdentity::observe();
        let mut record = identity.record(&entry, "new");
        record.state = STATE_OWNED.to_owned();
        record.representation = WRITABLE_REPRESENTATION.to_owned();
        record.baseline_hash = Some(sha256_hex(b"payload\n"));
        let outcome = retire_record(&record).expect("pristine retirement succeeds");
        assert!(matches!(outcome, RetireOutcome::Removed));
        assert!(!destination.exists());
    }

    #[test]
    fn unknown_newer_ledger_schema_is_refused_before_any_mutation() {
        let dir = TestDir::new();
        let state = dir.path().join("state");
        fs::create_dir_all(&state).expect("create state directory");
        let ledger_path = state.join(LEDGER_FILE_NAME);
        let payload = "{\"schemaVersion\":99,\"records\":{}}";
        fs::write(&ledger_path, payload).expect("plant newer state");
        let failure = LedgerState::load(&state).expect_err("newer schema is refused");
        assert!(matches!(failure.key, CodeKey::LedgerInvalid));
        // refused before anything was touched, so the file is byte-identical and
        // no rollback copy was taken, because no migration was attempted.
        assert_eq!(fs::read_to_string(&ledger_path).unwrap(), payload);
        assert!(!state.join(LEDGER_ROLLBACK_FILE_NAME).exists());
    }

    #[test]
    fn a_v1_ledger_migrates_to_v2_and_leaves_rollback_evidence() {
        let dir = TestDir::new();
        let state = dir.path().join("state");
        fs::create_dir_all(&state).expect("create state directory");
        let ledger_path = state.join(LEDGER_FILE_NAME);
        // byte-for-byte what the v1 coordinator could have written, camelCase and
        // none of the v2 fields, so the defaults are what get exercised.
        let original = concat!(
            "{\"schemaVersion\":1,\"records\":{\"test:/tmp/value\":{",
            "\"destination\":\"/tmp/value\",",
            "\"appliedArtifactTarget\":\"/nix/store/example\",",
            "\"managedRoot\":\"/tmp\",\"appliedBy\":\"new\",",
            "\"appliedGeneration\":null,",
            "\"lastSuccessfulReload\":{\"invocationId\":null,\"monotonicSeconds\":0.0},",
            "\"reloadActionIdentity\":null,\"bootId\":null}}}"
        );
        fs::write(&ledger_path, original).expect("plant v1 state");
        let ledger = LedgerState::load(&state).expect("v1 migrates");
        let record = ledger.record("test:/tmp/value").expect("migrated record");
        // writable did not exist in v1, so every v1 record is owned and symlink.
        assert_eq!(record.state, STATE_OWNED);
        assert_eq!(record.representation, NATIVE_REPRESENTATION);
        // the rollback copy is the evidence, and it is the untouched original.
        let rollback = state.join(LEDGER_ROLLBACK_FILE_NAME);
        assert_eq!(fs::read_to_string(&rollback).unwrap(), original);
    }

    // the causes that make a destination reload-eligible are the ones that commit
    // new furnish-applied content, and eligibility is read off the committed
    // record rather than off anything this coordinator does at the destination.
    // staging cannot run inside the test process, since run_executor re-executes
    // env::current_exe and inside these tests that is the test binary, so each
    // publishing cause is proven in two halves. the dispatch half proves which
    // route the reconciliation chose and that the pending record carried the
    // prior counter unchanged into it. the recovery half proves what that route
    // commits when it completes, advancing the same planted prior by exactly one.
    // both halves plant PLANTED_GENERATION, which is what lets them compose.

    #[test]
    fn initial_materialization_takes_the_new_route_and_starts_the_counter_at_zero() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "first\n");
        let destination = dir.path().join("value");
        let mut entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        // user scope so the launch fails on the nonexistent setpriv rather than
        // re-executing the test binary with a worker subcommand it cannot read.
        entry.authority.scope = "user".to_owned();
        let mut ledger = test_ledger(&dir);
        let failure = reconcile_writable_at(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &RunIdentity::observe(),
        )
        .expect_err("staging cannot run inside the test process");
        assert!(matches!(failure.key, CodeKey::ExecutorFailed));
        let record = committed(&ledger, &entry);
        assert_eq!(record.state, STATE_PENDING);
        assert_eq!(record.applied_by, "new");
        assert_eq!(
            record.intended_witness_hash.as_deref(),
            Some(sha256_hex(b"first\n").as_str())
        );
        assert!(record.stage_name.is_some());
        // there is no prior record to carry, so a first ownership is the one
        // advancing cause whose prior is zero rather than planted.
        assert_eq!(record.applied_operation_generation, 0);
        assert!(record.baseline_hash.is_none());
        assert!(!destination.exists());
    }

    #[test]
    fn self_heal_takes_the_repair_route_and_carries_the_prior_counter() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let baseline = sha256_hex(b"payload\n");
        let destination = dir.path().join("value");
        let mut entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        entry.authority.scope = "user".to_owned();
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_OWNED,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            Some(&baseline),
            Some(&baseline),
            None,
        );
        plant_generation(&mut ledger, &entry, PLANTED_GENERATION);
        let failure = reconcile_writable_at(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &RunIdentity::observe(),
        )
        .expect_err("staging cannot run inside the test process");
        assert!(matches!(failure.key, CodeKey::ExecutorFailed));
        let record = committed(&ledger, &entry);
        assert_eq!(record.state, STATE_PENDING);
        // an owned destination that has gone missing is a repair rather than a
        // first ownership, and the two differ only in what the record says.
        assert_eq!(record.applied_by, "repair");
        assert_eq!(record.baseline_hash.as_deref(), Some(baseline.as_str()));
        assert_eq!(record.applied_operation_generation, PLANTED_GENERATION);
    }

    #[test]
    fn source_only_propagation_takes_the_update_route_and_carries_the_prior_counter() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "second\n");
        let destination = plant_destination(&dir, "value", "first\n");
        let baseline = sha256_hex(b"first\n");
        let mut entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        entry.authority.scope = "user".to_owned();
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_OWNED,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            Some(&baseline),
            Some(&baseline),
            None,
        );
        plant_generation(&mut ledger, &entry, PLANTED_GENERATION);
        let failure = reconcile_writable_at(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &RunIdentity::observe(),
        )
        .expect_err("staging cannot run inside the test process");
        assert!(matches!(failure.key, CodeKey::ExecutorFailed));
        let record = committed(&ledger, &entry);
        assert_eq!(record.state, STATE_PENDING);
        assert_eq!(record.applied_by, "update");
        // the pending record names the source that has not landed while the
        // baseline still names the bytes at the destination, which is the one
        // state in which the two fields are allowed to differ.
        assert_eq!(
            record.intended_witness_hash.as_deref(),
            Some(sha256_hex(b"second\n").as_str())
        );
        assert_eq!(record.baseline_hash.as_deref(), Some(baseline.as_str()));
        assert_eq!(record.applied_operation_generation, PLANTED_GENERATION);
        assert_eq!(fs::read_to_string(&destination).unwrap(), "first\n");
    }

    #[test]
    fn source_wins_takes_the_update_route_from_a_two_sided_divergence() {
        // the preconditions are built explicitly rather than borrowed from the
        // source-only case, because this is the only advancing cause selected by
        // a declared policy instead of by a hash comparison. the destination and
        // the source are both off the baseline, so nothing here is derivable and
        // the policy is the only thing that can choose the publishing route.
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "declared\n");
        let destination = plant_destination(&dir, "value", "edited\n");
        let baseline = sha256_hex(b"baseline\n");
        let mut entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        entry.authority.scope = "user".to_owned();
        entry.on_conflict = ConflictPolicy::SourceWins;
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_OWNED,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            Some(&baseline),
            Some(&baseline),
            None,
        );
        plant_generation(&mut ledger, &entry, PLANTED_GENERATION);
        let failure = reconcile_writable_at(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &RunIdentity::observe(),
        )
        .expect_err("staging cannot run inside the test process");
        assert!(matches!(failure.key, CodeKey::ExecutorFailed));
        let record = committed(&ledger, &entry);
        assert_eq!(record.state, STATE_PENDING);
        assert_eq!(record.applied_by, "update");
        assert_eq!(record.applied_operation_generation, PLANTED_GENERATION);
        // the edit is still there. a policy that authorises discarding it does
        // not discard it before the replacement content exists.
        assert_eq!(fs::read_to_string(&destination).unwrap(), "edited\n");
    }

    #[test]
    fn a_completed_new_publish_advances_the_counter_by_exactly_one() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = plant_destination(&dir, "value", "payload\n");
        let intended = sha256_hex(b"payload\n");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_PENDING,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            None,
            Some(&intended),
            Some(".furnish.test.stage"),
        );
        // a first ownership has no prior, so a pending new record carrying a
        // nonzero generation is not a state the live route can reach. it is
        // planted anyway because the advance has to be prior-relative, and a
        // prior of zero cannot tell that apart from arithmetic that starts there.
        plant_generation(&mut ledger, &entry, PLANTED_GENERATION);
        recover_pending(&entry, &mut ledger, &RunIdentity::observe()).expect("recovery converges");
        let record = committed(&ledger, &entry);
        assert_eq!(record.state, STATE_OWNED);
        assert_eq!(record.applied_by, "new");
        // the same prior the dispatch half carried unchanged, advanced once here.
        assert_eq!(record.applied_operation_generation, PLANTED_GENERATION + 1);
        assert_eq!(record.baseline_hash.as_deref(), Some(intended.as_str()));
        assert_eq!(
            record.intended_witness_hash.as_deref(),
            Some(intended.as_str())
        );
    }

    #[test]
    fn a_completed_repair_advances_the_counter_by_exactly_one() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = plant_destination(&dir, "value", "payload\n");
        let intended = sha256_hex(b"payload\n");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_PENDING,
            "repair",
            WRITABLE_REPRESENTATION,
            &source,
            Some(&sha256_hex(b"older\n")),
            Some(&intended),
            Some(".furnish.test.stage"),
        );
        plant_generation(&mut ledger, &entry, PLANTED_GENERATION);
        recover_pending(&entry, &mut ledger, &RunIdentity::observe()).expect("recovery converges");
        let record = committed(&ledger, &entry);
        assert_eq!(record.state, STATE_OWNED);
        assert_eq!(record.applied_by, "repair");
        assert_eq!(record.applied_operation_generation, PLANTED_GENERATION + 1);
        // the stale baseline the pending record carried is replaced by the
        // witness that landed, not kept alongside it.
        assert_eq!(record.baseline_hash.as_deref(), Some(intended.as_str()));
        assert_eq!(
            record.intended_witness_hash.as_deref(),
            Some(intended.as_str())
        );
    }

    #[test]
    fn a_completed_update_advances_the_counter_by_exactly_one() {
        // one advance half per applied_by the publishing routes can commit, and
        // source-wins publishes through the same route as source-only
        // propagation under the same applied_by, so it needs no second copy of
        // this. what distinguishes the two is the dispatch, which is where they
        // are each proven.
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "second\n");
        let destination = plant_destination(&dir, "value", "second\n");
        let intended = sha256_hex(b"second\n");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_PENDING,
            "update",
            WRITABLE_REPRESENTATION,
            &source,
            Some(&sha256_hex(b"first\n")),
            Some(&intended),
            Some(".furnish.test.stage"),
        );
        plant_generation(&mut ledger, &entry, PLANTED_GENERATION);
        recover_pending(&entry, &mut ledger, &RunIdentity::observe()).expect("recovery converges");
        let record = committed(&ledger, &entry);
        assert_eq!(record.state, STATE_OWNED);
        assert_eq!(record.applied_by, "update");
        assert_eq!(record.applied_operation_generation, PLANTED_GENERATION + 1);
        assert_eq!(record.baseline_hash.as_deref(), Some(intended.as_str()));
        assert_eq!(
            record.intended_witness_hash.as_deref(),
            Some(intended.as_str())
        );
    }

    #[test]
    fn a_settled_destination_publishes_nothing_and_leaves_the_counter_alone() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = plant_destination(&dir, "value", "payload\n");
        let baseline = sha256_hex(b"payload\n");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_OWNED,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            Some(&baseline),
            Some(&baseline),
            None,
        );
        plant_generation(&mut ledger, &entry, PLANTED_GENERATION);
        reconcile_writable_at(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &RunIdentity::observe(),
        )
        .expect("a settled destination reconciles");
        let record = committed(&ledger, &entry);
        // the record is refreshed so that when this was last reconciled has a
        // live answer, and refreshing is not applying.
        assert_eq!(record.state, STATE_OWNED);
        assert_eq!(record.applied_operation_generation, PLANTED_GENERATION);
        assert_eq!(record.baseline_hash.as_deref(), Some(baseline.as_str()));
        assert_eq!(
            record.intended_witness_hash.as_deref(),
            Some(baseline.as_str())
        );
    }

    #[test]
    fn a_runtime_edit_under_an_unchanged_source_is_preserved_and_advances_nothing() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "payload\n");
        let destination = plant_destination(&dir, "value", "user edit\n");
        let baseline = sha256_hex(b"payload\n");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_OWNED,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            Some(&baseline),
            Some(&baseline),
            None,
        );
        plant_generation(&mut ledger, &entry, PLANTED_GENERATION);
        reconcile_writable_at(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &RunIdentity::observe(),
        )
        .expect("an unchanged source preserves the edit");
        assert_eq!(fs::read_to_string(&destination).unwrap(), "user edit\n");
        let record = committed(&ledger, &entry);
        // the baseline still names what furnish wrote, because what furnish wrote
        // is what a later source change will be measured against.
        assert_eq!(record.baseline_hash.as_deref(), Some(baseline.as_str()));
        assert_eq!(record.applied_operation_generation, PLANTED_GENERATION);
    }

    #[test]
    fn runtime_wins_settles_the_conflict_without_publishing_or_advancing() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "declared\n");
        let destination = plant_destination(&dir, "value", "edited\n");
        let intended = sha256_hex(b"declared\n");
        let mut entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        entry.on_conflict = ConflictPolicy::RuntimeWins;
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_OWNED,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            Some(&sha256_hex(b"baseline\n")),
            Some(&sha256_hex(b"baseline\n")),
            None,
        );
        plant_generation(&mut ledger, &entry, PLANTED_GENERATION);
        reconcile_writable_at(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &RunIdentity::observe(),
        )
        .expect("runtime wins settles rather than refusing");
        assert_eq!(fs::read_to_string(&destination).unwrap(), "edited\n");
        let record = committed(&ledger, &entry);
        // the baseline advances to the source that was refused so the same
        // conflict is not rediscovered every run, and nothing was applied, so
        // the counter does not move with it.
        assert_eq!(record.baseline_hash.as_deref(), Some(intended.as_str()));
        assert_eq!(
            record.intended_witness_hash.as_deref(),
            Some(intended.as_str())
        );
        assert_eq!(record.applied_operation_generation, PLANTED_GENERATION);
    }

    #[test]
    fn the_error_policy_refuses_a_two_sided_divergence_and_commits_nothing() {
        let dir = TestDir::new();
        let source = write_source(&dir, "source", "declared\n");
        let destination = plant_destination(&dir, "value", "edited\n");
        let entry = sample_writable_entry(
            dir.path().to_str().unwrap(),
            destination.to_str().unwrap(),
            &source,
        );
        let mut ledger = test_ledger(&dir);
        plant_record(
            &mut ledger,
            &entry,
            STATE_OWNED,
            "new",
            WRITABLE_REPRESENTATION,
            &source,
            Some(&sha256_hex(b"baseline\n")),
            Some(&sha256_hex(b"baseline\n")),
            None,
        );
        plant_generation(&mut ledger, &entry, PLANTED_GENERATION);
        let before = committed(&ledger, &entry);
        let failure = reconcile_writable_at(
            &entry,
            Path::new("/nonexistent/setpriv"),
            0,
            &mut ledger,
            &RunIdentity::observe(),
        )
        .expect_err("the declared policy is to refuse");
        assert!(matches!(failure.key, CodeKey::ConflictingDestination));
        assert_eq!(fs::read_to_string(&destination).unwrap(), "edited\n");
        // an untouched counter is a weaker claim than no commit at all, and no
        // commit at all is what refusing promises, so the whole record is
        // compared. a ledger record is not comparable directly, and its encoded
        // form is the shape the file on disk would have held anyway.
        assert_eq!(
            serde_json::to_value(&before).unwrap(),
            serde_json::to_value(committed(&ledger, &entry)).unwrap()
        );
    }

    #[test]
    fn every_owned_writable_record_holds_a_baseline_equal_to_its_witness() {
        // the walk is filtered to owned records deliberately. a pending record is
        // supposed to carry a baseline that differs from its witness, because the
        // witness names the source that has not landed yet, and the dispatch
        // halves above commit exactly those records on purpose.
        let dir = TestDir::new();
        let mut ledger = test_ledger(&dir);
        let identity = RunIdentity::observe();
        let setpriv = Path::new("/nonexistent/setpriv");

        let settled_source = write_source(&dir, "settled-source", "same\n");
        let settled_destination = plant_destination(&dir, "settled-value", "same\n");
        let settled = sample_writable_entry(
            dir.path().to_str().unwrap(),
            settled_destination.to_str().unwrap(),
            &settled_source,
        );
        plant_record(
            &mut ledger,
            &settled,
            STATE_OWNED,
            "new",
            WRITABLE_REPRESENTATION,
            &settled_source,
            Some(&sha256_hex(b"same\n")),
            Some(&sha256_hex(b"same\n")),
            None,
        );
        reconcile_writable_at(&settled, setpriv, 0, &mut ledger, &identity)
            .expect("the refreshing route settles");

        let stale_source = write_source(&dir, "stale-source", "landed\n");
        let stale_destination = plant_destination(&dir, "stale-value", "landed\n");
        let stale = sample_writable_entry(
            dir.path().to_str().unwrap(),
            stale_destination.to_str().unwrap(),
            &stale_source,
        );
        plant_record(
            &mut ledger,
            &stale,
            STATE_OWNED,
            "update",
            WRITABLE_REPRESENTATION,
            &stale_source,
            Some(&sha256_hex(b"before\n")),
            Some(&sha256_hex(b"before\n")),
            None,
        );
        reconcile_writable_at(&stale, setpriv, 1, &mut ledger, &identity)
            .expect("the advancing route settles");

        let refused_source = write_source(&dir, "refused-source", "declared\n");
        let refused_destination = plant_destination(&dir, "refused-value", "edited\n");
        let mut refused = sample_writable_entry(
            dir.path().to_str().unwrap(),
            refused_destination.to_str().unwrap(),
            &refused_source,
        );
        refused.on_conflict = ConflictPolicy::RuntimeWins;
        plant_record(
            &mut ledger,
            &refused,
            STATE_OWNED,
            "new",
            WRITABLE_REPRESENTATION,
            &refused_source,
            Some(&sha256_hex(b"baseline\n")),
            Some(&sha256_hex(b"baseline\n")),
            None,
        );
        reconcile_writable_at(&refused, setpriv, 2, &mut ledger, &identity)
            .expect("the policy route settles");

        let recovered_source = write_source(&dir, "recovered-source", "recovered\n");
        let recovered_destination = plant_destination(&dir, "recovered-value", "recovered\n");
        let recovered = sample_writable_entry(
            dir.path().to_str().unwrap(),
            recovered_destination.to_str().unwrap(),
            &recovered_source,
        );
        plant_record(
            &mut ledger,
            &recovered,
            STATE_PENDING,
            "update",
            WRITABLE_REPRESENTATION,
            &recovered_source,
            Some(&sha256_hex(b"before\n")),
            Some(&sha256_hex(b"recovered\n")),
            Some(".furnish.test.stage"),
        );
        recover_pending(&recovered, &mut ledger, &identity).expect("the recovery route settles");

        let owned_writable: Vec<LedgerRecord> = ledger
            .recorded()
            .into_iter()
            .map(|(_, record)| record)
            .filter(|record| {
                record.state == STATE_OWNED && record.representation == WRITABLE_REPRESENTATION
            })
            .collect();
        // four routes, four distinct commit paths, and the count is asserted so
        // that a route which silently stopped committing cannot leave this
        // passing over a smaller set than it was written for.
        assert_eq!(owned_writable.len(), 4);
        for record in owned_writable {
            let baseline = record
                .baseline_hash
                .as_deref()
                .expect("an owned writable record names what furnish last wrote");
            assert_eq!(Some(baseline), record.intended_witness_hash.as_deref());
        }
    }

    #[test]
    fn every_owned_symlink_record_holds_no_baseline_and_a_target_witness() {
        let dir = TestDir::new();
        let mut ledger = test_ledger(&dir);
        let target = dir.path().join("target");
        fs::write(&target, b"linked").expect("create link target");

        // written by a reconciliation: the backward transition restatement, which
        // sets the representation and therefore owes the reading that
        // representation fixes.
        let restored_destination = dir.path().join("restored-value");
        symlink(&target, &restored_destination).expect("plant symlink destination");
        let restored = sample_writable_entry(
            dir.path().to_str().unwrap(),
            restored_destination.to_str().unwrap(),
            target.to_str().unwrap(),
        );
        plant_record(
            &mut ledger,
            &restored,
            STATE_PENDING,
            TRANSITION_MARKER,
            WRITABLE_REPRESENTATION,
            target.to_str().unwrap(),
            Some(&sha256_hex(b"linked")),
            Some(&sha256_hex(b"linked")),
            Some(".furnish.test.stage"),
        );
        recover_pending(&restored, &mut ledger, &RunIdentity::observe())
            .expect("the transition converges backward");
        let record = committed(&ledger, &restored);
        assert_eq!(record.representation, NATIVE_REPRESENTATION);
        assert_eq!(
            record.intended_witness_hash.as_deref(),
            Some(sha256_hex(target.to_str().unwrap().as_bytes()).as_str())
        );

        // not written by a reconciliation: a record planted the way the v1
        // migration and RunIdentity::record leave one, with both fields at their
        // defaults.
        let planted_destination = dir.path().join("planted-value");
        let planted = sample_entry(
            dir.path().to_str().unwrap(),
            planted_destination.to_str().unwrap(),
            target.to_str().unwrap(),
        );
        record_ownership(&mut ledger, &planted, target.to_str().unwrap());

        let owned_symlinks: Vec<LedgerRecord> = ledger
            .recorded()
            .into_iter()
            .map(|(_, record)| record)
            .filter(|record| {
                record.state == STATE_OWNED && record.representation == NATIVE_REPRESENTATION
            })
            .collect();
        assert_eq!(owned_symlinks.len(), 2);
        for record in owned_symlinks {
            // a path string is not content at the destination, so a symlink
            // record never carries a baseline under any state.
            assert!(record.baseline_hash.is_none());
            // the absent witness is a carve-out for records no reconciliation
            // wrote, which today means migrated v1 records and records planted
            // before a publish. it is permitted here by name rather than by
            // silence, and it expires when the v1 migration path does.
            if let Some(witness) = record.intended_witness_hash.as_deref() {
                assert_eq!(
                    witness,
                    sha256_hex(record.applied_artifact_target.as_bytes())
                );
            }
        }
    }

    // characterization pins for behaviors no route observes from outside the
    // crate. pure or ledger-only, so they run in the default build and never
    // reach a worker.
    mod characterization_pins {
        use super::*;

        #[test]
        fn sha256_reproduces_block_edge_answers() {
            // 55 bytes is the last single-block length, 64 forces a second
            // block for the padding alone, 119 and 120 put the length word at
            // the two edges of it. pinned to reference digests, because a
            // padding bug here is self-consistent with the function it checks.
            assert_eq!(
                sha256_hex(&[b'a'; 55]),
                "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
            );
            assert_eq!(
                sha256_hex(&[b'a'; 64]),
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
            );
            assert_eq!(
                sha256_hex(&[b'a'; 119]),
                "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb"
            );
            assert_eq!(
                sha256_hex(&[b'a'; 120]),
                "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c"
            );
        }

        // a manifest builder so each refusal below can name exactly the check
        // it pins. entry fields are set before the manifest exists, which is
        // the only order that keeps two failing checks in one manifest.
        fn manifest_with(mut entries: Vec<Entry>, on_conflict: ConflictPolicy) -> Manifest {
            for entry in &mut entries {
                entry.on_conflict = on_conflict;
            }
            Manifest {
                schema_version: MANIFEST_SCHEMA_VERSION,
                diagnostic_contract: DiagnosticContract {
                    schema_version: DIAGNOSTIC_SCHEMA_VERSION,
                    codes: DiagnosticCodes::default(),
                },
                entries,
            }
        }

        #[test]
        fn manifest_schema_outranks_contract_schema() {
            let entry = sample_entry("/managed", "/managed/value", "/desired/target");
            let mut manifest = manifest_with(vec![entry], ConflictPolicy::Error);
            manifest.schema_version = 99;
            manifest.diagnostic_contract.schema_version = 0;
            let failure =
                validate_manifest(&manifest).expect_err("manifest schema is checked first");
            assert_eq!(failure.label, "manifest");
        }

        #[test]
        fn entry_schema_mismatch_is_reported_before_the_executor_tuple() {
            let mut entry = sample_entry("/managed", "/managed/value", "/desired/target");
            entry.schema_version = 99;
            entry.executor.identity = "bogus".to_owned();
            let manifest = manifest_with(vec![entry], ConflictPolicy::Error);
            let failure = validate_manifest(&manifest)
                .expect_err("entry schema is checked before the executor tuple");
            assert_eq!(
                failure.message,
                "entry schema does not match the manifest schema"
            );
        }

        #[test]
        fn an_unsupported_executor_tuple_is_reported_before_the_lifecycle_strategies() {
            let mut entry = sample_entry("/managed", "/managed/value", "/desired/target");
            entry.executor.identity = "bogus".to_owned();
            entry.cleanup_strategy = "bogus".to_owned();
            let manifest = manifest_with(vec![entry], ConflictPolicy::Error);
            let failure = validate_manifest(&manifest)
                .expect_err("the executor tuple is checked before the lifecycle strategies");
            assert_eq!(
                failure.message,
                "unsupported executor tuple (bogus, 1, symlink)"
            );
        }

        #[test]
        fn lifecycle_strategy_mismatch_is_reported_before_the_authority_scope() {
            let mut entry = sample_entry("/managed", "/managed/value", "/desired/target");
            entry.cleanup_strategy = "bogus".to_owned();
            entry.authority.scope = "host".to_owned();
            let manifest = manifest_with(vec![entry], ConflictPolicy::Error);
            let failure = validate_manifest(&manifest)
                .expect_err("the lifecycle strategies are checked before the authority scope");
            assert_eq!(
                failure.message,
                "symlink reconciliation requires exact-symlink-target lifecycle strategies"
            );
        }

        #[test]
        fn authority_scope_is_reported_before_the_canonical_form() {
            let mut entry = sample_entry("/managed", "/managed/value", "/desired/target");
            entry.authority.scope = "host".to_owned();
            entry.filesystem_identity.canonical = "bogus".to_owned();
            let manifest = manifest_with(vec![entry], ConflictPolicy::Error);
            let failure = validate_manifest(&manifest)
                .expect_err("the authority scope is checked before the canonical form");
            assert_eq!(failure.message, "authority scope must be user or system");
        }

        #[test]
        fn the_canonical_form_is_checked_last() {
            let mut entry = sample_entry("/managed", "/managed/value", "/desired/target");
            entry.filesystem_identity.canonical = "bogus".to_owned();
            let manifest = manifest_with(vec![entry], ConflictPolicy::Error);
            let failure = validate_manifest(&manifest)
                .expect_err("a valid entry fails only on the canonical form");
            assert_eq!(failure.message, "filesystem identity is not canonical");
        }

        #[test]
        fn the_first_failing_entry_decides_the_diagnostic() {
            let mut first = sample_entry("/managed", "/managed/first", "/desired/target");
            first.filesystem_identity.canonical = "bogus".to_owned();
            let mut second = sample_entry("/managed", "/managed/second", "/desired/target");
            second.authority.scope = "host".to_owned();
            let manifest = manifest_with(vec![first, second], ConflictPolicy::Error);
            let failure =
                validate_manifest(&manifest).expect_err("the earlier entry fails the manifest");
            assert_eq!(failure.message, "filesystem identity is not canonical");
        }

        #[test]
        fn executor_qualification_table_is_exact() {
            assert_eq!(EXECUTOR_PROFILES.len(), 2);
            for profile in EXECUTOR_PROFILES.iter() {
                assert!(
                    profile_for(
                        profile.identity,
                        profile.protocol_version,
                        profile.representation
                    )
                    .is_some()
                );
            }
            assert!(profile_for(NATIVE_EXECUTOR_IDENTITY, 2, NATIVE_REPRESENTATION).is_none());
            assert!(profile_for(NATIVE_WRITABLE_IDENTITY, 1, NATIVE_REPRESENTATION).is_none());
            assert!(profile_for("bogus", 1, NATIVE_REPRESENTATION).is_none());
        }

        #[test]
        fn transition_gate_table_is_exact() {
            assert_eq!(TRANSITION_PAIRS.len(), 2);
            assert!(transition_is_gated(
                NATIVE_REPRESENTATION,
                WRITABLE_REPRESENTATION
            ));
            assert!(transition_is_gated(
                WRITABLE_REPRESENTATION,
                NATIVE_REPRESENTATION
            ));
            assert!(!transition_is_gated(
                NATIVE_REPRESENTATION,
                NATIVE_REPRESENTATION
            ));
            assert!(!transition_is_gated(
                WRITABLE_REPRESENTATION,
                WRITABLE_REPRESENTATION
            ));
        }

        #[test]
        fn transition_source_lookup_is_exact() {
            assert_eq!(
                transition_source_of(WRITABLE_REPRESENTATION),
                Some(NATIVE_REPRESENTATION)
            );
            assert_eq!(
                transition_source_of(NATIVE_REPRESENTATION),
                Some(WRITABLE_REPRESENTATION)
            );
            assert_eq!(transition_source_of("bogus"), None);
        }

        #[test]
        fn kind_to_representation_lookup_is_exact() {
            assert_eq!(
                representation_of_kind(SYMLINK_MODE),
                Some(NATIVE_REPRESENTATION)
            );
            assert_eq!(
                representation_of_kind(REGULAR_MODE),
                Some(WRITABLE_REPRESENTATION)
            );
            assert_eq!(representation_of_kind(0o040000), None);
        }

        #[test]
        fn pending_record_carries_the_prior_applied_state_forward_unchanged() {
            let identity = RunIdentity::observe();
            let entry = sample_entry("/managed", "/managed/value", "/desired/target");
            let mut prior = identity.record(&entry, "new");
            prior.baseline_hash = Some("a".repeat(64));
            prior.applied_operation_generation = 5;
            let pending = pending_record(
                &identity,
                &entry,
                TRANSITION_MARKER,
                Some(&prior),
                OsStr::new(".furnish.9.stage"),
                "b".repeat(64).as_str(),
            );
            assert_eq!(pending.state, STATE_PENDING);
            assert_eq!(pending.applied_by, TRANSITION_MARKER);
            assert_eq!(pending.stage_name.as_deref(), Some(".furnish.9.stage"));
            assert_eq!(
                pending.intended_witness_hash.as_deref(),
                Some("b".repeat(64).as_str())
            );
            assert_eq!(pending.baseline_hash, prior.baseline_hash);
            assert_eq!(pending.applied_operation_generation, 5);
        }

        #[test]
        fn owned_record_advances_the_generation_and_sets_the_baseline_by_representation() {
            let identity = RunIdentity::observe();
            let entry = sample_writable_entry("/managed", "/managed/value", "/tmp/source");
            let mut prior = identity.record(&entry, "new");
            prior.applied_operation_generation = 4;
            let owned = owned_record(
                &identity,
                &entry,
                "update",
                Some(&prior),
                "c".repeat(64).as_str(),
            );
            assert_eq!(owned.state, STATE_OWNED);
            assert_eq!(owned.applied_operation_generation, 5);
            assert_eq!(
                owned.baseline_hash.as_deref(),
                Some("c".repeat(64).as_str())
            );
        }

        #[test]
        fn owned_record_saturates_at_the_generation_ceiling() {
            let identity = RunIdentity::observe();
            let entry = sample_entry("/managed", "/managed/value", "/desired/target");
            let mut prior = identity.record(&entry, "new");
            prior.applied_operation_generation = u64::MAX;
            let owned = owned_record(
                &identity,
                &entry,
                "update",
                Some(&prior),
                "d".repeat(64).as_str(),
            );
            assert_eq!(owned.applied_operation_generation, u64::MAX);
        }

        #[test]
        fn baseline_for_is_a_writable_only_reading() {
            assert_eq!(
                baseline_for(WRITABLE_REPRESENTATION, "e".repeat(64).as_str()),
                Some("e".repeat(64))
            );
            assert_eq!(
                baseline_for(NATIVE_REPRESENTATION, "e".repeat(64).as_str()),
                None
            );
        }

        #[test]
        fn conflict_policy_uses_kebab_case_wire_names_and_refuses_absence() {
            // an entry written before onConflict existed must fail to
            // deserialize rather than reconcile under a guessed policy.
            let entry_json = |policy: &str| {
                format!(
                    "{{\"schemaVersion\":2,\"filesystemIdentity\":{{\"namespace\":\"test\",\"destination\":\"/managed/value\",\"canonical\":\"test:/managed/value\"}},\"authority\":{{\"scope\":\"system\",\"identity\":\"test/system\"}},\"managedRoot\":\"/managed\",{policy}\"representation\":\"symlink\",\"retainedArtifactTarget\":\"/desired/target\",\"executor\":{{\"identity\":\"furnish/native-symlink\",\"protocolVersion\":1}},\"cleanupStrategy\":\"exact-symlink-target\",\"selfHealStrategy\":\"exact-symlink-target\",\"provenance\":{{\"declaration\":\"unit-test\",\"source\":\"coordinator/src/main.rs\"}}}}"
                )
            };
            let entry: Entry = serde_json::from_str(&entry_json("\"onConflict\":\"error\","))
                .expect("error parses");
            assert!(matches!(entry.on_conflict, ConflictPolicy::Error));
            let entry: Entry = serde_json::from_str(&entry_json("\"onConflict\":\"source-wins\","))
                .expect("source-wins parses");
            assert!(matches!(entry.on_conflict, ConflictPolicy::SourceWins));
            let entry: Entry =
                serde_json::from_str(&entry_json("\"onConflict\":\"runtime-wins\","))
                    .expect("runtime-wins parses");
            assert!(matches!(entry.on_conflict, ConflictPolicy::RuntimeWins));
            assert!(
                serde_json::from_str::<Entry>(&entry_json("\"onConflict\":\"sourceWins\","))
                    .is_err()
            );
            assert!(serde_json::from_str::<Entry>(&entry_json("")).is_err());
        }

        #[test]
        fn diagnostic_serialization_omits_only_observed_and_nulls_other_absent_parts() {
            let codes = DiagnosticCodes::default();
            let plain = Failure::new(CodeKey::InvalidManifest, "label", "message");
            let encoded = serialize_diagnostic(&codes, &plain, None, "error").expect("serialize");
            let diagnostic: serde_json::Value = serde_json::from_str(&encoded).expect("decode");
            assert!(diagnostic.get("provenance").is_some());
            assert!(diagnostic["provenance"].is_null());
            assert!(diagnostic.get("cause").is_some());
            assert!(diagnostic["cause"].is_null());
            assert!(diagnostic.get("observed").is_none());
            let conflict = Failure::conflict(
                "label",
                None,
                "s".repeat(64).as_str(),
                "d".repeat(64).as_str(),
            );
            let encoded =
                serialize_diagnostic(&codes, &conflict, None, "error").expect("serialize");
            let diagnostic: serde_json::Value = serde_json::from_str(&encoded).expect("decode");
            assert!(diagnostic["observed"].get("baseline").is_some());
            assert!(diagnostic["observed"]["baseline"].is_null());
        }
    }

    // ledger characterization: the encoded bytes are pinned exactly where
    // every stamp can be fixed, and the load-time behavior is pinned as it
    // actually behaves rather than as the error arms read.
    mod ledger_pins {
        use super::*;

        fn state_with(dir: &TestDir, bytes: Option<&str>) -> PathBuf {
            let state = dir.path().join("state");
            fs::create_dir_all(&state).expect("create state directory");
            if let Some(bytes) = bytes {
                fs::write(state.join(LEDGER_FILE_NAME), bytes).expect("plant ledger bytes");
            }
            state
        }

        #[test]
        fn load_refuses_undecodable_applied_state() {
            let dir = TestDir::new();
            let state = state_with(&dir, Some("not json"));
            let failure = LedgerState::load(&state).expect_err("undecodable state is refused");
            assert!(matches!(failure.key, CodeKey::LedgerInvalid));
            assert!(failure.message.starts_with("cannot decode applied state"));
        }

        #[test]
        fn load_refuses_applied_state_without_a_schema_version() {
            let dir = TestDir::new();
            let state = state_with(&dir, Some("{\"records\":{}}"));
            let failure = LedgerState::load(&state).expect_err("a missing version is refused");
            assert!(matches!(failure.key, CodeKey::LedgerInvalid));
            // the version probe parses strictly, so the refusal arrives through
            // the decode path and the dedicated no-version arm is never reached.
            assert!(failure.message.starts_with("cannot decode applied state"));
        }

        #[test]
        fn load_normalizes_the_state_directory_mode_to_0755() {
            let dir = TestDir::new();
            let state = state_with(&dir, None);
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
                .expect("set a narrower state mode");
            LedgerState::load(&state).expect("load repairs the mode");
            let mode = fs::metadata(&state)
                .expect("stat state directory")
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(mode, 0o755);
        }

        #[test]
        fn an_empty_record_serializes_every_v2_field_with_null_defaults() {
            let identity = RunIdentity {
                invocation_id: None,
                monotonic_seconds: 0.0,
                boot_id: None,
                system_generation: None,
            };
            let entry = sample_entry("/managed", "/managed/value", "/desired/target");
            let record = identity.record(&entry, "new");
            let encoded = serde_json::to_value(&record).expect("encode record");
            assert_eq!(encoded["appliedGeneration"], serde_json::Value::Null);
            assert_eq!(encoded["reloadActionIdentity"], serde_json::Value::Null);
            assert_eq!(encoded["bootId"], serde_json::Value::Null);
            assert_eq!(encoded["baselineHash"], serde_json::Value::Null);
            assert_eq!(encoded["intendedWitnessHash"], serde_json::Value::Null);
            assert_eq!(encoded["stageName"], serde_json::Value::Null);
            assert_eq!(encoded["unresolvedRetirement"], serde_json::Value::Null);
            assert_eq!(encoded["state"], "owned");
            assert_eq!(encoded["representation"], "symlink");
            assert_eq!(encoded["appliedOperationGeneration"], 0);
        }

        #[test]
        fn the_ledger_write_produces_exact_bytes() {
            // every stamp that varies from run to run is fixed here, so the
            // file is pinned byte for byte: schema first, records second,
            // canonical keys sorted, record fields in declaration order, nulls
            // emitted rather than omitted.
            let dir = TestDir::new();
            let state = state_with(&dir, None);
            let mut ledger = LedgerState::load(&state).expect("load empty state");
            let record = LedgerRecord {
                destination: "/managed/value".to_owned(),
                applied_artifact_target: "/nix/store/target".to_owned(),
                managed_root: "/managed".to_owned(),
                applied_by: "new".to_owned(),
                applied_generation: None,
                last_successful_reload: ReloadEvidence {
                    invocation_id: None,
                    monotonic_seconds: 0.0,
                },
                reload_action_identity: None,
                boot_id: None,
                state: STATE_OWNED.to_owned(),
                representation: WRITABLE_REPRESENTATION.to_owned(),
                // Opaque serialization token, not a claimed content digest;
                // production writes it unchanged into both JSON fields.
                baseline_hash: Some("a".repeat(64)),
                intended_witness_hash: Some("a".repeat(64)),
                applied_operation_generation: 0,
                stage_name: None,
                unresolved_retirement: None,
            };
            ledger
                .commit("test:/managed/value", record)
                .expect("commit");
            let bytes = fs::read(state.join(LEDGER_FILE_NAME)).expect("read ledger file");
            let expected = "{\"schemaVersion\":2,\"records\":{\"test:/managed/value\":{\"destination\":\"/managed/value\",\"appliedArtifactTarget\":\"/nix/store/target\",\"managedRoot\":\"/managed\",\"appliedBy\":\"new\",\"appliedGeneration\":null,\"lastSuccessfulReload\":{\"invocationId\":null,\"monotonicSeconds\":0.0},\"reloadActionIdentity\":null,\"bootId\":null,\"state\":\"owned\",\"representation\":\"writable\",\"baselineHash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"intendedWitnessHash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"appliedOperationGeneration\":0,\"stageName\":null,\"unresolvedRetirement\":null}}}";
            assert_eq!(String::from_utf8(bytes).expect("utf8"), expected);
        }

        #[test]
        fn run_identity_links_every_record_to_the_current_system_generation() {
            let identity = RunIdentity::observe();
            let entry = sample_entry("/managed", "/managed/value", "/desired/target");
            let record = identity.record(&entry, "new");
            let expected = fs::read_link("/run/current-system")
                .ok()
                .map(|path| path.to_string_lossy().into_owned());
            assert_eq!(record.applied_generation, expected);
        }

        #[test]
        fn a_migrated_v1_record_carries_no_witness() {
            let dir = TestDir::new();
            let original = concat!(
                "{\"schemaVersion\":1,\"records\":{\"test:/tmp/value\":{",
                "\"destination\":\"/tmp/value\",",
                "\"appliedArtifactTarget\":\"/nix/store/example\",",
                "\"managedRoot\":\"/tmp\",\"appliedBy\":\"new\",",
                "\"appliedGeneration\":null,",
                "\"lastSuccessfulReload\":{\"invocationId\":null,\"monotonicSeconds\":0.0},",
                "\"reloadActionIdentity\":null,\"bootId\":null}}}"
            );
            let state = state_with(&dir, Some(original));
            let ledger = LedgerState::load(&state).expect("v1 migrates");
            let record = ledger.record("test:/tmp/value").expect("migrated record");
            // the v1 writer had no witness to carry, so the field deserializes
            // to its default and stays absent until a reconciliation writes one.
            assert!(record.intended_witness_hash.is_none());
        }

        #[test]
        fn a_record_planted_before_any_publish_carries_no_witness() {
            let dir = TestDir::new();
            let mut ledger = test_ledger(&dir);
            let target = dir.path().join("target");
            fs::write(&target, b"linked").expect("create link target");
            let entry = sample_entry(
                dir.path().to_str().unwrap(),
                dir.path().join("value").to_str().unwrap(),
                target.to_str().unwrap(),
            );
            record_ownership(&mut ledger, &entry, target.to_str().unwrap());
            let record = committed(&ledger, &entry);
            assert!(record.intended_witness_hash.is_none());
            assert!(record.baseline_hash.is_none());
        }
    }

    // publish_exchange verifies both sides after the rename: the destination
    // must hold the expected link and the stage must hold the recorded one.
    // the crash rows downstream turn on exactly this, so each refusal gets
    // its own pin here.
    mod publish_mechanics_pins {
        use super::*;

        #[test]
        fn an_exchange_refuses_to_displace_other_than_the_recorded_target() {
            let dir = TestDir::new();
            let (parent, name) = dir.entry_parent("value");
            fs::write(dir.path().join("stage"), b"staged").expect("plant stage");
            let recorded = dir.path().join("recorded-target");
            let failure = publish_exchange(
                &parent,
                &name,
                OsStr::new("stage"),
                "/dest",
                OsStr::new("/expected"),
                recorded.as_os_str(),
            )
            .expect_err("a nameless destination cannot be exchanged");
            assert!(matches!(failure.key, CodeKey::PublishRace));
            assert_eq!(failure.operation, Some("renameat2-exchange-publish"));
            assert_eq!(failure.errno, Some(Errno::NOENT.raw_os_error()));
            // a failed exchange removes the unpublished stage and orphans
            // nothing; only a landed exchange followed by a crash can leave
            // the displaced link behind forever (defect candidate [D]).
            assert!(!dir.path().join("stage").exists());
        }

        #[test]
        fn an_exchange_requires_the_displaced_object_to_equal_the_recorded_target() {
            let dir = TestDir::new();
            let (parent, name) = dir.entry_parent("value");
            let recorded = dir.path().join("recorded-target");
            symlink(&recorded, dir.path().join("value")).expect("plant recorded destination");
            let expected = dir.path().join("expected-target");
            symlink(&expected, dir.path().join("stage")).expect("plant staged link");
            let failure = publish_exchange(
                &parent,
                &name,
                OsStr::new("stage"),
                "/dest",
                expected.as_os_str(),
                OsStr::new("/somewhere/else"),
            )
            .expect_err("the displaced link must equal the recorded target");
            assert!(matches!(failure.key, CodeKey::RepairVerification));
            // both sides were exchanged and the verification refused after, so
            // the destination now holds the staged link.
            assert_eq!(fs::read_link(dir.path().join("value")).unwrap(), expected);
        }

        #[test]
        fn an_exchange_requires_the_published_side_to_equal_the_expected_target() {
            let dir = TestDir::new();
            let (parent, name) = dir.entry_parent("value");
            let recorded = dir.path().join("recorded-target");
            symlink(&recorded, dir.path().join("value")).expect("plant recorded destination");
            let staged = dir.path().join("staged-target");
            symlink(&staged, dir.path().join("stage")).expect("plant staged link");
            let failure = publish_exchange(
                &parent,
                &name,
                OsStr::new("stage"),
                "/dest",
                OsStr::new("/expected-elsewhere"),
                recorded.as_os_str(),
            )
            .expect_err("the published link must equal the expected target");
            assert!(matches!(failure.key, CodeKey::RepairVerification));
            // the exchange happened before the refusal, so the recorded link
            // now sits at the stage name.
            assert_eq!(fs::read_link(dir.path().join("stage")).unwrap(), recorded);
        }
    }

    // a backward restatement owes the witness reading of the representation it
    // restates, and a record that cannot produce that reading is refused
    // rather than reinterpreted.
    mod transition_pins {
        use super::*;

        #[test]
        fn a_writable_backward_restatement_requires_a_recorded_baseline() {
            let dir = TestDir::new();
            fs::write(dir.path().join("value"), b"writable bytes\n")
                .expect("plant writable destination");
            let entry = sample_entry(
                dir.path().to_str().unwrap(),
                dir.path().join("value").to_str().unwrap(),
                "/nix/store/target",
            );
            let mut ledger = test_ledger(&dir);
            plant_record(
                &mut ledger,
                &entry,
                STATE_PENDING,
                TRANSITION_MARKER,
                NATIVE_REPRESENTATION,
                "/nix/store/target",
                None,
                Some(&sha256_hex("/nix/store/target".as_bytes())),
                Some(".furnish.test.stage"),
            );
            let failure = recover_pending(&entry, &mut ledger, &RunIdentity::observe())
                .expect_err("restating writable without a baseline is refused");
            assert!(matches!(failure.key, CodeKey::TransitionRefused));
            assert_eq!(
                failure.message,
                "refusing to restate a writable destination with no recorded baseline"
            );
            assert_eq!(committed(&ledger, &entry).state, STATE_PENDING);
        }

        #[test]
        fn an_ungated_pending_representation_is_refused() {
            let dir = TestDir::new();
            let entry = sample_entry(
                dir.path().to_str().unwrap(),
                dir.path().join("value").to_str().unwrap(),
                "/nix/store/target",
            );
            let mut ledger = test_ledger(&dir);
            plant_record(
                &mut ledger,
                &entry,
                STATE_PENDING,
                TRANSITION_MARKER,
                "bogus",
                "/nix/store/target",
                None,
                None,
                Some(".furnish.test.stage"),
            );
            let failure = recover_pending(&entry, &mut ledger, &RunIdentity::observe())
                .expect_err("an ungated representation is refused");
            assert!(matches!(failure.key, CodeKey::TransitionRefused));
            assert_eq!(
                failure.message,
                "pending transition names a representation pair that is not gated"
            );
            assert_eq!(committed(&ledger, &entry).state, STATE_PENDING);
        }

        #[test]
        fn a_pending_transition_without_a_stage_name_is_refused() {
            let dir = TestDir::new();
            let entry = sample_entry(
                dir.path().to_str().unwrap(),
                dir.path().join("value").to_str().unwrap(),
                "/nix/store/target",
            );
            let mut ledger = test_ledger(&dir);
            plant_record(
                &mut ledger,
                &entry,
                STATE_PENDING,
                TRANSITION_MARKER,
                NATIVE_REPRESENTATION,
                "/nix/store/target",
                None,
                Some(&sha256_hex("/nix/store/target".as_bytes())),
                None,
            );
            let failure = recover_pending(&entry, &mut ledger, &RunIdentity::observe())
                .expect_err("a stageless transition record is refused");
            assert!(matches!(failure.key, CodeKey::TransitionRefused));
            assert_eq!(
                failure.message,
                "pending transition record carries no staging name"
            );
            assert_eq!(committed(&ledger, &entry).state, STATE_PENDING);
        }
    }

    // the recovery and update halves the required crash rows turn on, driven
    // against planted state the way the rest of the suite drives them.
    mod recovery_pins {
        use super::*;

        #[test]
        fn recovery_restamps_a_completed_publish_with_a_prior_record() {
            let dir = TestDir::new();
            let source = write_source(&dir, "source", "payload\n");
            let destination = plant_destination(&dir, "value", "payload\n");
            let intended = sha256_hex(b"payload\n");
            let entry = sample_writable_entry(
                dir.path().to_str().unwrap(),
                destination.to_str().unwrap(),
                &source,
            );
            let mut ledger = test_ledger(&dir);
            plant_record(
                &mut ledger,
                &entry,
                STATE_PENDING,
                "update",
                WRITABLE_REPRESENTATION,
                &source,
                Some(&sha256_hex(b"older\n")),
                Some(&intended),
                Some(".furnish.test.stage"),
            );
            plant_generation(&mut ledger, &entry, PLANTED_GENERATION);
            recover_pending(&entry, &mut ledger, &RunIdentity::observe())
                .expect("recovery converges");
            let record = committed(&ledger, &entry);
            assert_eq!(record.state, STATE_OWNED);
            assert_eq!(record.applied_by, "update");
            assert_eq!(record.applied_operation_generation, PLANTED_GENERATION + 1);
            assert_eq!(record.baseline_hash.as_deref(), Some(intended.as_str()));
            assert!(record.stage_name.is_none());
            // the reload evidence and the generation stamp describe the run
            // that committed the recovery, not the run that wrote the pending.
            assert!(record.last_successful_reload.monotonic_seconds > 0.0);
            let generation = fs::read_link("/run/current-system")
                .ok()
                .map(|path| path.to_string_lossy().into_owned());
            assert_eq!(record.applied_generation, generation);
        }

        #[test]
        fn a_stale_pending_record_converges_and_is_carried_forward_by_the_same_run() {
            let dir = TestDir::new();
            let source = write_source(&dir, "source", "new payload\n");
            let destination = plant_destination(&dir, "value", "old payload\n");
            let old_intended = sha256_hex(b"old payload\n");
            let mut entry = sample_writable_entry(
                dir.path().to_str().unwrap(),
                destination.to_str().unwrap(),
                &source,
            );
            entry.authority.scope = "user".to_owned();
            let mut ledger = test_ledger(&dir);
            plant_record(
                &mut ledger,
                &entry,
                STATE_PENDING,
                "new",
                WRITABLE_REPRESENTATION,
                &source,
                None,
                Some(&old_intended),
                Some(".furnish.test.stage"),
            );
            plant_generation(&mut ledger, &entry, PLANTED_GENERATION);
            let failure = reconcile_entry(
                &entry,
                Path::new("/nonexistent/setpriv"),
                0,
                &mut ledger,
                &RunIdentity::observe(),
            )
            .expect_err("staging cannot run inside the test process");
            assert!(matches!(failure.key, CodeKey::ExecutorFailed));
            let record = committed(&ledger, &entry);
            // recovery and reconciliation are two recorded steps: the recovery
            // landed owned at the old source, and the ordinary path is now
            // pending an update toward the current one.
            assert_eq!(record.state, STATE_PENDING);
            assert_eq!(record.applied_by, "update");
            assert_eq!(
                record.intended_witness_hash.as_deref(),
                Some(sha256_hex(b"new payload\n").as_str())
            );
            assert_eq!(record.baseline_hash.as_deref(), Some(old_intended.as_str()));
            assert_eq!(record.applied_operation_generation, PLANTED_GENERATION + 1);
            assert_eq!(fs::read_to_string(&destination).unwrap(), "old payload\n");
        }

        #[test]
        fn an_update_death_before_publication_retires_the_pending_record_and_keeps_the_bytes() {
            let dir = TestDir::new();
            let source = write_source(&dir, "source", "new payload\n");
            let destination = plant_destination(&dir, "value", "old payload\n");
            let entry = sample_writable_entry(
                dir.path().to_str().unwrap(),
                destination.to_str().unwrap(),
                &source,
            );
            let mut ledger = test_ledger(&dir);
            plant_record(
                &mut ledger,
                &entry,
                STATE_PENDING,
                "update",
                WRITABLE_REPRESENTATION,
                &source,
                Some(&sha256_hex(b"old payload\n")),
                Some(&sha256_hex(b"new payload\n")),
                Some(".furnish.test.stage"),
            );
            recover_pending(&entry, &mut ledger, &RunIdentity::observe())
                .expect("recovery converges");
            // the destination was not authored by the pending record, so the
            // record is cleared and the bytes are left exactly as found.
            assert!(
                ledger
                    .record(&entry.filesystem_identity.canonical)
                    .is_none()
            );
            assert_eq!(fs::read_to_string(&destination).unwrap(), "old payload\n");
        }
    }

    // the writable rows whose route choice is the behavior: the ordinary
    // update that never consults the policy, and the two refusals that fire
    // before any policy could matter.
    mod update_route_pins {
        use super::*;

        #[test]
        fn an_ordinary_update_publishes_without_consulting_the_conflict_policy() {
            // the destination is still exactly the baseline and only the
            // source moved, so the policy is never read. setting it to error
            // is what proves that: the route still publishes.
            let dir = TestDir::new();
            let source = write_source(&dir, "source", "second\n");
            let destination = plant_destination(&dir, "value", "first\n");
            let baseline = sha256_hex(b"first\n");
            let mut entry = sample_writable_entry(
                dir.path().to_str().unwrap(),
                destination.to_str().unwrap(),
                &source,
            );
            entry.on_conflict = ConflictPolicy::Error;
            entry.authority.scope = "user".to_owned();
            let mut ledger = test_ledger(&dir);
            plant_record(
                &mut ledger,
                &entry,
                STATE_OWNED,
                "new",
                WRITABLE_REPRESENTATION,
                &source,
                Some(&baseline),
                Some(&baseline),
                None,
            );
            let failure = reconcile_writable_at(
                &entry,
                Path::new("/nonexistent/setpriv"),
                0,
                &mut ledger,
                &RunIdentity::observe(),
            )
            .expect_err("staging cannot run inside the test process");
            assert!(matches!(failure.key, CodeKey::ExecutorFailed));
            let record = committed(&ledger, &entry);
            assert_eq!(record.state, STATE_PENDING);
            assert_eq!(record.applied_by, "update");
            assert_eq!(
                record.intended_witness_hash.as_deref(),
                Some(sha256_hex(b"second\n").as_str())
            );
            assert_eq!(record.baseline_hash.as_deref(), Some(baseline.as_str()));
            assert_eq!(fs::read_to_string(&destination).unwrap(), "first\n");
        }

        #[test]
        fn a_writable_destination_without_a_recorded_baseline_is_refused_under_every_policy() {
            let dir = TestDir::new();
            let source = write_source(&dir, "source", "declared\n");
            let destination = plant_destination(&dir, "value", "bytes\n");
            let mut entry = sample_writable_entry(
                dir.path().to_str().unwrap(),
                destination.to_str().unwrap(),
                &source,
            );
            entry.on_conflict = ConflictPolicy::SourceWins;
            let mut ledger = test_ledger(&dir);
            plant_record(
                &mut ledger,
                &entry,
                STATE_OWNED,
                "new",
                WRITABLE_REPRESENTATION,
                &source,
                None,
                None,
                None,
            );
            let failure = reconcile_writable_at(
                &entry,
                Path::new("/nonexistent/setpriv"),
                0,
                &mut ledger,
                &RunIdentity::observe(),
            )
            .expect_err("a missing baseline refuses whichever policy is declared");
            assert!(matches!(failure.key, CodeKey::ConflictingDestination));
            assert_eq!(
                failure.message,
                "refusing to reconcile a writable destination with no recorded baseline"
            );
            assert_eq!(fs::read_to_string(&destination).unwrap(), "bytes\n");
        }

        #[test]
        fn a_destination_that_is_not_a_regular_file_is_refused_before_any_hashing() {
            let dir = TestDir::new();
            let source = write_source(&dir, "source", "payload\n");
            let target = dir.path().join("target");
            fs::write(&target, b"live").expect("create link target");
            let destination = dir.path().join("value");
            symlink(&target, &destination).expect("plant symlink at the destination");
            let entry = sample_writable_entry(
                dir.path().to_str().unwrap(),
                destination.to_str().unwrap(),
                &source,
            );
            let mut ledger = test_ledger(&dir);
            let baseline = sha256_hex(b"payload\n");
            plant_record(
                &mut ledger,
                &entry,
                STATE_OWNED,
                "new",
                WRITABLE_REPRESENTATION,
                &source,
                Some(&baseline),
                Some(&baseline),
                None,
            );
            let failure = reconcile_writable_at(
                &entry,
                Path::new("/nonexistent/setpriv"),
                0,
                &mut ledger,
                &RunIdentity::observe(),
            )
            .expect_err("a non-regular destination is refused");
            assert!(matches!(failure.key, CodeKey::ConflictingDestination));
            assert_eq!(
                failure.message,
                "refusing a destination that is not a regular file"
            );
            assert_eq!(fs::read_link(&destination).unwrap(), target);
        }
    }

    // the crash boundaries the binary fault rows reproduce with real process
    // deaths, planted here directly so the convergence is pinned even where
    // no fault point exists.
    mod crash_boundary_pins {
        use super::*;

        #[test]
        fn an_update_death_with_edited_displaced_bytes_restores_and_refuses() {
            let dir = TestDir::new();
            let source = write_source(&dir, "source", "new payload\n");
            let destination = plant_destination(&dir, "value", "new payload\n");
            let stage = ".furnish.test.stage";
            fs::write(dir.path().join(stage), "the user edited this\n")
                .expect("plant edited displaced file");
            let entry = sample_writable_entry(
                dir.path().to_str().unwrap(),
                destination.to_str().unwrap(),
                &source,
            );
            let mut ledger = test_ledger(&dir);
            plant_record(
                &mut ledger,
                &entry,
                STATE_PENDING,
                "update",
                WRITABLE_REPRESENTATION,
                &source,
                Some(&sha256_hex(b"old payload\n")),
                Some(&sha256_hex(b"new payload\n")),
                Some(stage),
            );
            let failure = recover_pending(&entry, &mut ledger, &RunIdentity::observe())
                .expect_err("edited displaced bytes reverse the exchange");
            assert!(matches!(failure.key, CodeKey::PendingRecovery));
            // the edited bytes are back at the destination and the published
            // content, which is furnish's own, is removed with the stage.
            assert_eq!(
                fs::read_to_string(&destination).unwrap(),
                "the user edited this\n"
            );
            assert!(!dir.path().join(stage).exists());
            let record = committed(&ledger, &entry);
            assert_eq!(record.state, STATE_OWNED);
            assert_eq!(
                record.baseline_hash.as_deref(),
                Some(sha256_hex(b"old payload\n").as_str())
            );
            assert_eq!(
                record.intended_witness_hash.as_deref(),
                Some(sha256_hex(b"old payload\n").as_str())
            );
        }

        #[test]
        fn a_retired_pending_record_turns_ownership_into_a_conflict() {
            // the full arc of a writable update death before publication:
            // recovery retires the unauthored pending record, and the same
            // run's ordinary path then sees an occupied destination with no
            // record and refuses to adopt it.
            let dir = TestDir::new();
            let source = write_source(&dir, "source", "new payload\n");
            let destination = plant_destination(&dir, "value", "old payload\n");
            let mut entry = sample_writable_entry(
                dir.path().to_str().unwrap(),
                destination.to_str().unwrap(),
                &source,
            );
            entry.authority.scope = "user".to_owned();
            let mut ledger = test_ledger(&dir);
            plant_record(
                &mut ledger,
                &entry,
                STATE_PENDING,
                "update",
                WRITABLE_REPRESENTATION,
                &source,
                Some(&sha256_hex(b"old payload\n")),
                Some(&sha256_hex(b"new payload\n")),
                Some(".furnish.test.stage"),
            );
            let failure = reconcile_entry(
                &entry,
                Path::new("/nonexistent/setpriv"),
                0,
                &mut ledger,
                &RunIdentity::observe(),
            )
            .expect_err("a retired pending record leaves no ownership to publish over");
            assert!(matches!(failure.key, CodeKey::ConflictingDestination));
            assert!(
                ledger
                    .record(&entry.filesystem_identity.canonical)
                    .is_none()
            );
            assert_eq!(fs::read_to_string(&destination).unwrap(), "old payload\n");
        }

        #[test]
        fn a_landed_exchange_converges_as_a_steady_state_and_restamps_the_record() {
            // the owned-symlink death that no fault point can reach: the
            // exchange has landed, the ledger still records the old target,
            // and the next ordinary run sees a destination equal to the
            // declaration, so it takes the steady-state branch and refreshes
            // the record rather than refusing. nothing was ever pending, so
            // the displaced link at the stage name is nobody's to clean.
            let dir = TestDir::new();
            let recorded_target = dir.path().join("recorded-target");
            fs::write(&recorded_target, b"live").expect("create recorded target");
            let desired_target = dir.path().join("desired-target");
            fs::write(&desired_target, b"desired").expect("create desired target");
            let destination = dir.path().join("value");
            symlink(&desired_target, &destination).expect("plant exchanged destination");
            let orphan = dir.path().join(".furnish.9999.0.stage");
            symlink(&recorded_target, &orphan).expect("plant orphaned displaced link");
            let entry = sample_entry(
                dir.path().to_str().unwrap(),
                destination.to_str().unwrap(),
                desired_target.to_str().unwrap(),
            );
            let mut ledger = test_ledger(&dir);
            record_ownership(&mut ledger, &entry, recorded_target.to_str().unwrap());
            reconcile_entry(
                &entry,
                Path::new("/nonexistent/setpriv"),
                0,
                &mut ledger,
                &RunIdentity::observe(),
            )
            .expect("a destination equal to the declaration is a steady state");
            assert_eq!(fs::read_link(&destination).unwrap(), desired_target);
            let record = committed(&ledger, &entry);
            // the record now names the target the crashed run published, while
            // still crediting the branch the prior record carried.
            assert_eq!(
                record.applied_artifact_target,
                desired_target.to_str().unwrap()
            );
            assert_eq!(record.applied_by, "new");
            assert_eq!(record.state, STATE_OWNED);
            assert!(fs::symlink_metadata(&orphan).is_ok());
        }

        #[test]
        fn a_mismatched_displaced_hash_reverses_the_exchange() {
            // the displaced bytes are re-hashed after the exchange and a
            // mismatch reverses it, returning both sides to their pre-exchange
            // state before the race is reported. the reverse's own result is
            // discarded, so only the successful reverse is observable here.
            let dir = TestDir::new();
            let (parent, name) = dir.entry_parent("value");
            fs::write(dir.path().join("value"), "original\n").expect("plant destination");
            fs::write(dir.path().join("stage"), "staged\n").expect("plant stage");
            let failure = publish_writable_exchange(
                &parent,
                &name,
                OsStr::new("stage"),
                "/dest",
                sha256_hex(b"different\n").as_str(),
                sha256_hex(b"staged\n").as_str(),
            )
            .expect_err("a displaced mismatch reverses the exchange");
            assert!(matches!(failure.key, CodeKey::PublishRace));
            assert_eq!(
                failure.message,
                "destination changed between observation and publication; exchange reversed"
            );
            assert_eq!(fs::read(dir.path().join("value")).unwrap(), b"original\n");
            assert!(!dir.path().join("stage").exists());
        }
    }
}
