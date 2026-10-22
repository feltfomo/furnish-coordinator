use crate::manifest::{DiagnosticCodes, Provenance};
use rustix::io::Errno;
use serde::Serialize;
use std::io;

pub(crate) const DIAGNOSTIC_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapDiagnostic<'a> {
    schema_version: u64,
    severity: &'static str,
    code: &'static str,
    message: &'a str,
    primary: Primary<'a>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum DiagnosticFormat {
    #[default]
    Json,
    Plain,
}

pub(crate) fn emit_bootstrap(message: &str, label: &str, format: DiagnosticFormat) {
    if matches!(format, DiagnosticFormat::Plain) {
        eprintln!("furnish: error [furnish/runtime-bootstrap] {label}: {message}");
        return;
    }
    let envelope = BootstrapDiagnostic {
        schema_version: DIAGNOSTIC_SCHEMA_VERSION,
        severity: "error",
        code: "furnish/runtime-bootstrap",
        message,
        primary: Primary { label },
    };
    match serde_json::to_string(&envelope) {
        Ok(line) => eprintln!("{line}"),
        Err(_) => eprintln!("furnish: failed to serialize bootstrap diagnostic"),
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Diagnostic<'a> {
    pub(crate) schema_version: u64,
    pub(crate) severity: &'a str,
    pub(crate) code: &'a str,
    pub(crate) message: &'a str,
    pub(crate) primary: Primary<'a>,
    pub(crate) provenance: Option<&'a Provenance>,
    pub(crate) cause: Option<Cause<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) observed: Option<ObservedHashes<'a>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Primary<'a> {
    pub(crate) label: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) struct Cause<'a> {
    pub(crate) operation: &'a str,
    pub(crate) errno: i32,
}

// b, s, and d are the three hashes reported when onConflict is error.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ObservedHashes<'a> {
    pub(crate) baseline: Option<&'a str>,
    pub(crate) source: &'a str,
    pub(crate) destination: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CodeKey {
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

// a refusal that an activation script can branch on without parsing the
// diagnostic. the classes are what an operator would do differently, not one
// code per key, because a code per key would make every new key a contract
// change for anything that reads the status.
pub(crate) const EXIT_REFUSED: u8 = 1;
pub(crate) const EXIT_USAGE: u8 = 2;
pub(crate) const EXIT_LEDGER: u8 = 3;
pub(crate) const EXIT_CONFLICT: u8 = 4;
pub(crate) const EXIT_INTERRUPTED: u8 = 5;

impl CodeKey {
    pub(crate) fn exit_code(self) -> u8 {
        match self {
            // the ledger cannot be trusted, so nothing here is about the
            // declaration and rerunning unchanged will not help.
            Self::LedgerUnreadable | Self::LedgerInvalid | Self::LedgerWriteFailed => EXIT_LEDGER,
            // something is at the destination that furnish does not own, or
            // both sides moved off the baseline. a human decides.
            Self::ConflictingDestination | Self::UnresolvedRetirement => EXIT_CONFLICT,
            // a previous run died mid-transaction and recovery could not
            // finish it, so the destination is between two known states.
            Self::PendingRecovery => EXIT_INTERRUPTED,
            // everything else is the coordinator declining to act on the
            // declaration or the filesystem condition it found.
            _ => EXIT_REFUSED,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Failure {
    pub(crate) key: CodeKey,
    pub(crate) message: String,
    pub(crate) label: String,
    pub(crate) cause: Option<Cause<'static>>,
    // set only on conflict diagnostics; carries b, s, d so the caller does
    // not have to thread them through a separate code path.
    pub(crate) observed: Option<Box<(Option<String>, String, String)>>,
    pub(crate) cleanup_warning: Option<Box<Failure>>,
}

pub(crate) type Result<T> = std::result::Result<T, Failure>;

impl Failure {
    pub(crate) fn new(key: CodeKey, label: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            key,
            message: message.into(),
            label: label.into(),
            cause: None,
            observed: None,
            cleanup_warning: None,
        }
    }

    pub(crate) fn conflict(
        label: impl Into<String>,
        baseline: Option<&str>,
        source: &str,
        destination: &str,
    ) -> Self {
        Self {
            key: CodeKey::ConflictingDestination,
            message: "destination and source have both diverged from the baseline and this declaration's policy is to refuse".to_owned(),
            label: label.into(),
            cause: None,
            observed: Some(Box::new((
                baseline.map(str::to_owned),
                source.to_owned(),
                destination.to_owned(),
            ))),
            cleanup_warning: None,
        }
    }

    pub(crate) fn syscall(
        key: CodeKey,
        label: impl Into<String>,
        operation: &'static str,
        errno: Errno,
    ) -> Self {
        Self {
            key,
            message: format!("{operation} failed"),
            label: label.into(),
            cause: Some(Cause {
                operation,
                errno: errno.raw_os_error(),
            }),
            observed: None,
            cleanup_warning: None,
        }
    }

    pub(crate) fn io(
        key: CodeKey,
        label: impl Into<String>,
        operation: &'static str,
        error: &io::Error,
    ) -> Self {
        Self {
            key,
            message: format!("{operation} failed: {error}"),
            label: label.into(),
            cause: error.raw_os_error().map(|errno| Cause { operation, errno }),
            observed: None,
            cleanup_warning: None,
        }
    }
}

// every syscall site used to spell out the same map_err closure, which rustfmt
// then spread over five lines and pushed the operation name away from the call
// it names. the label and operation stay on the call here.
pub(crate) trait Context<T> {
    fn at(self, key: CodeKey, label: impl Into<String>, operation: &'static str) -> Result<T>;
}

impl<T> Context<T> for std::result::Result<T, Errno> {
    fn at(self, key: CodeKey, label: impl Into<String>, operation: &'static str) -> Result<T> {
        self.map_err(|errno| Failure::syscall(key, label, operation, errno))
    }
}

impl<T> Context<T> for std::result::Result<T, io::Error> {
    fn at(self, key: CodeKey, label: impl Into<String>, operation: &'static str) -> Result<T> {
        self.map_err(|error| Failure::io(key, label, operation, &error))
    }
}

pub(crate) fn code(codes: &DiagnosticCodes, key: CodeKey) -> &str {
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

#[cfg(test)]
pub(crate) fn serialize_failure(
    codes: &DiagnosticCodes,
    failure: &Failure,
    provenance: Option<&Provenance>,
) -> serde_json::Result<String> {
    serialize_diagnostic(codes, failure, provenance, "error")
}

pub(crate) fn serialize_diagnostic(
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
        cause: failure.cause.as_ref().map(|cause| Cause {
            operation: cause.operation,
            errno: cause.errno,
        }),
        observed: failure.observed.as_deref().map(|(b, s, d)| ObservedHashes {
            baseline: b.as_deref(),
            source: s,
            destination: d,
        }),
    })
}

pub(crate) fn emit_failure(
    codes: &DiagnosticCodes,
    failure: &Failure,
    provenance: Option<&Provenance>,
    format: DiagnosticFormat,
) {
    emit_diagnostic(codes, failure, provenance, "error", format);
    if let Some(cleanup) = failure.cleanup_warning.as_deref() {
        emit_warning(codes, cleanup, provenance, format);
    }
}

// loud but not fatal. what an unresolved retirement blocks is the retirement,
// not the activation around it, so this path reports and continues rather than
// returning a Failure.
pub(crate) fn emit_warning(
    codes: &DiagnosticCodes,
    failure: &Failure,
    provenance: Option<&Provenance>,
    format: DiagnosticFormat,
) {
    emit_diagnostic(codes, failure, provenance, "warning", format);
}

fn emit_diagnostic(
    codes: &DiagnosticCodes,
    failure: &Failure,
    provenance: Option<&Provenance>,
    severity: &str,
    format: DiagnosticFormat,
) {
    if matches!(format, DiagnosticFormat::Plain) {
        eprintln!(
            "furnish: {severity} [{}] {}: {}",
            code(codes, failure.key),
            failure.label,
            failure.message
        );
        if let Some(cause) = &failure.cause {
            eprintln!(
                "    cause: {}: {}",
                cause.operation,
                io::Error::from_raw_os_error(cause.errno)
            );
        }
        if let Some(provenance) = provenance {
            eprintln!(
                "    source: {} ({})",
                provenance.source, provenance.declaration
            );
        }
        if let Some((baseline, source, destination)) = failure.observed.as_deref() {
            eprintln!(
                "    hashes: baseline={}, source={source}, destination={destination}",
                baseline.as_deref().unwrap_or("unrecorded")
            );
        }
        return;
    }
    match serialize_diagnostic(codes, failure, provenance, severity) {
        Ok(line) => eprintln!("{line}"),
        Err(_) => eprintln!("furnish: failed to serialize runtime diagnostic"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let encoded = serialize_diagnostic(&codes, &conflict, None, "error").expect("serialize");
        let diagnostic: serde_json::Value = serde_json::from_str(&encoded).expect("decode");
        assert!(diagnostic["observed"].get("baseline").is_some());
        assert!(diagnostic["observed"]["baseline"].is_null());
    }
}

#[cfg(test)]
mod failure_layout_tests {
    use super::*;

    #[test]
    fn failure_keeps_cold_payloads_behind_pointers() {
        assert!(std::mem::size_of::<Failure>() <= 96);
    }
}
