use crate::manifest::{DiagnosticCodes, Provenance};
use rustix::io::Errno;
use serde::Serialize;
use std::io;

pub(crate) const DIAGNOSTIC_SCHEMA_VERSION: u64 = 1;

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

// b, s, and d are the three hashes reported when onConflict is error. they
// travel in the diagnostic so a reader can reconstruct what the coordinator
// saw without re-reading either the manifest or the destination.
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

#[derive(Debug)]
pub(crate) struct Failure {
    pub(crate) key: CodeKey,
    pub(crate) message: String,
    pub(crate) label: String,
    pub(crate) operation: Option<&'static str>,
    pub(crate) errno: Option<i32>,
    // set only on conflict diagnostics; carries b, s, d so the caller does
    // not have to thread them through a separate code path.
    pub(crate) observed: Option<(Option<String>, String, String)>,
}

pub(crate) type Result<T> = std::result::Result<T, Failure>;

impl Failure {
    pub(crate) fn new(key: CodeKey, label: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            key,
            message: message.into(),
            label: label.into(),
            operation: None,
            errno: None,
            observed: None,
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
            operation: None,
            errno: None,
            observed: Some((
                baseline.map(str::to_owned),
                source.to_owned(),
                destination.to_owned(),
            )),
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
            operation: Some(operation),
            errno: Some(errno.raw_os_error()),
            observed: None,
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
            operation: Some(operation),
            errno: error.raw_os_error(),
            observed: None,
        }
    }
}

pub(crate) fn code<'a>(codes: &'a DiagnosticCodes, key: CodeKey) -> &'a str {
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

pub(crate) fn emit_failure(
    codes: &DiagnosticCodes,
    failure: &Failure,
    provenance: Option<&Provenance>,
) {
    match serialize_failure(codes, failure, provenance) {
        Ok(line) => eprintln!("{line}"),
        Err(_) => eprintln!("furnish: failed to serialize runtime diagnostic"),
    }
}

// loud but not fatal. what an unresolved retirement blocks is the retirement,
// not the activation around it, so this path reports and continues rather than
// returning a Failure.
pub(crate) fn emit_warning(
    codes: &DiagnosticCodes,
    failure: &Failure,
    provenance: Option<&Provenance>,
) {
    match serialize_diagnostic(codes, failure, provenance, "warning") {
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
