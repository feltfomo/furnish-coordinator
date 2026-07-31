use crate::diagnostic::{CodeKey, DIAGNOSTIC_SCHEMA_VERSION, Failure, Result};
use serde::{Deserialize, Serialize};

pub(crate) const MANIFEST_SCHEMA_VERSION: u64 = 2;
pub(crate) const NATIVE_EXECUTOR_IDENTITY: &str = "furnish/native-symlink";
pub(crate) const NATIVE_EXECUTOR_PROTOCOL: u64 = 1;
pub(crate) const NATIVE_REPRESENTATION: &str = "symlink";
pub(crate) const NATIVE_WRITABLE_IDENTITY: &str = "furnish/native-writable";
pub(crate) const NATIVE_WRITABLE_PROTOCOL: u64 = 1;
pub(crate) const WRITABLE_REPRESENTATION: &str = "writable";
// qualification is a table lookup, not a chain of name comparisons. nothing in
// the protocol asks whether an executor is the native one; it asks whether the
// tuple it presents appears here.
pub(crate) struct ExecutorProfile {
    pub(crate) identity: &'static str,
    pub(crate) protocol_version: u64,
    pub(crate) representation: &'static str,
    pub(crate) lifecycle_strategy: &'static str,
    pub(crate) worker_subcommand: &'static str,
    pub(crate) worker_value_flag: &'static str,
}

pub(crate) const EXECUTOR_PROFILES: [ExecutorProfile; 2] = [
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

// transfer is generic over representation pairs; the gate is the set of pairs
// that actually exist today.
pub(crate) const TRANSITION_PAIRS: [(&str, &str); 2] = [
    (NATIVE_REPRESENTATION, WRITABLE_REPRESENTATION),
    (WRITABLE_REPRESENTATION, NATIVE_REPRESENTATION),
];

pub(crate) fn profile_for(
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

pub(crate) fn transition_is_gated(from: &str, to: &str) -> bool {
    TRANSITION_PAIRS
        .iter()
        .any(|(source, target)| *source == from && *target == to)
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Manifest {
    pub(crate) schema_version: u64,
    pub(crate) diagnostic_contract: DiagnosticContract,
    pub(crate) entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticContract {
    pub(crate) schema_version: u64,
    pub(crate) codes: DiagnosticCodes,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticCodes {
    pub(crate) invalid_manifest: String,
    pub(crate) unsupported_executor: String,
    pub(crate) invalid_destination: String,
    pub(crate) parent_traversal: String,
    pub(crate) conflicting_destination: String,
    pub(crate) executor_failed: String,
    pub(crate) staging_verification: String,
    pub(crate) publish_race: String,
    pub(crate) final_verification: String,
    pub(crate) ledger_unreadable: String,
    pub(crate) ledger_invalid: String,
    pub(crate) ledger_write_failed: String,
    pub(crate) repair_verification: String,
    pub(crate) unresolvable_desired_target: String,
    pub(crate) content_verification: String,
    pub(crate) transition_refused: String,
    pub(crate) unresolved_retirement: String,
    pub(crate) pending_recovery: String,
}

// how a destination that diverged from its baseline gets resolved. the choice
// travels with the entry rather than with the run, and it has no default here,
// so a manifest written before the choice existed fails to deserialize instead
// of reconciling under a guess about what its author wanted.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ConflictPolicy {
    Error,
    SourceWins,
    RuntimeWins,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Entry {
    pub(crate) schema_version: u64,
    pub(crate) filesystem_identity: FilesystemIdentity,
    pub(crate) authority: Authority,
    pub(crate) managed_root: String,
    pub(crate) on_conflict: ConflictPolicy,
    pub(crate) representation: String,
    pub(crate) retained_artifact_target: String,
    pub(crate) executor: Executor,
    pub(crate) cleanup_strategy: String,
    pub(crate) self_heal_strategy: String,
    pub(crate) provenance: Provenance,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FilesystemIdentity {
    pub(crate) namespace: String,
    pub(crate) destination: String,
    pub(crate) canonical: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Authority {
    pub(crate) scope: String,
    pub(crate) identity: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Executor {
    pub(crate) identity: String,
    pub(crate) protocol_version: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Provenance {
    pub(crate) declaration: String,
    pub(crate) source: String,
}

pub(crate) fn validate_manifest(manifest: &Manifest) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_tuple_is_exact() {
        assert_eq!(NATIVE_EXECUTOR_IDENTITY, "furnish/native-symlink");
        assert_eq!(NATIVE_EXECUTOR_PROTOCOL, 1);
        assert_eq!(NATIVE_REPRESENTATION, "symlink");
    }
}
