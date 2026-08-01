use crate::diagnostic::{CodeKey, DIAGNOSTIC_SCHEMA_VERSION, Failure, Result};
use crate::executor::WorkerProgram;
use crate::ledger::{AuthorityScope, Representation};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path};

pub(crate) const MANIFEST_SCHEMA_VERSION: u64 = 2;
pub(crate) const NATIVE_EXECUTOR_IDENTITY: &str = "furnish/native-symlink";
pub(crate) const NATIVE_EXECUTOR_PROTOCOL: u64 = 1;
pub(crate) const NATIVE_REPRESENTATION: Representation = Representation::Symlink;
pub(crate) const NATIVE_WRITABLE_IDENTITY: &str = "furnish/native-writable";
pub(crate) const NATIVE_WRITABLE_PROTOCOL: u64 = 1;
pub(crate) const WRITABLE_REPRESENTATION: Representation = Representation::Writable;

pub(crate) struct ExecutorProfile {
    pub(crate) identity: &'static str,
    pub(crate) protocol_version: u64,
    pub(crate) representation: Representation,
    pub(crate) lifecycle_strategy: &'static str,
    pub(crate) worker_kind: WorkerProgram,
}

pub(crate) const EXECUTOR_PROFILES: [ExecutorProfile; 2] = [
    ExecutorProfile {
        identity: NATIVE_EXECUTOR_IDENTITY,
        protocol_version: NATIVE_EXECUTOR_PROTOCOL,
        representation: NATIVE_REPRESENTATION,
        lifecycle_strategy: "exact-symlink-target",
        worker_kind: WorkerProgram::Symlink,
    },
    ExecutorProfile {
        identity: NATIVE_WRITABLE_IDENTITY,
        protocol_version: NATIVE_WRITABLE_PROTOCOL,
        representation: WRITABLE_REPRESENTATION,
        lifecycle_strategy: "exact-source-content",
        worker_kind: WorkerProgram::Writable,
    },
];

pub(crate) fn profile_for(
    identity: &str,
    protocol_version: u64,
    representation: Representation,
) -> Option<&'static ExecutorProfile> {
    EXECUTOR_PROFILES.iter().find(|profile| {
        profile.identity == identity
            && profile.protocol_version == protocol_version
            && profile.representation == representation
    })
}

fn unique_profile_for_wire<'a>(
    profiles: &'a [ExecutorProfile],
    identity: &str,
    protocol_version: u64,
    representation: &str,
) -> std::result::Result<Option<&'a ExecutorProfile>, ()> {
    let mut matches = profiles.iter().filter(|profile| {
        profile.identity == identity
            && profile.protocol_version == protocol_version
            && profile.representation.as_str() == representation
    });
    let profile = matches.next();
    if matches.next().is_some() {
        Err(())
    } else {
        Ok(profile)
    }
}

fn profile_for_wire(
    identity: &str,
    protocol_version: u64,
    representation: &str,
) -> std::result::Result<Option<&'static ExecutorProfile>, ()> {
    unique_profile_for_wire(
        &EXECUTOR_PROFILES,
        identity,
        protocol_version,
        representation,
    )
}

#[derive(Debug)]
pub(crate) struct Manifest {
    pub(crate) schema_version: u64,
    pub(crate) diagnostic_contract: DiagnosticContract,
    pub(crate) entries: Vec<Entry>,
}

#[derive(Debug)]
pub(crate) struct DiagnosticContract {
    pub(crate) schema_version: u64,
    pub(crate) codes: DiagnosticCodes,
}

#[derive(Clone, Debug, Default, Deserialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ConflictPolicy {
    Error,
    SourceWins,
    RuntimeWins,
}

#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) schema_version: u64,
    pub(crate) filesystem_identity: FilesystemIdentity,
    pub(crate) authority: Authority,
    pub(crate) managed_root: String,
    pub(crate) on_conflict: ConflictPolicy,
    pub(crate) representation: Representation,
    pub(crate) retained_artifact_target: String,
    pub(crate) executor: Executor,
    pub(crate) cleanup_strategy: String,
    pub(crate) self_heal_strategy: String,
    pub(crate) provenance: Provenance,
}

#[derive(Debug)]
pub(crate) struct FilesystemIdentity {
    pub(crate) namespace: String,
    pub(crate) destination: String,
    pub(crate) canonical: String,
}

#[derive(Debug)]
pub(crate) struct Authority {
    pub(crate) scope: AuthorityScope,
    pub(crate) identity: String,
}

#[derive(Debug)]
pub(crate) struct Executor {
    pub(crate) identity: String,
    pub(crate) protocol_version: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Provenance {
    pub(crate) declaration: String,
    pub(crate) source: String,
}

#[derive(Debug)]
pub(crate) struct DecodedManifest(RawManifest);

impl DecodedManifest {
    pub(crate) fn diagnostic_codes(&self) -> &DiagnosticCodes {
        &self.0.diagnostic_contract.codes
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawManifest {
    schema_version: u64,
    diagnostic_contract: RawDiagnosticContract,
    entries: Vec<RawEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDiagnosticContract {
    schema_version: u64,
    codes: DiagnosticCodes,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEntry {
    schema_version: u64,
    filesystem_identity: RawFilesystemIdentity,
    authority: RawAuthority,
    managed_root: String,
    on_conflict: ConflictPolicy,
    representation: String,
    retained_artifact_target: String,
    executor: RawExecutor,
    cleanup_strategy: String,
    self_heal_strategy: String,
    provenance: Provenance,
}

#[derive(Debug, Deserialize)]
struct RawFilesystemIdentity {
    namespace: String,
    destination: String,
    canonical: String,
}

#[derive(Debug, Deserialize)]
struct RawAuthority {
    scope: String,
    identity: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawExecutor {
    identity: String,
    protocol_version: u64,
}

pub(crate) fn decode_manifest(bytes: &[u8]) -> serde_json::Result<DecodedManifest> {
    serde_json::from_slice(bytes).map(DecodedManifest)
}

pub(crate) fn validate_manifest(decoded: DecodedManifest) -> Result<Manifest> {
    let raw = decoded.0;
    if raw.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(Failure::new(
            CodeKey::InvalidManifest,
            "manifest",
            format!(
                "manifest schema {} is unsupported; expected {}",
                raw.schema_version, MANIFEST_SCHEMA_VERSION
            ),
        ));
    }
    if raw.diagnostic_contract.schema_version != DIAGNOSTIC_SCHEMA_VERSION {
        return Err(Failure::new(
            CodeKey::InvalidManifest,
            "diagnostic contract",
            format!(
                "diagnostic schema {} is unsupported; expected {}",
                raw.diagnostic_contract.schema_version, DIAGNOSTIC_SCHEMA_VERSION
            ),
        ));
    }
    let mut entries = Vec::with_capacity(raw.entries.len());
    let mut canonicals = BTreeSet::new();
    let mut destinations = BTreeSet::new();
    for entry in raw.entries {
        if entry.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(Failure::new(
                CodeKey::InvalidManifest,
                &entry.filesystem_identity.canonical,
                "entry schema does not match the manifest schema",
            ));
        }
        let profile = match profile_for_wire(
            &entry.executor.identity,
            entry.executor.protocol_version,
            &entry.representation,
        ) {
            Ok(Some(profile)) => profile,
            Ok(None) => {
                return Err(Failure::new(
                    CodeKey::UnsupportedExecutor,
                    &entry.filesystem_identity.canonical,
                    format!(
                        "unsupported executor tuple ({}, {}, {})",
                        entry.executor.identity,
                        entry.executor.protocol_version,
                        entry.representation
                    ),
                ));
            }
            Err(()) => {
                return Err(Failure::new(
                    CodeKey::InvalidManifest,
                    &entry.filesystem_identity.canonical,
                    "executor tuple matches more than one qualified profile",
                ));
            }
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
        let managed_root = Path::new(&entry.managed_root);
        let mut root_components = managed_root.components();
        if !managed_root.is_absolute()
            || !matches!(root_components.next(), Some(Component::RootDir))
            || root_components.clone().next().is_none()
            || root_components.any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(Failure::new(
                CodeKey::InvalidManifest,
                &entry.filesystem_identity.canonical,
                "managedRoot must be an absolute path with only normal components",
            ));
        }
        let scope = AuthorityScope::parse(&entry.authority.scope).map_err(|error| {
            Failure::new(
                CodeKey::InvalidManifest,
                &entry.filesystem_identity.canonical,
                error.to_string(),
            )
        })?;
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
        if !canonicals.insert(entry.filesystem_identity.canonical.clone()) {
            return Err(Failure::new(
                CodeKey::InvalidManifest,
                &entry.filesystem_identity.canonical,
                "filesystem identity canonical is duplicated",
            ));
        }
        if !destinations.insert(entry.filesystem_identity.destination.clone()) {
            return Err(Failure::new(
                CodeKey::InvalidDestination,
                &entry.filesystem_identity.destination,
                "physical destination is declared more than once",
            ));
        }
        entries.push(Entry {
            schema_version: entry.schema_version,
            filesystem_identity: FilesystemIdentity {
                namespace: entry.filesystem_identity.namespace,
                destination: entry.filesystem_identity.destination,
                canonical: entry.filesystem_identity.canonical,
            },
            authority: Authority {
                scope,
                identity: entry.authority.identity,
            },
            managed_root: entry.managed_root,
            on_conflict: entry.on_conflict,
            representation: profile.representation,
            retained_artifact_target: entry.retained_artifact_target,
            executor: Executor {
                identity: entry.executor.identity,
                protocol_version: entry.executor.protocol_version,
            },
            cleanup_strategy: entry.cleanup_strategy,
            self_heal_strategy: entry.self_heal_strategy,
            provenance: entry.provenance,
        });
    }
    Ok(Manifest {
        schema_version: raw.schema_version,
        diagnostic_contract: DiagnosticContract {
            schema_version: raw.diagnostic_contract.schema_version,
            codes: raw.diagnostic_contract.codes,
        },
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_tuple_is_exact() {
        assert_eq!(NATIVE_EXECUTOR_IDENTITY, "furnish/native-symlink");
        assert_eq!(NATIVE_EXECUTOR_PROTOCOL, 1);
        assert_eq!(NATIVE_REPRESENTATION.as_str(), "symlink");
    }

    #[test]
    fn an_ambiguous_executor_profile_table_is_refused() {
        let profiles = [
            ExecutorProfile {
                identity: NATIVE_EXECUTOR_IDENTITY,
                protocol_version: NATIVE_EXECUTOR_PROTOCOL,
                representation: NATIVE_REPRESENTATION,
                lifecycle_strategy: "exact-symlink-target",
                worker_kind: WorkerProgram::Symlink,
            },
            ExecutorProfile {
                identity: NATIVE_EXECUTOR_IDENTITY,
                protocol_version: NATIVE_EXECUTOR_PROTOCOL,
                representation: NATIVE_REPRESENTATION,
                lifecycle_strategy: "exact-symlink-target",
                worker_kind: WorkerProgram::Symlink,
            },
        ];
        assert!(matches!(
            unique_profile_for_wire(
                &profiles,
                NATIVE_EXECUTOR_IDENTITY,
                NATIVE_EXECUTOR_PROTOCOL,
                NATIVE_REPRESENTATION.as_str(),
            ),
            Err(())
        ));
    }

    fn manifest_with_entries(entries: serde_json::Value) -> DecodedManifest {
        decode_manifest(
            serde_json::json!({
                "schemaVersion": MANIFEST_SCHEMA_VERSION,
                "diagnosticContract": {
                    "schemaVersion": DIAGNOSTIC_SCHEMA_VERSION,
                    "codes": {
                        "invalidManifest": "invalid-manifest",
                        "unsupportedExecutor": "unsupported-executor",
                        "invalidDestination": "invalid-destination",
                        "parentTraversal": "parent-traversal",
                        "conflictingDestination": "conflicting-destination",
                        "executorFailed": "executor-failed",
                        "stagingVerification": "staging-verification",
                        "publishRace": "publish-race",
                        "finalVerification": "final-verification",
                        "ledgerUnreadable": "ledger-unreadable",
                        "ledgerInvalid": "ledger-invalid",
                        "ledgerWriteFailed": "ledger-write-failed",
                        "repairVerification": "repair-verification",
                        "unresolvableDesiredTarget": "unresolvable-desired-target",
                        "contentVerification": "content-verification",
                        "transitionRefused": "transition-refused",
                        "unresolvedRetirement": "unresolved-retirement",
                        "pendingRecovery": "pending-recovery"
                    }
                },
                "entries": entries
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap()
    }

    fn entry(destination: &str, canonical: &str, managed_root: &str) -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": MANIFEST_SCHEMA_VERSION,
            "filesystemIdentity": {
                "namespace": "test",
                "destination": destination,
                "canonical": canonical
            },
            "authority": {"scope": "system", "identity": "test/system"},
            "managedRoot": managed_root,
            "onConflict": "error",
            "representation": "symlink",
            "retainedArtifactTarget": "/nix/store/target",
            "executor": {
                "identity": NATIVE_EXECUTOR_IDENTITY,
                "protocolVersion": NATIVE_EXECUTOR_PROTOCOL
            },
            "cleanupStrategy": "exact-symlink-target",
            "selfHealStrategy": "exact-symlink-target",
            "provenance": {"declaration": "test", "source": "manifest tests"}
        })
    }

    #[test]
    fn duplicate_canonicals_are_refused_before_reconciliation() {
        let entries = serde_json::json!([
            entry("/managed/a", "test:/managed/a", "/managed"),
            entry("/managed/a", "test:/managed/a", "/managed")
        ]);
        let failure = validate_manifest(manifest_with_entries(entries)).unwrap_err();
        assert!(matches!(failure.key, CodeKey::InvalidManifest));
        assert_eq!(
            failure.message,
            "filesystem identity canonical is duplicated"
        );
    }

    #[test]
    fn duplicate_physical_destinations_are_refused_before_reconciliation() {
        let first = entry("/managed/a", "test:/managed/a", "/managed");
        let mut second = entry("/managed/a", "other:/managed/a", "/managed");
        second["filesystemIdentity"]["namespace"] = serde_json::json!("other");
        let entries = serde_json::json!([first, second]);
        let failure = validate_manifest(manifest_with_entries(entries)).unwrap_err();
        assert!(matches!(failure.key, CodeKey::InvalidDestination));
        assert_eq!(
            failure.message,
            "physical destination is declared more than once"
        );
    }

    #[test]
    fn non_normal_managed_roots_are_refused_before_reconciliation() {
        for managed_root in ["relative", "/", "/managed/../other"] {
            let entries = serde_json::json!([entry("/managed/a", "test:/managed/a", managed_root)]);
            let failure = validate_manifest(manifest_with_entries(entries)).unwrap_err();
            assert!(matches!(failure.key, CodeKey::InvalidManifest));
            assert_eq!(
                failure.message,
                "managedRoot must be an absolute path with only normal components"
            );
        }
    }
}
