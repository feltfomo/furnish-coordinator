use crate::ledger::{LedgerRecord, RecordStatus, ReloadEvidence};
use crate::manifest::Entry;
use std::{env, fs};

#[derive(Debug)]
pub(crate) struct RunIdentity {
    pub(crate) invocation_id: Option<String>,
    pub(crate) monotonic_seconds: f64,
    pub(crate) boot_id: Option<String>,
    pub(crate) system_generation: Option<String>,
}

impl RunIdentity {
    pub(crate) fn observe() -> Self {
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
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .map(|value| value.trim().to_owned()),
            system_generation: fs::read_link("/run/current-system")
                .ok()
                .map(|path| path.to_string_lossy().into_owned()),
        }
    }

    pub(crate) fn record(&self, entry: &Entry, status: RecordStatus) -> LedgerRecord {
        LedgerRecord {
            destination: entry.filesystem_identity.destination.clone(),
            applied_artifact_target: entry.retained_artifact_target.clone(),
            managed_root: entry.managed_root.clone(),
            representation: entry.representation,
            baseline_hash: None,
            intended_witness_hash: None,
            applied_operation_generation: 0,
            status,
            applied_generation: self.system_generation.clone(),
            last_successful_reload: ReloadEvidence {
                invocation_id: self.invocation_id.clone(),
                monotonic_seconds: self.monotonic_seconds,
            },
            reload_action_identity: None,
            boot_id: self.boot_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{AppliedOperation, AuthorityScope, RecordStatus, Representation};
    use crate::manifest::{
        Authority, ConflictPolicy, Executor, FilesystemIdentity, NATIVE_EXECUTOR_IDENTITY,
        NATIVE_EXECUTOR_PROTOCOL, Provenance,
    };

    #[test]
    fn run_identity_links_every_record_to_the_current_system_generation() {
        let identity = RunIdentity::observe();
        let entry = Entry {
            schema_version: 2,
            filesystem_identity: FilesystemIdentity {
                namespace: "test".to_owned(),
                destination: "/managed/value".to_owned(),
                canonical: "test:/managed/value".to_owned(),
            },
            authority: Authority {
                scope: AuthorityScope::User,
                identity: "1000".to_owned(),
            },
            managed_root: "/managed".to_owned(),
            on_conflict: ConflictPolicy::Error,
            representation: Representation::Symlink,
            retained_artifact_target: "/desired/target".to_owned(),
            executor: Executor {
                identity: NATIVE_EXECUTOR_IDENTITY.to_owned(),
                protocol_version: NATIVE_EXECUTOR_PROTOCOL,
            },
            cleanup_strategy: "exact-symlink-target".to_owned(),
            self_heal_strategy: "exact-symlink-target".to_owned(),
            provenance: Provenance {
                declaration: "test".to_owned(),
                source: "test".to_owned(),
            },
        };
        let record = identity.record(
            &entry,
            RecordStatus::Owned {
                applied_by: AppliedOperation::New,
                unresolved_retirement: None,
            },
        );
        let expected = fs::read_link("/run/current-system")
            .ok()
            .map(|path| path.to_string_lossy().into_owned());
        assert_eq!(record.applied_generation, expected);
    }
}
