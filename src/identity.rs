use crate::manifest::{Entry, NATIVE_REPRESENTATION};
use serde::{Deserialize, Serialize};
use std::{env, fs};

pub(crate) const STATE_PENDING: &str = "pending";
pub(crate) const STATE_OWNED: &str = "owned";
pub(crate) fn default_state() -> String {
    STATE_OWNED.to_owned()
}

pub(crate) fn default_representation() -> String {
    NATIVE_REPRESENTATION.to_owned()
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReloadEvidence {
    pub(crate) invocation_id: Option<String>,
    pub(crate) monotonic_seconds: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LedgerRecord {
    pub(crate) destination: String,
    pub(crate) applied_artifact_target: String,
    // retirement has to prove the destination sits beneath a managed root, and
    // by the time an entry is retired the declaration that named that root is
    // gone. the record is the only place left to read it from.
    pub(crate) managed_root: String,
    // which branch published the target above, one of new, update, or repair. a
    // record that cannot say how it was decided is not evidence of a decision.
    pub(crate) applied_by: String,
    pub(crate) applied_generation: Option<String>,
    pub(crate) last_successful_reload: ReloadEvidence,
    pub(crate) reload_action_identity: Option<String>,
    pub(crate) boot_id: Option<String>,
    // everything below is v2. the defaults describe what a v1 record could only
    // have been, since writable did not exist and pending state was never
    // written, so every v1 record is an owned symlink as a matter of what the
    // code could produce rather than an assumption about the data.
    #[serde(default = "default_state")]
    pub(crate) state: String,
    #[serde(default = "default_representation")]
    pub(crate) representation: String,
    // only a representation that keeps bytes at the destination can drift under
    // the user, so a symlink record carries no baseline. a path that writes one
    // for a symlink is writing a claim it cannot check. under runtime-wins the
    // baseline is the source that was refused rather than bytes that were ever
    // written here, so read it as the last source this record was reconciled
    // against and not as a copy of what sits at the destination.
    #[serde(default)]
    pub(crate) baseline_hash: Option<String>,
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
    pub(crate) intended_witness_hash: Option<String>,
    #[serde(default)]
    pub(crate) applied_operation_generation: u64,
    // recovery has to find the displaced object by name, and a writable file
    // displaced by a transition or by an update to its source may hold edited
    // bytes.
    #[serde(default)]
    pub(crate) stage_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) prior_owned: Option<PriorOwned>,
    #[serde(default)]
    pub(crate) unresolved_retirement: Option<UnresolvedRetirement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PriorOwned {
    pub(crate) destination: String,
    pub(crate) applied_artifact_target: String,
    pub(crate) managed_root: String,
    pub(crate) applied_by: String,
    pub(crate) applied_generation: Option<String>,
    pub(crate) last_successful_reload: ReloadEvidence,
    pub(crate) reload_action_identity: Option<String>,
    pub(crate) boot_id: Option<String>,
    pub(crate) representation: String,
    pub(crate) baseline_hash: Option<String>,
    pub(crate) intended_witness_hash: Option<String>,
    pub(crate) applied_operation_generation: u64,
    pub(crate) unresolved_retirement: Option<UnresolvedRetirement>,
}

impl PriorOwned {
    pub(crate) fn capture(record: &LedgerRecord) -> Self {
        Self {
            destination: record.destination.clone(),
            applied_artifact_target: record.applied_artifact_target.clone(),
            managed_root: record.managed_root.clone(),
            applied_by: record.applied_by.clone(),
            applied_generation: record.applied_generation.clone(),
            last_successful_reload: record.last_successful_reload.clone(),
            reload_action_identity: record.reload_action_identity.clone(),
            boot_id: record.boot_id.clone(),
            representation: record.representation.clone(),
            baseline_hash: record.baseline_hash.clone(),
            intended_witness_hash: record.intended_witness_hash.clone(),
            applied_operation_generation: record.applied_operation_generation,
            unresolved_retirement: record.unresolved_retirement.clone(),
        }
    }

    pub(crate) fn restore(&self) -> LedgerRecord {
        LedgerRecord {
            destination: self.destination.clone(),
            applied_artifact_target: self.applied_artifact_target.clone(),
            managed_root: self.managed_root.clone(),
            applied_by: self.applied_by.clone(),
            applied_generation: self.applied_generation.clone(),
            last_successful_reload: self.last_successful_reload.clone(),
            reload_action_identity: self.reload_action_identity.clone(),
            boot_id: self.boot_id.clone(),
            state: STATE_OWNED.to_owned(),
            representation: self.representation.clone(),
            baseline_hash: self.baseline_hash.clone(),
            intended_witness_hash: self.intended_witness_hash.clone(),
            applied_operation_generation: self.applied_operation_generation,
            stage_name: None,
            prior_owned: None,
            unresolved_retirement: self.unresolved_retirement.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnresolvedRetirement {
    pub(crate) reason: String,
    pub(crate) observed_hash: Option<String>,
    pub(crate) baseline_hash: Option<String>,
}

// two runs can produce byte-identical values, so values alone cannot say which
// run produced a record. the invocation ID and the monotonic reading are what
// make a record evidence of a specific reconciliation rather than an assertion
// about a target.
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

    pub(crate) fn record(&self, entry: &Entry, applied_by: &str) -> LedgerRecord {
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
            prior_owned: None,
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

#[cfg(test)]
mod tests {
    use super::*;
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
                scope: "user".to_owned(),
                identity: "1000".to_owned(),
            },
            managed_root: "/managed".to_owned(),
            on_conflict: ConflictPolicy::Error,
            representation: NATIVE_REPRESENTATION.to_owned(),
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
        let record = identity.record(&entry, "new");
        let expected = fs::read_link("/run/current-system")
            .ok()
            .map(|path| path.to_string_lossy().into_owned());
        assert_eq!(record.applied_generation, expected);
    }
}
