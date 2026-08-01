use super::model::{
    AppliedOperation, LedgerRecord, OwnedRecord, PendingIntent, PriorOwned, RecordStatus,
    Representation,
};
use crate::identity::RunIdentity;
use crate::manifest::Entry;
use std::ffi::OsStr;

// nothing has been applied yet, so the prior record's applied state is carried
// across unchanged. a pending record that dropped it would make recovery
// converge to a state weaker than the one already durable. the publishing
// branch is named here and not only at the owned commit, because recovery
// promotes this record as it stands, and a record that named a branch it was
// not published by is not evidence of the decision that produced it.
pub(crate) fn pending_record(
    identity: &RunIdentity,
    entry: &Entry,
    intent: PendingIntent,
    prior: Option<OwnedRecord<'_>>,
    stage: &OsStr,
    witness_hash: &str,
) -> LedgerRecord {
    let mut record = identity.record(
        entry,
        RecordStatus::Pending {
            intent,
            stage_name: Some(stage.to_string_lossy().into_owned()),
            prior_owned: prior.map(PriorOwned::capture),
        },
    );
    record.intended_witness_hash = Some(witness_hash.to_owned());
    if let Some(prior) = prior {
        record.baseline_hash = prior.record.baseline_hash.clone();
        record.applied_operation_generation = prior.record.applied_operation_generation;
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
pub(crate) fn owned_record(
    identity: &RunIdentity,
    entry: &Entry,
    applied_by: AppliedOperation,
    prior: Option<OwnedRecord<'_>>,
    witness_hash: &str,
) -> LedgerRecord {
    let mut record = identity.record(
        entry,
        RecordStatus::Owned {
            applied_by,
            unresolved_retirement: None,
        },
    );
    record.intended_witness_hash = Some(witness_hash.to_owned());
    record.baseline_hash = baseline_for(entry.representation, witness_hash);
    record.applied_operation_generation = prior
        .map_or(0, |prior| prior.record.applied_operation_generation)
        .saturating_add(1);
    record
}

// a witness hash is a baseline only where it hashes bytes that live at the
// destination. for a symlink it hashes a path string, which is not a baseline
// and must not be stored as one.
pub(crate) fn baseline_for(representation: Representation, witness_hash: &str) -> Option<String> {
    (representation == Representation::Writable).then(|| witness_hash.to_owned())
}

// a run that publishes nothing must not erase what an earlier run recorded,
// because these fields describe the applied state, not the invocation that
// observed it. an unresolved retirement marker is deliberately NOT among them,
// since reaching this path means the destination is declared again, and being
// declared again is what resolves it.
pub(crate) fn carry_applied_state(prior: &LedgerRecord, record: &mut LedgerRecord) {
    record.baseline_hash = prior.baseline_hash.clone();
    record.intended_witness_hash = prior.intended_witness_hash.clone();
    record.applied_operation_generation = prior.applied_operation_generation;
}

impl PriorOwned {
    pub(crate) fn capture(owned: OwnedRecord<'_>) -> Self {
        let record = owned.record;
        Self {
            destination: record.destination.clone(),
            applied_artifact_target: record.applied_artifact_target.clone(),
            managed_root: record.managed_root.clone(),
            applied_by: owned.applied_by,
            applied_generation: record.applied_generation.clone(),
            last_successful_reload: record.last_successful_reload.clone(),
            reload_action_identity: record.reload_action_identity.clone(),
            boot_id: record.boot_id.clone(),
            representation: record.representation,
            baseline_hash: record.baseline_hash.clone(),
            intended_witness_hash: record.intended_witness_hash.clone(),
            applied_operation_generation: record.applied_operation_generation,
            unresolved_retirement: record.unresolved_retirement().cloned(),
        }
    }

    pub(crate) fn restore(&self) -> LedgerRecord {
        LedgerRecord {
            destination: self.destination.clone(),
            applied_artifact_target: self.applied_artifact_target.clone(),
            managed_root: self.managed_root.clone(),
            applied_generation: self.applied_generation.clone(),
            last_successful_reload: self.last_successful_reload.clone(),
            reload_action_identity: self.reload_action_identity.clone(),
            boot_id: self.boot_id.clone(),
            representation: self.representation,
            baseline_hash: self.baseline_hash.clone(),
            intended_witness_hash: self.intended_witness_hash.clone(),
            applied_operation_generation: self.applied_operation_generation,
            status: RecordStatus::Owned {
                applied_by: self.applied_by,
                unresolved_retirement: self.unresolved_retirement.clone(),
            },
        }
    }
}
