mod migration;
mod model;
mod persistence;
mod transaction;

pub(crate) use model::{
    AppliedOperation, AuthorityScope, LedgerRecord, PendingIntent, RecordStatus, ReloadEvidence,
    Representation, TransitionPair, UnresolvedRetirement,
};
pub(crate) use persistence::LedgerState;
pub(crate) use transaction::{baseline_for, owned_record, pending_record, refreshed_record};

pub(crate) const LEDGER_SCHEMA_VERSION: u64 = 3;
pub(crate) const LEDGER_FILE_NAME: &str = "applied-state.json";

// the rollback copy is named for the schema it holds, not for the migration
// that read it, so a host that has been through both migrations keeps both
// inputs and a downgrade to either version has the bytes it expects.
pub(crate) fn rollback_file_name(schema_version: u64) -> String {
    format!("applied-state.v{schema_version}.json")
}
const LEDGER_STAGE_PREFIX: &str = ".applied-state";
