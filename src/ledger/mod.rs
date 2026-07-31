mod migration;
mod model;
mod persistence;
mod transaction;

pub(crate) use model::{
    AppliedOperation, AuthorityScope, LedgerRecord, PendingIntent, RecordStatus, ReloadEvidence,
    Representation, TransitionPair, UnresolvedRetirement,
};
pub(crate) use persistence::LedgerState;
pub(crate) use transaction::{baseline_for, carry_applied_state, owned_record, pending_record};

pub(crate) const LEDGER_SCHEMA_VERSION: u64 = 2;
pub(crate) const LEDGER_FILE_NAME: &str = "applied-state.json";
pub(crate) const LEDGER_ROLLBACK_FILE_NAME: &str = "applied-state.v1.json";
const LEDGER_STAGE_PREFIX: &str = ".applied-state";
