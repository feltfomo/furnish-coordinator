use super::{
    AppliedOperation, Entry, LedgerState, OwnedRecord, PendingIntent, Result, RunIdentity,
    fault_point, owned_record, pending_record,
};
use std::ffi::OsStr;

// every route that puts something at a destination brackets its work between
// the same two ledger commits, and the pending one is the only reason a crash
// in the middle leaves a recoverable record instead of an unexplained object.
// the five routes used to spell the bracket out five times, which is five
// chances to invert the order or drop a fault point. it is written once here
// and the route supplies only the work in between.
pub(super) struct Publication<'a> {
    pub(super) entry: &'a Entry,
    pub(super) identity: &'a RunIdentity,
    pub(super) intent: PendingIntent,
    // what the owned record will claim once the work lands. it is not derived
    // from the intent, because a representation transfer is pending as a
    // transition and owned as an update.
    pub(super) applied_by: AppliedOperation,
    pub(super) prior: Option<OwnedRecord<'a>>,
    pub(super) stage: &'a OsStr,
    pub(super) witness: &'a str,
    // the transfer into a writable file keeps the recorded target on the
    // pending record, because until the exchange lands the object actually in
    // place is still the symlink, and recovery promotes this record as it
    // stands. every other route is publishing the target it declares.
    pub(super) pending_artifact_target: Option<&'a str>,
}

impl Publication<'_> {
    pub(super) fn run(
        self,
        ledger: &mut LedgerState,
        publish: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let canonical = &self.entry.filesystem_identity.canonical;
        let mut pending = pending_record(
            self.identity,
            self.entry,
            self.intent,
            self.prior,
            self.stage,
            self.witness,
        );
        if let Some(target) = self.pending_artifact_target {
            pending.applied_artifact_target = target.to_owned();
        }
        fault_point("pre-pending");
        ledger.commit(canonical, pending)?;
        fault_point("pending-committed");
        publish()?;
        // durable before the run returns, because a crash after this point
        // would otherwise leave a pending record for work that is finished,
        // and recovery would re-verify a destination that needs nothing.
        ledger.commit(
            canonical,
            owned_record(
                self.identity,
                self.entry,
                self.applied_by,
                self.prior,
                self.witness,
            ),
        )
    }
}
