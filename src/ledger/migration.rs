use super::LEDGER_SCHEMA_VERSION;
use super::model::{OWNED_STATE, SYMLINK_REPRESENTATION};

pub(super) trait V1Record {
    fn set_state(&mut self, state: &str);
    fn set_representation(&mut self, representation: &str);
    fn clear_stage_name(&mut self);
    fn clear_prior_owned(&mut self);
    fn clear_unresolved_retirement(&mut self);
}

pub(super) fn migrate_v1<'a, T>(
    schema_version: &mut u64,
    records: impl IntoIterator<Item = &'a mut T>,
) where
    T: V1Record + 'a,
{
    for record in records {
        record.set_state(OWNED_STATE);
        record.set_representation(SYMLINK_REPRESENTATION);
        record.clear_stage_name();
        record.clear_prior_owned();
        record.clear_unresolved_retirement();
    }
    *schema_version = LEDGER_SCHEMA_VERSION;
}
