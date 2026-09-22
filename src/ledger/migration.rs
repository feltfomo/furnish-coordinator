use super::model::{OWNED_STATE, SYMLINK_REPRESENTATION};
use crate::hash::name_untagged;

// schema 1 had no state, no representation, and no transaction fields, so every
// record it holds is an owned symlink and the fields that describe a pending
// transaction are noise to be cleared rather than data to be carried.
pub(super) trait V1Record {
    fn set_state(&mut self, state: &str);
    fn set_representation(&mut self, representation: &str);
    fn clear_stage_name(&mut self);
    fn clear_prior_owned(&mut self);
    fn clear_unresolved_retirement(&mut self);
}

// schema 2 stored bare digests. every one of them is sha-256, and v3 says so in
// the value itself.
pub(super) trait V2Record {
    // every place a record can hold a witness, including the ones nested under a
    // pending transaction and under an unresolved retirement. a migration that
    // named only the top level would leave recovery comparing a named value
    // against an unnamed one, which is the exact confusion the tag exists to end.
    fn witnesses(&mut self) -> Vec<&mut Option<String>>;
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
    *schema_version = 2;
}

pub(super) fn migrate_v2<'a, T>(
    schema_version: &mut u64,
    records: impl IntoIterator<Item = &'a mut T>,
) where
    T: V2Record + 'a,
{
    for record in records {
        for witness in record.witnesses() {
            name_untagged(witness);
        }
    }
    *schema_version = 3;
}
