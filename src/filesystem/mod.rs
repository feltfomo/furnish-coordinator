mod observe;
mod parent;
mod publish;
mod stage;

pub(crate) const SYMLINK_MODE: u32 = 0o120000;
pub(crate) const REGULAR_MODE: u32 = 0o100000;
const FILE_TYPE_MASK: u32 = 0o170000;
// one mode for both authority scopes. a mode that varies by scope is the
// deferred permissions feature arriving early under another name.
pub(crate) const WRITABLE_FILE_MODE: u32 = 0o644;

pub(crate) use observe::{
    DestinationObservation, hash_regular, observe_kind, observe_mode, symlink_target,
    verify_writable_destination, verify_writable_hash,
};
pub(crate) use parent::{ParentMode, open_parent, walk_parent};
pub(crate) use publish::{
    exchange_names, publish_exchange, publish_new, publish_writable_exchange, publish_writable_new,
    rollback_exchange, sync_parent,
};
#[cfg(test)]
pub(crate) use stage::FAIL_VERIFIED_DISPLACED_CLEANUP;
pub(crate) use stage::{
    DisplacedCleanup, cleanup_unpublished_after_failure, discard_displaced_under_policy,
    remove_unpublished_stage, remove_verified_displaced,
};
