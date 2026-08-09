# Filesystem safety

The coordinator treats path traversal, staging, and publication as separate security boundaries. It does not hand an arbitrary destination path to a worker and does not rely on path strings remaining stable across a transaction.

## Destination constraints

Every destination must be:

- absolute;
- a strict descendant of `managedRoot`;
- composed only of normal path components;
- physically unique within the manifest.

`managedRoot` itself must be an absolute non-root path containing only normal components. The coordinator never creates a missing managed root.

## Descriptor-based parent walk

Traversal starts from an open descriptor for `/`. Every parent component is opened relative to the previous descriptor with `O_DIRECTORY | O_NOFOLLOW`.

This means:

- a symlinked parent is refused rather than followed;
- a regular file in the parent chain is refused;
- `..` and other non-normal components are rejected;
- later operations remain anchored to the parent object that was actually inspected.

The final component is retained as one `OsString`; workers receive this one component and cannot perform another path walk.

## Parent creation boundary

Two walk modes exist:

- **Refuse** — used by recovery and retirement; never creates anything.
- **Create** — used once at the start of desired entry reconciliation.

Create mode may create only missing components strictly below the existing managed root. User-authority creation runs through the same reduced-privilege worker door as artifact staging.

New directories are created and verified at mode `0755`. If a component already exists as a directory, the worker leaves its mode unchanged.

## Worker process model

Workers reopen an inherited parent descriptor through `/proc/self/fd/<n>`, validate that the requested name is a single normal component, and perform one narrow operation:

- `symlinkat` for a staged link;
- exclusive `openat` plus exact write, `chmod`, and `fsync` for a writable stage;
- `mkdirat` plus exact-mode verification for a directory component.

User-scoped workers are launched through `setpriv`; system-scoped workers execute directly. The inherited parent descriptor intentionally crosses `exec`, while unrelated descriptors use close-on-exec behavior.

Worker stderr may contain a small strict JSON errno envelope. The parent accepts only known operation names and at most 512 bytes, so worker output cannot become an unbounded or invented diagnostic cause.

## Stage naming and cleanup

Entry stages are siblings of their destination:

```text
.furnish.<coordinator-pid>.<manifest-index>.stage
```

Before a new stage is created, a stale unpublished stage under that exact name is removed. A cleanup failure is preserved as a warning attached to the primary failure rather than replacing the original cause.

The coordinator never trusts worker success alone:

- staged symlinks must have the exact expected target;
- staged writable files must be regular files;
- writable bytes must hash to the source hash;
- writable mode must be exactly `0644`.

## Atomic publication

### New destination

The coordinator rechecks absence and publishes with `RENAME_NOREPLACE`. If another object appeared, the transaction refuses replacement and removes only the unpublished stage.

### Existing owned destination

The coordinator uses `RENAME_EXCHANGE`, placing the intended stage at the destination and the displaced object under the stage name. Both sides are then verified against pre-publication evidence.

For writable exchange, the displaced bytes are rehashed. If they changed between observation and publication, the exchange is reversed, both restored sides are verified, and the operation fails as a publish race.

## Displaced-object cleanup

There are two explicit cleanup meanings:

- `VerifiedOwned` — remove an object proven to be the prior Furnish-owned state;
- `PolicyDisplaced` — remove runtime bytes because `source-wins` explicitly authorized it.

These paths remain distinct so policy authority cannot be confused with ownership proof.

## Durability order

A writable worker syncs staged file contents before returning. Publication then follows this order:

1. stage verification;
1. atomic rename or exchange;
1. parent-directory `fsync`;
1. final destination verification;
1. owned-ledger commit.

Pending-ledger intent is committed before staging and publication. The ledger itself syncs staged bytes and its directory name, giving recovery a durable decision record across process death or power loss.

## Exact modes

| Object | Mode |
| --- | --- |
| Created destination parent | `0755` |
| Writable destination/stage | `0644` |
| State directory | `0755` |
| Ledger file/stage | `0644` |
| Lock file request | `0600` |

Modes are set and then observed; they are not left to ambient `umask` assumptions.

## Safety refusals

The coordinator refuses rather than guessing when it encounters:

- a missing managed root;
- a symlink or non-directory in the parent chain;
- a destination equal to or outside its managed root;
- an unrecorded existing destination;
- an owned destination that no longer matches its record;
- a writable record without a baseline;
- ambiguous pending transaction sides;
- a representation transition that would discard edited content.
