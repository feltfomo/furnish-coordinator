# Coordinator architecture

## Runtime position

The Nix compiler emits a deterministic manifest and retains declared source artifacts in the system closure while preserving external link targets as literal paths. The NixOS integration invokes the coordinator with the manifest, state directory, lock name, and `setpriv` path. The coordinator converts that declarative input into guarded filesystem transactions and durable ownership evidence.

```text
Program declarations
        ↓
Furnish Nix compiler
        ↓
validated manifest + retained artifacts
        ↓
furnish-coordinator reconcile
        ↓
destination filesystem + applied-state ledger
```

The coordinator does not discover declarations, choose executors dynamically, or infer managed roots. Those decisions arrive in the manifest and are accepted only when they match a compiled-in qualified executor profile.

## Entry points

`main.rs` removes `argv[0]` and delegates to `furnish_coordinator::run`. `lib.rs` exposes only that process entry and keeps implementation modules private.

`target.rs` owns source retention semantics and validation. External targets never require filesystem access; retained sources keep their replacement availability checks.

`cli.rs` selects one of seven effective command paths:

- `reconcile` — the host-level orchestration command, or a read-only report under `--dry-run`;
- `status` — the same report without `--setpriv`, which it has no use for;
- `release` and `discard` — the two exits from an unresolved retirement;
- `stage-native-symlink` — create one staged symlink;
- `stage-native-writable` — create and sync one staged regular file;
- `create-native-directory` — create one parent component.

The worker commands are internal execution doors, not user APIs. They operate on an inherited parent descriptor and a single normal path component.

The four host-level verbs open the same session: read and validate the manifest, take the host lock, then load the ledger under it. A read-only verb holding the same lock is what keeps a report from being a torn read of a ledger a concurrent run is rewriting.

## Top-level reconciliation order

`reconcile` follows a strict order:

1. Read the manifest bytes.
1. Decode JSON.
1. Preserve the decoded diagnostic code registry.
1. Validate schema and every entry.
1. Open and exclusively lock the host lock file.
1. Load or migrate the ledger while holding the lock.
1. Observe run identity.
1. Reconcile manifest entries in manifest order.
1. Stop on the first failing entry.
1. Sweep ledger records not present in the desired canonical set.
1. Commit successful retirements or unresolved-retirement evidence.
1. Exit successfully only after the full desired pass and retirement sweep finish.

Manifest read and JSON decode failures use a fixed bootstrap diagnostic because the manifest-supplied diagnostic contract is not yet trustworthy. Validation failures can use the decoded registry, but still happen before the lock is created.

## Per-entry flow

Each entry is reconciled through a shared skeleton:

1. Resolve its destination parent once using a descriptor-based walk that may create descendants below the managed root.
1. Recover any pending ledger record before ordinary decision logic.
1. If an owned record changes representation, enter the gated transition path.
1. Otherwise select writable or symlink reconciliation.
1. Make pending intent durable before staging or publishing.
1. Stage through the qualified executor worker.
1. Verify the stage independently.
1. Publish atomically.
1. Verify the final destination and required mode.
1. Commit the resulting owned record.

A pending recovery may first restore or promote old intent and then allow ordinary reconciliation to advance to the current declaration. Recovery and current reconciliation are intentionally separate decisions.

Steps 5 through 10 are one bracket, written once in `reconcile::publication`. Each route supplies only the staging and publication in the middle; the pending commit, the two fault points around it, and the owned commit are not restated per route.

## Durable and deferred ledger changes

A change that a filesystem mutation is about to depend on is durable before it returns. The pending record in the publication bracket is the reason the distinction exists: without it on disk, a crash mid-publication leaves an object no later run can explain.

A change that only records an observation is deferred and flushed once on the way out of the run. These are the paths that publish nothing — a destination already equal to its source, a preserved runtime edit, a runtime-wins decision, an unresolved-retirement marker, and the removal of a record whose destination is already gone. The whole document is rewritten and fsynced on every durable change, so a host whose entries are all settled used to rewrite an N-record document N times.

The flush runs on every exit from a run, including a refused one, so deferring decides when a change becomes durable and never whether it does. Only a crash can lose one, and what is lost is an observation the next run re-derives from the same destination.

## Module boundaries

### `manifest`

Decodes the wire document and validates schema versions, diagnostic codes, executor tuples, lifecycle strategies, authority scopes, canonical identities, managed roots, and duplicate destinations.

### `lock`

Validates a one-component lock name, opens the lock directory without following symlinks, opens the lock file with `NOFOLLOW`, and takes an exclusive `flock`.

### `filesystem`

Provides refusing or creating parent walks, destination observation, exact hashing, stage cleanup, atomic publication, exchange rollback, directory synchronization, and final verification.

Two renames are deliberately distinct. Publication uses the one that removes the stage when the rename fails, since a stage left at a refused publication is an orphan nothing returns for. Recovery uses the bare one, because there the stage holds the bytes being restored and unlinking it would destroy what the restore exists to preserve.

### `executor` and `cli`

Launch reduced-privilege workers, transport bounded errno evidence, parse worker arguments strictly, and implement the three narrow worker operations.

### `ledger`

Owns the in-memory record model, JSON decoding and validation, the v1 and v2 migrations, atomic persistence, the durable-or-deferred write distinction, transaction constructors, and exact prior-owned snapshots.

### `reconcile`

Contains the state machine: symlink handling, writable hash decisions, representation transitions, pending recovery, and retirement.

Two of those decisions are extracted as pure functions of what was observed. `symlink_action` takes the destination observation, the desired target, and the record; `writable_action` takes the three hash equalities and the declared policy. The apply path acts on the answer and the read-only report prints it, which is what makes a dry run unable to describe a decision a real run would not make. Reads are duplicated between the two paths, because reads are not decisions; the decisions are not.

The report walks parents in refusing mode, so describing a run never leaves a directory behind, and it never calls recovery, because recovery writes. A pending record is reported as pending rather than resolved.

### `diagnostic`

Maps internal failure keys through the manifest’s diagnostic registry and emits one-line JSON envelopes with optional provenance, syscall cause, and observed hashes. It also maps each key to a refusal class an activation script can branch on without parsing the envelope. The classes are what an operator would do differently, so a new key joins an existing class rather than adding a code.

### `identity`

Captures the systemd invocation, monotonic uptime, boot ID, and current system generation for newly written records.

### `fault`

Provides feature-gated process-abort boundaries and one reverse-exchange failure seam. The production build compiles these paths to no-ops.

## Ordering and atomicity

Manifest order is behavior: entries reconcile sequentially, and the first failure ends the run. The retirement sweep runs only after every desired entry succeeds. A failure therefore leaves later desired entries and all undeclared records untouched for that run.

Atomic rename protects one destination publication; the run is not an all-or-nothing transaction across all entries. The durable ledger records each successful boundary so a later run can reason from completed work rather than pretending the whole manifest committed together.

## Authority model

System-scoped workers run directly. User-scoped workers are launched through `setpriv` with the declared real/effective user identity, that account's primary group resolved through the system user database, and initialized supplementary groups. The coordinator still owns traversal, observation, policy decisions, publication, verification, and ledger writes.

The authority boundary therefore changes who performs the narrow write, not who controls the transaction.
