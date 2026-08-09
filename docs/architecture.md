# Coordinator architecture

## Runtime position

The Nix compiler emits a deterministic manifest and retains every referenced artifact in the system closure. The NixOS integration invokes the coordinator with the manifest, state directory, lock name, and `setpriv` path. The coordinator converts that declarative input into guarded filesystem transactions and durable ownership evidence.

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

`cli.rs` selects one of four effective command paths:

- `reconcile` — the host-level orchestration command;
- `stage-native-symlink` — create one staged symlink;
- `stage-native-writable` — create and sync one staged regular file;
- `create-native-directory` — create one parent component.

The worker commands are internal execution doors, not user APIs. They operate on an inherited parent descriptor and a single normal path component.

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

## Module boundaries

### `manifest`

Decodes the wire document and validates schema versions, diagnostic codes, executor tuples, lifecycle strategies, authority scopes, canonical identities, managed roots, and duplicate destinations.

### `lock`

Validates a one-component lock name, opens the lock directory without following symlinks, opens the lock file with `NOFOLLOW`, and takes an exclusive `flock`.

### `filesystem`

Provides refusing or creating parent walks, destination observation, exact hashing, stage cleanup, atomic publication, exchange rollback, directory synchronization, and final verification.

### `executor` and `cli`

Launch reduced-privilege workers, transport bounded errno evidence, parse worker arguments strictly, and implement the three narrow worker operations.

### `ledger`

Owns the in-memory record model, JSON decoding and validation, v1 migration, atomic persistence, transaction constructors, and exact prior-owned snapshots.

### `reconcile`

Contains the state machine: symlink handling, writable hash decisions, representation transitions, pending recovery, and retirement.

### `diagnostic`

Maps internal failure keys through the manifest’s diagnostic registry and emits one-line JSON envelopes with optional provenance, syscall cause, and observed hashes.

### `identity`

Captures the systemd invocation, monotonic uptime, boot ID, and current system generation for newly written records.

### `fault`

Provides feature-gated process-abort boundaries and one reverse-exchange failure seam. The production build compiles these paths to no-ops.

## Ordering and atomicity

Manifest order is behavior: entries reconcile sequentially, and the first failure ends the run. The retirement sweep runs only after every desired entry succeeds. A failure therefore leaves later desired entries and all undeclared records untouched for that run.

Atomic rename protects one destination publication; the run is not an all-or-nothing transaction across all entries. The durable ledger records each successful boundary so a later run can reason from completed work rather than pretending the whole manifest committed together.

## Authority model

System-scoped workers run directly. User-scoped workers are launched through `setpriv` with matching real/effective user and group identity plus initialized supplementary groups. The coordinator still owns traversal, observation, policy decisions, publication, verification, and ledger writes.

The authority boundary therefore changes who performs the narrow write, not who controls the transaction.
