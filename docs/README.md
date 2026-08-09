# Furnish coordinator

The Furnish coordinator is the privileged runtime that reconciles a validated Furnish manifest with the host filesystem. It is not the declaration compiler and it is not a general file-copy utility. The Nix side decides the desired declarations, executor tuple, lifecycle strategy, diagnostic codes, and retained artifacts; the coordinator enforces that contract at activation and service time.

This documentation is for maintainers, reviewers, and operators diagnosing runtime behavior. Normal configuration should continue through Program and the Nix-facing Furnish layer rather than by invoking coordinator workers directly.

## Responsibilities

The coordinator owns the runtime side of these guarantees:

- validate the manifest before taking a lock or mutating state;
- serialize host reconciliation under one lock;
- treat the ledger as ownership evidence rather than a cache;
- traverse destination parents without following symlinks;
- perform user-scoped writes through a reduced-privilege worker;
- stage and independently verify every artifact;
- publish with atomic rename operations;
- make pending intent durable before changing a destination;
- recover interrupted publications conservatively;
- preserve runtime edits unless policy explicitly authorizes replacement;
- retire only artifacts still provably Furnish-owned;
- emit machine-readable diagnostics using the manifest’s code registry.

## Documentation map

- [Architecture](architecture.md) — process boundaries, module map, and top-level run order.
- [Reconciliation lifecycle](reconciliation-lifecycle.md) — symlinks, writable files, conflict policies, transitions, and retirement.
- [Filesystem safety](filesystem-safety.md) — descriptor traversal, workers, staging, publication, and modes.
- [Ledger and recovery](ledger-and-recovery.md) — ownership records, pending transactions, crash recovery, and migration.
- [Diagnostics and operations](diagnostics-and-operations.md) — JSON diagnostics, failure boundaries, and operator interpretation.
- [Testing and contributing](testing-and-contributing.md) — test layers, fault injection, and change invariants.
- [Reference](reference.md) — commands, schemas, constants, states, and quick tables.

The surrounding Nix-facing documentation remains in [Furnish](../README.md), [architecture](../architecture.md), [declaration contract](../declaration-contract.md), and [runtime integration](../runtime-integration.md).

## Source map

```text
coordinator/
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── cli.rs
│   ├── diagnostic.rs
│   ├── executor.rs
│   ├── fault.rs
│   ├── hash.rs
│   ├── identity.rs
│   ├── lock.rs
│   ├── manifest.rs
│   ├── filesystem/
│   │   ├── mod.rs
│   │   ├── observe.rs
│   │   ├── parent.rs
│   │   ├── publish.rs
│   │   └── stage.rs
│   ├── ledger/
│   │   ├── mod.rs
│   │   ├── migration.rs
│   │   ├── model.rs
│   │   ├── persistence.rs
│   │   └── transaction.rs
│   └── reconcile/
│       ├── mod.rs
│       ├── context.rs
│       ├── recovery.rs
│       ├── retirement.rs
│       ├── symlink.rs
│       ├── transition.rs
│       └── writable.rs
└── tests/
    ├── characterization.rs
    ├── cli.rs
    ├── crash_recovery.rs
    ├── diagnostics.rs
    └── lifecycle.rs
```

## Core trust model

A matching filesystem object is not ownership evidence. Ownership comes from a durable ledger record plus an exact observation that agrees with that record. This prevents Furnish from adopting, replacing, or deleting an unrelated object merely because it happens to match the current declaration.

Likewise, a worker’s successful exit status is not sufficient evidence. The coordinator reopens and verifies the staged object before publication, verifies the published object afterward, and commits owned state only after those checks succeed.

## Stable invariants

Changes should preserve these invariants unless the wire and lifecycle contracts are intentionally versioned:

1. Validation happens before locking and mutation.
1. Ledger reads and writes happen under the host lock.
1. Missing managed roots are refused; only descendants below an existing root may be created.
1. Parent traversal never follows symlinks.
1. Pending state is durable before publication.
1. Owned state is committed only after final verification.
1. Unrecorded existing destinations are never silently adopted.
1. Edited writable content is never removed during ordinary retirement.
1. Ambiguous recovery preserves transaction names and fails rather than guessing.
1. An empty manifest is a real empty desired set, not a no-op.
