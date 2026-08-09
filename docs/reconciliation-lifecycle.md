# Reconciliation lifecycle

The coordinator reconciles two representations: `symlink` and `writable`. Both use the same ownership rule: an existing object is managed only when durable ledger evidence and the current filesystem observation agree.

## Applied operations

Owned records identify the branch that last reached the destination:

- `new` — first publication into an absent destination;
- `update` — a declared change or authorized replacement;
- `repair` — restoration of a previously recorded destination that disappeared or whose recorded store target was reaped.

`appliedOperationGeneration` advances only when an apply reaches the destination. A steady observation or `runtime-wins` decision does not increment it.

## Symlink lifecycle

### Absent destination

The coordinator writes pending intent, stages the exact target, verifies the staged link, publishes with `RENAME_NOREPLACE`, verifies the final target, and commits owned state.

An existing prior record classifies this as `repair`; no record classifies it as `new`.

### Exact desired target

A matching symlink is a steady state. If a record exists, applied-state fields are carried forward and run metadata is refreshed. If no record exists, the link is left untouched and remains unowned. Equality is not adoption proof.

### Different observed object

Without a record, replacement is refused. With a record, the current symlink must still point to the target recorded as Furnish-owned. Only then may the coordinator exchange it for the new staged link.

The operation is classified as:

- `update` when the recorded target still resolves;
- `repair` when the recorded target was reaped.

The desired target must resolve before republishing. This avoids manufacturing a broken link while attempting repair.

## Writable lifecycle

Writable decisions compare:

- **B** — the recorded baseline hash;
- **S** — the current source artifact hash;
- **D** — the current destination hash.

A writable record must have a baseline before an existing destination can be reconciled. Without one, every conflict policy refuses because the coordinator cannot prove what it last wrote.

| Relationship | Meaning | Result |
| --- | --- | --- |
| `D = S = B` | Settled | Preserve destination and generation; refresh record metadata |
| `S = B`, `D ≠ B` | Runtime-only edit | Preserve destination; carry applied state |
| `D = B`, `S ≠ B` | Source-only change | Publish update through exchange |
| `D = S`, `B ≠ S` | Publication landed but baseline is stale | Verify destination, advance record as recovery |
| `D ≠ B`, `S ≠ B`, `D ≠ S` | Two-sided divergence | Apply `onConflict` |

An existing regular file with no ledger record is refused even if its bytes equal the source. A non-regular object is also refused.

## Conflict policies

### `error`

Two-sided divergence returns a conflict diagnostic carrying B, S, and D. Neither destination nor ledger is changed.

### `source-wins`

The source is staged and atomically exchanged into place. The displaced runtime bytes may be discarded because the declaration explicitly authorizes source authority. The new source hash becomes both baseline and intended witness.

### `runtime-wins`

The destination remains untouched. The ledger baseline and intended witness advance to the source version that was declined, preventing the same source change from being rediscovered as a new conflict each run. The apply generation does not advance because no publication occurred.

Conflict policy is consulted only for genuine two-sided divergence. A normal source-only update publishes regardless of policy.

## Representation transitions

Transitions are explicit gated transfers, not ordinary reconciliation.

### Symlink to writable

The current destination must be exactly the symlink recorded as Furnish-owned. The coordinator then:

1. hashes the writable source;
1. commits pending transition state with a prior-owned snapshot;
1. stages and verifies the regular file;
1. exchanges the two names;
1. syncs and verifies the destination;
1. removes the displaced recorded link;
1. commits writable owned state.

A foreign or changed link is refused.

### Writable to symlink

The writable record must have a baseline, and current destination bytes must still match it. Edited content is never silently converted away. After proof, the coordinator stages the link, exchanges names, verifies the target, removes the displaced pristine file, and commits symlink owned state.

## Retirement

After every desired entry succeeds, the coordinator compares the manifest’s canonical identities with all ledger records.

### Symlink retirement

A missing destination or a symlink still matching the recorded target is retired. Only the link is removed, never its target. A changed object is refused.

### Writable retirement

A missing destination is already retired. A regular file matching its baseline is removed. An edited regular file is preserved, ownership remains recorded, and an `unresolved-retirement` warning records the reason and observed hash. A changed representation is refused.

Redeclaring an unresolved destination clears the retirement marker through ordinary reconciliation.

### Pending retirement

A pending record with no declaration cannot be safely recovered because its transaction contract is absent. Retirement refuses it and preserves both transaction names.

## Empty manifests and partial runs

An empty manifest means the desired set is empty, so all provably owned records are retired.

If any desired entry fails, the coordinator returns before retirement. Earlier successful entries remain committed, while later entries and undeclared records are untouched. This ordering prevents cleanup from running after an incomplete desired-state pass.
