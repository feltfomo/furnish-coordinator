# Ledger and recovery

`applied-state.json` is the coordinator’s durable ownership journal. It is not regenerated from the current manifest and it is not safe to delete merely to clear an error. Without the ledger, an existing destination is unowned and cannot be repaired, replaced, or retired based only on equality.

## Ledger document

The current schema is version 2:

```json
{
  "schemaVersion": 2,
  "records": {
    "namespace:/absolute/destination": {
      "destination": "/absolute/destination",
      "appliedArtifactTarget": "/nix/store/...",
      "managedRoot": "/managed/root",
      "appliedBy": "new",
      "appliedGeneration": "/nix/store/...-nixos-system-...",
      "lastSuccessfulReload": {
        "invocationId": "...",
        "monotonicSeconds": 123.0
      },
      "reloadActionIdentity": null,
      "bootId": "...",
      "state": "owned",
      "representation": "writable",
      "baselineHash": "...",
      "intendedWitnessHash": "...",
      "appliedOperationGeneration": 1,
      "stageName": null,
      "unresolvedRetirement": null
    }
  }
}
```

Records are ordered by canonical identity through a `BTreeMap`, producing deterministic bytes.

## Record states

### Owned

An owned record carries:

- `appliedBy`: `new`, `update`, or `repair`;
- optional unresolved-retirement evidence;
- representation and artifact identity;
- writable baseline or symlink witness;
- operation generation and run identity.

For writable entries, `baselineHash` and `intendedWitnessHash` normally match. For symlinks, the witness hashes the target path string, but `baselineHash` remains null because target text is not content stored at the destination.

### Pending

A pending record carries:

- an apply intent or representation-transition intent;
- the intended representation and witness;
- the sibling stage name;
- an optional exact `priorOwned` snapshot.

Pending is durable evidence that a transaction may have changed one or both names. It is not treated as owned until recovery proves the intended publication landed.

## Transaction bracket

A publishing path follows this logical bracket:

```text
observe prior state
    ↓
commit pending + priorOwned + intended witness
    ↓
stage and verify
    ↓
publish and verify
    ↓
commit owned
```

A crash before the pending commit leaves no transaction claim. A crash after it leaves enough evidence for recovery to classify the destination and stage.

## Prior-owned snapshots

`priorOwned` captures the complete earlier ownership record, including representation, artifact, baseline, witness, operation generation, run identity, and unresolved retirement.

If publication did not complete and the current destination still proves that exact prior state, recovery can remove a verified unpublished stage and restore the snapshot byte-for-model rather than synthesizing weaker ownership.

## Apply recovery

Recovery runs before current declaration logic.

### Forward completion

If the destination has the pending representation and exact intended witness, the pending operation is promoted to owned. The operation generation advances once.

If an exchange left a displaced object under the stage name, that side must also be proven:

- a displaced writable file is checked against the recorded baseline;
- a displaced symlink is checked against `priorOwned`;
- a mismatched or unknown object is preserved and refused.

Under `source-wins`, changed displaced writable bytes may be discarded. Otherwise they are restored and the update is refused.

### Prior state remains

If the intended publication did not land but the destination exactly matches `priorOwned`, any verified unpublished stage is removed and the prior record is restored.

### Ambiguous state

If neither forward completion nor prior ownership can be proved, recovery fails with `pending-recovery` and preserves transaction names. This is intentional forensic evidence, not leaked temporary state to clean automatically.

## Transition recovery

Pending transitions encode the direction explicitly:

- symlink to writable;
- writable to symlink.

Recovery verifies the destination representation, intended witness, displaced stage, and prior snapshot together. A completed transition is promoted only after both sides agree with the transaction evidence.

For writable-to-symlink, edited displaced bytes are exchanged back into the destination and preserved. The intended link remains as the cleanup side and is removed only after the restored state is verified.

## Writable crash windows

Important convergent states include:

- pending committed, nothing staged — restore prior ownership;
- stage written but unpublished — verify and remove stage, restore prior ownership;
- exchange landed with pristine displaced bytes — verify both sides and complete;
- exchange landed with edited displaced bytes under `error` — reverse exchange, restore edits, refuse;
- exchange landed with edited displaced bytes under `source-wins` — discard displaced bytes and complete;
- destination already equals intended content with stale owned baseline — verify and advance as recovery.

## Ledger persistence

Every write:

1. serializes the complete v2 document;
1. writes a sibling `.applied-state.<pid>.stage` file;
1. forces mode `0644` and verifies it;
1. writes and syncs the bytes;
1. atomically renames the stage to `applied-state.json`;
1. opens and syncs the state directory.

The state directory is created or normalized to `0755`. An existing stale ledger stage is truncated and normalized before reuse.

## Schema migration

Version 1 records migrate to version 2 as owned symlinks. Transaction and retirement-only fields are cleared. Before the first v2 write, the exact v1 input is retained as:

```text
applied-state.v1.json
```

A ledger newer than version 2 is refused before mutation. Unknown, malformed, or unsupported record fields are validated into the typed model rather than silently interpreted.

## Unresolved retirement

When an undeclared writable destination no longer matches its baseline, the file and record remain. The owned record gains:

- a reason;
- the observed destination hash;
- the recorded baseline hash.

This marker explains why cleanup did not occur. Redeclaration resolves the marker because the destination is once again part of the desired set.
