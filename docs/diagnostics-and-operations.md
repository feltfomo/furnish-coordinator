# Diagnostics and operations

The coordinator writes one-line JSON diagnostics to stderr. Successful runs are normally silent, except that an unresolved retirement is a warning and still exits successfully.

## Bootstrap diagnostics

Manifest read and decode failures happen before the manifest’s diagnostic registry can be trusted. They use a fixed envelope:

```json
{
  "schemaVersion": 1,
  "severity": "error",
  "code": "furnish/runtime-bootstrap",
  "message": "cannot read manifest: ...",
  "primary": {
    "label": "/path/to/manifest.json"
  }
}
```

Bootstrap failures happen before lock acquisition, so they do not create a lock file or state directory.

## Runtime diagnostic envelope

After decode, failures use the manifest-supplied code strings:

```json
{
  "schemaVersion": 1,
  "severity": "error",
  "code": "runtime/conflicting-destination",
  "message": "...",
  "primary": {
    "label": "/managed/value"
  },
  "provenance": {
    "declaration": "...",
    "source": "..."
  },
  "cause": {
    "operation": "read-destination",
    "errno": 13
  },
  "observed": {
    "baseline": "...",
    "source": "...",
    "destination": "..."
  }
}
```

`provenance` and `cause` are present as null when unavailable. `observed` is emitted only for conflict diagnostics carrying the B/S/D hash evidence.

A cleanup failure may be emitted as a secondary warning after the primary error. Cleanup never hides the original transaction failure.

## Diagnostic registry

The manifest supplies strings for these semantic keys:

- `invalidManifest`
- `unsupportedExecutor`
- `invalidDestination`
- `parentTraversal`
- `conflictingDestination`
- `executorFailed`
- `stagingVerification`
- `publishRace`
- `finalVerification`
- `ledgerUnreadable`
- `ledgerInvalid`
- `ledgerWriteFailed`
- `repairVerification`
- `unresolvableDesiredTarget`
- `contentVerification`
- `transitionRefused`
- `unresolvedRetirement`
- `pendingRecovery`

The Rust code selects the semantic key; the Nix manifest controls the externally rendered code string.

## Exit behavior

| Situation | Exit | Typical stderr |
| --- | --- | --- |
| Successful settled run | `0` | Empty |
| Successful apply or repair | `0` | Empty |
| Unresolved edited-file retirement | `0` | Warning JSON |
| Invalid CLI grammar | `1` | Empty |
| Manifest bootstrap failure | `1` | Bootstrap JSON |
| Validation or runtime refusal | `1` | Runtime JSON |
| Worker failure when invoked internally | `1` | Bounded evidence consumed by parent |

Every intentional process result is success or failure; there are no specialized exit codes.

## Reading common failures

### `invalid-manifest`

Look for schema mismatch, canonical identity mismatch, invalid authority scope, lifecycle-strategy mismatch, malformed managed root, duplicate canonical identity, or an unsafe lock name.

### `unsupported-executor`

The tuple of executor identity, protocol version, and representation does not match exactly one compiled profile. Fix the Nix/compiler contract rather than changing runtime state.

### `invalid-destination` or `parent-traversal`

Check that the destination is a strict descendant of an existing managed root and that every existing parent is a real directory, not a symlink or file.

### `conflicting-destination`

The coordinator lacks ownership proof, observed a changed object, found no writable baseline, or encountered genuine two-sided divergence under `error`. For writable divergence, inspect the emitted baseline, source, and destination hashes.

### `publish-race`

The destination changed after observation or appeared before publication. The coordinator either refused `NOREPLACE` or reversed an exchange after proving the displaced bytes changed.

### `pending-recovery`

The ledger records an interrupted transaction whose forward or prior state cannot be proved. Preserve the destination, stage, ledger, and diagnostic together when investigating.

### `unresolved-retirement`

This is a nonfatal warning. The declaration disappeared, but an edited writable file was preserved. The ledger retains ownership and the observed hash so the orphan remains explained.

### `ledger-invalid`

Do not delete or hand-edit the ledger as a first response. A newer schema, malformed record, or unsupported state can remove the coordinator’s ability to prove ownership. Preserve the file and diagnose the version or field error.

## Operational evidence to collect

For a runtime incident, collect:

1. the exact JSON diagnostic line or lines;
1. the active manifest;
1. `applied-state.json` and any `applied-state.v1.json` rollback copy;
1. destination type, target or content hash, and mode;
1. any sibling `.furnish.*.stage` object;
1. current system generation and service invocation context.

Do not unlink a surviving stage until its relationship to a pending record is understood. Recovery may need both transaction names to distinguish forward completion from rollback.

## Safe operator posture

- Prefer correcting the declaration or filesystem condition and rerunning reconciliation.
- Do not treat a matching unrecorded destination as safe to adopt.
- Do not replace an edited writable file merely to clear an unresolved retirement.
- Do not manually advance hashes or change a pending record to owned.
- Back up transaction objects and the ledger before any manual recovery experiment.
- Keep diagnostic code changes coordinated with the Nix manifest contract.
