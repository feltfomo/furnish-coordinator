# Coordinator reference

## Reconcile command

```text
furnish-coordinator reconcile \
  --manifest <path> \
  --lock-name <one-component-name> \
  --setpriv <path> \
  --state-dir <path> \
  [--lock-dir <path>]
```

`--lock-dir` defaults to `/run/lock`.

The reconcile parser intentionally preserves compatibility behavior:

- option lookup scans overlapping argument pairs;
- unknown option/value pairs are ignored;
- repeated options use the first occurrence;
- a flag-looking string may still serve as the previous option’s value.

All four required options must resolve. Invalid grammar exits `1` silently.

## Internal worker commands

```text
furnish-coordinator stage-native-symlink \
  --parent-fd <fd> --name <component> --target <target>

furnish-coordinator stage-native-writable \
  --parent-fd <fd> --name <component> --source <path>

furnish-coordinator create-native-directory \
  --parent-fd <fd> --name <component>
```

Worker grammar is strict. Unknown, repeated, malformed, or incomplete pairs fail. `--name` must be exactly one normal path component.

## Versions and files

| Contract | Value |
| --- | --- |
| Manifest schema | `2` |
| Diagnostic schema | `1` |
| Ledger schema | `2` |
| Ledger file | `applied-state.json` |
| v1 rollback file | `applied-state.v1.json` |
| Default lock directory | `/run/lock` |

## Executor profiles

| Identity | Protocol | Representation | Lifecycle strategy | Worker |
| --- | ---: | --- | --- | --- |
| `furnish/native-symlink` | `1` | `symlink` | `exact-symlink-target` | `stage-native-symlink` |
| `furnish/native-writable` | `1` | `writable` | `exact-source-content` | `stage-native-writable` |

Both `cleanupStrategy` and `selfHealStrategy` must equal the profile lifecycle strategy.

## Manifest entry fields

```text
schemaVersion
filesystemIdentity.namespace
filesystemIdentity.destination
filesystemIdentity.canonical
authority.scope
authority.identity
managedRoot
onConflict
representation
retainedArtifactTarget
executor.identity
executor.protocolVersion
cleanupStrategy
selfHealStrategy
provenance.declaration
provenance.source
```

Canonical identity must be exactly:

```text
<namespace>:<destination>
```

Authority scope is `user` or `system`. Conflict policy is `error`, `source-wins`, or `runtime-wins`.

## Ledger record fields

```text
destination
appliedArtifactTarget
managedRoot
appliedBy
appliedGeneration
lastSuccessfulReload.invocationId
lastSuccessfulReload.monotonicSeconds
reloadActionIdentity
bootId
state
representation
baselineHash
intendedWitnessHash
appliedOperationGeneration
stageName
priorOwned
unresolvedRetirement
```

`priorOwned` appears only when present. Other optional fields serialize as explicit nulls according to the v2 contract.

## State vocabulary

| Dimension | Values |
| --- | --- |
| Record state | `owned`, `pending` |
| Representation | `symlink`, `writable` |
| Applied operation | `new`, `update`, `repair` |
| Pending intent | apply operation, representation transition |
| Transition | symlink → writable, writable → symlink |

## Ownership proof

| Situation | Owned? |
| --- | --- |
| Existing object, no ledger record | No |
| Matching symlink, no ledger record | No |
| Matching writable bytes, no ledger record | No |
| Ledger record plus exact recorded symlink | Yes |
| Writable record plus exact baseline | Yes |
| Pending record | Transaction evidence, not owned until recovered |

## Writable hash symbols

| Symbol | Meaning |
| --- | --- |
| B | Last recorded writable baseline |
| S | Current declared source content |
| D | Current destination content |

| Condition | Decision |
| --- | --- |
| `D = S = B` | Settled |
| `S = B`, `D ≠ B` | Preserve runtime edit |
| `D = B`, `S ≠ B` | Publish source update |
| `D = S`, `B ≠ S` | Advance stale baseline as recovery |
| All differ | Consult conflict policy |

## Modes

| Object | Exact/requested mode |
| --- | --- |
| Worker-created directory | `0755` |
| Writable stage and destination | `0644` |
| State directory | `0755` |
| Ledger stage and file | `0644` |
| Lock file | `0600` request, never widened by coordinator |

## Publication primitives

| Case | Primitive | Key property |
| --- | --- | --- |
| Destination absent | `renameat2(..., RENAME_NOREPLACE)` | Never replaces an appearing object |
| Destination owned | `renameat2(..., RENAME_EXCHANGE)` | Preserves displaced side for verification |
| Rollback | reverse `RENAME_EXCHANGE` | Restores both names atomically |

## Diagnostic envelope fields

| Field | Presence |
| --- | --- |
| `schemaVersion` | Always |
| `severity` | Always |
| `code` | Always |
| `message` | Always |
| `primary.label` | Always |
| `provenance` | Runtime envelope; object or null |
| `cause` | Runtime envelope; object or null |
| `observed` | Conflict evidence only |

## Run ordering

```text
read → decode → validate → lock → load ledger
     → reconcile entries in order
     → retire undeclared records
     → success
```

The first desired-entry failure stops the run and prevents the retirement sweep.
