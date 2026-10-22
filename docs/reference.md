# Coordinator reference

## Reconcile command

```text
furnish-coordinator reconcile \
  --manifest <path> \
  --lock-name <one-component-name> \
  --setpriv <path> \
  --state-dir <path> \
  [--lock-dir <path>] \
  [--dry-run]
```

`--lock-dir` defaults to `/run/lock`.

The reconcile parser intentionally preserves compatibility behavior:

- option lookup scans overlapping argument pairs;
- unknown option/value pairs are ignored;
- repeated options use the first occurrence;
- a flag-looking string may still serve as the previous option’s value.

`--dry-run` is value-less and is scanned rather than paired, so it cannot swallow the argument after it. It takes the host lock and loads the ledger, then prints the report and stops. Nothing is published and nothing is written to applied state.

All four required options must resolve. Invalid grammar exits `2` silently.

## Read-only command

```text
furnish-coordinator status \
  --manifest <path> \
  --lock-name <one-component-name> \
  --state-dir <path> \
  [--lock-dir <path>]
```

`status` is `reconcile --dry-run` without `--setpriv`, which it has no use for because it never launches an executor. It takes the same host lock, so a report is never a torn read of a ledger a concurrent run is rewriting, and it walks parents in refusing mode, so it never creates a directory a real run would.

One tab-separated line per destination on stdout, and one line per record whose destination the manifest no longer declares:

| Word | Meaning |
| --- | --- |
| `settled` | the destination already holds what the declaration asks for |
| `publish` | the name is free and nothing records ownership of it |
| `repair` | the name is free and a record claims it |
| `republish` | an owned symlink would be exchanged for the desired target |
| `replace` | an owned writable file would be exchanged for the source content |
| `transition` | the recorded representation is not the declared one |
| `recover` | a pending record is present and recovery would run first |
| `refused` | a real run would refuse; the diagnostic is emitted as a warning |
| `retire` | the record is undeclared and its destination would be removed |
| `blocked` | the record is undeclared and its retirement is already blocked |

A report does not stop at the first refusal, because the point of asking is to see every destination at once.

The words come from the same two decision cores the apply path calls, so the report cannot name a decision a real run would not reach. `recover` is the one verdict it cannot resolve further: which way recovery would go depends on what recovery finds, and finding out is not a read.

## Resolution commands

```text
furnish-coordinator release|discard \
  --destination <path> \
  --manifest <path> \
  --lock-name <one-component-name> \
  --state-dir <path> \
  [--lock-dir <path>]
```

The only exit from an unresolved retirement. `release` drops the ownership record and leaves the file, which makes the destination foreign; a later declaration of it refuses rather than adopts. `discard` drops both.

Both take the manifest for its diagnostic registry, even though the destination they act on is by definition not declared in it. Both refuse when:

- the manifest still declares the destination;
- applied state records no ownership of it;
- more than one canonical identity records it;
- the record carries no unresolved retirement.

The marker is the authorization. Without it these would be a way to drop ownership of a live destination, or delete a file, without the coordinator ever having decided that retirement was blocked.

`discard` additionally re-reads the file and refuses unless it still hashes to the marker's observed hash. If the destination moved again since the marker was written, the operator would be authorizing the destruction of content they have not seen.

## Exit codes

Refusal classes, not one code per diagnostic. A code per key would make every new key a contract change for anything that reads the status.

| Code | Class | Keys |
| --- | --- | --- |
| `0` | success | — |
| `1` | refused | everything not listed below |
| `2` | usage | unparsable arguments, unreadable or undecodable manifest |
| `3` | ledger | `ledgerUnreadable`, `ledgerInvalid`, `ledgerWriteFailed` |
| `4` | conflict | `conflictingDestination`, `unresolvedRetirement` |
| `5` | interrupted | `pendingRecovery` |

`status` and `reconcile --dry-run` exit `4` when the host does not match its declaration, so an activation script can branch on drift without reading stdout. A refusal in the report decides the status instead, under the class of the first one reported.

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
| Manifest schema written | `3` |
| Manifest schemas accepted | `2`, `3` |
| Diagnostic schema | `1` |
| Ledger schema | `3` |
| Ledger file | `applied-state.json` |
| Rollback file | `applied-state.v<schema>.json` |
| Witness algorithm written | `blake3` |
| Witness algorithms read | `blake3`, `sha256`, untagged hex as `sha256` |
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
target.kind
target.path
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

Schema 3 targets are `{ "kind": "retained" | "external", "path": "..." }`.
External targets require `symlink` and a normalized absolute path distinct from the destination. The target may be absent and is never opened for reconciliation. Schema 2 manifests retain their `retainedArtifactTarget` field and decode as retained sources. Mixed target fields or entry/manifest schema versions are refused. The ledger stays at schema 3 because it records the published link text and representation independently of source retention.

Host verbs accept `--diagnostic-format plain|json`. JSON is the default. Plain output includes severity, diagnostic code, destination, message and any cause or provenance, with the same exit status. Lexicon selects plain output for activation and its service.

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
