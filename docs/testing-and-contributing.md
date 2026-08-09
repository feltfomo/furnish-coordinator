# Testing and contributing

The coordinator’s tests are contract tests as much as implementation tests. Many intentionally pin ordering, exact messages, JSON key presence, modes, hashes, and crash boundaries. Refactoring should preserve these behaviors unless the corresponding contract is deliberately changed.

## Integration suites

### `tests/cli.rs`

Characterizes command grammar and worker behavior:

- required reconcile options;
- silent failure for invalid grammar;
- permissive reconcile parsing and first-occurrence wins;
- strict worker parsing;
- inherited parent descriptors;
- exact symlink targets;
- exclusive writable staging and mode `0644`;
- one-component directory names and mode `0755`.

### `tests/characterization.rs`

Pins host-facing filesystem boundaries:

- lock creation, mode, default directory, and symlink refusal;
- destination and managed-root constraints;
- refusal of symlinked or regular-file parents;
- noncreation of a missing managed root;
- controlled creation of descendants below the root.

### `tests/diagnostics.rs`

Pins bootstrap and runtime JSON shapes, registry-selected codes, validation order, provenance, null behavior, syscall cause data, conflict hashes, and the rule that a refused run commits no ledger mutation.

### `tests/lifecycle.rs`

Drives the binary end to end through:

- steady symlink and writable states;
- no-adoption behavior;
- all writable hash relationships and policies;
- updates, repairs, and representation transitions;
- pristine and edited retirement;
- empty-manifest retirement;
- retirement suppression after an entry failure.

### `tests/crash_recovery.rs`

Runs only with `fault-injection`. It causes real process aborts at transaction boundaries and verifies subsequent ordinary-binary recovery, including pending commits, landed exchanges, edited displaced bytes, policy-authorized discard, symlink updates, and legacy pending records.

## Unit-test coverage

Module-local tests cover:

- exact SHA-256 answers, including padding boundaries;
- CLI parser compatibility;
- strict bounded worker evidence;
- lock serialization and `NOFOLLOW` behavior;
- manifest profile uniqueness and duplicate destinations;
- ledger model transitions and exact serialization;
- v1 migration and rollback evidence;
- stale ledger-stage replacement and exact modes;
- destination observation and stage cleanup;
- transition gating and recovery edge cases;
- failure payload size and diagnostic null semantics.

## Fault injection

The `fault-injection` feature enables process death at named boundaries. Production builds compile `fault_point` to an inline no-op.

Important boundaries include:

- `pre-pending`
- `pending-committed`
- `stage-written`
- `stage-synced`
- `exchange-published`
- `published`
- `published-synced`
- `verified`

A separate `reverse-exchange-restore-failed` seam tests preservation when rollback itself fails.

Fault tests use real aborts rather than returned errors so the next process sees the same durable state a crash or power loss would leave.

## Local Rust gate

From the coordinator crate directory:

```fish
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --features fault-injection
```

The repository-level gate should still run afterward from `/etc/skadi`:

```fish
nix fmt
nix flake check -L
```

The Rust commands verify the crate directly; the Nix gate verifies packaging, integration, and repository formatting.

## Change checklist

### Changing the manifest

- Version the manifest schema when wire compatibility changes.
- Update raw decode types, typed validation, Nix emission, diagnostics, and tests together.
- Keep executor qualification a unique tuple of identity, protocol, and representation.
- Reject ambiguity before mutation.

### Adding an executor or representation

- Add a qualified executor profile.
- Define exact staging output and independent verification.
- Define cleanup and self-heal strategy names.
- Extend ledger representation parsing and serialization.
- Define every steady state, conflict, transition, retirement, and recovery path.
- Add no-adoption and crash-boundary tests.

A staging implementation alone is insufficient; lifecycle and recovery semantics are part of the executor contract.

### Changing ledger state

- Treat schema changes as durable protocol changes.
- Preserve downgrade evidence before migration.
- Update exact serialization tests.
- Define how old pending and owned records recover.
- Refuse newer unknown schemas before mutation.

### Changing publication

- Keep stage and destination on the same filesystem.
- Preserve `NOREPLACE` for acquisition and `EXCHANGE` for owned replacement.
- Verify the displaced side after exchange.
- Sync the parent directory before owned commit.
- Add fault points around every newly introduced durable boundary.

### Changing diagnostics

- Keep bootstrap diagnostics independent of manifest decode.
- Keep runtime codes routed through the manifest registry.
- Preserve provenance at entry failures.
- Emit syscall operation and errno only from bounded known evidence.
- Do not let cleanup errors replace the primary failure.

## Review questions

Before accepting a coordinator change, ask:

1. What durable evidence authorizes this mutation?
1. Can a matching foreign object be mistaken for owned state?
1. What happens if the process dies immediately before and after each write or rename?
1. Can recovery prove both sides, or does it guess?
1. Could edited runtime data be discarded without explicit policy?
1. Does a worker receive more path authority than one parent descriptor and one component?
1. Are file and directory modes asserted rather than assumed?
1. Does the retirement sweep still run only after all desired entries succeed?
1. Are the ledger, manifest, and diagnostic contracts still version-aligned?
