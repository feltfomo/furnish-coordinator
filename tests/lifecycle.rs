// characterization of the steady states, the representation transitions,
// and retirement. the binary is driven end to end, with ledgers and
// destinations planted directly.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

// the classes the coordinator exits with. a bare number in an assertion
// stops saying which kind of refusal the test is about.
const EXIT_REFUSED: i32 = 1;
const EXIT_CONFLICT: i32 = 4;

fn coordinator() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_furnish-coordinator"))
}

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn unique_dir(name: &str) -> PathBuf {
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "furnish-life-{name}-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create test directory");
    path
}

fn os<'a>(args: &'a [&'a str]) -> Vec<&'a OsStr> {
    args.iter().map(OsStr::new).collect()
}

// Witnesses carry the name of the hash that produced them, and every witness a
// schema 3 ledger holds is blake3. These are reference digests of the payloads
// below, not values copied out of this crate's own output.
const PAYLOAD_HASH: &str =
    "blake3:d58a7a4a1898506d5ccdca5cec0184d35d75e42ce82c17daf46d75b5f905fcb0";
const OLD_PAYLOAD_HASH: &str =
    "blake3:0c2611ccc1f9773c37871e353b6efdf7584ef5556b09b6a34f9b33c65a9d47e8";
const NEW_PAYLOAD_HASH: &str =
    "blake3:cba3f8e817c5f802a01fcd6b9ce9e33435f21f26f6ad6577963ee68125010044";
const FIRST_HASH: &str = "blake3:dbada8e50433646218ab917906cb7d5402e83c34fcd9c2ef6fd9069d04fbb494";
const SECOND_HASH: &str = "blake3:a74e619132c4c530d0d738f3cceddefaf06a79aad18b5be1a3bcbc054c1f3f84";
// Opaque planted prior-state token: it is not the hash of current file content.
// Production treats it as ledger evidence rather than deriving it in this test.
// It still has to name an algorithm, because a witness that names none is
// refused as an unreadable record rather than read as a mismatch.
const BASELINE_HASH: &str =
    "blake3:3b2c67b04a2403e79a83f3a7aceb95116c1b4c8c1063f0271096c4810348f67d";
const DECLARED_HASH: &str =
    "blake3:fe94c0fc24eb262d34a5c2fea3dbbbfd675c7f3f9eac08906e0e223a2093a5df";

fn codes_json() -> &'static str {
    concat!(
        "\"invalidManifest\":\"runtime/invalid-manifest\",",
        "\"unsupportedExecutor\":\"runtime/unsupported-executor\",",
        "\"invalidDestination\":\"runtime/invalid-destination\",",
        "\"parentTraversal\":\"runtime/parent-traversal\",",
        "\"conflictingDestination\":\"runtime/conflicting-destination\",",
        "\"executorFailed\":\"runtime/executor-failed\",",
        "\"stagingVerification\":\"runtime/staging-verification\",",
        "\"publishRace\":\"runtime/publish-race\",",
        "\"finalVerification\":\"runtime/final-verification\",",
        "\"ledgerUnreadable\":\"runtime/ledger-unreadable\",",
        "\"ledgerInvalid\":\"runtime/ledger-invalid\",",
        "\"ledgerWriteFailed\":\"runtime/ledger-write-failed\",",
        "\"repairVerification\":\"runtime/repair-verification\",",
        "\"unresolvableDesiredTarget\":\"runtime/unresolvable-desired-target\",",
        "\"contentVerification\":\"runtime/content-verification\",",
        "\"transitionRefused\":\"runtime/transition-refused\",",
        "\"unresolvedRetirement\":\"runtime/unresolved-retirement\",",
        "\"pendingRecovery\":\"runtime/pending-recovery\""
    )
}

fn manifest_json(entries: &str) -> String {
    format!(
        "{{\"schemaVersion\":2,\"diagnosticContract\":{{\"schemaVersion\":1,\"codes\":{{{}}}}},\"entries\":{}}}",
        codes_json(),
        entries
    )
}

fn entry_json(
    root: &Path,
    name: &str,
    artifact: &Path,
    representation: &str,
    executor: &str,
    strategy: &str,
    on_conflict: &str,
) -> String {
    let destination = root.join(name);
    format!(
        "{{\"schemaVersion\":2,\"filesystemIdentity\":{{\"namespace\":\"test\",\"destination\":{dest},\"canonical\":\"test:{dest_str}\"}},\"authority\":{{\"scope\":\"system\",\"identity\":\"test/system\"}},\"managedRoot\":{root},\"onConflict\":\"{on_conflict}\",\"representation\":\"{representation}\",\"retainedArtifactTarget\":{artifact},\"executor\":{{\"identity\":\"{executor}\",\"protocolVersion\":1}},\"cleanupStrategy\":\"{strategy}\",\"selfHealStrategy\":\"{strategy}\",\"provenance\":{{\"declaration\":\"test\",\"source\":\"lifecycle\"}}}}",
        dest = serde_json::to_string(destination.to_str().unwrap()).unwrap(),
        dest_str = destination.to_str().unwrap(),
        root = serde_json::to_string(root.to_str().unwrap()).unwrap(),
        artifact = serde_json::to_string(artifact.to_str().unwrap()).unwrap(),
    )
}

fn writable_entry_json(root: &Path, name: &str, source: &Path, on_conflict: &str) -> String {
    entry_json(
        root,
        name,
        source,
        "writable",
        "furnish/native-writable",
        "exact-source-content",
        on_conflict,
    )
}

fn symlink_entry_json(root: &Path, name: &str, target: &Path) -> String {
    entry_json(
        root,
        name,
        target,
        "symlink",
        "furnish/native-symlink",
        "exact-symlink-target",
        "error",
    )
}

fn opt(value: Option<&str>) -> String {
    match value {
        Some(value) => format!("\"{value}\""),
        None => "null".to_owned(),
    }
}

#[allow(clippy::too_many_arguments)]
fn record_json(
    destination: &Path,
    artifact: &Path,
    managed_root: &Path,
    applied_by: &str,
    state: &str,
    representation: &str,
    baseline: Option<&str>,
    witness: Option<&str>,
    generation: u64,
    stage: Option<&str>,
) -> String {
    format!(
        "{{\"destination\":{dest},\"appliedArtifactTarget\":{artifact},\"managedRoot\":{root},\"appliedBy\":\"{applied_by}\",\"appliedGeneration\":null,\"lastSuccessfulReload\":{{\"invocationId\":null,\"monotonicSeconds\":0.0}},\"reloadActionIdentity\":null,\"bootId\":null,\"state\":\"{state}\",\"representation\":\"{representation}\",\"baselineHash\":{baseline},\"intendedWitnessHash\":{witness},\"appliedOperationGeneration\":{generation},\"stageName\":{stage},\"unresolvedRetirement\":null}}",
        dest = serde_json::to_string(destination.to_str().unwrap()).unwrap(),
        artifact = serde_json::to_string(artifact.to_str().unwrap()).unwrap(),
        root = serde_json::to_string(managed_root.to_str().unwrap()).unwrap(),
        baseline = opt(baseline),
        witness = opt(witness),
        stage = opt(stage),
    )
}

fn plant_ledger(dir: &Path, canonical: &str, record: &str) {
    let state = dir.join("state");
    fs::create_dir_all(&state).expect("create state dir");
    let mut text = String::from("{\"schemaVersion\":3,\"records\":{\"");
    text.push_str(canonical);
    text.push_str("\":");
    text.push_str(record);
    text.push_str("}}");
    fs::write(state.join("applied-state.json"), text).expect("plant ledger");
}

fn run_reconcile(dir: &Path) -> Output {
    let lock = dir.join("lock");
    fs::create_dir_all(&lock).expect("create lock dir");
    Command::new(coordinator())
        .args(os(&[
            "reconcile",
            "--manifest",
            dir.join("manifest.json").to_str().unwrap(),
            "--lock-name",
            "test.lock",
            "--setpriv",
            "/nonexistent/setpriv",
            "--state-dir",
            dir.join("state").to_str().unwrap(),
            "--lock-dir",
            lock.to_str().unwrap(),
        ]))
        .output()
        .expect("run coordinator")
}

// the read-only and resolution verbs take the same manifest, lock, and state
// directory the apply path takes, so one helper drives all of them.
fn run_verb(dir: &Path, verb: &str, extra: &[&str]) -> Output {
    let lock = dir.join("lock");
    fs::create_dir_all(&lock).expect("create lock dir");
    let manifest = dir.join("manifest.json");
    let state = dir.join("state");
    let mut args = vec![
        verb,
        "--manifest",
        manifest.to_str().unwrap(),
        "--lock-name",
        "test.lock",
        "--state-dir",
        state.to_str().unwrap(),
        "--lock-dir",
        lock.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    Command::new(coordinator())
        .args(os(&args))
        .output()
        .expect("run coordinator")
}

fn report_lines(output: &Output) -> Vec<String> {
    String::from_utf8(output.stdout.clone())
        .expect("stdout utf8")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn read_ledger(dir: &Path) -> serde_json::Value {
    serde_json::from_str(
        &fs::read_to_string(dir.join("state").join("applied-state.json")).expect("read ledger"),
    )
    .expect("ledger parses")
}

fn record_at(dir: &Path, destination: &Path) -> serde_json::Value {
    let ledger = read_ledger(dir);
    ledger["records"][format!("test:{}", destination.to_str().unwrap())].clone()
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
}

fn stderr_line(output: &Output) -> serde_json::Value {
    let text = String::from_utf8(output.stderr.clone()).expect("stderr utf8");
    serde_json::from_str(text.lines().next().expect("one diagnostic line"))
        .expect("diagnostic parses")
}

#[test]
fn an_owned_symlink_at_the_declared_target_is_a_steady_state() {
    let dir = unique_dir("symlink-steady");
    let target = dir.join("target");
    fs::write(&target, b"live").expect("create link target");
    let destination = dir.join("value");
    std::os::unix::fs::symlink(&target, &destination).expect("plant destination link");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!("[{}]", symlink_entry_json(&dir, "value", &target))),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &target,
            &dir,
            "new",
            "owned",
            "symlink",
            None,
            None,
            3,
            None,
        ),
    );
    let before = fs::symlink_metadata(&destination).unwrap().ino();
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    // nothing was published: the link is the same object and the generation
    // the record carried is the generation it keeps.
    assert_eq!(fs::symlink_metadata(&destination).unwrap().ino(), before);
    assert_eq!(fs::read_link(&destination).unwrap(), target);
    let record = record_at(&dir, &destination);
    assert_eq!(record["appliedOperationGeneration"], 3);
    assert_eq!(record["state"], "owned");
}

#[test]
fn an_exact_symlink_without_a_record_is_not_adopted() {
    let dir = unique_dir("symlink-no-adopt");
    let target = dir.join("target");
    fs::write(&target, b"live").expect("create link target");
    let destination = dir.join("value");
    std::os::unix::fs::symlink(&target, &destination).expect("plant destination link");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!("[{}]", symlink_entry_json(&dir, "value", &target))),
    )
    .expect("write manifest");
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(fs::read_link(&destination).unwrap(), target);
    // Absence is the evidence that the exact unrecorded symlink was not adopted.
    assert!(!dir.join("state").join("applied-state.json").exists());
}

#[test]
fn a_settled_writable_destination_is_refreshed_without_advancing() {
    let dir = unique_dir("writable-settled");
    let source = dir.join("source");
    fs::write(&source, "payload\n").expect("write source");
    let destination = dir.join("value");
    fs::write(&destination, "payload\n").expect("plant destination");
    set_mode(&destination, 0o644);
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(PAYLOAD_HASH),
            Some(PAYLOAD_HASH),
            5,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(fs::read(&destination).unwrap(), b"payload\n");
    let record = record_at(&dir, &destination);
    assert_eq!(record["appliedOperationGeneration"], 5);
    assert_eq!(record["baselineHash"], PAYLOAD_HASH);
}

#[test]
fn an_edit_under_an_unchanged_source_is_preserved() {
    let dir = unique_dir("writable-edit");
    let source = dir.join("source");
    fs::write(&source, "payload\n").expect("write source");
    let destination = dir.join("value");
    fs::write(&destination, "user edit\n").expect("plant edited destination");
    set_mode(&destination, 0o644);
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(PAYLOAD_HASH),
            Some(PAYLOAD_HASH),
            5,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(fs::read(&destination).unwrap(), b"user edit\n");
    let record = record_at(&dir, &destination);
    assert_eq!(record["appliedOperationGeneration"], 5);
    assert_eq!(record["baselineHash"], PAYLOAD_HASH);
}

#[test]
fn a_stale_baseline_advances_as_recovery_without_a_conflict() {
    // the destination already equals the source while the recorded baseline
    // does not: the crash window between publish and commit, converged here
    // rather than reported as a conflict.
    let dir = unique_dir("stale-baseline");
    let source = dir.join("source");
    fs::write(&source, "payload\n").expect("write source");
    let destination = dir.join("value");
    fs::write(&destination, "payload\n").expect("plant destination");
    set_mode(&destination, 0o644);
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            // Opaque planted mismatch token: it names no file content and is
            // replaced when production advances the stale baseline. The
            // algorithm tag is still required, since a witness naming none is
            // refused as unreadable rather than treated as a stale baseline.
            Some("blake3:0000000000000000000000000000000000000000000000000000000000000000"),
            None,
            3,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let record = record_at(&dir, &destination);
    assert_eq!(record["baselineHash"], PAYLOAD_HASH);
    assert_eq!(record["intendedWitnessHash"], PAYLOAD_HASH);
    assert_eq!(record["appliedOperationGeneration"], 4);
}

#[test]
fn runtime_wins_settles_the_conflict_without_publishing() {
    let dir = unique_dir("runtime-wins");
    let source = dir.join("source");
    fs::write(&source, "declared\n").expect("write source");
    let destination = dir.join("value");
    fs::write(&destination, "edited\n").expect("plant edited destination");
    set_mode(&destination, 0o644);
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "runtime-wins")
        )),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(BASELINE_HASH),
            Some(BASELINE_HASH),
            5,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(fs::read(&destination).unwrap(), b"edited\n");
    let record = record_at(&dir, &destination);
    // the baseline advances to the source that was refused so the same
    // conflict is not rediscovered every run; nothing was applied, so the
    // counter does not move with it.
    assert_eq!(record["baselineHash"], DECLARED_HASH);
    assert_eq!(record["intendedWitnessHash"], DECLARED_HASH);
    assert_eq!(record["appliedOperationGeneration"], 5);
}

#[test]
fn the_error_policy_refuses_a_two_sided_divergence_and_commits_nothing() {
    let dir = unique_dir("error-policy");
    let source = dir.join("source");
    fs::write(&source, "declared\n").expect("write source");
    let destination = dir.join("value");
    fs::write(&destination, "edited\n").expect("plant edited destination");
    set_mode(&destination, 0o644);
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(BASELINE_HASH),
            Some(BASELINE_HASH),
            5,
            None,
        ),
    );
    let before = fs::read_to_string(dir.join("state").join("applied-state.json")).unwrap();
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(EXIT_CONFLICT));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["code"], "runtime/conflicting-destination");
    assert_eq!(fs::read(&destination).unwrap(), b"edited\n");
    assert_eq!(
        fs::read_to_string(dir.join("state").join("applied-state.json")).unwrap(),
        before
    );
}

#[test]
fn source_wins_publishes_through_the_update_route() {
    let dir = unique_dir("source-wins");
    let source = dir.join("source");
    fs::write(&source, "declared\n").expect("write source");
    let destination = dir.join("value");
    fs::write(&destination, "edited\n").expect("plant edited destination");
    set_mode(&destination, 0o644);
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "source-wins")
        )),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(BASELINE_HASH),
            Some(BASELINE_HASH),
            5,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(fs::read(&destination).unwrap(), b"declared\n");
    let record = record_at(&dir, &destination);
    assert_eq!(record["baselineHash"], DECLARED_HASH);
    assert_eq!(record["intendedWitnessHash"], DECLARED_HASH);
    assert_eq!(record["appliedOperationGeneration"], 6);
}

#[test]
fn a_destination_equal_to_the_source_without_a_record_is_refused() {
    // equality is not adoption proof: an identical destination furnish never
    // recorded is refused rather than claimed.
    let dir = unique_dir("no-adopt");
    let source = dir.join("source");
    fs::write(&source, "payload\n").expect("write source");
    let destination = dir.join("value");
    fs::write(&destination, "payload\n").expect("plant destination");
    set_mode(&destination, 0o644);
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(EXIT_CONFLICT));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["code"], "runtime/conflicting-destination");
    assert_eq!(
        diagnostic["message"],
        "refusing to take ownership of a pre-existing destination: applied state records no furnish ownership of it"
    );
    // Absence is the evidence that the equal unrecorded file was not adopted.
    assert!(!dir.join("state").join("applied-state.json").exists());
}

#[test]
fn an_ordinary_update_publishes_when_only_the_source_moved() {
    // the destination is still exactly the baseline and only the source
    // moved, so the policy is never consulted. declaring error and watching
    // the publish land is what proves that.
    let dir = unique_dir("ordinary-update");
    let source = dir.join("source");
    fs::write(&source, "second\n").expect("write source");
    let destination = dir.join("value");
    fs::write(&destination, "first\n").expect("plant destination");
    set_mode(&destination, 0o644);
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(FIRST_HASH),
            Some(FIRST_HASH),
            0,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(fs::read(&destination).unwrap(), b"second\n");
    let record = record_at(&dir, &destination);
    assert_eq!(record["baselineHash"], SECOND_HASH);
    assert_eq!(record["intendedWitnessHash"], SECOND_HASH);
    assert_eq!(record["appliedOperationGeneration"], 1);
}

#[test]
fn a_writable_destination_without_a_recorded_baseline_is_refused_under_every_policy() {
    let dir = unique_dir("no-baseline");
    let source = dir.join("source");
    fs::write(&source, "declared\n").expect("write source");
    let destination = dir.join("value");
    fs::write(&destination, "edited\n").expect("plant edited destination");
    set_mode(&destination, 0o644);
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "source-wins")
        )),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            None,
            None,
            5,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(EXIT_CONFLICT));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["code"], "runtime/conflicting-destination");
    assert_eq!(
        diagnostic["message"],
        "refusing to reconcile a writable destination with no recorded baseline"
    );
    assert_eq!(fs::read(&destination).unwrap(), b"edited\n");
}

#[test]
fn a_destination_that_is_not_a_regular_file_is_refused() {
    let dir = unique_dir("non-regular");
    let source = dir.join("source");
    fs::write(&source, "payload\n").expect("write source");
    let target = dir.join("target");
    fs::write(&target, b"live").expect("create link target");
    let destination = dir.join("value");
    std::os::unix::fs::symlink(&target, &destination).expect("plant symlink destination");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(PAYLOAD_HASH),
            Some(PAYLOAD_HASH),
            5,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(EXIT_CONFLICT));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["code"], "runtime/conflicting-destination");
    assert_eq!(
        diagnostic["message"],
        "refusing a destination that is not a regular file"
    );
    assert_eq!(fs::read_link(&destination).unwrap(), target);
}

#[test]
fn an_undeclared_owned_symlink_is_retired() {
    let dir = unique_dir("retire-symlink");
    let target = dir.join("target");
    fs::write(&target, b"live").expect("create link target");
    let destination = dir.join("value");
    std::os::unix::fs::symlink(&target, &destination).expect("plant destination link");
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &target,
            &dir,
            "new",
            "owned",
            "symlink",
            None,
            None,
            0,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(fs::symlink_metadata(&destination).is_err());
    // retirement removes what furnish published, never what it pointed at.
    assert!(target.is_file());
    let ledger = read_ledger(&dir);
    assert_eq!(ledger["records"].as_object().unwrap().len(), 0);
}

#[test]
fn an_undeclared_pristine_writable_is_retired() {
    let dir = unique_dir("retire-writable");
    let source = dir.join("source");
    let destination = dir.join("value");
    fs::write(&destination, "payload\n").expect("plant pristine destination");
    set_mode(&destination, 0o644);
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(PAYLOAD_HASH),
            Some(PAYLOAD_HASH),
            0,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(!destination.exists());
    let ledger = read_ledger(&dir);
    assert_eq!(ledger["records"].as_object().unwrap().len(), 0);
}

const USER_EDIT_HASH: &str =
    "blake3:7cd1f44542aa41323cd7aea0ae2952dddb46c28e84a6d07aa06c01e44aa5bb74";

#[test]
fn an_edited_writable_is_never_deleted_and_its_retirement_is_recorded() {
    // edited data is never deleted to satisfy cleanup: the file stays, the
    // record stays to explain it, the warning is emitted, and the run still
    // exits 0.
    let dir = unique_dir("retire-edited");
    let source = dir.join("source");
    let destination = dir.join("value");
    fs::write(&destination, "the user edited this\n").expect("plant edited destination");
    set_mode(&destination, 0o644);
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(PAYLOAD_HASH),
            Some(PAYLOAD_HASH),
            0,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["severity"], "warning");
    assert_eq!(diagnostic["code"], "runtime/unresolved-retirement");
    assert!(
        diagnostic["message"]
            .as_str()
            .unwrap()
            .starts_with("retirement is blocked: ")
    );
    assert_eq!(fs::read(&destination).unwrap(), b"the user edited this\n");
    let record = record_at(&dir, &destination);
    assert_eq!(record["state"], "owned");
    assert_eq!(
        record["unresolvedRetirement"]["reason"],
        "writable destination no longer matches its baseline"
    );
    assert_eq!(
        record["unresolvedRetirement"]["observedHash"],
        USER_EDIT_HASH
    );
    assert_eq!(record["unresolvedRetirement"]["baselineHash"], PAYLOAD_HASH);
}

#[test]
fn redeclaring_after_an_unresolved_retirement_resolves_it() {
    let dir = unique_dir("retire-redeclare");
    let source = dir.join("source");
    let destination = dir.join("value");
    fs::write(&destination, "the user edited this\n").expect("plant edited destination");
    set_mode(&destination, 0o644);
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(PAYLOAD_HASH),
            Some(PAYLOAD_HASH),
            0,
            None,
        ),
    );
    let first = run_reconcile(&dir);
    assert_eq!(first.status.code(), Some(0));
    // declared again, the destination reconciles under the same baseline and
    // the marker is carried nowhere.
    fs::write(&source, "payload\n").expect("write source");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    let second = run_reconcile(&dir);
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(fs::read(&destination).unwrap(), b"the user edited this\n");
    let record = record_at(&dir, &destination);
    assert_eq!(record["baselineHash"], PAYLOAD_HASH);
    assert_eq!(record["unresolvedRetirement"], serde_json::Value::Null);
}

#[test]
fn retirement_refuses_a_destination_that_stopped_matching_its_record() {
    let dir = unique_dir("retire-refused");
    let recorded = dir.join("recorded-target");
    fs::write(&recorded, b"live").expect("create recorded target");
    let other = dir.join("other-target");
    fs::write(&other, b"other").expect("create other target");
    let destination = dir.join("value");
    std::os::unix::fs::symlink(&other, &destination).expect("plant replaced link");
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &recorded,
            &dir,
            "new",
            "owned",
            "symlink",
            None,
            None,
            0,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(EXIT_CONFLICT));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["code"], "runtime/conflicting-destination");
    assert_eq!(
        diagnostic["message"],
        "refusing to retire a destination that is no longer the link recorded as furnish-owned"
    );
    assert_eq!(fs::read_link(&destination).unwrap(), other);
}

#[test]
fn an_empty_manifest_retires_everything() {
    // a manifest with no entries is a real desired set, not a no-op.
    let dir = unique_dir("retire-all");
    let source = dir.join("source");
    let first = dir.join("value-a");
    let second = dir.join("value-b");
    for destination in [&first, &second] {
        fs::write(destination, "payload\n").expect("plant destination");
        set_mode(destination, 0o644);
    }
    let state = dir.join("state");
    fs::create_dir_all(&state).expect("create state dir");
    fs::write(
        state.join("applied-state.json"),
        format!(
            "{{\"schemaVersion\":3,\"records\":{{\"test:{}\":{},\"test:{}\":{}}}}}",
            first.to_str().unwrap(),
            record_json(
                &first,
                &source,
                &dir,
                "new",
                "owned",
                "writable",
                Some(PAYLOAD_HASH),
                Some(PAYLOAD_HASH),
                0,
                None
            ),
            second.to_str().unwrap(),
            record_json(
                &second,
                &source,
                &dir,
                "new",
                "owned",
                "writable",
                Some(PAYLOAD_HASH),
                Some(PAYLOAD_HASH),
                0,
                None
            ),
        ),
    )
    .expect("plant ledger");
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(!first.exists());
    assert!(!second.exists());
    let ledger = read_ledger(&dir);
    assert_eq!(ledger["records"].as_object().unwrap().len(), 0);
}

#[test]
fn a_failing_entry_means_the_retirement_sweep_never_runs() {
    // the entry loop returns on the first failure and the sweep is downstream
    // of it, so an undeclared owned record survives a failed run untouched.
    let dir = unique_dir("sweep-skipped");
    let source = dir.join("source");
    fs::write(&source, "payload\n").expect("write source");
    let failing = dir.join("failing");
    fs::write(&failing, "foreign").expect("plant foreign destination");
    let undeclared = dir.join("undeclared");
    let target = dir.join("target");
    fs::write(&target, b"live").expect("create link target");
    std::os::unix::fs::symlink(&target, &undeclared).expect("plant undeclared link");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "failing", &source, "error")
        )),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", undeclared.to_str().unwrap()),
        &record_json(
            &undeclared,
            &target,
            &dir,
            "new",
            "owned",
            "symlink",
            None,
            None,
            0,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(EXIT_CONFLICT));
    assert_eq!(fs::read_link(&undeclared).unwrap(), target);
    let record = record_at(&dir, &undeclared);
    assert_eq!(record["state"], "owned");
}

fn stage_files_in(dir: &Path) -> usize {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".furnish."))
        .count()
}

#[test]
fn a_transfer_from_symlink_to_writable_lands_when_the_record_matches() {
    let dir = unique_dir("to-writable");
    let old_target = dir.join("old-target");
    fs::write(&old_target, b"live").expect("create old target");
    let destination = dir.join("value");
    std::os::unix::fs::symlink(&old_target, &destination).expect("plant destination link");
    let source = dir.join("source");
    fs::write(&source, "new payload\n").expect("write source");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &old_target,
            &dir,
            "new",
            "owned",
            "symlink",
            None,
            None,
            2,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(fs::read(&destination).unwrap(), b"new payload\n");
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o7777,
        0o644
    );
    let record = record_at(&dir, &destination);
    assert_eq!(record["representation"], "writable");
    assert_eq!(record["baselineHash"], NEW_PAYLOAD_HASH);
    assert_eq!(record["intendedWitnessHash"], NEW_PAYLOAD_HASH);
    assert_eq!(record["appliedOperationGeneration"], 3);
    assert_eq!(stage_files_in(&dir), 0);
    // unlinking a symlink never touches its pointee.
    assert!(old_target.is_file());
}

#[test]
fn a_transfer_from_symlink_to_writable_requires_the_recorded_link() {
    let dir = unique_dir("to-writable-refused");
    let recorded = dir.join("recorded-target");
    fs::write(&recorded, b"live").expect("create recorded target");
    let other = dir.join("other-target");
    fs::write(&other, b"other").expect("create other target");
    let destination = dir.join("value");
    std::os::unix::fs::symlink(&other, &destination).expect("plant foreign link");
    let source = dir.join("source");
    fs::write(&source, "new payload\n").expect("write source");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &recorded,
            &dir,
            "new",
            "owned",
            "symlink",
            None,
            None,
            2,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(EXIT_REFUSED));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["code"], "runtime/transition-refused");
    assert_eq!(
        diagnostic["message"],
        "refusing to transfer a destination that is not the link recorded as furnish-owned"
    );
    assert_eq!(fs::read_link(&destination).unwrap(), other);
}

#[test]
fn a_transfer_from_writable_to_symlink_lands_when_the_destination_is_pristine() {
    let dir = unique_dir("to-symlink");
    let source = dir.join("source");
    let destination = dir.join("value");
    fs::write(&destination, "old payload\n").expect("plant pristine destination");
    set_mode(&destination, 0o644);
    let target = dir.join("target");
    fs::write(&target, b"live").expect("create link target");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!("[{}]", symlink_entry_json(&dir, "value", &target))),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(OLD_PAYLOAD_HASH),
            Some(OLD_PAYLOAD_HASH),
            2,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(fs::read_link(&destination).unwrap(), target);
    let record = record_at(&dir, &destination);
    assert_eq!(record["representation"], "symlink");
    // a path string is not content at the destination, so a symlink record
    // carries no baseline and its witness hashes the target string.
    assert_eq!(record["baselineHash"], serde_json::Value::Null);
    // the target string is a test path, so the digest is not pinned here, but
    // the witness still has to name the hash that produced it.
    let witness = record["intendedWitnessHash"].as_str().unwrap();
    assert!(witness.starts_with("blake3:"));
    assert_eq!(witness.len(), "blake3:".len() + 64);
    assert_eq!(record["appliedOperationGeneration"], 3);
    assert_eq!(stage_files_in(&dir), 0);
}

#[test]
fn a_transfer_from_writable_to_symlink_refuses_an_edited_destination() {
    let dir = unique_dir("to-symlink-refused");
    let source = dir.join("source");
    let destination = dir.join("value");
    fs::write(&destination, "the user edited this\n").expect("plant edited destination");
    set_mode(&destination, 0o644);
    let target = dir.join("target");
    fs::write(&target, b"live").expect("create link target");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!("[{}]", symlink_entry_json(&dir, "value", &target))),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(OLD_PAYLOAD_HASH),
            Some(OLD_PAYLOAD_HASH),
            2,
            None,
        ),
    );
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(EXIT_REFUSED));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["code"], "runtime/transition-refused");
    assert_eq!(
        diagnostic["message"],
        "refusing to transfer a writable destination that no longer matches its baseline"
    );
    assert_eq!(fs::read(&destination).unwrap(), b"the user edited this\n");
    let record = record_at(&dir, &destination);
    assert_eq!(record["representation"], "writable");
    assert_eq!(record["baselineHash"], OLD_PAYLOAD_HASH);
    assert_eq!(stage_files_in(&dir), 0);
}

#[test]
fn a_settled_host_reports_nothing_to_do_and_a_drifted_one_reports_the_verb() {
    let dir = unique_dir("status-settled");
    let target = dir.join("target");
    fs::write(&target, b"live").expect("create link target");
    let destination = dir.join("value");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!("[{}]", symlink_entry_json(&dir, "value", &target))),
    )
    .expect("write manifest");
    fs::create_dir_all(dir.join("state")).expect("create state dir");

    // nothing is planted, so the name is free and no record claims it.
    let drifted = run_verb(&dir, "status", &[]);
    assert_eq!(drifted.status.code(), Some(EXIT_CONFLICT));
    assert_eq!(
        report_lines(&drifted),
        vec![format!("publish\t{}", destination.to_str().unwrap())]
    );
    // reading is not deciding: the report left the destination alone.
    assert!(fs::symlink_metadata(&destination).is_err());
    assert!(!dir.join("state").join("applied-state.json").exists());

    std::os::unix::fs::symlink(&target, &destination).expect("plant destination link");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &target,
            &dir,
            "new",
            "owned",
            "symlink",
            None,
            None,
            3,
            None,
        ),
    );
    let settled = run_verb(&dir, "status", &[]);
    assert_eq!(settled.status.code(), Some(0));
    assert_eq!(
        report_lines(&settled),
        vec![format!("settled\t{}", destination.to_str().unwrap())]
    );
}

#[test]
fn a_status_report_never_creates_the_parent_a_run_would_make() {
    // the apply path walks with creation enabled, so a missing directory is
    // not drift it reports but work it does. the report has to reach the same
    // verdict without leaving the directory behind.
    let dir = unique_dir("status-parent");
    let target = dir.join("target");
    fs::write(&target, b"live").expect("create link target");
    let nested = dir.join("nested");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            symlink_entry_json(&dir, "nested/value", &target)
        )),
    )
    .expect("write manifest");
    fs::create_dir_all(dir.join("state")).expect("create state dir");
    let output = run_verb(&dir, "status", &[]);
    assert_eq!(output.status.code(), Some(EXIT_CONFLICT));
    assert_eq!(
        report_lines(&output),
        vec![format!(
            "publish\t{}",
            nested.join("value").to_str().unwrap()
        )]
    );
    assert!(!nested.exists());
}

#[test]
fn a_dry_run_reports_the_replacement_it_would_make_and_writes_nothing() {
    let dir = unique_dir("dry-run");
    let source = dir.join("source");
    fs::write(&source, "new payload\n").expect("write source");
    let destination = dir.join("value");
    fs::write(&destination, "payload\n").expect("plant destination");
    set_mode(&destination, 0o644);
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(PAYLOAD_HASH),
            Some(PAYLOAD_HASH),
            4,
            None,
        ),
    );
    let planted = fs::read_to_string(dir.join("state").join("applied-state.json"))
        .expect("read planted ledger");
    let output = run_verb(
        &dir,
        "reconcile",
        &["--setpriv", "/nonexistent/setpriv", "--dry-run"],
    );
    assert_eq!(output.status.code(), Some(EXIT_CONFLICT));
    assert_eq!(
        report_lines(&output),
        vec![format!("replace\t{}", destination.to_str().unwrap())]
    );
    assert_eq!(fs::read(&destination).unwrap(), b"payload\n");
    assert_eq!(
        fs::read_to_string(dir.join("state").join("applied-state.json")).unwrap(),
        planted
    );
}

// the marked record the resolution verbs act on is produced rather than
// planted, because the marker is the authorization and a planted one would
// prove nothing about the path that writes it.
fn block_a_retirement(name: &str) -> (PathBuf, PathBuf) {
    let dir = unique_dir(name);
    let source = dir.join("source");
    let destination = dir.join("value");
    fs::write(&destination, "the user edited this\n").expect("plant edited destination");
    set_mode(&destination, 0o644);
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &source,
            &dir,
            "new",
            "owned",
            "writable",
            Some(PAYLOAD_HASH),
            Some(PAYLOAD_HASH),
            0,
            None,
        ),
    );
    assert_eq!(run_reconcile(&dir).status.code(), Some(0));
    assert_eq!(
        record_at(&dir, &destination)["unresolvedRetirement"]["observedHash"],
        USER_EDIT_HASH
    );
    (dir, destination)
}

#[test]
fn release_drops_the_ownership_record_and_leaves_the_file() {
    let (dir, destination) = block_a_retirement("release");
    let output = run_verb(
        &dir,
        "release",
        &["--destination", destination.to_str().unwrap()],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(fs::read(&destination).unwrap(), b"the user edited this\n");
    assert!(record_at(&dir, &destination).is_null());
    // the destination is foreign now, so a later status of a manifest that
    // declares it again would refuse rather than adopt it.
    let repeated = run_verb(
        &dir,
        "release",
        &["--destination", destination.to_str().unwrap()],
    );
    assert_eq!(repeated.status.code(), Some(EXIT_CONFLICT));
}

#[test]
fn discard_refuses_content_that_changed_after_the_retirement_was_blocked() {
    let (dir, destination) = block_a_retirement("discard-moved");
    fs::write(&destination, "edited again\n").expect("edit past the marker");
    let refused = run_verb(
        &dir,
        "discard",
        &["--destination", destination.to_str().unwrap()],
    );
    assert_eq!(refused.status.code(), Some(EXIT_REFUSED));
    assert_eq!(
        stderr_line(&refused)["code"],
        "runtime/content-verification"
    );
    assert!(destination.exists());
    assert!(!record_at(&dir, &destination).is_null());

    fs::write(&destination, "the user edited this\n").expect("restore the reported content");
    let discarded = run_verb(
        &dir,
        "discard",
        &["--destination", destination.to_str().unwrap()],
    );
    assert_eq!(discarded.status.code(), Some(0));
    assert!(!destination.exists());
    assert!(record_at(&dir, &destination).is_null());
}

#[test]
fn the_resolution_verbs_refuse_a_destination_the_manifest_still_declares() {
    let dir = unique_dir("resolve-declared");
    let target = dir.join("target");
    fs::write(&target, b"live").expect("create link target");
    let destination = dir.join("value");
    std::os::unix::fs::symlink(&target, &destination).expect("plant destination link");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!("[{}]", symlink_entry_json(&dir, "value", &target))),
    )
    .expect("write manifest");
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            &target,
            &dir,
            "new",
            "owned",
            "symlink",
            None,
            None,
            3,
            None,
        ),
    );
    for verb in ["release", "discard"] {
        let output = run_verb(
            &dir,
            verb,
            &["--destination", destination.to_str().unwrap()],
        );
        assert_eq!(output.status.code(), Some(EXIT_CONFLICT));
        assert_eq!(
            stderr_line(&output)["code"],
            "runtime/conflicting-destination"
        );
        assert!(fs::symlink_metadata(&destination).is_ok());
    }
}
