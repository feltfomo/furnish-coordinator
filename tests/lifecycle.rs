// characterization of the steady states, the representation transitions,
// and retirement. the binary is driven end to end, with ledgers and
// destinations planted directly.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

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

const PAYLOAD_HASH: &str = "d4e4877bac978b7952f0d544fc52ebff5411d351d129f1f056fa43f11da9af2b";
const OLD_PAYLOAD_HASH: &str = "6b53c9c192925718563767d10eb93b8940d8a9af8d9cc412b154d6209f5a1162";
const NEW_PAYLOAD_HASH: &str = "47e398fd8b576f545397f4b4db4e470b55d4fbe4b4ca219fb0be6abf307e82d0";
const FIRST_HASH: &str = "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41";
const SECOND_HASH: &str = "480c2336b410f1ad5f8bf1b28944490255804b65350c527787e74ebdd511e3a4";
// Opaque planted prior-state token: it is not the hash of current file content.
// Production treats it as ledger evidence rather than deriving it in this test.
const BASELINE_HASH: &str = "3b2c67b04a2403e79a83f3a7aceb95116c1b4c8c1063f0271096c4810348f67d";
const DECLARED_HASH: &str = "a23c9e491c7f53f7ce9ea426ce849525c4373091b668c3c8606ad8859a3b4670";

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
    let mut text = String::from("{\"schemaVersion\":2,\"records\":{\"");
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
            // replaced when production advances the stale baseline.
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
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
    assert_eq!(output.status.code(), Some(1));
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
    assert_eq!(output.status.code(), Some(1));
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
    assert_eq!(output.status.code(), Some(1));
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
    assert_eq!(output.status.code(), Some(1));
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

const USER_EDIT_HASH: &str = "5cac19b153577e104af440b1642d1a89dfcf3d1df00523d5c40ac5738136463a";

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
    assert_eq!(output.status.code(), Some(1));
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
            "{{\"schemaVersion\":2,\"records\":{{\"test:{}\":{},\"test:{}\":{}}}}}",
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
    assert_eq!(output.status.code(), Some(1));
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
    assert_eq!(output.status.code(), Some(1));
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
    assert_eq!(record["intendedWitnessHash"].as_str().unwrap().len(), 64);
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
    assert_eq!(output.status.code(), Some(1));
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
