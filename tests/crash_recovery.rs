// characterization of the crash boundaries. rows that need a real process
// death run only under the fault-injection build and are inert in the default
// one; everything else plants the state a death would have left and runs the
// ordinary binary against it.
#![cfg(feature = "fault-injection")]

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
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
        "furnish-crash-{name}-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create test directory");
    path
}

fn os<'a>(args: &'a [&'a str]) -> Vec<&'a OsStr> {
    args.iter().map(OsStr::new).collect()
}

const OLD_PAYLOAD_HASH: &str = "6b53c9c192925718563767d10eb93b8940d8a9af8d9cc412b154d6209f5a1162";
const NEW_PAYLOAD_HASH: &str = "47e398fd8b576f545397f4b4db4e470b55d4fbe4b4ca219fb0be6abf307e82d0";
const FIRST_HASH: &str = "b640e840b19d378660b32fb51ae18d67dccb4a8596a29e7bd72c1b2ae5928f41";
const SECOND_HASH: &str = "480c2336b410f1ad5f8bf1b28944490255804b65350c527787e74ebdd511e3a4";

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

fn writable_entry_json(root: &Path, name: &str, source: &Path, on_conflict: &str) -> String {
    let destination = root.join(name);
    format!(
        "{{\"schemaVersion\":2,\"filesystemIdentity\":{{\"namespace\":\"test\",\"destination\":{dest},\"canonical\":\"test:{dest_str}\"}},\"authority\":{{\"scope\":\"system\",\"identity\":\"test/system\"}},\"managedRoot\":{root},\"onConflict\":\"{on_conflict}\",\"representation\":\"writable\",\"retainedArtifactTarget\":{artifact},\"executor\":{{\"identity\":\"furnish/native-writable\",\"protocolVersion\":1}},\"cleanupStrategy\":\"exact-source-content\",\"selfHealStrategy\":\"exact-source-content\",\"provenance\":{{\"declaration\":\"test\",\"source\":\"crash-recovery\"}}}}",
        dest = serde_json::to_string(destination.to_str().unwrap()).unwrap(),
        dest_str = destination.to_str().unwrap(),
        root = serde_json::to_string(root.to_str().unwrap()).unwrap(),
        artifact = serde_json::to_string(source.to_str().unwrap()).unwrap(),
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
    prior_owned: Option<&str>,
) -> String {
    let prior_owned = prior_owned
        .map(|value| format!(",\"priorOwned\":{value}"))
        .unwrap_or_default();
    format!(
        "{{\"destination\":{dest},\"appliedArtifactTarget\":{artifact},\"managedRoot\":{root},\"appliedBy\":\"{applied_by}\",\"appliedGeneration\":null,\"lastSuccessfulReload\":{{\"invocationId\":null,\"monotonicSeconds\":0.0}},\"reloadActionIdentity\":null,\"bootId\":null,\"state\":\"{state}\",\"representation\":\"{representation}\",\"baselineHash\":{baseline},\"intendedWitnessHash\":{witness},\"appliedOperationGeneration\":{generation},\"stageName\":{stage}{prior_owned},\"unresolvedRetirement\":null}}",
        dest = serde_json::to_string(destination.to_str().unwrap()).unwrap(),
        artifact = serde_json::to_string(artifact.to_str().unwrap()).unwrap(),
        root = serde_json::to_string(managed_root.to_str().unwrap()).unwrap(),
        baseline = opt(baseline),
        witness = opt(witness),
        stage = opt(stage),
    )
}

#[allow(clippy::too_many_arguments)]
fn prior_owned_json(
    destination: &Path,
    artifact: &Path,
    managed_root: &Path,
    applied_by: &str,
    representation: &str,
    baseline: Option<&str>,
    witness: Option<&str>,
    generation: u64,
) -> String {
    serde_json::json!({
        "destination": destination,
        "appliedArtifactTarget": artifact,
        "managedRoot": managed_root,
        "appliedBy": applied_by,
        "appliedGeneration": serde_json::Value::Null,
        "lastSuccessfulReload": {
            "invocationId": serde_json::Value::Null,
            "monotonicSeconds": 0.0
        },
        "reloadActionIdentity": serde_json::Value::Null,
        "bootId": serde_json::Value::Null,
        "representation": representation,
        "baselineHash": baseline,
        "intendedWitnessHash": witness,
        "appliedOperationGeneration": generation,
        "unresolvedRetirement": serde_json::Value::Null
    })
    .to_string()
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

fn run_reconcile(dir: &Path, fault_point: Option<&str>) -> Output {
    let lock = dir.join("lock");
    fs::create_dir_all(&lock).expect("create lock dir");
    let mut command = Command::new(coordinator());
    command.args(os(&[
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
    ]));
    if let Some(fault_point) = fault_point {
        command.env("FURNISH_FAULT_POINT", fault_point);
    }
    command.output().expect("run coordinator")
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
fn a_writable_update_death_after_the_pending_commit_restores_prior_ownership() {
    // a death with the pending record committed and nothing staged restores
    // the exact prior-owned snapshot before ordinary reconciliation resumes.
    let dir = unique_dir("update-death");
    let source = dir.join("source");
    fs::write(&source, "first\n").expect("write source");
    let destination = dir.join("value");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    let established = run_reconcile(&dir, None);
    assert_eq!(established.status.code(), Some(0));
    fs::write(&source, "second\n").expect("bump source");
    let crashed = run_reconcile(&dir, Some("pending-committed"));
    assert!(!crashed.status.success());
    let pending = record_at(&dir, &destination);
    assert_eq!(pending["state"], "pending");
    assert_eq!(pending["appliedBy"], "update");
    assert_eq!(pending["baselineHash"], FIRST_HASH);
    assert_eq!(pending["intendedWitnessHash"], SECOND_HASH);
    assert!(pending["stageName"].is_string());
    assert!(pending["priorOwned"].is_object());
    assert_eq!(fs::read(&destination).unwrap(), b"first\n");
    fs::write(&source, "first\n").expect("restore declared source");
    let recovered = run_reconcile(&dir, None);
    assert_eq!(recovered.status.code(), Some(0));
    assert!(recovered.stderr.is_empty());
    assert_eq!(fs::read(&destination).unwrap(), b"first\n");
    let record = record_at(&dir, &destination);
    assert_eq!(record["state"], "owned");
    assert_eq!(record["appliedBy"], "new");
    assert_eq!(record["baselineHash"], FIRST_HASH);
    assert_eq!(record["intendedWitnessHash"], FIRST_HASH);
    assert_eq!(record["appliedOperationGeneration"], 1);
    assert_eq!(record["stageName"], serde_json::Value::Null);
    assert!(record.get("priorOwned").is_none());
}

#[test]
fn recovery_promotes_a_legacy_pending_record_after_forward_completion() {
    // prior-owned is absent in this planted legacy record, but exact forward
    // completion is sufficient to promote it without reconstructing the past.
    let dir = unique_dir("legacy-forward");
    let source = dir.join("source");
    fs::write(&source, "new payload\n").expect("write source");
    let destination = dir.join("value");
    fs::write(&destination, "new payload\n").expect("plant published content");
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
            "update",
            "pending",
            "writable",
            Some(OLD_PAYLOAD_HASH),
            Some(NEW_PAYLOAD_HASH),
            7,
            Some(".furnish.dead.0.stage"),
            None,
        ),
    );
    let output = run_reconcile(&dir, None);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let record = record_at(&dir, &destination);
    assert_eq!(record["state"], "owned");
    assert_eq!(record["appliedBy"], "update");
    assert_eq!(record["baselineHash"], NEW_PAYLOAD_HASH);
    assert_eq!(record["intendedWitnessHash"], NEW_PAYLOAD_HASH);
    assert_eq!(record["appliedOperationGeneration"], 8);
    assert_eq!(record["stageName"], serde_json::Value::Null);
}

#[test]
fn a_death_after_the_exchange_with_edited_displaced_bytes_restores_and_refuses() {
    // the stage may hold displaced user bytes, so recovery hashes it before
    // anything unlinks it. an edited file goes back to the destination and
    // the update is refused.
    let dir = unique_dir("exchange-edited");
    let source = dir.join("source");
    fs::write(&source, "first\n").expect("write source");
    let destination = dir.join("value");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    let established = run_reconcile(&dir, None);
    assert_eq!(established.status.code(), Some(0));
    fs::write(&source, "second\n").expect("bump source");
    let crashed = run_reconcile(&dir, Some("exchange-published"));
    assert!(!crashed.status.success());
    // simulate the edit landing while the process was dead.
    let stage = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .find(|name| name.starts_with(".furnish.") && name.ends_with(".stage"))
        .expect("a displaced stage survived the crash");
    fs::write(dir.join(&stage), "the user edited this\n").expect("edit the displaced bytes");
    let recovered = run_reconcile(&dir, None);
    assert_eq!(recovered.status.code(), Some(1));
    let diagnostic = stderr_line(&recovered);
    assert_eq!(diagnostic["code"], "runtime/pending-recovery");
    assert_eq!(fs::read(&destination).unwrap(), b"the user edited this\n");
    assert!(fs::read_dir(&dir).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".furnish.")
    }));
    let record = record_at(&dir, &destination);
    assert_eq!(record["state"], "owned");
    assert_eq!(record["baselineHash"], FIRST_HASH);
    assert_eq!(record["intendedWitnessHash"], FIRST_HASH);
}

#[test]
fn a_death_after_the_exchange_with_pristine_displaced_bytes_completes_the_update() {
    let dir = unique_dir("exchange-pristine");
    let source = dir.join("source");
    fs::write(&source, "first\n").expect("write source");
    let destination = dir.join("value");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "error")
        )),
    )
    .expect("write manifest");
    let established = run_reconcile(&dir, None);
    assert_eq!(established.status.code(), Some(0));
    fs::write(&source, "second\n").expect("bump source");
    let crashed = run_reconcile(&dir, Some("exchange-published"));
    assert!(!crashed.status.success());
    let recovered = run_reconcile(&dir, None);
    assert_eq!(recovered.status.code(), Some(0));
    assert_eq!(fs::read(&destination).unwrap(), b"second\n");
    let record = record_at(&dir, &destination);
    assert_eq!(record["state"], "owned");
    assert_eq!(record["baselineHash"], SECOND_HASH);
    assert_eq!(record["intendedWitnessHash"], SECOND_HASH);
    assert!(fs::read_dir(&dir).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".furnish.")
    }));
}

fn symlink_entry_json(root: &Path, name: &str, target: &Path) -> String {
    let destination = root.join(name);
    format!(
        "{{\"schemaVersion\":2,\"filesystemIdentity\":{{\"namespace\":\"test\",\"destination\":{dest},\"canonical\":\"test:{dest_str}\"}},\"authority\":{{\"scope\":\"system\",\"identity\":\"test/system\"}},\"managedRoot\":{root},\"onConflict\":\"error\",\"representation\":\"symlink\",\"retainedArtifactTarget\":{artifact},\"executor\":{{\"identity\":\"furnish/native-symlink\",\"protocolVersion\":1}},\"cleanupStrategy\":\"exact-symlink-target\",\"selfHealStrategy\":\"exact-symlink-target\",\"provenance\":{{\"declaration\":\"test\",\"source\":\"crash-recovery\"}}}}",
        dest = serde_json::to_string(destination.to_str().unwrap()).unwrap(),
        dest_str = destination.to_str().unwrap(),
        root = serde_json::to_string(root.to_str().unwrap()).unwrap(),
        artifact = serde_json::to_string(target.to_str().unwrap()).unwrap(),
    )
}

#[test]
fn an_owned_symlink_update_death_after_the_pending_commit_restores_prior_ownership() {
    let dir = unique_dir("symlink-pending");
    let recorded_target = dir.join("recorded-target");
    fs::write(&recorded_target, b"recorded").expect("create recorded target");
    let desired_target = dir.join("desired-target");
    fs::write(&desired_target, b"desired").expect("create desired target");
    let destination = dir.join("value");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            symlink_entry_json(&dir, "value", &recorded_target)
        )),
    )
    .expect("write recorded manifest");
    let established = run_reconcile(&dir, None);
    assert_eq!(established.status.code(), Some(0));
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            symlink_entry_json(&dir, "value", &desired_target)
        )),
    )
    .expect("write desired manifest");

    let crashed = run_reconcile(&dir, Some("pending-committed"));

    assert!(!crashed.status.success());
    let pending = record_at(&dir, &destination);
    assert_eq!(pending["state"], "pending");
    assert_eq!(pending["appliedBy"], "update");
    assert_eq!(
        pending["priorOwned"]["appliedArtifactTarget"],
        recorded_target.to_str().unwrap()
    );
    assert_eq!(fs::read_link(&destination).unwrap(), recorded_target);
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            symlink_entry_json(&dir, "value", &recorded_target)
        )),
    )
    .expect("restore recorded manifest");

    let recovered = run_reconcile(&dir, None);

    assert_eq!(recovered.status.code(), Some(0));
    assert_eq!(fs::read_link(&destination).unwrap(), recorded_target);
    let record = record_at(&dir, &destination);
    assert_eq!(record["state"], "owned");
    assert_eq!(record["appliedBy"], "new");
    assert!(record.get("priorOwned").is_none());
}

#[test]
fn a_death_after_an_owned_symlink_exchange_removes_the_displaced_link_on_recovery() {
    let dir = unique_dir("symlink-exchange");
    let recorded_target = dir.join("recorded-target");
    fs::write(&recorded_target, b"recorded").expect("create recorded target");
    let desired_target = dir.join("desired-target");
    fs::write(&desired_target, b"desired").expect("create desired target");
    let destination = dir.join("value");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            symlink_entry_json(&dir, "value", &recorded_target)
        )),
    )
    .expect("write recorded manifest");
    let established = run_reconcile(&dir, None);
    assert_eq!(established.status.code(), Some(0));
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            symlink_entry_json(&dir, "value", &desired_target)
        )),
    )
    .expect("write desired manifest");

    let crashed = run_reconcile(&dir, Some("exchange-published"));

    assert!(!crashed.status.success());
    assert_eq!(fs::read_link(&destination).unwrap(), desired_target);
    let pending = record_at(&dir, &destination);
    assert_eq!(pending["state"], "pending");
    assert_eq!(pending["appliedBy"], "update");
    assert!(pending["priorOwned"].is_object());
    let stage = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .find(|name| name.starts_with(".furnish.") && name.ends_with(".stage"))
        .expect("the displaced link survived the crash");
    assert_eq!(fs::read_link(dir.join(&stage)).unwrap(), recorded_target);

    let recovered = run_reconcile(&dir, None);

    assert_eq!(recovered.status.code(), Some(0));
    assert_eq!(fs::read_link(&destination).unwrap(), desired_target);
    assert!(fs::symlink_metadata(dir.join(&stage)).is_err());
    let record = record_at(&dir, &destination);
    assert_eq!(record["state"], "owned");
    assert_eq!(record["appliedBy"], "update");
    assert!(record.get("priorOwned").is_none());
}

#[test]
fn a_landed_owned_symlink_exchange_removes_the_verified_displaced_link() {
    let dir = unique_dir("landed-exchange");
    // the literal target path strings hash to FIRST_HASH and SECOND_HASH by construction.
    let recorded_target = Path::new("first\n");
    let desired_target = Path::new("second\n");
    let destination = dir.join("value");
    std::os::unix::fs::symlink(desired_target, &destination).expect("plant exchanged destination");
    let stage = ".furnish.9999.0.stage";
    std::os::unix::fs::symlink(recorded_target, dir.join(stage))
        .expect("plant displaced recorded link");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            symlink_entry_json(&dir, "value", desired_target)
        )),
    )
    .expect("write manifest");
    let prior_owned = prior_owned_json(
        &destination,
        recorded_target,
        &dir,
        "new",
        "symlink",
        None,
        Some(FIRST_HASH),
        0,
    );
    plant_ledger(
        &dir,
        &format!("test:{}", destination.to_str().unwrap()),
        &record_json(
            &destination,
            desired_target,
            &dir,
            "update",
            "pending",
            "symlink",
            None,
            Some(SECOND_HASH),
            0,
            Some(stage),
            Some(&prior_owned),
        ),
    );
    let output = run_reconcile(&dir, None);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(fs::read_link(&destination).unwrap(), desired_target);
    let record = record_at(&dir, &destination);
    assert_eq!(
        record["appliedArtifactTarget"],
        desired_target.to_str().unwrap()
    );
    assert_eq!(record["appliedBy"], "update");
    assert_eq!(record["state"], "owned");
    assert_eq!(record["intendedWitnessHash"], SECOND_HASH);
    assert!(record.get("priorOwned").is_none());
    assert!(fs::symlink_metadata(dir.join(stage)).is_err());
}

#[test]
fn a_death_after_the_exchange_with_edited_displaced_bytes_discards_under_source_wins() {
    // the same displaced-edit state, but the declaration authorizes
    // discarding it. the stage is removed without a restore and the update
    // completes.
    let dir = unique_dir("exchange-source-wins");
    let source = dir.join("source");
    fs::write(&source, "first\n").expect("write source");
    let destination = dir.join("value");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            writable_entry_json(&dir, "value", &source, "source-wins")
        )),
    )
    .expect("write manifest");
    let established = run_reconcile(&dir, None);
    assert_eq!(established.status.code(), Some(0));
    fs::write(&source, "second\n").expect("bump source");
    let crashed = run_reconcile(&dir, Some("exchange-published"));
    assert!(!crashed.status.success());
    let stage = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .find(|name| name.starts_with(".furnish.") && name.ends_with(".stage"))
        .expect("a displaced stage survived the crash");
    fs::write(dir.join(&stage), "the user edited this\n").expect("edit the displaced bytes");
    let recovered = run_reconcile(&dir, None);
    assert_eq!(recovered.status.code(), Some(0));
    assert_eq!(fs::read(&destination).unwrap(), b"second\n");
    let record = record_at(&dir, &destination);
    assert_eq!(record["state"], "owned");
    assert_eq!(record["baselineHash"], SECOND_HASH);
    assert!(fs::read_dir(&dir).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".furnish.")
    }));
}
