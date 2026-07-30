// characterization of the diagnostic surface: the bootstrap shape the
// manifest cannot describe, the validation refusals, and the exact key set of
// a runtime diagnostic.

use std::ffi::OsStr;
use std::fs;
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
        "furnish-diag-{name}-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create test directory");
    path
}

fn os<'a>(args: &'a [&'a str]) -> Vec<&'a OsStr> {
    args.iter().map(OsStr::new).collect()
}

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

fn writable_entry_json(root: &Path, name: &str, source: &Path) -> String {
    let destination = root.join(name);
    format!(
        "{{\"schemaVersion\":2,\"filesystemIdentity\":{{\"namespace\":\"test\",\"destination\":{dest},\"canonical\":\"test:{dest_str}\"}},\"authority\":{{\"scope\":\"system\",\"identity\":\"test/system\"}},\"managedRoot\":{root},\"onConflict\":\"error\",\"representation\":\"writable\",\"retainedArtifactTarget\":{source},\"executor\":{{\"identity\":\"furnish/native-writable\",\"protocolVersion\":1}},\"cleanupStrategy\":\"exact-source-content\",\"selfHealStrategy\":\"exact-source-content\",\"provenance\":{{\"declaration\":\"test\",\"source\":\"diagnostics\"}}}}",
        dest = serde_json::to_string(destination.to_str().unwrap()).unwrap(),
        dest_str = destination.to_str().unwrap(),
        root = serde_json::to_string(root.to_str().unwrap()).unwrap(),
        source = serde_json::to_string(source.to_str().unwrap()).unwrap(),
    )
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

fn stderr_line(output: &Output) -> serde_json::Value {
    let text = String::from_utf8(output.stderr.clone()).expect("stderr utf8");
    let mut lines = text.lines();
    let first = lines.next().expect("one diagnostic line");
    let value: serde_json::Value = serde_json::from_str(first).expect("diagnostic parses");
    assert!(lines.next().is_none(), "exactly one diagnostic line");
    value
}

#[test]
fn an_unreadable_manifest_produces_the_bootstrap_shape_and_no_lock() {
    let dir = unique_dir("unreadable");
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(1));
    let diagnostic = stderr_line(&output);
    let object = diagnostic.as_object().unwrap();
    let mut keys: Vec<&String> = object.keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["code", "message", "primary", "schemaVersion", "severity"]
    );
    assert_eq!(diagnostic["schemaVersion"], 1);
    assert_eq!(diagnostic["severity"], "error");
    assert_eq!(diagnostic["code"], "furnish/runtime-bootstrap");
    assert!(
        diagnostic["message"]
            .as_str()
            .unwrap()
            .starts_with("cannot read manifest: ")
    );
    assert!(
        diagnostic["primary"]["label"]
            .as_str()
            .unwrap()
            .ends_with("manifest.json")
    );
    // the lock is acquired only after the manifest validates, so a bootstrap
    // failure leaves no lock file behind.
    assert!(!dir.join("lock").join("test.lock").exists());
}

#[test]
fn an_undecodable_manifest_produces_the_bootstrap_shape_and_no_lock() {
    let dir = unique_dir("undecodable");
    fs::write(dir.join("manifest.json"), "not json").expect("write manifest");
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(1));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["code"], "furnish/runtime-bootstrap");
    assert!(
        diagnostic["message"]
            .as_str()
            .unwrap()
            .starts_with("cannot decode manifest: ")
    );
    assert!(!dir.join("lock").join("test.lock").exists());
}

#[test]
fn a_manifest_missing_a_code_fails_to_decode() {
    let dir = unique_dir("missing-code");
    let manifest = "{\"schemaVersion\":2,\"diagnosticContract\":{\"schemaVersion\":1,\"codes\":{\"invalidManifest\":\"x\"}},\"entries\":[]}";
    fs::write(dir.join("manifest.json"), manifest).expect("write manifest");
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(1));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["code"], "furnish/runtime-bootstrap");
}

#[test]
fn an_unsupported_manifest_schema_is_refused_with_the_manifest_label() {
    let dir = unique_dir("schema");
    let manifest = manifest_json("[]").replace("\"schemaVersion\":2", "\"schemaVersion\":99");
    fs::write(dir.join("manifest.json"), manifest).expect("write manifest");
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(1));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["code"], "runtime/invalid-manifest");
    assert_eq!(
        diagnostic["message"],
        "manifest schema 99 is unsupported; expected 2"
    );
    assert_eq!(diagnostic["primary"]["label"], "manifest");
    assert!(diagnostic.get("provenance").is_some());
    assert!(diagnostic["provenance"].is_null());
}

fn refuse(dir: &Path, manifest: String) -> serde_json::Value {
    // validation completes before the lock is acquired, so a refusal leaves
    // no lock file behind either.
    fs::write(dir.join("manifest.json"), manifest).expect("write manifest");
    let output = run_reconcile(dir);
    assert_eq!(output.status.code(), Some(1));
    assert!(!dir.join("lock").join("test.lock").exists());
    stderr_line(&output)
}

#[test]
fn an_unsupported_diagnostic_contract_schema_is_refused() {
    let dir = unique_dir("contract-schema");
    let manifest = manifest_json("[]").replace(
        "\"diagnosticContract\":{\"schemaVersion\":1",
        "\"diagnosticContract\":{\"schemaVersion\":0",
    );
    let diagnostic = refuse(&dir, manifest);
    assert_eq!(diagnostic["code"], "runtime/invalid-manifest");
    assert_eq!(
        diagnostic["message"],
        "diagnostic schema 0 is unsupported; expected 1"
    );
    assert_eq!(diagnostic["primary"]["label"], "diagnostic contract");
    assert!(diagnostic.get("provenance").is_some());
    assert!(diagnostic["provenance"].is_null());
}

#[test]
fn an_entry_with_an_unsupported_executor_tuple_is_refused() {
    let dir = unique_dir("tuple");
    let source = dir.join("source");
    fs::write(&source, "payload\n").expect("write source");
    let entry = writable_entry_json(&dir, "value", &source).replace(
        "\"identity\":\"furnish/native-writable\"",
        "\"identity\":\"bogus\"",
    );
    let diagnostic = refuse(&dir, manifest_json(&format!("[{entry}]")));
    assert_eq!(diagnostic["code"], "runtime/unsupported-executor");
    assert_eq!(
        diagnostic["message"],
        "unsupported executor tuple (bogus, 1, writable)"
    );
    assert_eq!(
        diagnostic["primary"]["label"],
        format!("test:{}", dir.join("value").to_str().unwrap())
    );
}

#[test]
fn an_entry_whose_authority_scope_is_unknown_is_refused() {
    let dir = unique_dir("scope");
    let source = dir.join("source");
    fs::write(&source, "payload\n").expect("write source");
    let entry = writable_entry_json(&dir, "value", &source)
        .replace("\"scope\":\"system\"", "\"scope\":\"host\"");
    let diagnostic = refuse(&dir, manifest_json(&format!("[{entry}]")));
    assert_eq!(diagnostic["code"], "runtime/invalid-manifest");
    assert_eq!(
        diagnostic["message"],
        "authority scope must be user or system"
    );
}

#[test]
fn an_entry_whose_identity_is_not_canonical_is_refused() {
    // This only discriminates the canonical check once writable_entry_json
    // emits valid path strings instead of double-encoded ones.
    let dir = unique_dir("canonical");
    let source = dir.join("source");
    fs::write(&source, "payload\n").expect("write source");
    let destination = dir.join("value");
    let entry = writable_entry_json(&dir, "value", &source).replace(
        &format!("\"canonical\":\"test:{}\"", destination.to_str().unwrap()),
        "\"canonical\":\"bogus\"",
    );
    let diagnostic = refuse(&dir, manifest_json(&format!("[{entry}]")));
    assert_eq!(diagnostic["code"], "runtime/invalid-manifest");
    assert_eq!(
        diagnostic["message"],
        "filesystem identity is not canonical"
    );
    assert_eq!(diagnostic["primary"]["label"], "bogus");
}

#[test]
fn an_entry_with_a_lifecycle_mismatch_is_refused() {
    let dir = unique_dir("lifecycle");
    let source = dir.join("source");
    fs::write(&source, "payload\n").expect("write source");
    let entry = writable_entry_json(&dir, "value", &source).replace(
        "\"cleanupStrategy\":\"exact-source-content\"",
        "\"cleanupStrategy\":\"bogus\"",
    );
    let diagnostic = refuse(&dir, manifest_json(&format!("[{entry}]")));
    assert_eq!(diagnostic["code"], "runtime/invalid-manifest");
    assert_eq!(
        diagnostic["message"],
        "writable reconciliation requires exact-source-content lifecycle strategies"
    );
}

#[test]
fn the_first_failing_entry_decides_the_diagnostic() {
    let dir = unique_dir("first-failing");
    let source = dir.join("source");
    fs::write(&source, "payload\n").expect("write source");
    let first = writable_entry_json(&dir, "first", &source).replace(
        &format!(
            "\"canonical\":\"test:{}\"",
            dir.join("first").to_str().unwrap()
        ),
        "\"canonical\":\"bogus\"",
    );
    let second = writable_entry_json(&dir, "second", &source)
        .replace("\"scope\":\"system\"", "\"scope\":\"host\"");
    let diagnostic = refuse(&dir, manifest_json(&format!("[{first},{second}]")));
    assert_eq!(
        diagnostic["message"],
        "filesystem identity is not canonical"
    );
}

// Opaque planted prior-state token: it is not the hash of file content.
// Production reports it unchanged as the observed baseline without recomputing it.
const BASELINE_HASH: &str = "3b2c67b04a2403e79a83f3a7aceb95116c1b4c8c1063f0271096c4810348f67d";
const DECLARED_HASH: &str = "a23c9e491c7f53f7ce9ea426ce849525c4373091b668c3c8606ad8859a3b4670";
const EDITED_HASH: &str = "68f01b289aedcf28e96fce1f9444365e83b9bfc7e1bf32df20f1f15966835316";

fn ledger_record_json(root: &Path, name: &str, source: &Path, baseline: &str) -> String {
    let destination = root.join(name);
    format!(
        "{{\"destination\":{dest},\"appliedArtifactTarget\":{src},\"managedRoot\":{managed},\"appliedBy\":\"new\",\"appliedGeneration\":null,\"lastSuccessfulReload\":{{\"invocationId\":null,\"monotonicSeconds\":0.0}},\"reloadActionIdentity\":null,\"bootId\":null,\"state\":\"owned\",\"representation\":\"writable\",\"baselineHash\":\"{baseline}\",\"intendedWitnessHash\":\"{baseline}\",\"appliedOperationGeneration\":0,\"stageName\":null,\"unresolvedRetirement\":null}}",
        dest = serde_json::to_string(destination.to_str().unwrap()).unwrap(),
        src = serde_json::to_string(source.to_str().unwrap()).unwrap(),
        managed = serde_json::to_string(root.to_str().unwrap()).unwrap(),
    )
}

#[test]
fn a_conflict_diagnostic_carries_the_full_runtime_shape() {
    // the destination and the source have both moved off the baseline, so the
    // declared policy refuses and the diagnostic carries b, s, and d.
    let dir = unique_dir("conflict");
    let source = dir.join("source");
    fs::write(&source, "declared\n").expect("write source");
    let destination = dir.join("value");
    fs::write(&destination, "edited\n").expect("plant edited destination");
    let manifest = manifest_json(&format!(
        "[{}]",
        writable_entry_json(&dir, "value", &source)
    ));
    fs::write(dir.join("manifest.json"), manifest).expect("write manifest");
    let state = dir.join("state");
    fs::create_dir_all(&state).expect("create state dir");
    let ledger = format!(
        "{{\"schemaVersion\":2,\"records\":{{\"test:{}\":{}}}}}",
        destination.to_str().unwrap(),
        ledger_record_json(&dir, "value", &source, BASELINE_HASH)
    );
    fs::write(state.join("applied-state.json"), &ledger).expect("plant ledger");
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(1));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["schemaVersion"], 1);
    assert_eq!(diagnostic["severity"], "error");
    assert_eq!(diagnostic["code"], "runtime/conflicting-destination");
    assert_eq!(
        diagnostic["message"],
        "destination and source have both diverged from the baseline and this declaration's policy is to refuse"
    );
    assert_eq!(
        diagnostic["primary"]["label"],
        destination.to_str().unwrap()
    );
    assert_eq!(diagnostic["provenance"]["declaration"], "test");
    assert_eq!(diagnostic["provenance"]["source"], "diagnostics");
    assert!(diagnostic.get("cause").is_some());
    assert!(diagnostic["cause"].is_null());
    assert_eq!(diagnostic["observed"]["baseline"], BASELINE_HASH);
    assert_eq!(diagnostic["observed"]["source"], DECLARED_HASH);
    assert_eq!(diagnostic["observed"]["destination"], EDITED_HASH);
    // a refusal commits nothing: the ledger is byte-identical afterwards.
    assert_eq!(
        fs::read_to_string(state.join("applied-state.json")).unwrap(),
        ledger
    );
}
