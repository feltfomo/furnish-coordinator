// characterization of the host lock, the bounded traversal, and the ledger
// artifact as it lands on disk.

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
        "furnish-char-{name}-{}-{sequence}",
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

fn run_reconcile_with_lock_name(dir: &Path, lock_name: &str) -> Output {
    let lock = dir.join("lock");
    fs::create_dir_all(&lock).expect("create lock dir");
    Command::new(coordinator())
        .args(os(&[
            "reconcile",
            "--manifest",
            dir.join("manifest.json").to_str().unwrap(),
            "--lock-name",
            lock_name,
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

fn run_reconcile(dir: &Path) -> Output {
    run_reconcile_with_lock_name(dir, "test.lock")
}

fn stderr_line(output: &Output) -> serde_json::Value {
    let text = String::from_utf8(output.stderr.clone()).expect("stderr utf8");
    serde_json::from_str(text.lines().next().expect("one diagnostic line"))
        .expect("diagnostic parses")
}

#[test]
fn a_successful_run_leaves_the_lock_file_with_its_requested_mode() {
    let dir = unique_dir("lock-mode");
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    let lock = dir.join("lock").join("test.lock");
    // openat requests owner read and write only; the umask can narrow that
    // further but never widen it.
    assert_eq!(
        fs::metadata(&lock).unwrap().permissions().mode() & 0o7777,
        0o600
    );
}

#[test]
fn a_lock_name_with_a_separator_is_refused_with_the_bare_name_label() {
    let dir = unique_dir("lock-separator");
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    let output = run_reconcile_with_lock_name(&dir, "a/b.lock");
    assert_eq!(output.status.code(), Some(1));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["code"], "runtime/invalid-manifest");
    assert_eq!(
        diagnostic["message"],
        "lock name must be one normal path component"
    );
    assert_eq!(diagnostic["primary"]["label"], "a/b.lock");
}

#[test]
fn a_lock_name_that_is_a_symlink_is_refused_without_being_followed() {
    let dir = unique_dir("lock-symlink");
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    let lock = dir.join("lock");
    fs::create_dir(&lock).expect("create lock dir");
    std::os::unix::fs::symlink("/elsewhere", lock.join("test.lock")).expect("plant lock symlink");
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(1));
    let diagnostic = stderr_line(&output);
    assert_eq!(diagnostic["code"], "runtime/invalid-manifest");
    assert_eq!(diagnostic["cause"]["operation"], "openat-lock");
    assert_eq!(diagnostic["cause"]["errno"], 40);
    assert_eq!(
        fs::read_link(dir.join("lock").join("test.lock")).unwrap(),
        PathBuf::from("/elsewhere")
    );
}

#[test]
fn the_default_lock_dir_is_used_when_lock_dir_is_omitted() {
    // the answer depends on whether /run/lock exists and is writable here, so
    // both outcomes are pinned: a lock left under it, or a refusal naming it.
    let dir = unique_dir("default-lock");
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    let name = format!("furnish-cli-test-{}.lock", std::process::id());
    let output = Command::new(coordinator())
        .args(os(&[
            "reconcile",
            "--manifest",
            dir.join("manifest.json").to_str().unwrap(),
            "--lock-name",
            &name,
            "--setpriv",
            "/nonexistent/setpriv",
            "--state-dir",
            dir.join("state").to_str().unwrap(),
        ]))
        .output()
        .expect("run coordinator");
    if output.status.code() == Some(0) {
        let lock = Path::new("/run/lock").join(&name);
        assert!(lock.is_file());
        fs::remove_file(&lock).ok();
    } else {
        assert_eq!(output.status.code(), Some(1));
        let diagnostic = stderr_line(&output);
        let label = diagnostic["primary"]["label"].as_str().unwrap();
        assert!(label == "/run/lock" || label == format!("/run/lock/{name}"));
    }
}

fn entry_json(destination: &str, managed_root: &str, source: &str) -> String {
    format!(
        "{{\"schemaVersion\":2,\"filesystemIdentity\":{{\"namespace\":\"test\",\"destination\":{dest},\"canonical\":\"test:{dest_str}\"}},\"authority\":{{\"scope\":\"system\",\"identity\":\"test/system\"}},\"managedRoot\":{root},\"onConflict\":\"error\",\"representation\":\"writable\",\"retainedArtifactTarget\":{src},\"executor\":{{\"identity\":\"furnish/native-writable\",\"protocolVersion\":1}},\"cleanupStrategy\":\"exact-source-content\",\"selfHealStrategy\":\"exact-source-content\",\"provenance\":{{\"declaration\":\"test\",\"source\":\"characterization\"}}}}",
        dest = serde_json::to_string(destination).unwrap(),
        dest_str = destination,
        root = serde_json::to_string(managed_root).unwrap(),
        src = serde_json::to_string(source).unwrap(),
    )
}

fn refuse_with_entry(dir: &Path, entry: String) -> serde_json::Value {
    let source = dir.join("source");
    fs::write(&source, "payload\n").expect("write source");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!("[{entry}]")),
    )
    .expect("write manifest");
    let output = run_reconcile(dir);
    assert_eq!(output.status.code(), Some(1));
    stderr_line(&output)
}

#[test]
fn a_relative_destination_is_refused() {
    let dir = unique_dir("relative");
    let diagnostic = refuse_with_entry(
        &dir,
        entry_json("relative/value", dir.to_str().unwrap(), "/tmp/source"),
    );
    assert_eq!(diagnostic["code"], "runtime/invalid-destination");
    assert_eq!(
        diagnostic["message"],
        "destination must be an absolute descendant of managedRoot"
    );
    assert_eq!(diagnostic["primary"]["label"], "relative/value");
}

#[test]
fn a_destination_equal_to_the_managed_root_is_refused() {
    let dir = unique_dir("equal-root");
    let root = dir.join("managed");
    fs::create_dir_all(&root).expect("create managed root");
    let diagnostic = refuse_with_entry(
        &dir,
        entry_json(
            root.to_str().unwrap(),
            root.to_str().unwrap(),
            "/tmp/source",
        ),
    );
    assert_eq!(diagnostic["code"], "runtime/invalid-destination");
    assert_eq!(
        diagnostic["message"],
        "destination must be an absolute descendant of managedRoot"
    );
}

#[test]
fn a_destination_outside_the_managed_root_is_refused() {
    let dir = unique_dir("outside-root");
    let root = dir.join("managed");
    fs::create_dir_all(&root).expect("create managed root");
    let outside = dir.join("other").join("value");
    let diagnostic = refuse_with_entry(
        &dir,
        entry_json(
            outside.to_str().unwrap(),
            root.to_str().unwrap(),
            "/tmp/source",
        ),
    );
    assert_eq!(diagnostic["code"], "runtime/invalid-destination");
    assert_eq!(
        diagnostic["message"],
        "destination must be an absolute descendant of managedRoot"
    );
}

#[test]
fn an_absent_managed_root_is_never_created() {
    let dir = unique_dir("absent-root");
    let root = dir.join("absent");
    let destination = root.join("value");
    let diagnostic = refuse_with_entry(
        &dir,
        entry_json(
            destination.to_str().unwrap(),
            root.to_str().unwrap(),
            "/tmp/source",
        ),
    );
    assert_eq!(diagnostic["code"], "runtime/parent-traversal");
    assert_eq!(diagnostic["cause"]["operation"], "openat-parent-component");
    assert_eq!(diagnostic["cause"]["errno"], 2);
    assert!(!root.exists());
}

#[test]
fn missing_components_below_the_root_are_created_with_an_exact_mode() {
    let dir = unique_dir("create-components");
    let root = dir.join("managed");
    fs::create_dir_all(&root).expect("create managed root");
    let source = dir.join("source");
    fs::write(&source, "payload\n").expect("write source");
    let destination = root.join("a").join("b").join("value");
    fs::write(
        dir.join("manifest.json"),
        manifest_json(&format!(
            "[{}]",
            entry_json(
                destination.to_str().unwrap(),
                root.to_str().unwrap(),
                source.to_str().unwrap(),
            )
        )),
    )
    .expect("write manifest");
    let output = run_reconcile(&dir);
    assert_eq!(output.status.code(), Some(0));
    for component in [root.join("a"), root.join("a").join("b")] {
        assert_eq!(
            fs::metadata(&component).unwrap().permissions().mode() & 0o7777,
            0o755
        );
    }
    assert_eq!(fs::read(&destination).unwrap(), b"payload\n");
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o7777,
        0o644
    );
}

#[test]
fn a_symlinked_component_is_refused_and_left_untouched() {
    let dir = unique_dir("symlinked-component");
    let real = dir.join("real");
    fs::create_dir(&real).expect("create real directory");
    let link = dir.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("plant symlinked component");
    let destination = link.join("nested").join("value");
    let diagnostic = refuse_with_entry(
        &dir,
        entry_json(
            destination.to_str().unwrap(),
            link.to_str().unwrap(),
            "/tmp/source",
        ),
    );
    assert_eq!(diagnostic["code"], "runtime/parent-traversal");
    assert_eq!(diagnostic["cause"]["operation"], "openat-parent-component");
    // O_DIRECTORY|O_NOFOLLOW refuses the unfollowed symlink as not a
    // directory; ELOOP belongs to the lock open alone.
    assert_eq!(diagnostic["cause"]["errno"], 20);
    assert_eq!(fs::read_link(&link).unwrap(), real);
    assert!(!real.join("nested").exists());
}

#[test]
fn a_regular_file_component_is_refused_and_left_untouched() {
    let dir = unique_dir("file-component");
    let root = dir.join("managed");
    fs::create_dir(&root).expect("create managed root");
    let occupied = root.join("occupied");
    fs::write(&occupied, b"foreign").expect("plant regular file component");
    let destination = occupied.join("value");
    let diagnostic = refuse_with_entry(
        &dir,
        entry_json(
            destination.to_str().unwrap(),
            root.to_str().unwrap(),
            "/tmp/source",
        ),
    );
    assert_eq!(diagnostic["code"], "runtime/parent-traversal");
    assert_eq!(diagnostic["cause"]["operation"], "openat-parent-component");
    assert_eq!(diagnostic["cause"]["errno"], 20);
    assert_eq!(fs::read(&occupied).unwrap(), b"foreign");
}
