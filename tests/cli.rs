// characterization of the command line grammar. every exit status the binary
// produces is 0 or 1, and option lookup is an overlapping windows-find rather
// than a positional parse.

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
        "furnish-cli-{name}-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create test directory");
    path
}

fn run(args: &[&OsStr]) -> Output {
    Command::new(coordinator())
        .args(args)
        .output()
        .expect("run coordinator")
}

fn os<'a>(args: &'a [&'a str]) -> Vec<&'a OsStr> {
    args.iter().map(OsStr::new).collect()
}

fn assert_silent_failure(output: &Output) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
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

fn run_reconcile(dir: &Path, extra: &[&str]) -> Output {
    let manifest = dir.join("manifest.json");
    let state = dir.join("state");
    let lock = dir.join("lock");
    fs::create_dir_all(&lock).expect("create lock dir");
    let mut argv = vec![
        "reconcile",
        "--manifest",
        manifest.to_str().unwrap(),
        "--lock-name",
        "test.lock",
        "--setpriv",
        "/nonexistent/setpriv",
        "--state-dir",
        state.to_str().unwrap(),
        "--lock-dir",
        lock.to_str().unwrap(),
    ];
    argv.extend_from_slice(extra);
    run(&os(&argv))
}

#[test]
fn reconcile_requires_all_four_options() {
    for missing in ["--manifest", "--lock-name", "--setpriv", "--state-dir"] {
        let mut argv = vec![
            "reconcile",
            "--manifest",
            "m",
            "--lock-name",
            "l",
            "--setpriv",
            "s",
            "--state-dir",
            "d",
        ];
        let position = argv.iter().position(|arg| *arg == missing).unwrap();
        argv.drain(position..=position + 1);
        assert_silent_failure(&run(&os(&argv)));
    }
}

#[test]
fn an_unknown_subcommand_fails_silently() {
    assert_silent_failure(&run(&os(&["bogus-subcommand"])));
}

#[test]
fn reconcile_ignores_unknown_flags_but_workers_refuse_them() {
    let dir = unique_dir("unknown-flag");
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    let output = run_reconcile(&dir, &["--bogus", "q"]);
    assert_eq!(output.status.code(), Some(0));
    // the same stray flag is a hard failure inside a worker parse loop.
    assert_silent_failure(&run(&os(&["stage-native-symlink", "--bogus", "q"])));
}

#[test]
fn a_repeated_option_resolves_to_its_first_occurrence() {
    let dir = unique_dir("repeated");
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    fs::create_dir_all(dir.join("lock")).expect("create lock dir");
    let first = dir.join("first");
    let second = dir.join("second");
    let output = run(&os(&[
        "reconcile",
        "--manifest",
        dir.join("manifest.json").to_str().unwrap(),
        "--lock-name",
        "test.lock",
        "--setpriv",
        "/nonexistent/setpriv",
        "--state-dir",
        first.to_str().unwrap(),
        "--state-dir",
        second.to_str().unwrap(),
        "--lock-dir",
        dir.join("lock").to_str().unwrap(),
    ]));
    assert_eq!(output.status.code(), Some(0));
    assert!(first.is_dir());
    assert!(!second.exists());
}

#[test]
fn a_flag_string_in_a_value_position_is_still_a_flag() {
    // option() scans overlapping pairs, so "--setpriv --state-dir /w" makes
    // --state-dir resolve to "/w" while --setpriv resolves to "--state-dir".
    let dir = unique_dir("value-position");
    fs::write(dir.join("manifest.json"), manifest_json("[]")).expect("write manifest");
    let state = dir.join("w");
    fs::create_dir_all(dir.join("lock")).expect("create lock dir");
    let output = run(&os(&[
        "reconcile",
        "--manifest",
        dir.join("manifest.json").to_str().unwrap(),
        "--lock-name",
        "test.lock",
        "--setpriv",
        "--state-dir",
        state.to_str().unwrap(),
        "--lock-dir",
        dir.join("lock").to_str().unwrap(),
    ]));
    assert_eq!(output.status.code(), Some(0));
    // With an empty manifest, no executor runs, so this observes the
    // --state-dir parse but not the --setpriv half of the claim.
    assert!(state.is_dir());
}

#[test]
fn the_symlink_worker_requires_its_three_arguments() {
    for argv in [
        vec!["stage-native-symlink", "--name", "stage", "--target", "/t"],
        vec!["stage-native-symlink", "--parent-fd", "1", "--target", "/t"],
        vec![
            "stage-native-symlink",
            "--parent-fd",
            "1",
            "--name",
            "stage",
        ],
    ] {
        assert_silent_failure(&run(&os(&argv)));
    }
}

#[test]
fn the_symlink_worker_fails_when_the_parent_fd_cannot_be_opened() {
    let output = run(&os(&[
        "stage-native-symlink",
        "--parent-fd",
        "99",
        "--name",
        "stage",
        "--target",
        "/t",
    ]));
    assert_silent_failure(&output);
}

#[test]
fn the_symlink_worker_publishes_an_exact_target() {
    // the worker re-opens the inherited descriptor through /proc/self/fd, so
    // a directory handed over as this process's stdout is a valid parent.
    let dir = unique_dir("symlink-worker");
    let parent = fs::File::open(&dir).expect("open directory as descriptor");
    let output = Command::new(coordinator())
        .args(os(&[
            "stage-native-symlink",
            "--parent-fd",
            "1",
            "--name",
            "stage",
            "--target",
            "/nix/store/x",
        ]))
        .stdout(std::process::Stdio::from(parent))
        .output()
        .expect("run symlink worker");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        fs::read_link(dir.join("stage")).unwrap(),
        PathBuf::from("/nix/store/x")
    );
}

#[test]
fn the_writable_worker_stages_exact_content_with_an_exclusive_create() {
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_dir("writable-worker");
    let source = dir.join("source");
    fs::write(&source, b"payload\n").expect("write source");
    let invoke = |parent: fs::File| {
        Command::new(coordinator())
            .args(os(&[
                "stage-native-writable",
                "--parent-fd",
                "1",
                "--name",
                "stage",
                "--source",
                source.to_str().unwrap(),
            ]))
            .stdout(std::process::Stdio::from(parent))
            .output()
            .expect("run writable worker")
    };
    let output = invoke(fs::File::open(&dir).expect("open directory as descriptor"));
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(fs::read(dir.join("stage")).unwrap(), b"payload\n");
    assert_eq!(
        fs::metadata(dir.join("stage"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o644
    );
    // the create is exclusive, so the same name is refused a second time.
    let again = invoke(fs::File::open(&dir).expect("open directory as descriptor"));
    assert_silent_failure(&again);
}

#[test]
fn the_directory_worker_refuses_a_multi_component_name() {
    let dir = unique_dir("directory-worker");
    let parent = fs::File::open(&dir).expect("open directory as descriptor");
    let output = Command::new(coordinator())
        .args(os(&[
            "create-native-directory",
            "--parent-fd",
            "1",
            "--name",
            "a/b",
        ]))
        .stdout(std::process::Stdio::from(parent))
        .output()
        .expect("run directory worker");
    assert_silent_failure(&output);
    assert!(!dir.join("a").exists());
}

#[test]
fn the_directory_worker_creates_with_an_exact_mode_and_leaves_an_existing_dir_untouched() {
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_dir("directory-worker-mode");
    let invoke = |parent: fs::File, name: &str| {
        Command::new(coordinator())
            .args(os(&[
                "create-native-directory",
                "--parent-fd",
                "1",
                "--name",
                name,
            ]))
            .stdout(std::process::Stdio::from(parent))
            .output()
            .expect("run directory worker")
    };
    let created = invoke(
        fs::File::open(&dir).expect("open directory as descriptor"),
        "created",
    );
    assert_eq!(created.status.code(), Some(0));
    assert_eq!(
        fs::metadata(dir.join("created"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );
    // an existing component is success and is left exactly as it was found.
    let existing = dir.join("existing");
    fs::create_dir(&existing).expect("plant existing dir");
    fs::set_permissions(&existing, fs::Permissions::from_mode(0o700)).expect("set mode");
    let again = invoke(
        fs::File::open(&dir).expect("open directory as descriptor"),
        "existing",
    );
    assert_eq!(again.status.code(), Some(0));
    assert_eq!(
        fs::metadata(&existing).unwrap().permissions().mode() & 0o7777,
        0o700
    );
}
