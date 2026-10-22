use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    manifest: Value,
}

impl Fixture {
    fn new() -> Self {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "furnish-external-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&root).unwrap();
        let destination = root.join("link");
        Self {
            manifest: json!({
                "schemaVersion": 3,
                "diagnosticContract": { "schemaVersion": 1, "codes": {
                    "invalidManifest": "invalid-manifest",
                    "invalidDestination": "invalid-destination",
                    "parentTraversal": "parent-traversal",
                    "executorFailed": "executor-failed",
                    "stagingVerification": "staging-verification",
                    "publishRace": "publish-race",
                    "finalVerification": "final-verification",
                    "ledgerUnreadable": "ledger-unreadable",
                    "ledgerInvalid": "ledger-invalid",
                    "ledgerWriteFailed": "ledger-write-failed",
                    "repairVerification": "repair-verification",
                    "contentVerification": "content-verification",
                    "transitionRefused": "transition-refused",
                    "unresolvedRetirement": "unresolved-retirement",
                    "unsupportedExecutor": "unsupported-executor",
                    "conflictingDestination": "conflict",
                    "unresolvableDesiredTarget": "missing-target",
                    "pendingRecovery": "pending-recovery"
                }},
                "entries": [{
                    "schemaVersion": 3,
                    "filesystemIdentity": { "namespace": "test", "destination": destination,
                        "canonical": format!("test:{}", destination.display()) },
                    "authority": { "scope": "system", "identity": "test/system" },
                    "managedRoot": root,
                    "onConflict": "error",
                    "representation": "symlink",
                    "target": { "kind": "external", "path": root.join("checkout") },
                    "executor": { "identity": "furnish/native-symlink", "protocolVersion": 1 },
                    "cleanupStrategy": "exact-symlink-target",
                    "selfHealStrategy": "exact-symlink-target",
                    "provenance": { "declaration": "external-link", "source": "integration" }
                }]
            }),
            root,
        }
    }

    fn entry(&mut self) -> &mut Value {
        &mut self.manifest["entries"][0]
    }
    fn link(&self) -> PathBuf {
        self.root.join("link")
    }
    fn target(&self) -> PathBuf {
        self.root.join("checkout")
    }

    fn command(&self, verb: &str) -> Command {
        let manifest_path = self.root.join("manifest.json");
        fs::write(&manifest_path, serde_json::to_vec(&self.manifest).unwrap()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_furnish-coordinator"));
        command
            .arg(verb)
            .arg("--manifest")
            .arg(manifest_path)
            .arg("--lock-dir")
            .arg(&self.root)
            .arg("--lock-name")
            .arg("host.lock")
            .arg("--state-dir")
            .arg(self.root.join("state"))
            .arg("--setpriv")
            .arg("unused-for-system-authority");
        command
    }

    fn run(&self) -> Output {
        self.command("reconcile").output().unwrap()
    }
    fn apply(&self) {
        let output = self.run();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fn ledger(&self) -> Value {
        serde_json::from_slice(&fs::read(self.root.join("state/applied-state.json")).unwrap())
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn missing_checkout_can_appear_change_and_disappear_without_republication() {
    let fixture = Fixture::new();
    fixture.apply();
    assert_eq!(fs::read_link(fixture.link()).unwrap(), fixture.target());
    let before = fs::read(fixture.root.join("state/applied-state.json")).unwrap();
    let status = fixture.command("status").output().unwrap();
    assert!(status.status.success());
    assert!(String::from_utf8_lossy(&status.stdout).starts_with("settled\t"));
    assert_eq!(
        before,
        fs::read(fixture.root.join("state/applied-state.json")).unwrap()
    );
    fs::create_dir(fixture.target()).unwrap();
    fs::write(fixture.target().join("SKILL.md"), "first").unwrap();
    fixture.apply();
    fs::write(fixture.target().join("SKILL.md"), "edited").unwrap();
    assert_eq!(
        fs::read_to_string(fixture.link().join("SKILL.md")).unwrap(),
        "edited"
    );
    fs::remove_file(fixture.target().join("SKILL.md")).unwrap();
    fs::remove_dir(fixture.target()).unwrap();
    fixture.apply();
    assert_eq!(fs::read_link(fixture.link()).unwrap(), fixture.target());
}

#[test]
fn repair_and_retarget_allow_absent_external_targets() {
    let mut fixture = Fixture::new();
    fixture.apply();
    fs::remove_file(fixture.link()).unwrap();
    fixture.apply();
    let next = fixture.root.join("other-checkout");
    fixture.entry()["target"]["path"] = json!(next);
    let plan = fixture
        .command("reconcile")
        .arg("--dry-run")
        .output()
        .unwrap();
    assert_eq!(plan.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&plan.stdout).starts_with("republish\t"));
    assert_eq!(fs::read_link(fixture.link()).unwrap(), fixture.target());
    fixture.apply();
    assert_eq!(fs::read_link(fixture.link()).unwrap(), next);
}

#[test]
fn retirement_removes_only_the_link() {
    let mut fixture = Fixture::new();
    fs::create_dir(fixture.target()).unwrap();
    fs::write(fixture.target().join("SKILL.md"), "keep").unwrap();
    fixture.apply();
    fixture.manifest["entries"] = json!([]);
    fixture.apply();
    assert!(fs::symlink_metadata(fixture.link()).is_err());
    assert_eq!(
        fs::read_to_string(fixture.target().join("SKILL.md")).unwrap(),
        "keep"
    );
}

#[test]
fn matching_foreign_links_are_never_adopted() {
    let mut fixture = Fixture::new();
    symlink(fixture.target(), fixture.link()).unwrap();
    fixture.apply();
    assert!(!fixture.root.join("state/applied-state.json").exists());
    fixture.manifest["entries"] = json!([]);
    fixture.apply();
    assert_eq!(fs::read_link(fixture.link()).unwrap(), fixture.target());
}

#[test]
fn conflicting_destinations_and_changed_owned_links_are_preserved() {
    for directory in [false, true] {
        let fixture = Fixture::new();
        if directory {
            fs::create_dir(fixture.link()).unwrap();
        } else {
            fs::write(fixture.link(), "foreign").unwrap();
        }
        assert_eq!(fixture.run().status.code(), Some(4));
        assert!(fs::symlink_metadata(fixture.link()).is_ok());
    }
    let fixture = Fixture::new();
    fixture.apply();
    fs::remove_file(fixture.link()).unwrap();
    symlink("foreign", fixture.link()).unwrap();
    assert_eq!(fixture.run().status.code(), Some(4));
    assert_eq!(fs::read_link(fixture.link()).unwrap(), Path::new("foreign"));
}

#[test]
fn retained_and_external_sources_can_replace_each_other() {
    let mut fixture = Fixture::new();
    fixture.apply();
    let retained = fixture.root.join("retained");
    fs::write(&retained, "retained").unwrap();
    fixture.entry()["target"] = json!({ "kind": "retained", "path": retained });
    fixture.apply();
    assert_eq!(fs::read_link(fixture.link()).unwrap(), retained);
    fixture.entry()["target"] = json!({ "kind": "external", "path": fixture.target() });
    fixture.apply();
    assert_eq!(fs::read_link(fixture.link()).unwrap(), fixture.target());
}

#[test]
fn absent_retained_replacements_still_refuse_in_apply_and_report() {
    let mut fixture = Fixture::new();
    fixture.apply();
    fixture.entry()["target"] = json!({ "kind": "retained", "path": fixture.root.join("absent") });
    for verb in ["reconcile", "status"] {
        let output = fixture.command(verb).output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("missing-target"));
    }
    assert_eq!(fs::read_link(fixture.link()).unwrap(), fixture.target());
}

#[test]
fn malformed_or_writable_external_targets_refuse_before_mutation() {
    for path in [
        "relative", "/", "/a/../b", "/a//b", "/a/", "/a/./b", "/a\0b",
    ] {
        let mut fixture = Fixture::new();
        fixture.entry()["target"]["path"] = json!(path);
        assert!(!fixture.run().status.success(), "{path:?}");
        assert!(!fixture.root.join("host.lock").exists());
        assert!(fs::symlink_metadata(fixture.link()).is_err());
    }
    let mut fixture = Fixture::new();
    fixture.entry()["representation"] = json!("writable");
    fixture.entry()["executor"]["identity"] = json!("furnish/native-writable");
    fixture.entry()["cleanupStrategy"] = json!("exact-source-content");
    fixture.entry()["selfHealStrategy"] = json!("exact-source-content");
    assert_eq!(fixture.run().status.code(), Some(1));
    assert!(!fixture.root.join("host.lock").exists());
}

#[cfg(feature = "fault-injection")]
#[test]
fn interrupted_external_publication_and_retargeting_recover() {
    for point in ["pending-committed", "stage-synced", "published", "verified"] {
        let fixture = Fixture::new();
        let crashed = fixture
            .command("reconcile")
            .env("FURNISH_FAULT_POINT", point)
            .output()
            .unwrap();
        assert!(!crashed.status.success());
        fixture.apply();
        fixture.apply();
        assert_eq!(fs::read_link(fixture.link()).unwrap(), fixture.target());
    }
    for point in [
        "pending-committed",
        "stage-synced",
        "exchange-published",
        "verified",
    ] {
        let mut fixture = Fixture::new();
        fixture.apply();
        let next = fixture.root.join("next");
        fixture.entry()["target"]["path"] = json!(next);
        let crashed = fixture
            .command("reconcile")
            .env("FURNISH_FAULT_POINT", point)
            .output()
            .unwrap();
        assert!(!crashed.status.success());
        fixture.apply();
        fixture.apply();
        assert_eq!(fs::read_link(fixture.link()).unwrap(), next);
    }
}

#[test]
fn diagnostic_formats_preserve_status_and_explain_blocked_retirement() {
    let mut fixture = Fixture::new();
    let source = fixture.root.join("source");
    fs::write(&source, "original").unwrap();
    fixture.entry()["target"] = json!({ "kind": "retained", "path": source });
    fixture.entry()["representation"] = json!("writable");
    fixture.entry()["executor"]["identity"] = json!("furnish/native-writable");
    fixture.entry()["cleanupStrategy"] = json!("exact-source-content");
    fixture.entry()["selfHealStrategy"] = json!("exact-source-content");
    fixture.apply();
    fs::write(fixture.link(), "edited").unwrap();
    fixture.manifest["entries"] = json!([]);
    let json_output = fixture.run();
    assert!(json_output.status.success());
    let diagnostic: Value = serde_json::from_slice(&json_output.stderr).unwrap();
    assert_eq!(diagnostic["severity"], "warning");
    assert_eq!(diagnostic["code"], "unresolved-retirement");
    let plain = fixture
        .command("reconcile")
        .args(["--diagnostic-format", "plain"])
        .output()
        .unwrap();
    assert!(plain.status.success());
    let text = String::from_utf8(plain.stderr).unwrap();
    assert!(text.starts_with("furnish: warning [unresolved-retirement]"));
    assert!(text.contains(fixture.link().to_str().unwrap()));
    assert!(text.contains("ownership record are preserved"));
    assert!(!text.contains("schemaVersion"));
    assert_eq!(fs::read_to_string(fixture.link()).unwrap(), "edited");
    assert_eq!(fixture.ledger()["records"].as_object().unwrap().len(), 1);
}

#[test]
fn plain_diagnostics_cover_bootstrap_and_manifest_failures() {
    let mut fixture = Fixture::new();
    fixture.entry()["target"]["path"] = json!("relative");
    let plain = fixture
        .command("reconcile")
        .args(["--diagnostic-format", "plain"])
        .output()
        .unwrap();
    assert_eq!(plain.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&plain.stderr).starts_with("furnish: error [invalid-manifest]")
    );
    fixture.manifest = json!({});
    let plain = fixture
        .command("reconcile")
        .args(["--diagnostic-format", "plain"])
        .output()
        .unwrap();
    assert_eq!(plain.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&plain.stderr).contains("furnish/runtime-bootstrap"));
    for arguments in [
        vec!["--diagnostic-format"],
        vec!["--diagnostic-format", "bogus"],
    ] {
        let invalid = fixture
            .command("reconcile")
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(invalid.status.code(), Some(2));
        assert!(invalid.stderr.is_empty());
    }
}
