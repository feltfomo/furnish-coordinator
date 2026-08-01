use super::migration::{V1Record, migrate_v1};
use super::model::{
    AppliedOperation, LedgerRecord, ModelError, OWNED_STATE, PENDING_STATE, PendingIntent,
    PriorOwned, RecordStatus, ReloadEvidence, Representation, SYMLINK_REPRESENTATION,
    TRANSITION_MARKER, TransitionPair, UnresolvedRetirement,
};
use super::{
    LEDGER_FILE_NAME, LEDGER_ROLLBACK_FILE_NAME, LEDGER_SCHEMA_VERSION, LEDGER_STAGE_PREFIX,
};
use crate::diagnostic::{CodeKey, Failure, Result};
use rustix::fs::{Mode, OFlags, fsync, open};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RawLedgerRecord {
    pub(super) destination: String,
    pub(super) applied_artifact_target: String,
    pub(super) managed_root: String,
    pub(super) applied_by: String,
    pub(super) applied_generation: Option<String>,
    pub(super) last_successful_reload: RawReloadEvidence,
    pub(super) reload_action_identity: Option<String>,
    pub(super) boot_id: Option<String>,
    #[serde(default = "default_state")]
    pub(super) state: String,
    #[serde(default = "default_representation")]
    pub(super) representation: String,
    #[serde(default)]
    pub(super) baseline_hash: Option<String>,
    #[serde(default)]
    pub(super) intended_witness_hash: Option<String>,
    #[serde(default)]
    pub(super) applied_operation_generation: u64,
    #[serde(default)]
    pub(super) stage_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) prior_owned: Option<RawPriorOwned>,
    #[serde(default)]
    pub(super) unresolved_retirement: Option<RawUnresolvedRetirement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RawPriorOwned {
    pub(super) destination: String,
    pub(super) applied_artifact_target: String,
    pub(super) managed_root: String,
    pub(super) applied_by: String,
    pub(super) applied_generation: Option<String>,
    pub(super) last_successful_reload: RawReloadEvidence,
    pub(super) reload_action_identity: Option<String>,
    pub(super) boot_id: Option<String>,
    pub(super) representation: String,
    pub(super) baseline_hash: Option<String>,
    pub(super) intended_witness_hash: Option<String>,
    pub(super) applied_operation_generation: u64,
    pub(super) unresolved_retirement: Option<RawUnresolvedRetirement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RawReloadEvidence {
    pub(super) invocation_id: Option<String>,
    pub(super) monotonic_seconds: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RawUnresolvedRetirement {
    pub(super) reason: String,
    pub(super) observed_hash: Option<String>,
    pub(super) baseline_hash: Option<String>,
}

fn default_state() -> String {
    OWNED_STATE.to_owned()
}

fn default_representation() -> String {
    SYMLINK_REPRESENTATION.to_owned()
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RawLedger {
    pub(super) schema_version: u64,
    pub(super) records: BTreeMap<String, RawLedgerRecord>,
}

#[derive(Debug)]
pub(crate) struct LedgerState {
    directory: PathBuf,
    path: PathBuf,
    records: BTreeMap<String, LedgerRecord>,
}

impl LedgerState {
    pub(crate) fn load(directory: &Path) -> Result<Self> {
        let label = directory.to_string_lossy().into_owned();
        let path = directory.join(LEDGER_FILE_NAME);
        let existing = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(Failure::io(
                    CodeKey::LedgerUnreadable,
                    path.to_string_lossy(),
                    "read-applied-state",
                    &error,
                ));
            }
        };
        let on_disk_version = match existing.as_deref() {
            Some(bytes) => {
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Version {
                    schema_version: u64,
                }
                let version: Version = serde_json::from_slice(bytes).map_err(|error| {
                    Failure::new(
                        CodeKey::LedgerInvalid,
                        path.to_string_lossy(),
                        format!("cannot decode applied state: {error}"),
                    )
                })?;
                Some(version.schema_version)
            }
            None => None,
        };
        if let Some(version) = on_disk_version
            && version > LEDGER_SCHEMA_VERSION
        {
            return Err(Failure::new(
                CodeKey::LedgerInvalid,
                path.to_string_lossy(),
                format!(
                    "applied-state schema {version} is newer than this coordinator supports ({LEDGER_SCHEMA_VERSION}); refusing before any mutation"
                ),
            ));
        }
        fs::create_dir_all(directory).map_err(|error| {
            Failure::io(
                CodeKey::LedgerUnreadable,
                &label,
                "create-state-directory",
                &error,
            )
        })?;
        // writability is the privilege here, since anything that can write this
        // file can claim ownership of a destination. readability is not, and
        // keeping it readable lets the unprivileged harness verify that the
        // record survived a root wipe without being handed root to look.
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).map_err(|error| {
            Failure::io(
                CodeKey::LedgerUnreadable,
                &label,
                "chmod-state-directory",
                &error,
            )
        })?;
        // asserted rather than assumed. a mode that is 0755 because it was chosen
        // is a decision; a mode that is 0755 because of this host's umask is an
        // accident that will silently be something else on the next host.
        let mode = fs::metadata(directory)
            .map_err(|error| {
                Failure::io(
                    CodeKey::LedgerUnreadable,
                    &label,
                    "stat-state-directory",
                    &error,
                )
            })?
            .permissions()
            .mode()
            & 0o7777;
        if mode != 0o755 {
            return Err(Failure::new(
                CodeKey::LedgerUnreadable,
                &label,
                format!("state directory mode is {mode:04o}; expected 0755"),
            ));
        }
        let (records, migrated) = match existing {
            // an absent ledger is a cold start, not a clean bill of health. it
            // proves nothing was recorded, so nothing is owned, so nothing is
            // repairable until acquisition-from-absence records something.
            None => (BTreeMap::new(), false),
            Some(bytes) => {
                let version = on_disk_version.expect("existing ledger has a decoded version");
                if version == LEDGER_SCHEMA_VERSION {
                    (decode_records(&bytes, &path)?, false)
                } else if version == 1 {
                    // the copy is the rollback evidence, and it is written before the
                    // first v2 write so a downgrade always has the exact input the
                    // migration consumed.
                    let rollback = directory.join(LEDGER_ROLLBACK_FILE_NAME);
                    fs::write(&rollback, &bytes).map_err(|error| {
                        Failure::io(
                            CodeKey::LedgerWriteFailed,
                            rollback.to_string_lossy(),
                            "write-applied-state-rollback",
                            &error,
                        )
                    })?;
                    let mut document: RawLedger =
                        serde_json::from_slice(&bytes).map_err(|error| {
                            Failure::new(
                                CodeKey::LedgerInvalid,
                                path.to_string_lossy(),
                                format!("cannot decode applied state: {error}"),
                            )
                        })?;
                    migrate_v1(&mut document.schema_version, document.records.values_mut());
                    (validate_records(document, &path)?, true)
                } else {
                    return Err(Failure::new(
                        CodeKey::LedgerInvalid,
                        path.to_string_lossy(),
                        format!(
                            "applied-state schema {version} is unsupported; expected {LEDGER_SCHEMA_VERSION}"
                        ),
                    ));
                }
            }
        };
        let state = Self {
            directory: directory.to_path_buf(),
            path,
            records,
        };
        if migrated {
            state.write()?;
        }
        Ok(state)
    }

    pub(crate) fn record(&self, canonical: &str) -> Option<&LedgerRecord> {
        self.records.get(canonical)
    }

    pub(crate) fn recorded(&self) -> Vec<(String, LedgerRecord)> {
        self.records
            .iter()
            .map(|(canonical, record)| (canonical.clone(), record.clone()))
            .collect()
    }

    pub(crate) fn retire(&mut self, canonical: &str) -> Result<()> {
        self.records.remove(canonical);
        self.write()
    }

    pub(crate) fn commit(&mut self, canonical: &str, record: LedgerRecord) -> Result<()> {
        self.records.insert(canonical.to_owned(), record);
        self.write()
    }

    fn write(&self) -> Result<()> {
        let label = self.path.to_string_lossy().into_owned();
        let document = RawLedger {
            schema_version: LEDGER_SCHEMA_VERSION,
            records: self
                .records
                .iter()
                .map(|(canonical, record)| (canonical.clone(), record.clone().into()))
                .collect(),
        };
        let encoded = serde_json::to_vec(&document).map_err(|error| {
            Failure::new(
                CodeKey::LedgerWriteFailed,
                &label,
                format!("cannot encode applied state: {error}"),
            )
        })?;
        // staged beside the ledger rather than in a temporary directory, because
        // a rename across filesystems is not atomic and EXDEV here would mean
        // publishing evidence by copy.
        let stage = self.directory.join(format!(
            "{LEDGER_STAGE_PREFIX}.{}.stage",
            std::process::id()
        ));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&stage)
            .map_err(|error| {
                Failure::io(
                    CodeKey::LedgerWriteFailed,
                    &label,
                    "open-applied-state-stage",
                    &error,
                )
            })?;
        // openoptions mode is masked by the ambient umask, so the mode above is
        // a request, not a guarantee. it is set explicitly and asserted, since the
        // record has to be readable by the unprivileged verifier on every host,
        // not only on hosts whose umask happens to be 022.
        if let Err(error) = fs::set_permissions(&stage, fs::Permissions::from_mode(0o644)) {
            let _ = fs::remove_file(&stage);
            return Err(Failure::io(
                CodeKey::LedgerWriteFailed,
                &label,
                "chmod-applied-state-stage",
                &error,
            ));
        }
        match fs::metadata(&stage) {
            Ok(metadata) => {
                let mode = metadata.permissions().mode() & 0o7777;
                if mode != 0o644 {
                    let _ = fs::remove_file(&stage);
                    return Err(Failure::new(
                        CodeKey::LedgerWriteFailed,
                        &label,
                        format!("applied state mode is {mode:04o}; expected 0644"),
                    ));
                }
            }
            Err(error) => {
                let _ = fs::remove_file(&stage);
                return Err(Failure::io(
                    CodeKey::LedgerWriteFailed,
                    &label,
                    "stat-applied-state-stage",
                    &error,
                ));
            }
        }
        if let Err(error) = file.write_all(&encoded) {
            let _ = fs::remove_file(&stage);
            return Err(Failure::io(
                CodeKey::LedgerWriteFailed,
                &label,
                "write-applied-state-stage",
                &error,
            ));
        }
        // contents durable before the name is published, so a crash can lose the
        // update but cannot expose a truncated one under the real name.
        if let Err(error) = file.sync_all() {
            let _ = fs::remove_file(&stage);
            return Err(Failure::io(
                CodeKey::LedgerWriteFailed,
                &label,
                "fsync-applied-state-stage",
                &error,
            ));
        }
        drop(file);
        if let Err(error) = fs::rename(&stage, &self.path) {
            let _ = fs::remove_file(&stage);
            return Err(Failure::io(
                CodeKey::LedgerWriteFailed,
                &label,
                "rename-applied-state",
                &error,
            ));
        }
        let directory = open(
            &self.directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| {
            Failure::syscall(
                CodeKey::LedgerWriteFailed,
                &label,
                "open-state-directory",
                errno,
            )
        })?;
        // the bytes were synced; this syncs the name. without it the rename can
        // be lost across a power cut and the ledger reverts to a state that
        // disagrees with the symlink already on disk.
        fsync(&directory).map_err(|errno| {
            Failure::syscall(
                CodeKey::LedgerWriteFailed,
                &label,
                "fsync-state-directory",
                errno,
            )
        })?;
        Ok(())
    }
}

impl V1Record for RawLedgerRecord {
    fn set_state(&mut self, state: &str) {
        self.state = state.to_owned();
    }

    fn set_representation(&mut self, representation: &str) {
        self.representation = representation.to_owned();
    }

    fn clear_stage_name(&mut self) {
        self.stage_name = None;
    }

    fn clear_prior_owned(&mut self) {
        self.prior_owned = None;
    }

    fn clear_unresolved_retirement(&mut self) {
        self.unresolved_retirement = None;
    }
}

impl TryFrom<RawLedgerRecord> for LedgerRecord {
    type Error = ModelError;

    fn try_from(raw: RawLedgerRecord) -> std::result::Result<Self, Self::Error> {
        let representation = Representation::parse(&raw.representation)?;
        let status = match raw.state.as_str() {
            OWNED_STATE => {
                if raw.stage_name.is_some() {
                    return Err(ModelError::new("owned record carries a staging name"));
                }
                if raw.prior_owned.is_some() {
                    return Err(ModelError::new("owned record carries prior ownership"));
                }
                RecordStatus::Owned {
                    applied_by: AppliedOperation::parse(&raw.applied_by)?,
                    unresolved_retirement: raw.unresolved_retirement.map(Into::into),
                }
            }
            PENDING_STATE => {
                if raw.unresolved_retirement.is_some() {
                    return Err(ModelError::new(
                        "pending record carries an unresolved retirement",
                    ));
                }
                let intent = if raw.applied_by == TRANSITION_MARKER {
                    PendingIntent::Transition(TransitionPair::from_target(representation))
                } else {
                    PendingIntent::Apply(AppliedOperation::parse(&raw.applied_by)?)
                };
                RecordStatus::Pending {
                    intent,
                    stage_name: raw.stage_name,
                    prior_owned: raw
                        .prior_owned
                        .map(TryInto::try_into)
                        .transpose()?
                        .map(Box::new),
                }
            }
            value => {
                return Err(ModelError::new(format!(
                    "record state {value} is unsupported"
                )));
            }
        };
        Ok(Self {
            destination: raw.destination,
            applied_artifact_target: raw.applied_artifact_target,
            managed_root: raw.managed_root,
            applied_generation: raw.applied_generation,
            last_successful_reload: raw.last_successful_reload.into(),
            reload_action_identity: raw.reload_action_identity,
            boot_id: raw.boot_id,
            representation,
            baseline_hash: raw.baseline_hash,
            intended_witness_hash: raw.intended_witness_hash,
            applied_operation_generation: raw.applied_operation_generation,
            status,
        })
    }
}

impl From<LedgerRecord> for RawLedgerRecord {
    fn from(record: LedgerRecord) -> Self {
        let (state, applied_by, stage_name, prior_owned, unresolved_retirement) =
            match record.status {
                RecordStatus::Owned {
                    applied_by,
                    unresolved_retirement,
                } => (
                    OWNED_STATE.to_owned(),
                    applied_by.as_str().to_owned(),
                    None,
                    None,
                    unresolved_retirement.map(Into::into),
                ),
                RecordStatus::Pending {
                    intent,
                    stage_name,
                    prior_owned,
                } => {
                    let applied_by = match intent {
                        PendingIntent::Apply(operation) => operation.as_str(),
                        PendingIntent::Transition(_) => TRANSITION_MARKER,
                    };
                    (
                        PENDING_STATE.to_owned(),
                        applied_by.to_owned(),
                        stage_name,
                        prior_owned.map(|record| (*record).into()),
                        None,
                    )
                }
            };
        Self {
            destination: record.destination,
            applied_artifact_target: record.applied_artifact_target,
            managed_root: record.managed_root,
            applied_by,
            applied_generation: record.applied_generation,
            last_successful_reload: record.last_successful_reload.into(),
            reload_action_identity: record.reload_action_identity,
            boot_id: record.boot_id,
            state,
            representation: record.representation.as_str().to_owned(),
            baseline_hash: record.baseline_hash,
            intended_witness_hash: record.intended_witness_hash,
            applied_operation_generation: record.applied_operation_generation,
            stage_name,
            prior_owned,
            unresolved_retirement,
        }
    }
}

impl TryFrom<RawPriorOwned> for PriorOwned {
    type Error = ModelError;

    fn try_from(raw: RawPriorOwned) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            destination: raw.destination,
            applied_artifact_target: raw.applied_artifact_target,
            managed_root: raw.managed_root,
            applied_by: AppliedOperation::parse(&raw.applied_by)?,
            applied_generation: raw.applied_generation,
            last_successful_reload: raw.last_successful_reload.into(),
            reload_action_identity: raw.reload_action_identity,
            boot_id: raw.boot_id,
            representation: Representation::parse(&raw.representation)?,
            baseline_hash: raw.baseline_hash,
            intended_witness_hash: raw.intended_witness_hash,
            applied_operation_generation: raw.applied_operation_generation,
            unresolved_retirement: raw.unresolved_retirement.map(Into::into),
        })
    }
}

impl From<PriorOwned> for RawPriorOwned {
    fn from(record: PriorOwned) -> Self {
        Self {
            destination: record.destination,
            applied_artifact_target: record.applied_artifact_target,
            managed_root: record.managed_root,
            applied_by: record.applied_by.as_str().to_owned(),
            applied_generation: record.applied_generation,
            last_successful_reload: record.last_successful_reload.into(),
            reload_action_identity: record.reload_action_identity,
            boot_id: record.boot_id,
            representation: record.representation.as_str().to_owned(),
            baseline_hash: record.baseline_hash,
            intended_witness_hash: record.intended_witness_hash,
            applied_operation_generation: record.applied_operation_generation,
            unresolved_retirement: record.unresolved_retirement.map(Into::into),
        }
    }
}

impl From<RawReloadEvidence> for ReloadEvidence {
    fn from(value: RawReloadEvidence) -> Self {
        Self {
            invocation_id: value.invocation_id,
            monotonic_seconds: value.monotonic_seconds,
        }
    }
}

impl From<ReloadEvidence> for RawReloadEvidence {
    fn from(value: ReloadEvidence) -> Self {
        Self {
            invocation_id: value.invocation_id,
            monotonic_seconds: value.monotonic_seconds,
        }
    }
}

impl From<RawUnresolvedRetirement> for UnresolvedRetirement {
    fn from(value: RawUnresolvedRetirement) -> Self {
        Self {
            reason: value.reason,
            observed_hash: value.observed_hash,
            baseline_hash: value.baseline_hash,
        }
    }
}

impl From<UnresolvedRetirement> for RawUnresolvedRetirement {
    fn from(value: UnresolvedRetirement) -> Self {
        Self {
            reason: value.reason,
            observed_hash: value.observed_hash,
            baseline_hash: value.baseline_hash,
        }
    }
}

fn decode_records(bytes: &[u8], path: &Path) -> Result<BTreeMap<String, LedgerRecord>> {
    let document: RawLedger = serde_json::from_slice(bytes).map_err(|error| {
        Failure::new(
            CodeKey::LedgerInvalid,
            path.to_string_lossy(),
            format!("cannot decode applied state: {error}"),
        )
    })?;
    validate_records(document, path)
}

fn validate_records(document: RawLedger, path: &Path) -> Result<BTreeMap<String, LedgerRecord>> {
    document
        .records
        .into_iter()
        .map(|(canonical, record)| {
            LedgerRecord::try_from(record)
                .map(|record| (canonical.clone(), record))
                .map_err(|error| {
                    Failure::new(
                        CodeKey::LedgerInvalid,
                        path.to_string_lossy(),
                        format!("invalid applied state record {canonical}: {error}"),
                    )
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn state_directory(label: &str) -> PathBuf {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "furnish-persistence-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create persistence test directory");
        path
    }

    fn empty_ledger(directory: &Path) -> LedgerState {
        LedgerState {
            directory: directory.to_owned(),
            path: directory.join(LEDGER_FILE_NAME),
            records: BTreeMap::new(),
        }
    }

    fn stage_path(directory: &Path) -> PathBuf {
        directory.join(format!(
            "{LEDGER_STAGE_PREFIX}.{}.stage",
            std::process::id()
        ))
    }

    #[test]
    fn stale_stage_content_is_truncated_before_replacement() {
        let directory = state_directory("truncate");
        let stage = stage_path(&directory);
        fs::write(&stage, vec![b'x'; 4096]).expect("plant stale stage content");
        let ledger = empty_ledger(&directory);

        ledger.write().expect("replace through stale stage");

        assert_eq!(
            fs::read(directory.join(LEDGER_FILE_NAME)).expect("read replaced ledger"),
            br#"{"schemaVersion":2,"records":{}}"#
        );
        assert!(!stage.exists());
        fs::remove_dir_all(directory).expect("remove persistence test directory");
    }

    #[test]
    fn stale_stage_mode_is_normalized_before_rename() {
        let directory = state_directory("mode");
        let stage = stage_path(&directory);
        fs::write(&stage, b"stale").expect("plant stale stage file");
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o777))
            .expect("set stale stage mode");
        let ledger = empty_ledger(&directory);

        ledger.write().expect("replace stale stage mode");

        let mode = fs::metadata(directory.join(LEDGER_FILE_NAME))
            .expect("stat replaced ledger")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o644);
        assert!(!stage.exists());
        fs::remove_dir_all(directory).expect("remove persistence test directory");
    }
    fn sample_record(representation: Representation) -> LedgerRecord {
        LedgerRecord {
            destination: "/managed/value".to_owned(),
            applied_artifact_target: "/nix/store/target".to_owned(),
            managed_root: "/managed".to_owned(),
            applied_generation: None,
            last_successful_reload: ReloadEvidence {
                invocation_id: None,
                monotonic_seconds: 0.0,
            },
            reload_action_identity: None,
            boot_id: None,
            representation,
            baseline_hash: None,
            intended_witness_hash: None,
            applied_operation_generation: 0,
            status: RecordStatus::Owned {
                applied_by: AppliedOperation::New,
                unresolved_retirement: None,
            },
        }
    }

    #[test]
    fn an_empty_record_serializes_every_v2_field_with_null_defaults() {
        let directory = state_directory("empty-record");
        let mut ledger = empty_ledger(&directory);
        ledger.records.insert(
            "test:/managed/value".to_owned(),
            sample_record(Representation::Symlink),
        );

        ledger.write().expect("write empty record");

        let bytes = fs::read(directory.join(LEDGER_FILE_NAME)).expect("read ledger");
        let encoded: serde_json::Value = serde_json::from_slice(&bytes).expect("decode ledger");
        let record = &encoded["records"]["test:/managed/value"];
        assert_eq!(record["appliedGeneration"], serde_json::Value::Null);
        assert_eq!(record["reloadActionIdentity"], serde_json::Value::Null);
        assert_eq!(record["bootId"], serde_json::Value::Null);
        assert_eq!(record["baselineHash"], serde_json::Value::Null);
        assert_eq!(record["intendedWitnessHash"], serde_json::Value::Null);
        assert_eq!(record["stageName"], serde_json::Value::Null);
        assert!(record.get("priorOwned").is_none());
        assert_eq!(record["unresolvedRetirement"], serde_json::Value::Null);
        assert_eq!(record["state"], "owned");
        assert_eq!(record["representation"], "symlink");
        assert_eq!(record["appliedOperationGeneration"], 0);
        fs::remove_dir_all(directory).expect("remove persistence test directory");
    }

    #[test]
    fn the_ledger_write_produces_exact_bytes() {
        // fixed stamps pin field order, canonical ordering, and explicit nulls.
        let directory = state_directory("exact-bytes");
        let mut ledger = empty_ledger(&directory);
        let mut record = sample_record(Representation::Writable);
        // opaque serialization token, not a claimed content digest;
        // production writes it unchanged into both JSON fields.
        record.baseline_hash = Some("a".repeat(64));
        record.intended_witness_hash = Some("a".repeat(64));
        ledger
            .records
            .insert("test:/managed/value".to_owned(), record);

        ledger.write().expect("write exact record");

        let bytes = fs::read(directory.join(LEDGER_FILE_NAME)).expect("read ledger");
        let expected = "{\"schemaVersion\":2,\"records\":{\"test:/managed/value\":{\"destination\":\"/managed/value\",\"appliedArtifactTarget\":\"/nix/store/target\",\"managedRoot\":\"/managed\",\"appliedBy\":\"new\",\"appliedGeneration\":null,\"lastSuccessfulReload\":{\"invocationId\":null,\"monotonicSeconds\":0.0},\"reloadActionIdentity\":null,\"bootId\":null,\"state\":\"owned\",\"representation\":\"writable\",\"baselineHash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"intendedWitnessHash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"appliedOperationGeneration\":0,\"stageName\":null,\"unresolvedRetirement\":null}}}";
        assert_eq!(String::from_utf8(bytes).expect("utf8 ledger"), expected);
        fs::remove_dir_all(directory).expect("remove persistence test directory");
    }
}
