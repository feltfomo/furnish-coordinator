use std::fmt;

pub(super) const OWNED_STATE: &str = "owned";
pub(super) const PENDING_STATE: &str = "pending";
pub(super) const TRANSITION_MARKER: &str = "transition";
pub(super) const SYMLINK_REPRESENTATION: &str = "symlink";
pub(super) const WRITABLE_REPRESENTATION_TAG: &str = "writable";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityScope {
    User,
    System,
}

impl AuthorityScope {
    pub(crate) fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            "user" => Ok(Self::User),
            "system" => Ok(Self::System),
            _ => Err(ModelError::new("authority scope must be user or system")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Representation {
    Symlink,
    Writable,
}

impl Representation {
    pub(crate) fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            SYMLINK_REPRESENTATION => Ok(Self::Symlink),
            WRITABLE_REPRESENTATION_TAG => Ok(Self::Writable),
            _ => Err(ModelError::new(format!(
                "record representation {value} is unsupported"
            ))),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Symlink => SYMLINK_REPRESENTATION,
            Self::Writable => WRITABLE_REPRESENTATION_TAG,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AppliedOperation {
    New,
    Update,
    Repair,
}

impl AppliedOperation {
    pub(crate) fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            "new" => Ok(Self::New),
            "update" => Ok(Self::Update),
            "repair" => Ok(Self::Repair),
            _ => Err(ModelError::new(format!(
                "record appliedBy {value} is unsupported"
            ))),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Update => "update",
            Self::Repair => "repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitionPair {
    SymlinkToWritable,
    WritableToSymlink,
}

impl TryFrom<(Representation, Representation)> for TransitionPair {
    type Error = ModelError;

    fn try_from((from, to): (Representation, Representation)) -> Result<Self, Self::Error> {
        match (from, to) {
            (Representation::Symlink, Representation::Writable) => Ok(Self::SymlinkToWritable),
            (Representation::Writable, Representation::Symlink) => Ok(Self::WritableToSymlink),
            _ => Err(ModelError::new(format!(
                "no gated transfer from {} to {}",
                from.as_str(),
                to.as_str()
            ))),
        }
    }
}

impl TransitionPair {
    pub(crate) const fn source(self) -> Representation {
        match self {
            Self::SymlinkToWritable => Representation::Symlink,
            Self::WritableToSymlink => Representation::Writable,
        }
    }

    pub(crate) const fn target(self) -> Representation {
        match self {
            Self::SymlinkToWritable => Representation::Writable,
            Self::WritableToSymlink => Representation::Symlink,
        }
    }

    pub(crate) const fn from_target(target: Representation) -> Self {
        match target {
            Representation::Writable => Self::SymlinkToWritable,
            Representation::Symlink => Self::WritableToSymlink,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingIntent {
    Apply(AppliedOperation),
    Transition(TransitionPair),
}

#[derive(Clone, Debug)]
pub(crate) struct LedgerRecord {
    pub(crate) destination: String,
    pub(crate) applied_artifact_target: String,
    pub(crate) managed_root: String,
    pub(crate) applied_generation: Option<String>,
    pub(crate) last_successful_reload: ReloadEvidence,
    pub(crate) reload_action_identity: Option<String>,
    pub(crate) boot_id: Option<String>,
    pub(crate) representation: Representation,
    pub(crate) baseline_hash: Option<String>,
    pub(crate) intended_witness_hash: Option<String>,
    pub(crate) applied_operation_generation: u64,
    pub(crate) status: RecordStatus,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OwnedRecord<'a> {
    pub(crate) record: &'a LedgerRecord,
    pub(crate) applied_by: AppliedOperation,
}

#[derive(Clone, Debug)]
pub(crate) enum RecordStatus {
    Owned {
        applied_by: AppliedOperation,
        unresolved_retirement: Option<UnresolvedRetirement>,
    },
    Pending {
        intent: PendingIntent,
        stage_name: Option<String>,
        prior_owned: Option<Box<PriorOwned>>,
    },
}

impl LedgerRecord {
    pub(crate) fn owned(&self) -> Option<OwnedRecord<'_>> {
        match self.status {
            RecordStatus::Owned { applied_by, .. } => Some(OwnedRecord {
                record: self,
                applied_by,
            }),
            RecordStatus::Pending { .. } => None,
        }
    }

    pub(crate) fn is_owned(&self) -> bool {
        matches!(self.status, RecordStatus::Owned { .. })
    }

    pub(crate) fn is_pending(&self) -> bool {
        matches!(self.status, RecordStatus::Pending { .. })
    }

    #[cfg(test)]
    pub(crate) fn applied_by(&self) -> Option<AppliedOperation> {
        match self.status {
            RecordStatus::Owned { applied_by, .. } => Some(applied_by),
            RecordStatus::Pending {
                intent: PendingIntent::Apply(applied_by),
                ..
            } => Some(applied_by),
            RecordStatus::Pending {
                intent: PendingIntent::Transition(_),
                ..
            } => None,
        }
    }

    pub(crate) fn pending_intent(&self) -> Option<PendingIntent> {
        match self.status {
            RecordStatus::Pending { intent, .. } => Some(intent),
            RecordStatus::Owned { .. } => None,
        }
    }

    pub(crate) fn stage_name(&self) -> Option<&str> {
        match &self.status {
            RecordStatus::Pending { stage_name, .. } => stage_name.as_deref(),
            RecordStatus::Owned { .. } => None,
        }
    }

    pub(crate) fn prior_owned(&self) -> Option<&PriorOwned> {
        match &self.status {
            RecordStatus::Pending { prior_owned, .. } => prior_owned.as_deref(),
            RecordStatus::Owned { .. } => None,
        }
    }

    pub(crate) fn unresolved_retirement(&self) -> Option<&UnresolvedRetirement> {
        match &self.status {
            RecordStatus::Owned {
                unresolved_retirement,
                ..
            } => unresolved_retirement.as_ref(),
            RecordStatus::Pending { .. } => None,
        }
    }

    pub(crate) fn set_unresolved_retirement(&mut self, value: Option<UnresolvedRetirement>) {
        if let RecordStatus::Owned {
            unresolved_retirement,
            ..
        } = &mut self.status
        {
            *unresolved_retirement = value;
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PriorOwned {
    pub(crate) destination: String,
    pub(crate) applied_artifact_target: String,
    pub(crate) managed_root: String,
    pub(crate) applied_by: AppliedOperation,
    pub(crate) applied_generation: Option<String>,
    pub(crate) last_successful_reload: ReloadEvidence,
    pub(crate) reload_action_identity: Option<String>,
    pub(crate) boot_id: Option<String>,
    pub(crate) representation: Representation,
    pub(crate) baseline_hash: Option<String>,
    pub(crate) intended_witness_hash: Option<String>,
    pub(crate) applied_operation_generation: u64,
    pub(crate) unresolved_retirement: Option<UnresolvedRetirement>,
}

#[derive(Clone, Debug)]
pub(crate) struct ReloadEvidence {
    pub(crate) invocation_id: Option<String>,
    pub(crate) monotonic_seconds: f64,
}

#[derive(Clone, Debug)]
pub(crate) struct UnresolvedRetirement {
    pub(crate) reason: String,
    pub(crate) observed_hash: Option<String>,
    pub(crate) baseline_hash: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ModelError(String);

impl ModelError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ModelError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_record_has_no_owned_view() {
        let record = LedgerRecord {
            destination: "/tmp/value".to_owned(),
            applied_artifact_target: "/tmp/source".to_owned(),
            managed_root: "/tmp".to_owned(),
            applied_generation: None,
            last_successful_reload: ReloadEvidence {
                invocation_id: None,
                monotonic_seconds: 0.0,
            },
            reload_action_identity: None,
            boot_id: None,
            representation: Representation::Symlink,
            baseline_hash: None,
            intended_witness_hash: None,
            applied_operation_generation: 0,
            status: RecordStatus::Pending {
                intent: PendingIntent::Apply(AppliedOperation::New),
                stage_name: Some(".furnish.test.stage".to_owned()),
                prior_owned: None,
            },
        };

        assert!(record.owned().is_none());
    }

    #[test]
    fn every_representation_pair_has_exact_gating_result() {
        let representations = [Representation::Symlink, Representation::Writable];
        for from in representations {
            for to in representations {
                let result = TransitionPair::try_from((from, to));
                match (from, to) {
                    (Representation::Symlink, Representation::Writable) => {
                        assert_eq!(result.unwrap(), TransitionPair::SymlinkToWritable);
                    }
                    (Representation::Writable, Representation::Symlink) => {
                        assert_eq!(result.unwrap(), TransitionPair::WritableToSymlink);
                    }
                    _ => {
                        assert_eq!(
                            result.unwrap_err().to_string(),
                            format!(
                                "no gated transfer from {} to {}",
                                from.as_str(),
                                to.as_str()
                            )
                        );
                    }
                }
            }
        }
    }
}
