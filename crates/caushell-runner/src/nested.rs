use caushell_graph::NodeId;
use caushell_parse::ParsedCommandArtifact;
use caushell_profile::{
    MaterializedRecursivePayloadCandidate, RecursivePayloadOrigin, RecursivePayloadParseResult,
    SessionBindings, ValueMaterialization,
};
use caushell_types::{RuntimeInputSource, ShellKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NestedPayloadRecordId(pub usize);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedPayloadRecord {
    pub record_id: NestedPayloadRecordId,
    pub parent_ref: NestedPayloadParentRef,
    pub root_command_index: usize,
    pub depth: u8,
    pub bindings: SessionBindings,
    pub candidate: MaterializedRecursivePayloadCandidate,
    pub resolution: NestedPayloadResolution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NestedPayloadParentRef {
    RootCommand { command_index: usize },
    DerivedInvocation { node_id: NodeId },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NestedPayloadResolution {
    Parsed {
        shell_kind: ShellKind,
        parsed: ParsedCommandArtifact,
    },
    TruncatedByDepthBudget {
        max_depth: u8,
        next_candidate_count: usize,
    },
    RequiresRuntimeInput {
        source: RuntimeInputSource,
    },
    UnsupportedLanguage,
    ParseFailed {
        shell_kind: ShellKind,
        error: String,
    },
    UnresolvedMaterialization {
        materialization: ValueMaterialization,
    },
}

impl NestedPayloadRecord {
    pub fn from_parse_result(
        record_id: NestedPayloadRecordId,
        parent_ref: NestedPayloadParentRef,
        root_command_index: usize,
        depth: u8,
        bindings: SessionBindings,
        candidate: MaterializedRecursivePayloadCandidate,
        result: RecursivePayloadParseResult,
    ) -> Self {
        let resolution = match result {
            RecursivePayloadParseResult::Parsed(parsed) => NestedPayloadResolution::Parsed {
                shell_kind: parsed.shell_kind,
                parsed: parsed.artifact,
            },
            RecursivePayloadParseResult::RequiresRuntimeInput { .. } => {
                let ValueMaterialization::RequiresRuntimeInput { source, .. } =
                    &candidate.resolution
                else {
                    panic!(
                        "recursive payload runtime-input parse result must carry runtime input materialization"
                    );
                };
                NestedPayloadResolution::RequiresRuntimeInput {
                    source: source.to_runtime_input_source().expect(
                        "nested runtime input resolution should not use inherited environment",
                    ),
                }
            }
            RecursivePayloadParseResult::UnsupportedLanguage { .. } => {
                NestedPayloadResolution::UnsupportedLanguage
            }
            RecursivePayloadParseResult::ParseFailed {
                shell_kind, error, ..
            } => NestedPayloadResolution::ParseFailed {
                shell_kind,
                error: error.to_string(),
            },
        };

        Self {
            record_id,
            parent_ref,
            root_command_index,
            depth,
            bindings,
            candidate,
            resolution,
        }
    }

    pub fn is_parameter_origin(&self, slot_name: &str) -> bool {
        matches!(
            &self.candidate.candidate.origin,
            RecursivePayloadOrigin::Parameter { slot } if slot.as_str() == slot_name
        )
    }
}
