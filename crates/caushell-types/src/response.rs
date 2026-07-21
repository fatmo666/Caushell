use serde::{Deserialize, Serialize};

use crate::{
    Decision, DerivedInvocation, Evidence, ExecutionSemanticsFact, ExecutionUnit,
    ExecutionUnitFlow, Finding, NestedPayload, RuleId,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResponse {
    pub decision: Decision,
    pub reasons: Vec<String>,
    pub decision_trace: DecisionTrace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckDecisionProposal {
    pub source_pass: String,
    pub rule_id: RuleId,
    pub decision: Decision,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DecisionTrace {
    pub executed_passes: Vec<String>,
    pub findings: Vec<Finding>,
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub execution_units: Vec<ExecutionUnit>,
    #[serde(default)]
    pub derived_invocations: Vec<DerivedInvocation>,
    #[serde(default)]
    pub execution_unit_flows: Vec<ExecutionUnitFlow>,
    #[serde(default)]
    pub nested_payloads: Vec<NestedPayload>,
    #[serde(default)]
    pub execution_semantics: Vec<ExecutionSemanticsFact>,
    pub decision_proposals: Vec<CheckDecisionProposal>,
}

#[cfg(test)]
mod tests {
    use super::{CheckDecisionProposal, CheckResponse, Decision, DecisionTrace};
    use crate::{
        CommandSequenceNo, DerivedInvocation, DerivedInvocationOrigin, Evidence,
        ExecutionPayloadMode, ExecutionSemanticsFact, ExecutionUnit, ExecutionUnitFlow,
        ExecutionUnitKind, Finding, NestedPayload, NestedPayloadInput, NestedPayloadLanguage,
        NestedPayloadOrigin, NestedPayloadResolution, NestedPayloadResolutionKind,
        NestedPayloadSource, RuleId, ShellKind,
    };
    use serde_json::json;

    #[test]
    fn check_response_holds_decision_and_reasons() {
        let resp = CheckResponse {
            decision: Decision::NeedApproval,
            reasons: vec![
                "payload expands to exec-capable child command".to_string(),
                "command touches workspace boundary".to_string(),
            ],
            decision_trace: DecisionTrace::default(),
        };
        assert_eq!(resp.decision, Decision::NeedApproval);
        assert_eq!(resp.reasons.len(), 2);
        assert_eq!(
            resp.reasons[0],
            "payload expands to exec-capable child command"
        );
    }

    #[test]
    fn check_response_can_have_no_reasons() {
        let resp = CheckResponse {
            decision: Decision::Allow,
            reasons: vec![],
            decision_trace: DecisionTrace::default(),
        };

        assert_eq!(resp.decision, Decision::Allow);
        assert!(resp.reasons.is_empty());
    }

    #[test]
    fn check_response_uses_json_contract() {
        let response = CheckResponse {
            decision: Decision::NeedApproval,
            reasons: vec!["command unknown-tool has no registered profile".to_string()],
            decision_trace: DecisionTrace {
                executed_passes: vec!["resolve_policy".to_string()],
                findings: vec![],
                evidence: vec![],
                execution_units: vec![],
                derived_invocations: vec![],
                execution_unit_flows: vec![],
                nested_payloads: vec![],
                execution_semantics: vec![],
                decision_proposals: vec![CheckDecisionProposal {
                    source_pass: "resolve_policy".to_string(),
                    rule_id: RuleId::NoProfile,
                    decision: Decision::NeedApproval,
                    reason: "command unknown-tool has no registered profile".to_string(),
                }],
            },
        };

        let value =
            serde_json::to_value(&response).expect("expected check response to serialize to json");

        assert_eq!(
            value,
            json!({
                "decision": "need_approval",
                "reasons": [
                    "command unknown-tool has no registered profile"
                ],
                "decision_trace": {
                    "executed_passes": [
                        "resolve_policy"
                    ],
                    "findings": [],
                    "evidence": [],
                    "execution_units": [],
                    "derived_invocations": [],
                    "execution_unit_flows": [],
                    "nested_payloads": [],
                    "execution_semantics": [],
                    "decision_proposals": [
                        {
                            "source_pass": "resolve_policy",
                            "rule_id": "no_profile",
                            "decision": "need_approval",
                            "reason": "command unknown-tool has no registered profile"
                        }
                    ]
                }
            })
        );

        let roundtrip: CheckResponse =
            serde_json::from_value(value).expect("expected check response to deserialize");

        assert_eq!(roundtrip, response);
    }

    #[test]
    fn check_response_serializes_decision_trace() {
        let response = CheckResponse {
            decision: Decision::Deny,
            reasons: vec!["startup config path escaped workspace root".to_string()],
            decision_trace: DecisionTrace {
                executed_passes: vec![
                    "parse_command".to_string(),
                    "resolve_invocation".to_string(),
                    "outside_workspace_startup_config".to_string(),
                    "decision_assembly".to_string(),
                ],
                findings: vec![Finding::new(
                    RuleId::OutsideWorkspaceStartupConfig,
                    "startup config path /tmp/shared/team.rc for slot startup_config in command bash is outside workspace root /tmp/project",
                )],
                evidence: vec![Evidence::prior_path_write(
                    RuleId::OutsideWorkspaceScriptSource,
                    "/tmp/shared/build.sh",
                    CommandSequenceNo::new(3),
                    "echo hi > ../../shared/build.sh",
                )],
                execution_units: vec![
                    ExecutionUnit {
                        node_id: "command:sess-1:5".to_string(),
                        execution_kind: ExecutionUnitKind::TopLevel,
                        root_sequence_no: CommandSequenceNo::new(5),
                        depth: 0,
                        raw_text: "bash --rcfile ./team.rc -c 'echo ok'".to_string(),
                        shell_kind: ShellKind::Bash,
                    },
                    ExecutionUnit {
                        node_id: "derived:sess-1:5:0:0".to_string(),
                        execution_kind: ExecutionUnitKind::Derived,
                        root_sequence_no: CommandSequenceNo::new(5),
                        depth: 1,
                        raw_text: "echo ok".to_string(),
                        shell_kind: ShellKind::Bash,
                    },
                ],
                derived_invocations: vec![DerivedInvocation {
                    node_id: "derived:sess-1:5:0:0".to_string(),
                    root_sequence_no: CommandSequenceNo::new(5),
                    origin: DerivedInvocationOrigin::NestedPayload {
                        nested_record_id: 0,
                    },
                    derived_command_index: 0,
                    raw_text: "echo ok".to_string(),
                    command_name: Some("echo".to_string()),
                    shell_kind: ShellKind::Bash,
                    depth: 1,
                }],
                execution_unit_flows: vec![ExecutionUnitFlow {
                    from: ExecutionUnit {
                        node_id: "command:sess-1:5".to_string(),
                        execution_kind: ExecutionUnitKind::TopLevel,
                        root_sequence_no: CommandSequenceNo::new(5),
                        depth: 0,
                        raw_text: "bash --rcfile ./team.rc -c 'echo ok'".to_string(),
                        shell_kind: ShellKind::Bash,
                    },
                    to: ExecutionUnit {
                        node_id: "derived:sess-1:5:0:0".to_string(),
                        execution_kind: ExecutionUnitKind::Derived,
                        root_sequence_no: CommandSequenceNo::new(5),
                        depth: 1,
                        raw_text: "echo ok".to_string(),
                        shell_kind: ShellKind::Bash,
                    },
                }],
                nested_payloads: vec![NestedPayload {
                    node_id: "nested:sess-1:5:0".to_string(),
                    root_sequence_no: CommandSequenceNo::new(5),
                    root_command_index: 0,
                    record_id: 0,
                    depth: 1,
                    language: NestedPayloadLanguage::Bash,
                    source: NestedPayloadSource::InlineString,
                    origin: NestedPayloadOrigin::Parameter {
                        slot_name: "payload".to_string(),
                    },
                    input: NestedPayloadInput::ArgumentFragments {
                        text: "echo ok".to_string(),
                        fragments: vec![crate::NestedPayloadInputFragment {
                            text: "echo ok".to_string(),
                            quoted: true,
                            node_kind: "raw_string".to_string(),
                        }],
                    },
                    resolution: NestedPayloadResolution {
                        kind: NestedPayloadResolutionKind::Parsed,
                        runtime_input_source: None,
                        detail: Some("shell_kind=Bash;command_count=1".to_string()),
                    },
                }],
                execution_semantics: vec![ExecutionSemanticsFact {
                    node_id: "execution-semantics:command:sess-1:5".to_string(),
                    source: ExecutionUnit {
                        node_id: "command:sess-1:5".to_string(),
                        execution_kind: ExecutionUnitKind::TopLevel,
                        root_sequence_no: CommandSequenceNo::new(5),
                        depth: 0,
                        raw_text: "bash --rcfile ./team.rc -c 'echo ok'".to_string(),
                        shell_kind: ShellKind::Bash,
                    },
                    normalized_command_name: "bash".to_string(),
                    form_id: "command_string".to_string(),
                    payload_mode: Some(ExecutionPayloadMode::CommandString),
                    executes_payload: true,
                    opens_interactive_escape_surface: false,
                    interactive_escape_surface_kind: None,
                    interactive_escape_capabilities: vec![],
                    interactive_escape_requires_tty: false,
                    mutates_current_shell: false,
                    executes_remote_command: false,
                    executes_hook: false,
                    executes_imported_package_logic: false,
                    loads_in_process_code: false,
                    in_process_code_load_kinds: vec![],
                    loads_startup_config: true,
                    loads_project_config: false,
                    loads_tool_config: false,
                    executes_config_defined_task: false,
                    dispatches_child_command: false,
                    controls_process: false,
                    process_control_action: None,
                    process_control_target_kind: None,
                    process_control_broad_target: false,
                }],
                decision_proposals: vec![CheckDecisionProposal {
                    source_pass: "outside_workspace_startup_config".to_string(),
                    rule_id: RuleId::OutsideWorkspaceStartupConfig,
                    decision: Decision::Deny,
                    reason: "startup config path /tmp/shared/team.rc for slot startup_config in command bash is outside workspace root /tmp/project".to_string(),
                }],
            },
        };

        let value =
            serde_json::to_value(&response).expect("expected check response to serialize to json");

        assert_eq!(
            value,
            json!({
                "decision": "deny",
                "reasons": [
                    "startup config path escaped workspace root"
                ],
                "decision_trace": {
                    "executed_passes": [
                        "parse_command",
                        "resolve_invocation",
                        "outside_workspace_startup_config",
                        "decision_assembly"
                    ],
                    "findings": [
                        {
                            "rule_id": "outside_workspace_startup_config",
                            "message": "startup config path /tmp/shared/team.rc for slot startup_config in command bash is outside workspace root /tmp/project",
                            "enforcement_class": "normal"
                        }
                    ],
                    "evidence": [
                        {
                            "rule_id": "outside_workspace_script_source",
                            "kind": {
                                "kind": "prior_path_write",
                                "path": "/tmp/shared/build.sh",
                                "sequence_no": 3,
                                "command": "echo hi > ../../shared/build.sh"
                            },
                            "summary": "path /tmp/shared/build.sh was previously written at sequence 3 by command echo hi > ../../shared/build.sh"
                        }
                    ],
                    "execution_units": [
                        {
                            "node_id": "command:sess-1:5",
                            "execution_kind": "top_level",
                            "root_sequence_no": 5,
                            "depth": 0,
                            "raw_text": "bash --rcfile ./team.rc -c 'echo ok'",
                            "shell_kind": "bash"
                        },
                        {
                            "node_id": "derived:sess-1:5:0:0",
                            "execution_kind": "derived",
                            "root_sequence_no": 5,
                            "depth": 1,
                            "raw_text": "echo ok",
                            "shell_kind": "bash"
                        }
                    ],
                    "derived_invocations": [
                        {
                            "node_id": "derived:sess-1:5:0:0",
                            "root_sequence_no": 5,
                            "origin": {
                                "kind": "nested_payload",
                                "nested_record_id": 0
                            },
                            "derived_command_index": 0,
                            "raw_text": "echo ok",
                            "command_name": "echo",
                            "shell_kind": "bash",
                            "depth": 1
                        }
                    ],
                    "execution_unit_flows": [
                        {
                            "from": {
                                "node_id": "command:sess-1:5",
                                "execution_kind": "top_level",
                                "root_sequence_no": 5,
                                "depth": 0,
                                "raw_text": "bash --rcfile ./team.rc -c 'echo ok'",
                                "shell_kind": "bash"
                            },
                            "to": {
                                "node_id": "derived:sess-1:5:0:0",
                                "execution_kind": "derived",
                                "root_sequence_no": 5,
                                "depth": 1,
                                "raw_text": "echo ok",
                                "shell_kind": "bash"
                            }
                        }
                    ],
                    "nested_payloads": [
                        {
                            "node_id": "nested:sess-1:5:0",
                            "root_sequence_no": 5,
                            "root_command_index": 0,
                            "record_id": 0,
                            "depth": 1,
                            "language": "bash",
                            "source": "inline_string",
                            "origin": {
                                "kind": "parameter",
                                "slot_name": "payload"
                            },
                            "input": {
                                "kind": "argument_fragments",
                                "text": "echo ok",
                                "fragments": [
                                    {
                                        "text": "echo ok",
                                        "quoted": true,
                                        "node_kind": "raw_string"
                                    }
                                ]
                            },
                            "resolution": {
                                "kind": "parsed",
                                "detail": "shell_kind=Bash;command_count=1"
                            }
                        }
                    ],
                    "execution_semantics": [
                        {
                            "node_id": "execution-semantics:command:sess-1:5",
                            "source": {
                                "node_id": "command:sess-1:5",
                                "execution_kind": "top_level",
                                "root_sequence_no": 5,
                                "depth": 0,
                                "raw_text": "bash --rcfile ./team.rc -c 'echo ok'",
                                "shell_kind": "bash"
                            },
                            "normalized_command_name": "bash",
                            "form_id": "command_string",
                            "payload_mode": "command_string",
                            "executes_payload": true,
                            "opens_interactive_escape_surface": false,
                            "interactive_escape_surface_kind": null,
                            "interactive_escape_capabilities": [],
                            "interactive_escape_requires_tty": false,
                            "mutates_current_shell": false,
                            "executes_remote_command": false,
                            "executes_hook": false,
                            "executes_imported_package_logic": false,
                            "loads_in_process_code": false,
                            "in_process_code_load_kinds": [],
                            "loads_startup_config": true,
                            "loads_project_config": false,
                            "loads_tool_config": false,
                            "executes_config_defined_task": false,
                            "dispatches_child_command": false,
                            "controls_process": false,
                            "process_control_action": null,
                            "process_control_target_kind": null,
                            "process_control_broad_target": false
                        }
                    ],
                    "decision_proposals": [
                        {
                            "source_pass": "outside_workspace_startup_config",
                            "rule_id": "outside_workspace_startup_config",
                            "decision": "deny",
                            "reason": "startup config path /tmp/shared/team.rc for slot startup_config in command bash is outside workspace root /tmp/project"
                        }
                    ]
                }
            })
        );

        let roundtrip: CheckResponse =
            serde_json::from_value(value).expect("expected check response to deserialize");

        assert_eq!(roundtrip, response);
    }
}
