use serde::{Deserialize, Serialize};

use crate::{
    RuntimeInputCapture, RuntimeInputSource, RuntimeProducedValueKind, SessionAliasBinding,
    SessionFunctionBinding, SessionVariableBinding, SessionVariableValue,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ShellStateKnowledge {
    Complete,
    ExportedOnly,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellStateObservability {
    pub variables: ShellStateKnowledge,
    pub aliases: ShellStateKnowledge,
    pub functions: ShellStateKnowledge,
    #[serde(default, skip_serializing_if = "ShellStateKnowledge::is_unknown")]
    pub positional_parameters: ShellStateKnowledge,
}

impl Default for ShellStateObservability {
    fn default() -> Self {
        Self {
            variables: ShellStateKnowledge::Unknown,
            aliases: ShellStateKnowledge::Unknown,
            functions: ShellStateKnowledge::Unknown,
            positional_parameters: ShellStateKnowledge::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShellValueSnapshot {
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

impl ShellValueSnapshot {
    pub fn exact_scalar(value: impl Into<String>) -> Self {
        Self::ExactScalar {
            value: value.into(),
        }
    }

    pub fn runtime_produced(
        value: impl Into<String>,
        value_kind: RuntimeProducedValueKind,
    ) -> Self {
        Self::RuntimeProduced {
            value: value.into(),
            value_kind,
        }
    }

    pub fn opaque_dynamic(repr: impl Into<String>) -> Self {
        Self::OpaqueDynamic { repr: repr.into() }
    }

    pub fn runtime_input(source: RuntimeInputSource, capture: RuntimeInputCapture) -> Self {
        Self::RuntimeInput { source, capture }
    }
}

impl ShellStateKnowledge {
    pub fn is_unknown(&self) -> bool {
        *self == Self::Unknown
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellVariableSnapshot {
    pub name: String,
    pub value: ShellValueSnapshot,
    pub exported: bool,
}

impl ShellVariableSnapshot {
    pub fn new(name: impl Into<String>, value: ShellValueSnapshot, exported: bool) -> Self {
        Self {
            name: name.into(),
            value,
            exported,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellAliasSnapshot {
    pub name: String,
    pub body: String,
}

impl ShellAliasSnapshot {
    pub fn new(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellFunctionSnapshot {
    pub name: String,
    pub body: String,
}

impl ShellFunctionSnapshot {
    pub fn new(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellStateSnapshot {
    pub cwd: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variables: Vec<ShellVariableSnapshot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub positional_parameters: Vec<ShellValueSnapshot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<ShellAliasSnapshot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<ShellFunctionSnapshot>,
    #[serde(default, skip_serializing_if = "ShellStateObservability::is_unknown")]
    pub observability: ShellStateObservability,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ShellStateDelta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd_after: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upsert_variables: Vec<SessionVariableBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset_variables: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub positional_parameters_after: Option<Vec<SessionVariableValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub positional_parameters_unknown_after: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upsert_aliases: Vec<SessionAliasBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset_aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upsert_functions: Vec<SessionFunctionBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset_functions: Vec<String>,
}

impl ShellStateDelta {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_cwd_after(mut self, cwd_after: impl Into<String>) -> Self {
        self.cwd_after = Some(cwd_after.into());
        self
    }

    pub fn with_upsert_variable(mut self, binding: SessionVariableBinding) -> Self {
        self.upsert_variables.push(binding);
        self
    }

    pub fn with_unset_variable(mut self, name: impl Into<String>) -> Self {
        self.unset_variables.push(name.into());
        self
    }

    pub fn with_positional_parameters_after<I>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = SessionVariableValue>,
    {
        self.positional_parameters_after = Some(values.into_iter().collect());
        self.positional_parameters_unknown_after = None;
        self
    }

    pub fn with_positional_parameters_unknown_after(mut self) -> Self {
        self.positional_parameters_after = None;
        self.positional_parameters_unknown_after = Some(true);
        self
    }

    pub fn with_upsert_alias(mut self, binding: SessionAliasBinding) -> Self {
        self.upsert_aliases.push(binding);
        self
    }

    pub fn with_unset_alias(mut self, name: impl Into<String>) -> Self {
        self.unset_aliases.push(name.into());
        self
    }

    pub fn with_upsert_function(mut self, binding: SessionFunctionBinding) -> Self {
        self.upsert_functions.push(binding);
        self
    }

    pub fn with_unset_function(mut self, name: impl Into<String>) -> Self {
        self.unset_functions.push(name.into());
        self
    }

    pub fn is_empty(&self) -> bool {
        self.cwd_after.is_none()
            && self.upsert_variables.is_empty()
            && self.unset_variables.is_empty()
            && self.positional_parameters_after.is_none()
            && self.positional_parameters_unknown_after != Some(true)
            && self.upsert_aliases.is_empty()
            && self.unset_aliases.is_empty()
            && self.upsert_functions.is_empty()
            && self.unset_functions.is_empty()
    }
}

impl ShellStateObservability {
    pub fn is_unknown(&self) -> bool {
        self.variables == ShellStateKnowledge::Unknown
            && self.aliases == ShellStateKnowledge::Unknown
            && self.functions == ShellStateKnowledge::Unknown
            && self.positional_parameters == ShellStateKnowledge::Unknown
    }
}

impl ShellStateSnapshot {
    pub fn new(cwd: impl Into<String>) -> Self {
        Self {
            cwd: cwd.into(),
            variables: Vec::new(),
            positional_parameters: Vec::new(),
            aliases: Vec::new(),
            functions: Vec::new(),
            observability: ShellStateObservability::default(),
        }
    }

    pub fn cwd(&self) -> &str {
        self.cwd.as_str()
    }

    pub fn variable(&self, name: &str) -> Option<&ShellVariableSnapshot> {
        self.variables.iter().find(|binding| binding.name == name)
    }

    pub fn exported_variable(&self, name: &str) -> Option<&ShellVariableSnapshot> {
        self.variables
            .iter()
            .find(|binding| binding.name == name && binding.exported)
    }

    pub fn positional_parameter(&self, position: usize) -> Option<&ShellValueSnapshot> {
        if position == 0 {
            return None;
        }

        self.positional_parameters.get(position - 1)
    }

    pub fn alias(&self, name: &str) -> Option<&ShellAliasSnapshot> {
        self.aliases.iter().find(|binding| binding.name == name)
    }

    pub fn function(&self, name: &str) -> Option<&ShellFunctionSnapshot> {
        self.functions.iter().find(|binding| binding.name == name)
    }

    pub fn with_exact_scalar_variable(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        exported: bool,
    ) -> Self {
        self.variables.push(ShellVariableSnapshot::new(
            name,
            ShellValueSnapshot::exact_scalar(value),
            exported,
        ));
        self
    }

    pub fn with_opaque_dynamic_variable(
        mut self,
        name: impl Into<String>,
        repr: impl Into<String>,
        exported: bool,
    ) -> Self {
        self.variables.push(ShellVariableSnapshot::new(
            name,
            ShellValueSnapshot::opaque_dynamic(repr),
            exported,
        ));
        self
    }

    pub fn with_runtime_produced_variable(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        value_kind: RuntimeProducedValueKind,
        exported: bool,
    ) -> Self {
        self.variables.push(ShellVariableSnapshot::new(
            name,
            ShellValueSnapshot::runtime_produced(value, value_kind),
            exported,
        ));
        self
    }

    pub fn with_runtime_input_variable(
        mut self,
        name: impl Into<String>,
        source: RuntimeInputSource,
        capture: RuntimeInputCapture,
        exported: bool,
    ) -> Self {
        self.variables.push(ShellVariableSnapshot::new(
            name,
            ShellValueSnapshot::runtime_input(source, capture),
            exported,
        ));
        self
    }

    pub fn with_exact_scalar_positional_parameters<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.positional_parameters = values
            .into_iter()
            .map(ShellValueSnapshot::exact_scalar)
            .collect();
        self
    }

    pub fn with_alias(mut self, name: impl Into<String>, body: impl Into<String>) -> Self {
        self.aliases.push(ShellAliasSnapshot::new(name, body));
        self
    }

    pub fn with_function(mut self, name: impl Into<String>, body: impl Into<String>) -> Self {
        self.functions.push(ShellFunctionSnapshot::new(name, body));
        self
    }

    pub fn with_variable_knowledge(mut self, knowledge: ShellStateKnowledge) -> Self {
        self.observability.variables = knowledge;
        self
    }

    pub fn with_alias_knowledge(mut self, knowledge: ShellStateKnowledge) -> Self {
        self.observability.aliases = knowledge;
        self
    }

    pub fn with_function_knowledge(mut self, knowledge: ShellStateKnowledge) -> Self {
        self.observability.functions = knowledge;
        self
    }

    pub fn with_positional_parameter_knowledge(mut self, knowledge: ShellStateKnowledge) -> Self {
        self.observability.positional_parameters = knowledge;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ShellStateDelta, ShellStateKnowledge, ShellStateSnapshot, ShellValueSnapshot,
        ShellVariableSnapshot,
    };
    use crate::{
        CommandSequenceNo, RuntimeInputCapture, RuntimeInputSource, RuntimeProducedValueKind,
        SessionAliasBinding, SessionFunctionBinding, SessionVariableBinding, SessionVariableValue,
    };
    use serde_json::json;

    #[test]
    fn shell_state_snapshot_roundtrips_through_json_contract() {
        let snapshot = ShellStateSnapshot::new("/tmp/project")
            .with_exact_scalar_variable("USER_CMD", "echo ok", true)
            .with_alias("ll", "ls -la")
            .with_function("deploy", "bash ./deploy.sh;")
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete);

        let value = serde_json::to_value(&snapshot)
            .expect("expected shell state snapshot to serialize to json");

        assert_eq!(
            value,
            json!({
                "cwd": "/tmp/project",
                "variables": [
                    {
                        "name": "USER_CMD",
                        "value": {
                            "kind": "exact_scalar",
                            "value": "echo ok"
                        },
                        "exported": true
                    }
                ],
                "aliases": [
                    {
                        "name": "ll",
                        "body": "ls -la"
                    }
                ],
                "functions": [
                    {
                        "name": "deploy",
                        "body": "bash ./deploy.sh;"
                    }
                ],
                "observability": {
                    "variables": "complete",
                    "aliases": "complete",
                    "functions": "complete"
                }
            })
        );

        let roundtrip: ShellStateSnapshot =
            serde_json::from_value(value).expect("expected shell state snapshot to deserialize");

        assert_eq!(roundtrip, snapshot);
    }

    #[test]
    fn shell_state_snapshot_omits_unknown_observability_by_default() {
        let snapshot = ShellStateSnapshot::new("/tmp/project");

        let value = serde_json::to_value(&snapshot)
            .expect("expected shell state snapshot to serialize to json");

        assert_eq!(value, json!({ "cwd": "/tmp/project" }));
    }

    #[test]
    fn shell_state_snapshot_can_hold_runtime_input_derived_variable() {
        let snapshot = ShellStateSnapshot {
            cwd: "/tmp/project".to_string(),
            variables: vec![ShellVariableSnapshot::new(
                "USER_CMD",
                ShellValueSnapshot::RuntimeInput {
                    source: RuntimeInputSource::StdinPayload,
                    capture: RuntimeInputCapture::NotCaptured,
                },
                false,
            )],
            positional_parameters: Vec::new(),
            aliases: Vec::new(),
            functions: Vec::new(),
            observability: Default::default(),
        };

        assert_eq!(
            snapshot.variable("USER_CMD"),
            Some(&ShellVariableSnapshot::new(
                "USER_CMD",
                ShellValueSnapshot::RuntimeInput {
                    source: RuntimeInputSource::StdinPayload,
                    capture: RuntimeInputCapture::NotCaptured,
                },
                false,
            ))
        );
    }

    #[test]
    fn shell_state_snapshot_roundtrips_runtime_produced_variable() {
        let snapshot = ShellStateSnapshot::new("/tmp/project").with_runtime_produced_variable(
            "TMP_SCRIPT",
            "/tmp/tmp.abcd.sh",
            RuntimeProducedValueKind::Path,
            false,
        );

        let value = serde_json::to_value(&snapshot).expect("expected shell state to serialize");
        let roundtrip: ShellStateSnapshot =
            serde_json::from_value(value).expect("expected shell state to deserialize");

        assert_eq!(roundtrip, snapshot);
        assert_eq!(
            roundtrip.variable("TMP_SCRIPT"),
            Some(&ShellVariableSnapshot::new(
                "TMP_SCRIPT",
                ShellValueSnapshot::RuntimeProduced {
                    value: "/tmp/tmp.abcd.sh".to_string(),
                    value_kind: RuntimeProducedValueKind::Path,
                },
                false,
            ))
        );
    }

    #[test]
    fn shell_state_snapshot_roundtrips_positional_parameters_when_observed() {
        let snapshot = ShellStateSnapshot::new("/tmp/project")
            .with_exact_scalar_positional_parameters(["/", "/dev/sda"])
            .with_positional_parameter_knowledge(ShellStateKnowledge::Complete);

        let value = serde_json::to_value(&snapshot)
            .expect("expected shell state snapshot to serialize to json");

        assert_eq!(
            value,
            json!({
                "cwd": "/tmp/project",
                "positional_parameters": [
                    {
                        "kind": "exact_scalar",
                        "value": "/"
                    },
                    {
                        "kind": "exact_scalar",
                        "value": "/dev/sda"
                    }
                ],
                "observability": {
                    "variables": "unknown",
                    "aliases": "unknown",
                    "functions": "unknown",
                    "positional_parameters": "complete"
                }
            })
        );

        let roundtrip: ShellStateSnapshot =
            serde_json::from_value(value).expect("expected shell state snapshot to deserialize");

        assert_eq!(roundtrip, snapshot);
        assert_eq!(
            roundtrip.positional_parameter(2),
            Some(&ShellValueSnapshot::exact_scalar("/dev/sda"))
        );
    }

    #[test]
    fn shell_state_delta_roundtrips_through_json_contract() {
        let delta = ShellStateDelta::new()
            .with_cwd_after("/tmp/project/subdir")
            .with_upsert_variable(SessionVariableBinding::new(
                "USER_CMD",
                SessionVariableValue::exact_scalar("echo ok"),
                false,
                CommandSequenceNo::new(7),
            ))
            .with_unset_variable("OLD_VAR")
            .with_positional_parameters_after([
                SessionVariableValue::exact_scalar("/"),
                SessionVariableValue::exact_scalar("/dev/sda"),
            ])
            .with_upsert_alias(SessionAliasBinding::new(
                "ll",
                "ls -la",
                CommandSequenceNo::new(7),
            ))
            .with_unset_alias("oldalias")
            .with_upsert_function(SessionFunctionBinding::new(
                "deploy",
                "bash ./deploy.sh;",
                CommandSequenceNo::new(7),
            ))
            .with_unset_function("oldfunc");

        let value = serde_json::to_value(&delta).expect("expected shell state delta to serialize");

        assert_eq!(
            value,
            json!({
                "cwd_after": "/tmp/project/subdir",
                "upsert_variables": [
                    {
                        "name": "USER_CMD",
                        "value": {
                            "ExactScalar": "echo ok"
                        },
                        "exported": false,
                        "observed_at": 7
                    }
                ],
                "unset_variables": ["OLD_VAR"],
                "positional_parameters_after": [
                    {
                        "ExactScalar": "/"
                    },
                    {
                        "ExactScalar": "/dev/sda"
                    }
                ],
                "upsert_aliases": [
                    {
                        "name": "ll",
                        "body": "ls -la",
                        "observed_at": 7
                    }
                ],
                "unset_aliases": ["oldalias"],
                "upsert_functions": [
                    {
                        "name": "deploy",
                        "body": "bash ./deploy.sh;",
                        "observed_at": 7
                    }
                ],
                "unset_functions": ["oldfunc"]
            })
        );

        let roundtrip: ShellStateDelta =
            serde_json::from_value(value).expect("expected shell state delta to deserialize");

        assert_eq!(roundtrip, delta);
        assert!(!roundtrip.is_empty());
    }
}
