use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{CommandSequenceNo, RuntimeInputCapture, RuntimeInputSource};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProducedValueKind {
    Scalar,
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionVariableValue {
    ExactScalar(String),
    RuntimeProduced {
        value: String,
        kind: RuntimeProducedValueKind,
    },
    OpaqueDynamic {
        repr: String,
    },
    RuntimeInput {
        source: RuntimeInputSource,
        capture: RuntimeInputCapture,
    },
}

impl SessionVariableValue {
    pub fn exact_scalar(value: impl Into<String>) -> Self {
        Self::ExactScalar(value.into())
    }

    pub fn runtime_produced(value: impl Into<String>, kind: RuntimeProducedValueKind) -> Self {
        Self::RuntimeProduced {
            value: value.into(),
            kind,
        }
    }

    pub fn opaque_dynamic(repr: impl Into<String>) -> Self {
        Self::OpaqueDynamic { repr: repr.into() }
    }

    pub fn runtime_input(source: RuntimeInputSource, capture: RuntimeInputCapture) -> Self {
        Self::RuntimeInput { source, capture }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionVariableBinding {
    pub name: String,
    pub value: SessionVariableValue,
    pub exported: bool,
    pub observed_at: CommandSequenceNo,
}

impl SessionVariableBinding {
    pub fn new(
        name: impl Into<String>,
        value: SessionVariableValue,
        exported: bool,
        observed_at: CommandSequenceNo,
    ) -> Self {
        Self {
            name: name.into(),
            value,
            exported,
            observed_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionAliasBinding {
    pub name: String,
    pub body: String,
    pub observed_at: CommandSequenceNo,
}

impl SessionAliasBinding {
    pub fn new(
        name: impl Into<String>,
        body: impl Into<String>,
        observed_at: CommandSequenceNo,
    ) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
            observed_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionFunctionBinding {
    pub name: String,
    pub body: String,
    pub observed_at: CommandSequenceNo,
}

impl SessionFunctionBinding {
    pub fn new(
        name: impl Into<String>,
        body: impl Into<String>,
        observed_at: CommandSequenceNo,
    ) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
            observed_at,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCurrentWorkingDirectorySource {
    RuntimeSnapshot,
    StaticAnalysis,
}

impl Default for SessionCurrentWorkingDirectorySource {
    fn default() -> Self {
        Self::RuntimeSnapshot
    }
}

impl SessionCurrentWorkingDirectorySource {
    pub fn is_runtime_snapshot(&self) -> bool {
        *self == Self::RuntimeSnapshot
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionCurrentWorkingDirectory {
    pub path: String,
    pub observed_at: CommandSequenceNo,
    #[serde(
        default,
        skip_serializing_if = "SessionCurrentWorkingDirectorySource::is_runtime_snapshot"
    )]
    pub source: SessionCurrentWorkingDirectorySource,
}

impl SessionCurrentWorkingDirectory {
    pub fn new(path: impl Into<String>, observed_at: CommandSequenceNo) -> Self {
        Self::with_source(
            path,
            observed_at,
            SessionCurrentWorkingDirectorySource::RuntimeSnapshot,
        )
    }

    pub fn with_source(
        path: impl Into<String>,
        observed_at: CommandSequenceNo,
        source: SessionCurrentWorkingDirectorySource,
    ) -> Self {
        Self {
            path: path.into(),
            observed_at,
            source,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionPositionalParameters {
    pub values: Vec<SessionVariableValue>,
    pub observed_at: CommandSequenceNo,
}

impl SessionPositionalParameters {
    pub fn new<I>(values: I, observed_at: CommandSequenceNo) -> Self
    where
        I: IntoIterator<Item = SessionVariableValue>,
    {
        Self {
            values: values.into_iter().collect(),
            observed_at,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    last_sequence_no: Option<CommandSequenceNo>,
    variable_bindings: BTreeMap<String, SessionVariableBinding>,
    alias_bindings: BTreeMap<String, SessionAliasBinding>,
    function_bindings: BTreeMap<String, SessionFunctionBinding>,
    current_working_directory: Option<SessionCurrentWorkingDirectory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    positional_parameters: Option<SessionPositionalParameters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    positional_parameters_unknown_observed_at: Option<CommandSequenceNo>,
}

impl SessionSummary {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn last_sequence_no(&self) -> Option<CommandSequenceNo> {
        self.last_sequence_no
    }

    pub fn observe_sequence(&mut self, sequence_no: CommandSequenceNo) {
        if self.last_sequence_no < Some(sequence_no) {
            self.last_sequence_no = Some(sequence_no);
        }
    }

    pub fn upsert_variable_binding(&mut self, binding: SessionVariableBinding) {
        let name = binding.name.clone();
        let observed_at = binding.observed_at;

        let should_replace = match self.variable_bindings.get(name.as_str()) {
            Some(existing) => existing.observed_at <= binding.observed_at,
            None => true,
        };

        if should_replace {
            self.variable_bindings.insert(name, binding);
        }

        self.observe_sequence(observed_at);
    }

    pub fn set_exact_scalar_variable(
        &mut self,
        name: &str,
        value: impl Into<String>,
        exported: bool,
        observed_at: CommandSequenceNo,
    ) {
        self.upsert_variable_binding(SessionVariableBinding::new(
            name,
            SessionVariableValue::exact_scalar(value),
            exported,
            observed_at,
        ));
    }

    pub fn set_opaque_dynamic_variable(
        &mut self,
        name: &str,
        repr: impl Into<String>,
        exported: bool,
        observed_at: CommandSequenceNo,
    ) {
        self.upsert_variable_binding(SessionVariableBinding::new(
            name,
            SessionVariableValue::opaque_dynamic(repr),
            exported,
            observed_at,
        ));
    }

    pub fn set_runtime_produced_variable(
        &mut self,
        name: &str,
        value: impl Into<String>,
        kind: RuntimeProducedValueKind,
        exported: bool,
        observed_at: CommandSequenceNo,
    ) {
        self.upsert_variable_binding(SessionVariableBinding::new(
            name,
            SessionVariableValue::runtime_produced(value, kind),
            exported,
            observed_at,
        ));
    }

    pub fn set_runtime_input_variable(
        &mut self,
        name: &str,
        source: RuntimeInputSource,
        capture: RuntimeInputCapture,
        exported: bool,
        observed_at: CommandSequenceNo,
    ) {
        self.upsert_variable_binding(SessionVariableBinding::new(
            name,
            SessionVariableValue::runtime_input(source, capture),
            exported,
            observed_at,
        ));
    }

    pub fn unset_variable(&mut self, name: &str, observed_at: CommandSequenceNo) {
        let should_remove = match self.variable_bindings.get(name) {
            Some(existing) => existing.observed_at <= observed_at,
            None => false,
        };

        if should_remove {
            self.variable_bindings.remove(name);
        }

        self.observe_sequence(observed_at);
    }

    pub fn variable_binding(&self, name: &str) -> Option<&SessionVariableBinding> {
        self.variable_bindings.get(name)
    }

    pub fn variable_bindings(&self) -> impl Iterator<Item = &SessionVariableBinding> + '_ {
        self.variable_bindings.values()
    }

    pub fn set_current_working_directory(
        &mut self,
        path: impl Into<String>,
        observed_at: CommandSequenceNo,
    ) {
        self.set_current_working_directory_with_source(
            path,
            observed_at,
            SessionCurrentWorkingDirectorySource::RuntimeSnapshot,
        );
    }

    pub fn set_current_working_directory_with_source(
        &mut self,
        path: impl Into<String>,
        observed_at: CommandSequenceNo,
        source: SessionCurrentWorkingDirectorySource,
    ) {
        let cwd = SessionCurrentWorkingDirectory::with_source(path, observed_at, source);

        let should_replace = match &self.current_working_directory {
            Some(existing) => existing.observed_at <= cwd.observed_at,
            None => true,
        };

        if should_replace {
            self.current_working_directory = Some(cwd);
        }

        self.observe_sequence(observed_at);
    }

    pub fn current_working_directory(&self) -> Option<&SessionCurrentWorkingDirectory> {
        self.current_working_directory.as_ref()
    }

    pub fn set_positional_parameters<I>(&mut self, values: I, observed_at: CommandSequenceNo)
    where
        I: IntoIterator<Item = SessionVariableValue>,
    {
        let positional_parameters = SessionPositionalParameters::new(values, observed_at);

        let should_replace = match self.positional_parameters_observed_at() {
            Some(existing_observed_at) => existing_observed_at <= observed_at,
            None => true,
        };

        if should_replace {
            self.positional_parameters = Some(positional_parameters);
            self.positional_parameters_unknown_observed_at = None;
        }

        self.observe_sequence(observed_at);
    }

    pub fn forget_positional_parameters(&mut self, observed_at: CommandSequenceNo) {
        let should_replace = match self.positional_parameters_observed_at() {
            Some(existing_observed_at) => existing_observed_at <= observed_at,
            None => true,
        };

        if should_replace {
            self.positional_parameters = None;
            self.positional_parameters_unknown_observed_at = Some(observed_at);
        }

        self.observe_sequence(observed_at);
    }

    pub fn positional_parameters(&self) -> Option<&SessionPositionalParameters> {
        self.positional_parameters.as_ref()
    }

    pub fn positional_parameters_observed_at(&self) -> Option<CommandSequenceNo> {
        self.positional_parameters
            .as_ref()
            .map(|positional| positional.observed_at)
            .or(self.positional_parameters_unknown_observed_at)
    }

    pub fn upsert_alias_binding(&mut self, binding: SessionAliasBinding) {
        let name = binding.name.clone();
        let observed_at = binding.observed_at;

        let should_replace = match self.alias_bindings.get(name.as_str()) {
            Some(existing) => existing.observed_at <= binding.observed_at,
            None => true,
        };

        if should_replace {
            self.alias_bindings.insert(name, binding);
        }

        self.observe_sequence(observed_at);
    }

    pub fn set_alias(
        &mut self,
        name: &str,
        body: impl Into<String>,
        observed_at: CommandSequenceNo,
    ) {
        self.upsert_alias_binding(SessionAliasBinding::new(name, body, observed_at));
    }

    pub fn unset_alias(&mut self, name: &str, observed_at: CommandSequenceNo) {
        let should_remove = match self.alias_bindings.get(name) {
            Some(existing) => existing.observed_at <= observed_at,
            None => false,
        };

        if should_remove {
            self.alias_bindings.remove(name);
        }

        self.observe_sequence(observed_at);
    }

    pub fn alias_binding(&self, name: &str) -> Option<&SessionAliasBinding> {
        self.alias_bindings.get(name)
    }

    pub fn alias_bindings(&self) -> impl Iterator<Item = &SessionAliasBinding> + '_ {
        self.alias_bindings.values()
    }

    pub fn upsert_function_binding(&mut self, binding: SessionFunctionBinding) {
        let name = binding.name.clone();
        let observed_at = binding.observed_at;

        let should_replace = match self.function_bindings.get(name.as_str()) {
            Some(existing) => existing.observed_at <= binding.observed_at,
            None => true,
        };

        if should_replace {
            self.function_bindings.insert(name, binding);
        }

        self.observe_sequence(observed_at);
    }

    pub fn set_function(
        &mut self,
        name: &str,
        body: impl Into<String>,
        observed_at: CommandSequenceNo,
    ) {
        self.upsert_function_binding(SessionFunctionBinding::new(name, body, observed_at));
    }

    pub fn unset_function(&mut self, name: &str, observed_at: CommandSequenceNo) {
        let should_remove = match self.function_bindings.get(name) {
            Some(existing) => existing.observed_at <= observed_at,
            None => false,
        };

        if should_remove {
            self.function_bindings.remove(name);
        }

        self.observe_sequence(observed_at);
    }

    pub fn function_binding(&self, name: &str) -> Option<&SessionFunctionBinding> {
        self.function_bindings.get(name)
    }

    pub fn function_bindings(&self) -> impl Iterator<Item = &SessionFunctionBinding> + '_ {
        self.function_bindings.values()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RuntimeProducedValueKind, SessionAliasBinding, SessionCurrentWorkingDirectory,
        SessionCurrentWorkingDirectorySource, SessionFunctionBinding, SessionSummary,
        SessionVariableValue,
    };
    use crate::{CommandSequenceNo, RuntimeInputCapture, RuntimeInputSource};

    #[test]
    fn summary_tracks_last_sequence_monotonically() {
        let mut summary = SessionSummary::new();

        summary.observe_sequence(CommandSequenceNo::new(2));
        summary.observe_sequence(CommandSequenceNo::new(1));
        summary.observe_sequence(CommandSequenceNo::new(3));

        assert_eq!(summary.last_sequence_no(), Some(CommandSequenceNo::new(3)));
    }

    #[test]
    fn summary_can_store_exact_scalar_variable() {
        let mut summary = SessionSummary::new();

        summary.set_exact_scalar_variable("SCRIPT", "build.sh", false, CommandSequenceNo::new(4));

        let binding = summary
            .variable_binding("SCRIPT")
            .expect("expected variable binding to exist");

        assert_eq!(binding.name, "SCRIPT");
        assert!(!binding.exported);
        assert_eq!(binding.observed_at, CommandSequenceNo::new(4));
        assert_eq!(
            binding.value,
            SessionVariableValue::ExactScalar("build.sh".to_string())
        );
        assert_eq!(summary.last_sequence_no(), Some(CommandSequenceNo::new(4)));
    }

    #[test]
    fn summary_can_store_opaque_dynamic_variable() {
        let mut summary = SessionSummary::new();

        summary.set_opaque_dynamic_variable(
            "USER_CMD",
            "$payload",
            true,
            CommandSequenceNo::new(7),
        );

        let binding = summary
            .variable_binding("USER_CMD")
            .expect("expected variable binding to exist");

        assert!(binding.exported);
        assert_eq!(
            binding.value,
            SessionVariableValue::OpaqueDynamic {
                repr: "$payload".to_string(),
            }
        );
    }

    #[test]
    fn summary_can_store_runtime_input_variable() {
        let mut summary = SessionSummary::new();

        summary.set_runtime_input_variable(
            "USER_CMD",
            RuntimeInputSource::StdinData,
            RuntimeInputCapture::Descriptor {
                descriptor: "read USER_CMD".to_string(),
            },
            false,
            CommandSequenceNo::new(8),
        );

        let binding = summary
            .variable_binding("USER_CMD")
            .expect("expected variable binding to exist");

        assert!(!binding.exported);
        assert_eq!(
            binding.value,
            SessionVariableValue::RuntimeInput {
                source: RuntimeInputSource::StdinData,
                capture: RuntimeInputCapture::Descriptor {
                    descriptor: "read USER_CMD".to_string(),
                },
            }
        );
    }

    #[test]
    fn summary_can_store_positional_parameters() {
        let mut summary = SessionSummary::new();

        summary.set_positional_parameters(
            [
                SessionVariableValue::exact_scalar("/"),
                SessionVariableValue::exact_scalar("/dev/sda"),
            ],
            CommandSequenceNo::new(9),
        );

        let positional = summary
            .positional_parameters()
            .expect("expected positional parameters to exist");

        assert_eq!(
            positional.values,
            vec![
                SessionVariableValue::ExactScalar("/".to_string()),
                SessionVariableValue::ExactScalar("/dev/sda".to_string()),
            ]
        );
        assert_eq!(positional.observed_at, CommandSequenceNo::new(9));
        assert_eq!(summary.last_sequence_no(), Some(CommandSequenceNo::new(9)));
    }

    #[test]
    fn summary_preserves_newer_positional_parameters() {
        let mut summary = SessionSummary::new();

        summary.set_positional_parameters(
            [SessionVariableValue::exact_scalar("/")],
            CommandSequenceNo::new(9),
        );
        summary.set_positional_parameters(
            [SessionVariableValue::exact_scalar("/tmp")],
            CommandSequenceNo::new(7),
        );

        let positional = summary
            .positional_parameters()
            .expect("expected positional parameters to exist");

        assert_eq!(
            positional.values,
            vec![SessionVariableValue::ExactScalar("/".to_string())]
        );
        assert_eq!(summary.last_sequence_no(), Some(CommandSequenceNo::new(9)));
    }

    #[test]
    fn summary_can_forget_positional_parameters_without_resurrecting_older_values() {
        let mut summary = SessionSummary::new();

        summary.set_positional_parameters(
            [SessionVariableValue::exact_scalar("/")],
            CommandSequenceNo::new(7),
        );
        summary.forget_positional_parameters(CommandSequenceNo::new(9));
        summary.set_positional_parameters(
            [SessionVariableValue::exact_scalar("/tmp")],
            CommandSequenceNo::new(8),
        );

        assert!(summary.positional_parameters().is_none());
        assert_eq!(
            summary.positional_parameters_observed_at(),
            Some(CommandSequenceNo::new(9))
        );
        assert_eq!(summary.last_sequence_no(), Some(CommandSequenceNo::new(9)));
    }

    #[test]
    fn summary_can_store_runtime_produced_path_variable() {
        let mut summary = SessionSummary::new();

        summary.set_runtime_produced_variable(
            "TMP_SCRIPT",
            "/tmp/tmp.abcd.sh",
            RuntimeProducedValueKind::Path,
            false,
            CommandSequenceNo::new(9),
        );

        let binding = summary
            .variable_binding("TMP_SCRIPT")
            .expect("expected variable binding to exist");

        assert_eq!(
            binding.value,
            SessionVariableValue::RuntimeProduced {
                value: "/tmp/tmp.abcd.sh".to_string(),
                kind: RuntimeProducedValueKind::Path,
            }
        );
    }

    #[test]
    fn summary_ignores_stale_variable_update() {
        let mut summary = SessionSummary::new();

        summary.set_exact_scalar_variable("SCRIPT", "new.sh", false, CommandSequenceNo::new(8));
        summary.set_exact_scalar_variable("SCRIPT", "old.sh", false, CommandSequenceNo::new(3));

        let binding = summary
            .variable_binding("SCRIPT")
            .expect("expected variable binding to exist");

        assert_eq!(
            binding.value,
            SessionVariableValue::ExactScalar("new.sh".to_string())
        );
        assert_eq!(binding.observed_at, CommandSequenceNo::new(8));
    }

    #[test]
    fn summary_unset_removes_binding_when_newer() {
        let mut summary = SessionSummary::new();

        summary.set_exact_scalar_variable("SCRIPT", "build.sh", false, CommandSequenceNo::new(2));
        summary.unset_variable("SCRIPT", CommandSequenceNo::new(5));

        assert!(summary.variable_binding("SCRIPT").is_none());
        assert_eq!(summary.last_sequence_no(), Some(CommandSequenceNo::new(5)));
    }

    #[test]
    fn summary_ignores_stale_unset() {
        let mut summary = SessionSummary::new();

        summary.set_exact_scalar_variable("SCRIPT", "build.sh", false, CommandSequenceNo::new(9));
        summary.unset_variable("SCRIPT", CommandSequenceNo::new(4));

        let binding = summary
            .variable_binding("SCRIPT")
            .expect("expected variable binding to remain");

        assert_eq!(
            binding.value,
            SessionVariableValue::ExactScalar("build.sh".to_string())
        );
        assert_eq!(binding.observed_at, CommandSequenceNo::new(9));
    }

    #[test]
    fn summary_exposes_variable_bindings_iterator() {
        let mut summary = SessionSummary::new();

        summary.set_exact_scalar_variable("A", "1", false, CommandSequenceNo::new(1));
        summary.set_exact_scalar_variable("B", "2", true, CommandSequenceNo::new(2));

        let names: Vec<&str> = summary
            .variable_bindings()
            .map(|binding| binding.name.as_str())
            .collect();

        assert_eq!(names, vec!["A", "B"]);
    }

    #[test]
    fn summary_tracks_current_working_directory_monotonically() {
        let mut summary = SessionSummary::new();

        summary.set_current_working_directory("/tmp/project", CommandSequenceNo::new(2));
        summary.set_current_working_directory("/tmp/older", CommandSequenceNo::new(1));
        summary.set_current_working_directory("/tmp/next", CommandSequenceNo::new(4));

        assert_eq!(
            summary.current_working_directory(),
            Some(&SessionCurrentWorkingDirectory::new(
                "/tmp/next",
                CommandSequenceNo::new(4),
            ))
        );
    }

    #[test]
    fn summary_tracks_current_working_directory_source() {
        let mut summary = SessionSummary::new();

        summary.set_current_working_directory_with_source(
            "/",
            CommandSequenceNo::new(2),
            SessionCurrentWorkingDirectorySource::StaticAnalysis,
        );

        assert_eq!(
            summary.current_working_directory(),
            Some(&SessionCurrentWorkingDirectory::with_source(
                "/",
                CommandSequenceNo::new(2),
                SessionCurrentWorkingDirectorySource::StaticAnalysis,
            ))
        );
    }

    #[test]
    fn summary_can_store_alias_binding() {
        let mut summary = SessionSummary::new();

        summary.set_alias("ll", "ls -l", CommandSequenceNo::new(4));

        let binding = summary
            .alias_binding("ll")
            .expect("expected alias binding to exist");

        assert_eq!(
            binding,
            &SessionAliasBinding::new("ll", "ls -l", CommandSequenceNo::new(4))
        );
        assert_eq!(summary.last_sequence_no(), Some(CommandSequenceNo::new(4)));
    }

    #[test]
    fn summary_ignores_stale_alias_update() {
        let mut summary = SessionSummary::new();

        summary.set_alias("ll", "ls -lah", CommandSequenceNo::new(7));
        summary.set_alias("ll", "ls -l", CommandSequenceNo::new(3));

        let binding = summary
            .alias_binding("ll")
            .expect("expected alias binding to exist");

        assert_eq!(binding.body, "ls -lah");
        assert_eq!(binding.observed_at, CommandSequenceNo::new(7));
    }

    #[test]
    fn summary_unset_alias_removes_binding_when_newer() {
        let mut summary = SessionSummary::new();

        summary.set_alias("ll", "ls -l", CommandSequenceNo::new(2));
        summary.unset_alias("ll", CommandSequenceNo::new(5));

        assert!(summary.alias_binding("ll").is_none());
        assert_eq!(summary.last_sequence_no(), Some(CommandSequenceNo::new(5)));
    }

    #[test]
    fn summary_exposes_alias_bindings_iterator() {
        let mut summary = SessionSummary::new();

        summary.set_alias("g", "grep --color=auto", CommandSequenceNo::new(1));
        summary.set_alias("ll", "ls -l", CommandSequenceNo::new(2));

        let names: Vec<&str> = summary
            .alias_bindings()
            .map(|binding| binding.name.as_str())
            .collect();

        assert_eq!(names, vec!["g", "ll"]);
    }

    #[test]
    fn summary_can_store_function_binding() {
        let mut summary = SessionSummary::new();

        summary.set_function(
            "deploy",
            "bash ./scripts/build.sh;",
            CommandSequenceNo::new(4),
        );

        let binding = summary
            .function_binding("deploy")
            .expect("expected function binding to exist");

        assert_eq!(
            binding,
            &SessionFunctionBinding::new(
                "deploy",
                "bash ./scripts/build.sh;",
                CommandSequenceNo::new(4),
            )
        );
        assert_eq!(summary.last_sequence_no(), Some(CommandSequenceNo::new(4)));
    }

    #[test]
    fn summary_ignores_stale_function_update() {
        let mut summary = SessionSummary::new();

        summary.set_function("deploy", "bash new.sh;", CommandSequenceNo::new(7));
        summary.set_function("deploy", "bash old.sh;", CommandSequenceNo::new(3));

        let binding = summary
            .function_binding("deploy")
            .expect("expected function binding to exist");

        assert_eq!(binding.body, "bash new.sh;");
        assert_eq!(binding.observed_at, CommandSequenceNo::new(7));
    }

    #[test]
    fn summary_unset_function_removes_binding_when_newer() {
        let mut summary = SessionSummary::new();

        summary.set_function(
            "deploy",
            "bash ./scripts/build.sh;",
            CommandSequenceNo::new(2),
        );
        summary.unset_function("deploy", CommandSequenceNo::new(5));

        assert!(summary.function_binding("deploy").is_none());
        assert_eq!(summary.last_sequence_no(), Some(CommandSequenceNo::new(5)));
    }

    #[test]
    fn summary_exposes_function_bindings_iterator() {
        let mut summary = SessionSummary::new();

        summary.set_function("build", "bash ./build.sh;", CommandSequenceNo::new(1));
        summary.set_function("deploy", "bash ./deploy.sh;", CommandSequenceNo::new(2));

        let names: Vec<&str> = summary
            .function_bindings()
            .map(|binding| binding.name.as_str())
            .collect();

        assert_eq!(names, vec!["build", "deploy"]);
    }
}
