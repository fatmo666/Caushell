//! Child-process environment at one execution point. Entry snapshots are seeds,
//! not a configuration consumer API. Shell expansion still uses pre-command
//! bindings; prefix assignments are applied exactly once to this separate view.
use caushell_parse::ParsedCommandArtifact;
use caushell_profile::{EnvironmentValueRef, SessionBindings, SessionValue};
use caushell_runner::ParsedCommandRef;

#[derive(Debug, Clone)]
pub(crate) struct ExecutionEnvironment {
    bindings: SessionBindings,
}

impl ExecutionEnvironment {
    pub(crate) fn for_command(
        before: &SessionBindings,
        parsed: &ParsedCommandArtifact,
        command: &ParsedCommandRef,
    ) -> Self {
        Self {
            bindings: super::command_environment_bindings(before, parsed, command),
        }
    }

    pub(crate) fn value(&self, name: &str) -> EnvironmentValueRef<'_> {
        self.bindings.environment_value(name)
    }

    /// An absent export and an unobserved/dynamic export are different facts.
    pub(crate) fn scalar(&self, name: &str) -> Result<Option<&str>, String> {
        match self.value(name) {
            EnvironmentValueRef::Absent => Ok(None),
            EnvironmentValueRef::Present(SessionValue::ExactScalar(value))
            | EnvironmentValueRef::Present(SessionValue::RuntimeProduced { value, .. }) => {
                Ok(Some(value))
            }
            _ => Err(format!("execution environment {name} is unresolved")),
        }
    }
}
