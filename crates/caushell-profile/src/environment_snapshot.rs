use std::collections::BTreeMap;

use caushell_types::{ShellEnvironmentValue, ShellStateKnowledge, ShellStateSnapshot};

use crate::SessionValue;

pub fn environment_observations(
    snapshot: &ShellStateSnapshot,
) -> BTreeMap<String, Option<SessionValue>> {
    let mut observations = BTreeMap::new();
    for observation in snapshot.environment.iter().chain(
        snapshot
            .execution_frame
            .iter()
            .flat_map(|frame| &frame.environment),
    ) {
        let name = &observation.name;
        if name.is_empty() || name.contains(['=', '\0']) {
            continue;
        }
        observations
            .entry(name)
            .and_modify(|value| {
                if *value != &observation.value {
                    *value = &ShellEnvironmentValue::Unknown;
                }
            })
            .or_insert(&observation.value);
    }
    observations
        .into_iter()
        .map(|(name, value)| {
            let variables = || snapshot.variables.iter().filter(|v| v.name == *name);
            let conflict = match value {
                ShellEnvironmentValue::Present { value } => {
                    value.contains('\0')
                        || variables().any(|v| {
                            !v.exported
                                || matches!(&v.value, caushell_types::ShellValueSnapshot::ExactScalar { value: other } if other != value)
                                || matches!(&v.value, caushell_types::ShellValueSnapshot::RuntimeProduced { value: other, .. } if other != value)
                                || matches!(&v.value, caushell_types::ShellValueSnapshot::Structured { .. })
                        })
                        || (variables().next().is_none()
                            && snapshot.observability.variables != ShellStateKnowledge::Unknown)
                }
                ShellEnvironmentValue::Absent => variables().any(|v| v.exported),
                ShellEnvironmentValue::Unknown => false,
            };
            let value = if conflict {
                Some(SessionValue::opaque_dynamic("conflicting environment observations"))
            } else {
                match value {
                    ShellEnvironmentValue::Present { value } => {
                        Some(SessionValue::exact_scalar(value))
                    }
                    ShellEnvironmentValue::Absent => None,
                    ShellEnvironmentValue::Unknown => {
                        Some(SessionValue::opaque_dynamic("environment value is unobserved"))
                    }
                }
            };
            (name.clone(), value)
        })
        .collect()
}
