use crate::{
    CheckRequest, CommandSequenceNo, SessionId, ShellEnvironmentSnapshot, ShellEnvironmentValue,
    ShellKind, ShellPathnameSnapshot,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Supplied by the owning executor, never inferred from the hook process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionFrameBinding {
    pub protocol: u32,
    pub executor_instance_id: String,
    pub session_id: SessionId,
    pub sequence_no: CommandSequenceNo,
    pub runtime_name: String,
    pub shell_kind: ShellKind,
    pub cwd: String,
    pub command_sha256: String,
}

impl ExecutionFrameBinding {
    pub fn for_request(request: &CheckRequest, executor_instance_id: impl Into<String>) -> Self {
        Self {
            protocol: 1,
            executor_instance_id: executor_instance_id.into(),
            session_id: request.session_id.clone(),
            sequence_no: request.sequence_no,
            runtime_name: request.runtime.runtime_name.clone(),
            shell_kind: request.shell_kind,
            cwd: request.shell_state_before.cwd.clone(),
            command_sha256: format!("{:x}", Sha256::digest(request.command.as_bytes())),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionFrameRequirements {
    pub environment_names: BTreeSet<String>,
    /// Referenced variable roots, independently of their export attribute.
    /// An observer may supply a bounded literal nameref closure as typed values.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub variable_names: BTreeSet<String>,
    pub pathname: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionFramePlanRequest {
    pub request: crate::RuntimeCheckRequest,
    pub executor_instance_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionFramePlan {
    pub binding: ExecutionFrameBinding,
    pub requirements: ExecutionFrameRequirements,
}

/// Implemented at the executor boundary. Unavailable facts remain Unknown/None.
pub trait ExecutionFrameObserver {
    fn environment(&self, name: &str) -> ShellEnvironmentValue;
    fn variable(&self, _name: &str) -> ShellEnvironmentValue {
        ShellEnvironmentValue::Unknown
    }
    fn variable_is_integer(&self, _name: &str) -> bool {
        false
    }
    fn variable_values(&self, _names: &BTreeSet<String>) -> Vec<crate::ExecutionFrameVariable> {
        Vec::new()
    }
    /// Positive native-family contracts from a trusted, immutable executor
    /// inventory. Never infer these from OS, PATH spelling or task variables.
    fn native_variants(&self) -> std::collections::BTreeMap<String, String> {
        Default::default()
    }
    fn pathname(&self) -> Option<ShellPathnameSnapshot>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionFrameObservation {
    pub binding: ExecutionFrameBinding,
    pub environment: Vec<ShellEnvironmentSnapshot>,
    /// A partial, frame-local scalar view; never a child-environment grant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variables: Vec<ShellEnvironmentSnapshot>,
    /// Typed values plus the explicitly observed closure of literal namerefs.
    /// Legacy captures omit this field and retain their conservative behavior.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variable_values: Vec<crate::ExecutionFrameVariable>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub integer_variables: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub native_variants: std::collections::BTreeMap<String, String>,
    pub pathname: Option<ShellPathnameSnapshot>,
}

impl ExecutionFrameObservation {
    pub fn collect(
        binding: ExecutionFrameBinding,
        requirements: &ExecutionFrameRequirements,
        observer: &impl ExecutionFrameObserver,
    ) -> Result<Self, String> {
        if requirements.environment_names.len() > 128
            || requirements.variable_names.len() > 128
            || requirements
                .environment_names
                .iter()
                .chain(&requirements.variable_names)
                .any(|name| !valid_name(name))
        {
            return Err("execution frame requirements exceed their bounds".into());
        }
        let observation = Self {
            binding,
            variable_values: observer.variable_values(&requirements.variable_names),
            integer_variables: requirements
                .variable_names
                .iter()
                .filter(|n| observer.variable_is_integer(n))
                .cloned()
                .collect(),
            native_variants: observer.native_variants(),
            variables: requirements
                .variable_names
                .iter()
                .map(|name| ShellEnvironmentSnapshot {
                    name: name.clone(),
                    value: observer.variable(name),
                })
                .collect(),
            environment: requirements
                .environment_names
                .iter()
                .map(|name| ShellEnvironmentSnapshot {
                    name: name.clone(),
                    value: observer.environment(name),
                })
                .collect(),
            pathname: requirements.pathname.then(|| observer.pathname()).flatten(),
        };
        observation.validate_payload()?;
        Ok(observation)
    }

    pub fn validate(
        &self,
        request: &CheckRequest,
        previous_executor: Option<&str>,
    ) -> Result<(), String> {
        self.validate_payload()?;
        let expected =
            ExecutionFrameBinding::for_request(request, &self.binding.executor_instance_id);
        if self.binding != expected {
            return Err("execution frame does not match this request".into());
        }
        for observation in &self.environment {
            if request
                .shell_state_before
                .environment
                .iter()
                .any(|legacy| legacy.name == observation.name && legacy.value != observation.value)
            {
                return Err("execution frame conflicts with named environment observation".into());
            }
        }
        for observation in &self.variables {
            if self.integer_variables.contains(&observation.name)
                && self
                    .environment
                    .iter()
                    .chain(&request.shell_state_before.environment)
                    .any(|env| {
                        env.name == observation.name
                            && matches!(&env.value, ShellEnvironmentValue::Present { value } if {
                                let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
                                digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit())
                            })
                    })
            {
                return Err("integer proof conflicts with environment bytes".into());
            }
            if self.integer_variables.contains(&observation.name)
                && request.shell_state_before.variables.iter().any(|legacy| {
                    legacy.name == observation.name
                        && match &legacy.value {
                            crate::ShellValueSnapshot::Structured { .. } => true,
                            crate::ShellValueSnapshot::ExactScalar { value }
                            | crate::ShellValueSnapshot::RuntimeProduced { value, .. } => {
                                let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
                                digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit())
                            }
                            _ => false,
                        }
                })
            {
                return Err("integer proof conflicts with legacy scalar observation".into());
            }
            if request.shell_state_before.variables.iter().any(|legacy| {
                legacy.name == observation.name
                    && match (&legacy.value, &observation.value) {
                        (
                            crate::ShellValueSnapshot::ExactScalar { value: a }
                            | crate::ShellValueSnapshot::RuntimeProduced { value: a, .. },
                            ShellEnvironmentValue::Present { value: b },
                        ) => a != b,
                        (
                            crate::ShellValueSnapshot::Structured { .. },
                            ShellEnvironmentValue::Present { .. },
                        ) => true,
                        (_, ShellEnvironmentValue::Absent) => true,
                        _ => false,
                    }
            }) || self.environment.iter().any(|env| {
                env.name == observation.name
                    && matches!(env.value, ShellEnvironmentValue::Present { .. })
                    && observation.value != ShellEnvironmentValue::Unknown
                    && env.value != observation.value
            }) {
                return Err("execution frame conflicts with shell variable observation".into());
            }
        }
        for entry in &self.variable_values {
            use crate::ExecutionFrameVariableValue as V;
            for env in request
                .shell_state_before
                .environment
                .iter()
                .filter(|v| v.name == entry.name)
            {
                if let ShellEnvironmentValue::Present { value } = &env.value {
                    match &entry.value {
                        V::Unknown | V::Unsupported => {}
                        V::Scalar { value: current, .. } if current == value => {}
                        _ => return Err("typed variable conflicts with legacy environment".into()),
                    }
                }
            }
            for legacy in request
                .shell_state_before
                .variables
                .iter()
                .filter(|v| v.name == entry.name)
            {
                let compatible = match (&entry.value, &legacy.value) {
                    (V::Unknown | V::Unsupported, _) => true,
                    (
                        V::Scalar { value, .. },
                        crate::ShellValueSnapshot::ExactScalar { value: old }
                        | crate::ShellValueSnapshot::RuntimeProduced { value: old, .. },
                    ) => value == old,
                    (_, crate::ShellValueSnapshot::Structured { value }) => {
                        entry.value.session_value()
                            == Some(crate::SessionVariableValue::structured(value.clone()))
                    }
                    (V::Absent, _) => false,
                    (_, crate::ShellValueSnapshot::OpaqueDynamic { .. }) => true,
                    _ => false,
                };
                if !compatible {
                    return Err("typed variable conflicts with legacy shell observation".into());
                }
            }
        }
        if let (Some(a), Some(b)) = (&self.pathname, &request.shell_state_before.pathname) {
            if a != b {
                return Err("execution frame conflicts with pathname observation".into());
            }
        }
        let c = request.runtime.shell_runtime_capabilities;
        if (c.persists_variables
            || c.persists_exported_environment
            || c.persists_aliases
            || c.persists_functions
            || c.persists_positionals)
            && previous_executor.is_some_and(|id| id != self.binding.executor_instance_id)
        {
            return Err("persistent execution frame changed executor instance".into());
        }
        Ok(())
    }

    fn validate_payload(&self) -> Result<(), String> {
        let b = &self.binding;
        if b.protocol != 1
            || b.executor_instance_id.is_empty()
            || b.executor_instance_id.len() > 256
            || b.session_id.0.is_empty()
            || b.session_id.0.len() > 1024
            || b.runtime_name.len() > 256
            || b.cwd.len() > 4096
            || !b.cwd.starts_with('/')
            || b.cwd.contains('\0')
            || b.command_sha256.len() != 64
            || !b.command_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || self.environment.len() > 128
            || self.variables.len() > 128
            || self.integer_variables.len() > 128
            || self.native_variants.len() > 128
        {
            return Err("execution frame binding or payload exceeds its bounds".into());
        }
        let mut names = BTreeSet::new();
        let mut bytes = self.validate_variable_values()?;
        for name in &self.integer_variables {
            let Some(value) = self.variables.iter().find(|v| &v.name == name) else {
                return Err("integer proof has no scalar observation".into());
            };
            match &value.value {
                ShellEnvironmentValue::Absent => {
                    return Err("absent scalar has an integer proof".into());
                }
                ShellEnvironmentValue::Present { value } => {
                    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
                    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                        return Err("integer proof conflicts with observed bytes".into());
                    }
                }
                ShellEnvironmentValue::Unknown => {}
            }
        }
        for (name, variant) in &self.native_variants {
            if name.is_empty()
                || name.len() > 4096
                || name.contains(['\0', '\n'])
                || variant.is_empty()
                || variant.len() > 128
                || !variant
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            {
                return Err("invalid native variant contract".into());
            }
            bytes += name.len() + variant.len();
        }
        for (channel, entry) in self
            .environment
            .iter()
            .map(|e| (0, e))
            .chain(self.variables.iter().map(|e| (1, e)))
        {
            if !valid_name(&entry.name) || !names.insert((channel, &entry.name)) {
                return Err("execution frame environment names are invalid or duplicated".into());
            }
            bytes += entry.name.len();
            if let ShellEnvironmentValue::Present { value } = &entry.value {
                if value.contains('\0') {
                    return Err("execution frame environment contains NUL".into());
                }
                bytes += value.len();
            }
        }
        if let Some(p) = &self.pathname {
            for value in [
                &p.globignore,
                &p.lc_all,
                &p.lc_collate,
                &p.lc_ctype,
                &p.lang,
            ] {
                if let ShellEnvironmentValue::Present { value } = value {
                    if value.contains('\0') {
                        return Err("execution frame pathname contains NUL".into());
                    }
                    bytes += value.len();
                }
            }
        }
        if bytes > 65536 {
            return Err("execution frame values exceed their byte budget".into());
        }
        Ok(())
    }
}

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || i > 0 && b.is_ascii_digit())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionFrameEvidence {
    pub binding: ExecutionFrameBinding,
    pub accepted: bool,
    pub gap: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn request() -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("frame-bounds"),
            sequence_no: CommandSequenceNo(1),
            command: "printf hello".into(),
            shell_state_before: crate::ShellStateSnapshot::new("/workspace"),
            shell_kind: ShellKind::Bash,
            home: None,
            workspace_root: Some("/workspace".into()),
            runtime: crate::RuntimeMetadata {
                runtime_name: "owned".into(),
                tool_name: None,
                shell_runtime_capabilities: crate::ShellRuntimeCapabilities::request_only(),
            },
        }
    }

    #[test]
    fn integer_proofs_are_positive_bounded_and_request_local() {
        let request = request();
        let frame = ExecutionFrameObservation {
            binding: ExecutionFrameBinding::for_request(&request, "owner"),
            environment: vec![],
            pathname: None,
            variables: vec![ShellEnvironmentSnapshot {
                name: "counter".into(),
                value: ShellEnvironmentValue::Unknown,
            }],
            variable_values: Vec::new(),
            integer_variables: ["counter".into()].into(),
            native_variants: [("date".into(), "gnu_coreutils".into())].into(),
        };
        assert!(frame.validate(&request, None).is_ok());
        for value in [
            ShellEnvironmentValue::Absent,
            ShellEnvironmentValue::Present { value: "".into() },
            ShellEnvironmentValue::Present {
                value: "a[$(payload)]".into(),
            },
        ] {
            let mut f = frame.clone();
            f.variables[0].value = value;
            assert!(f.validate(&request, None).is_err());
        }
        let mut f = frame.clone();
        f.variables.clear();
        assert!(f.validate(&request, None).is_err());
        let mut f = frame.clone();
        f.environment.push(ShellEnvironmentSnapshot {
            name: "counter".into(),
            value: ShellEnvironmentValue::Present {
                value: "unsafe".into(),
            },
        });
        assert!(f.validate(&request, None).is_err());
        let mut f = frame.clone();
        f.native_variants
            .insert("date".into(), "unknown value".into());
        assert!(f.validate(&request, None).is_err());
        let mut f = frame.clone();
        f.binding.sequence_no = CommandSequenceNo(2);
        assert!(f.validate(&request, None).is_err());
        // Missing metadata remains backward compatible, never a positive fact.
        let mut old = serde_json::to_value(frame).unwrap();
        old.as_object_mut().unwrap().remove("integer_variables");
        old.as_object_mut().unwrap().remove("native_variants");
        let old: ExecutionFrameObservation = serde_json::from_value(old).unwrap();
        assert!(old.integer_variables.is_empty());
        assert!(old.native_variants.is_empty());
    }

    #[test]
    fn payload_bounds_and_names_are_checked_before_use() {
        let request = request();
        let frame = ExecutionFrameObservation {
            variable_values: Vec::new(),
            integer_variables: Default::default(),
            native_variants: Default::default(),
            variables: Vec::new(),
            binding: ExecutionFrameBinding::for_request(&request, "executor"),
            environment: vec![ShellEnvironmentSnapshot {
                name: "DECLARED_INPUT".into(),
                value: ShellEnvironmentValue::Unknown,
            }],
            pathname: None,
        };
        assert!(frame.validate(&request, None).is_ok());
        let mut duplicate = frame.clone();
        duplicate.environment.push(duplicate.environment[0].clone());
        assert!(duplicate.validate(&request, None).is_err());
        for value in ["with\0nul".to_owned(), "x".repeat(65536)] {
            let mut oversized = frame.clone();
            oversized.environment[0].value = ShellEnvironmentValue::Present { value };
            assert!(oversized.validate(&request, None).is_err());
        }
        for name in ["", "1NAME", "BAD[0]", "BAD-NAME"] {
            let mut invalid = frame.clone();
            invalid.environment[0].name = name.into();
            assert!(invalid.validate(&request, None).is_err());
        }
        let mut too_many = frame;
        too_many.environment = (0..129)
            .map(|n| ShellEnvironmentSnapshot {
                name: format!("INPUT_{n}"),
                value: ShellEnvironmentValue::Absent,
            })
            .collect();
        assert!(too_many.validate(&request, None).is_err());
    }

    #[test]
    fn collection_does_not_read_unrequested_or_invalid_inputs() {
        struct Observer(Cell<usize>);
        impl ExecutionFrameObserver for Observer {
            fn environment(&self, _: &str) -> ShellEnvironmentValue {
                self.0.set(self.0.get() + 1);
                ShellEnvironmentValue::Unknown
            }
            fn pathname(&self) -> Option<ShellPathnameSnapshot> {
                panic!("pathname was not requested")
            }
        }
        let observer = Observer(Cell::new(0));
        let binding = ExecutionFrameBinding::for_request(&request(), "executor");
        let mut requirements = ExecutionFrameRequirements::default();
        let empty =
            ExecutionFrameObservation::collect(binding.clone(), &requirements, &observer).unwrap();
        assert!(empty.environment.is_empty());
        assert_eq!(observer.0.get(), 0);
        requirements.environment_names.insert("BAD[0]".into());
        assert!(
            ExecutionFrameObservation::collect(binding.clone(), &requirements, &observer).is_err()
        );
        assert_eq!(observer.0.get(), 0);
        requirements.environment_names = (0..129).map(|n| format!("INPUT_{n}")).collect();
        assert!(ExecutionFrameObservation::collect(binding, &requirements, &observer).is_err());
        assert_eq!(observer.0.get(), 0);
    }
    #[test]
    fn scalar_channel_is_partial_bounded_and_conflict_checked() {
        let request = request();
        let mut frame = ExecutionFrameObservation {
            variable_values: Vec::new(),
            integer_variables: Default::default(),
            native_variants: Default::default(),
            binding: ExecutionFrameBinding::for_request(&request, "executor"),
            environment: vec![],
            pathname: None,
            variables: vec![ShellEnvironmentSnapshot {
                name: "VALUE".into(),
                value: ShellEnvironmentValue::Present {
                    value: "/opt/file".into(),
                },
            }],
        };
        assert!(frame.validate(&request, None).is_ok());
        frame.environment.push(ShellEnvironmentSnapshot {
            name: "VALUE".into(),
            value: ShellEnvironmentValue::Absent,
        });
        assert!(frame.validate(&request, None).is_ok()); // an unexported local
        frame.environment[0].value = ShellEnvironmentValue::Present {
            value: "different".into(),
        };
        assert!(frame.validate(&request, None).is_err());
        frame.variables[0].value = ShellEnvironmentValue::Unknown;
        assert!(frame.validate(&request, None).is_ok());
        frame.variables.push(frame.variables[0].clone());
        assert!(frame.validate(&request, None).is_err());
        frame.variables.pop();
        frame.variables[0].name = "BAD[0]".into();
        assert!(frame.validate(&request, None).is_err());
        frame.variables[0].name = "VALUE".into();
        frame.variables[0].value = ShellEnvironmentValue::Present {
            value: "x".repeat(65536),
        };
        assert!(frame.validate(&request, None).is_err());
    }

    #[test]
    fn legacy_observers_do_not_invent_shell_local_values() {
        struct Legacy;
        impl ExecutionFrameObserver for Legacy {
            fn environment(&self, _: &str) -> ShellEnvironmentValue {
                ShellEnvironmentValue::Absent
            }
            fn pathname(&self) -> Option<ShellPathnameSnapshot> {
                None
            }
        }
        let requirements = ExecutionFrameRequirements {
            environment_names: BTreeSet::new(),
            variable_names: ["LOCAL".into()].into_iter().collect(),
            pathname: false,
        };
        let frame = ExecutionFrameObservation::collect(
            ExecutionFrameBinding::for_request(&request(), "executor"),
            &requirements,
            &Legacy,
        )
        .unwrap();
        assert_eq!(frame.variables[0].value, ShellEnvironmentValue::Unknown);
        let legacy = serde_json::to_value(&ExecutionFrameObservation {
            variable_values: Vec::new(),
            integer_variables: Default::default(),
            native_variants: Default::default(),
            variables: vec![],
            ..frame
        })
        .unwrap();
        assert!(legacy.get("variables").is_none());
        assert!(
            serde_json::from_value::<ExecutionFrameObservation>(legacy)
                .unwrap()
                .variables
                .is_empty()
        );
    }
}
