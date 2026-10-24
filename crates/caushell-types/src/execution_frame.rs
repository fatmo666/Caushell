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
    fn pathname(&self) -> Option<ShellPathnameSnapshot>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionFrameObservation {
    pub binding: ExecutionFrameBinding,
    pub environment: Vec<ShellEnvironmentSnapshot>,
    pub pathname: Option<ShellPathnameSnapshot>,
}

impl ExecutionFrameObservation {
    pub fn collect(
        binding: ExecutionFrameBinding,
        requirements: &ExecutionFrameRequirements,
        observer: &impl ExecutionFrameObserver,
    ) -> Result<Self, String> {
        if requirements.environment_names.len() > 128
            || requirements
                .environment_names
                .iter()
                .any(|name| !valid_name(name))
        {
            return Err("execution frame requirements exceed their bounds".into());
        }
        let observation = Self {
            binding,
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
        {
            return Err("execution frame binding or payload exceeds its bounds".into());
        }
        let mut names = BTreeSet::new();
        let mut bytes = 0;
        for entry in &self.environment {
            if !valid_name(&entry.name) || !names.insert(&entry.name) {
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

fn valid_name(name: &str) -> bool {
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
    fn payload_bounds_and_names_are_checked_before_use() {
        let request = request();
        let frame = ExecutionFrameObservation {
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
}
