use caushell_profile::{execution_frame_requirements, load_command_profile_from_str};
use caushell_types::*;
use std::{cell::RefCell, collections::BTreeSet};

struct Observer {
    names: RefCell<Vec<String>>,
}
impl ExecutionFrameObserver for Observer {
    fn environment(&self, name: &str) -> ShellEnvironmentValue {
        self.names.borrow_mut().push(name.into());
        ShellEnvironmentValue::Unknown
    }
    fn pathname(&self) -> Option<ShellPathnameSnapshot> {
        None
    }
}

#[test]
fn declarations_drive_bounded_collection_without_tool_names_or_ambient_reads() {
    for name in ["arbitrary-a", "unrelated-b"] {
        let profile = load_command_profile_from_str(&format!(
            r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: {name}}}
option_scope: permuted_options
option_environment: {{name: DECLARED_OPTIONS, syntax: gnu_tar}}
environment_inputs:
  - name: program
    environment: {{name: DECLARED_PROGRAM}}
    semantic: {{kind: payload, language: opaque, source: dynamic_reference, recursive: true}}
forms: [{{id: run}}]
"#
        ))
        .unwrap();
        let requirements = execution_frame_requirements([&profile]);
        assert_eq!(
            requirements.environment_names,
            [
                "DECLARED_OPTIONS",
                "DECLARED_PROGRAM",
                "LC_ALL",
                "LC_CTYPE",
                "LANG"
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        let request = CheckRequest {
            session_id: SessionId::new("requirements"),
            sequence_no: CommandSequenceNo(1),
            command: name.into(),
            shell_state_before: ShellStateSnapshot::new("/workspace"),
            shell_kind: ShellKind::Bash,
            home: None,
            workspace_root: None,
            runtime: RuntimeMetadata {
                runtime_name: "owned".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
        };
        let observer = Observer {
            names: RefCell::new(Vec::new()),
        };
        let frame = ExecutionFrameObservation::collect(
            ExecutionFrameBinding::for_request(&request, "executor"),
            &requirements,
            &observer,
        )
        .unwrap();
        assert_eq!(
            observer
                .names
                .borrow()
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            requirements.environment_names
        );
        assert!(frame.pathname.is_none());
        assert!(
            frame
                .environment
                .iter()
                .all(|e| e.value == ShellEnvironmentValue::Unknown)
        );
        let mut invalid = requirements.clone();
        invalid.environment_names.insert("BAD[0]".into());
        assert!(
            ExecutionFrameObservation::collect(frame.binding.clone(), &invalid, &observer).is_err()
        );
    }
}

#[test]
fn implicit_configuration_and_output_dependencies_are_in_the_plan() {
    for name in ["first-owner", "another-owner"] {
        let profile=load_command_profile_from_str(&format!(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: {name}}}
implicit_config_files:
  - id: initialization
    sources:
      - {{kind: environment_directory, name: DECLARED_CONFIG_HOME, suffix: tool.rc, unless_environment_set: DECLARED_OVERRIDE}}
forms:
  - id: run
    parameters:
      - {{name: root_path, semantic: {{kind: path, role: read}}, binding: {{kind: remaining_positionals}}, cardinality: optional_many}}
    effects:
      - kind: write_path
        target:
          kind: configured_path
          sources: []
          environment: {{name: DECLARED_OUTPUT}}
          relative_to: {{slot: root_path, environment: {{name: DECLARED_ROOT}}, default_value: '.'}}
          missing: unknown
"#)).unwrap();
        let r = execution_frame_requirements([&profile]);
        for name in [
            "DECLARED_CONFIG_HOME",
            "DECLARED_OVERRIDE",
            "DECLARED_OUTPUT",
            "DECLARED_ROOT",
        ] {
            assert!(r.environment_names.contains(name), "{name}: {r:?}");
        }
    }
    let registry = caushell_profile::ProfileRegistry::built_in().unwrap();
    let r = execution_frame_requirements(registry.profiles());
    for name in ["CURL_HOME", "XDG_CONFIG_HOME", "HOME", "PIP_TARGET"] {
        assert!(r.environment_names.contains(name), "{name}");
    }
    assert!(r.environment_names.len() <= 128);
}
