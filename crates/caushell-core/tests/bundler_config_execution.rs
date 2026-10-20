use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("bundler-config-execution"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(request(command, 1))
}

fn opaque_configs(response: &CheckResponse) -> Vec<&NestedPayloadContextEvidence> {
    response
        .decision_trace
        .evidence
        .iter()
        .filter_map(|e| match &e.kind {
            EvidenceKind::NestedPayloadUnresolved(u)
                if matches!(
                    u.context.origin,
                    NestedPayloadOriginEvidence::ConfigDefinedTask { .. }
                ) && u.context.language == NestedPayloadLanguageEvidence::Opaque
                    && u.unresolved_execution_payload_subtype
                        == Some(UnresolvedExecutionPayloadSubtype::OpaqueNonShell) =>
            {
                Some(&u.context)
            }
            _ => None,
        })
        .collect()
}

#[test]
fn gemfile_evaluation_is_opaque_code_not_a_shell_string_pattern() {
    for body in [
        "system(\"/bin/sh\")",
        "system(\"rm -rf /\")",
        "source \"https://rubygems.org\"",
        "# no shell code",
    ] {
        let command = format!("printf '%s\\n' '{body}' >Gemfile; bundle install");
        let r = check(&command);
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
        assert!(
            !opaque_configs(&r).is_empty(),
            "{command}: {:?}",
            r.decision_trace.evidence
        );
        assert!(
            !r.decision_trace
                .derived_invocations
                .iter()
                .any(|i| i.command_name.as_deref() == Some("rm"))
        );
    }
}

#[test]
fn all_modeled_gemfile_evaluators_keep_the_code_boundary() {
    for command in [
        "bundle",
        "bundle install",
        "bundle install --local",
        "bundle exec printf SAFE",
        "bundle console",
    ] {
        let r = check(command);
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
        assert!(
            !opaque_configs(&r).is_empty(),
            "{command}: {:?}",
            r.decision_trace.evidence
        );
    }
}

#[test]
fn explicit_gemfiles_and_environment_select_the_actual_input() {
    for (command, expected) in [
        ("bundle install --gemfile /tmp/Altfile", "/tmp/Altfile"),
        ("bundle install -g /opt/Altfile", "/opt/Altfile"),
        (
            "bundle install --gemfile=./Altfile",
            "/bench/workspace/Altfile",
        ),
        (
            "BUNDLE_GEMFILE=/tmp/EnvironmentFile bundle install",
            "/tmp/EnvironmentFile",
        ),
        (
            "export BUNDLE_GEMFILE=/tmp/EnvironmentFile; bundle install",
            "/tmp/EnvironmentFile",
        ),
        (
            "BUNDLE_GEMFILE=/tmp/EnvironmentFile bundle install --gemfile ./CliFile",
            "/bench/workspace/CliFile",
        ),
        (
            "bundle exec --gemfile /tmp/Altfile printf SAFE",
            "/tmp/Altfile",
        ),
        (
            "bundle install --gemfile /tmp/First --gemfile /tmp/Last",
            "/tmp/Last",
        ),
        ("bundle install --gemfile=--help", "/bench/workspace/--help"),
    ] {
        let r = check(command);
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
        assert!(opaque_configs(&r).iter().any(|context| matches!(&context.origin,
            NestedPayloadOriginEvidence::ConfigDefinedTask {config_path, ..} if config_path == expected)),
            "{command}: {:?}", r.decision_trace.evidence);
    }
}

#[test]
fn unknown_sources_are_not_fabricated_as_a_current_directory_gemfile() {
    for command in [
        "bundle install",
        "bundle install --gemfile \"$FILE\"",
        "BUNDLE_GEMFILE=\"$FILE\" bundle install",
    ] {
        let r = check(command);
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
        assert!(!opaque_configs(&r).is_empty());
        assert!(opaque_configs(&r).iter().all(|context| !matches!(&context.origin,
            NestedPayloadOriginEvidence::ConfigDefinedTask {config_path, ..} if config_path == "/bench/workspace/Gemfile")));
    }
}

#[test]
fn wrapped_function_and_nested_shell_invocations_keep_configuration_execution() {
    for command in [
        "env bundle install --gemfile /tmp/Altfile",
        "sh -c 'bundle install --gemfile /tmp/Altfile'",
        "f() { bundle install --gemfile /tmp/Altfile; }; f",
        "printf '%s\\n' ignored | xargs -I{} bundle install --gemfile /tmp/Altfile",
    ] {
        let r = check(command);
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
        assert!(
            !opaque_configs(&r).is_empty(),
            "{command}: {:?}",
            r.decision_trace.evidence
        );
    }
}

#[test]
fn information_does_not_evaluate_a_gemfile_or_hide_child_arguments() {
    for command in [
        "bundle --help",
        "bundle --version",
        "bundle version",
        "bundle install --help",
        "bundle exec --help",
        "bundle console --help",
        "BUNDLE_GEMFILE=/opt/Altfile bundle --help",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
        assert!(
            opaque_configs(&r).is_empty(),
            "{command}: {:?}",
            r.decision_trace.evidence
        );
    }
    let r = check("bundle exec sh -c 'rm -rf /' --help");
    assert_eq!(r.decision, Decision::Deny, "{:?}", r.reasons);
    let r = check("bundle exec printf --help");
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.reasons);
    assert!(!opaque_configs(&r).is_empty());
    let r = check("bundle exec printf --gemfile /tmp/ChildArgument");
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(!opaque_configs(&r).is_empty());
    assert!(!opaque_configs(&r).iter().any(|context| matches!(&context.origin,
        NestedPayloadOriginEvidence::ConfigDefinedTask {config_path, ..} if config_path == "/tmp/ChildArgument")));
}

#[test]
fn execution_guard_and_dependency_policies_remain_separate() {
    for command in [
        "pip install --target ./vendor ./dist/pkg.whl",
        "pip install --target ./vendor requests",
        "printf SAFE",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
        assert!(opaque_configs(&r).is_empty());
    }
    let r = check("bundle exec sh -c 'rm -rf /'");
    assert_eq!(r.decision, Decision::Deny, "{:?}", r.reasons);
}

#[test]
fn prior_action_content_is_not_interpreted_as_bash() {
    let mut core = ShellQueryCore::new();
    assert_eq!(
        core.check(request("echo 'system(\"/bin/sh\")' >Gemfile", 1))
            .decision,
        Decision::Allow
    );
    let r = core.check(request("bundle install", 2));
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.reasons);
    assert!(!opaque_configs(&r).is_empty());
}
