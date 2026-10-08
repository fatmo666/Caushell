use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(resolved) => {
            assert!(
                resolved.bound.residuals.is_empty(),
                "{command}: {:?}",
                resolved.bound.residuals
            );
            resolved.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}

fn semantic_values(bound: &BoundInvocation, slot: &str) -> Vec<SemanticValueResolution> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| p.semantic_values())
        .map(|v| match v {
            SemanticValueRef::Projected { value, .. } => value.resolution.clone(),
            SemanticValueRef::Original(value) => {
                project_value(&ValueProjection::Identity, value).unwrap()
            }
        })
        .collect()
}

#[test]
fn mixed_outputs_are_projected_without_rewriting_the_source_operand() {
    let bound = resolve("nsys stats --output='-,result,@rm -f /opt/example,.' report.sqlite");
    assert_eq!(
        semantic_values(&bound, "report_bases"),
        [SemanticValueResolution::Known("result".into())]
    );
    assert_eq!(
        semantic_values(&bound, "default_report_outputs"),
        [SemanticValueResolution::Known("report.sqlite".into())]
    );
    let original = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "output")
        .unwrap();
    assert_eq!(original.values.len(), 1);
    assert!(original.projected_values.is_none());
    let projection = collect_dispatch_command_projection(&bound);
    assert!(projection.unresolved.is_empty());
    assert_eq!(projection.resolved.len(), 1);
    let child = &projection.resolved[0];
    assert_eq!(child.command.text, "rm");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["-f", "/opt/example"]
    );
    assert!(child.stdin_from_parent);
    assert!(child.argv.iter().all(|a| a.runtime_data));
}

#[test]
fn encoded_argv_does_not_become_shell_source() {
    let bound = resolve("nsys stats -o '@echo $TOKEN ; rm -f /opt/example >out' report.sqlite");
    let child = collect_dispatch_command_candidates(&bound).remove(0);
    assert_eq!(child.command.text, "echo");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["$TOKEN", ";", "rm", "-f", "/opt/example", ">out"]
    );
    assert!(
        child
            .to_command_fact()
            .tokens
            .iter()
            .all(|t| t.runtime_data && t.command_substitutions.is_empty())
    );
}

#[test]
fn multiple_outputs_and_commands_get_distinct_dispatch_identities() {
    let bound =
        resolve("nsys analyze -o '@echo one,@cat,-' --output='@rm -f /opt/example' report.sqlite");
    let projection = collect_dispatch_command_projection(&bound);
    assert_eq!(
        projection
            .resolved
            .iter()
            .map(|c| (c.dispatch_index, c.command.text.as_str()))
            .collect::<Vec<_>>(),
        [(0, "echo"), (1, "cat"), (2, "rm")]
    );
}

#[test]
fn dynamic_output_retains_unknown_file_and_command_candidates() {
    for command in [
        "nsys stats -o \"$OUTPUT\" report.sqlite",
        "nsys stats -o \"@echo $ARG\" report.sqlite",
        "nsys stats -o '@' report.sqlite",
        "nsys stats -o 'result,,@cat' report.sqlite",
    ] {
        let bound = resolve(command);
        assert!(
            !collect_dispatch_command_projection(&bound)
                .unresolved
                .is_empty(),
            "{command}"
        );
    }
}

#[test]
fn default_output_uses_the_first_present_source_not_an_unknown_fallback() {
    let bound = resolve("nsys stats --sqlite=/opt/a.sqlite -o . report.nsys-rep");
    assert_eq!(
        semantic_values(&bound, "default_report_outputs"),
        [SemanticValueResolution::Known("/opt/a.sqlite".into())]
    );
    let bound = resolve("nsys stats --sqlite=\"$SQLITE\" -o . report.nsys-rep");
    assert!(matches!(
        semantic_values(&bound, "default_report_outputs")[0],
        SemanticValueResolution::Unknown(_)
    ));
}

#[test]
fn stdout_does_not_drop_parent_sqlite_preparation() {
    let bound = resolve("nsys stats -o - /opt/report.nsys-rep");
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    assert!(
        collect_dispatch_command_projection(&bound)
            .resolved
            .is_empty()
    );
    let bound = resolve("nsys stats -o - report.sqlite");
    assert!(
        !bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
}

#[test]
fn help_suppresses_modifier_execution_and_writes() {
    let bound = resolve("nsys stats --help -o '@rm -f /opt/example' --sqlite /opt/a.sqlite");
    assert!(bound.effects.is_empty());
    assert!(
        collect_dispatch_command_projection(&bound)
            .resolved
            .is_empty()
    );
}

#[test]
fn profile_dispatch_preserves_application_argv_and_output_inheritance() {
    let bound = resolve(
        "nsys profile -t cuda,nvtx -s none -f true -o reports/run env MODE=lab rm -f /opt/example",
    );
    assert_eq!(bound.form_id.as_str(), "profile_explicit_output");
    let child = collect_dispatch_command_projection(&bound)
        .resolved
        .remove(0);
    assert_eq!(child.command.text, "env");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["MODE=lab", "rm", "-f", "/opt/example"]
    );
    assert!(child.stdout_to_parent);
    assert!(!child.stdin_from_parent);
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    assert!(
        !bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ControlProcess)
    );
}

#[test]
fn child_options_after_application_do_not_reconfigure_profiler() {
    let bound =
        resolve("nsys profile echo --output=/opt/child --duration=10 --kill=sigkill --help");
    assert_eq!(bound.form_id.as_str(), "profile_default_output");
    assert!(
        !bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ControlProcess)
    );
    assert_eq!(
        collect_dispatch_command_projection(&bound).resolved[0]
            .argv
            .len(),
        4
    );
    assert!(
        !bound
            .applied_modifiers
            .iter()
            .any(|m| m.as_str() == "profile_information")
    );
}

#[test]
fn profile_duration_and_range_shutdown_declare_control_without_a_fake_pid() {
    for command in [
        "nsys profile -d 10 echo ok",
        "nsys profile --duration=10 --kill=sigterm -o reports/run echo ok",
        "nsys profile -c nvtx echo ok",
        "nsys profile --capture-range=cudaProfilerApi --capture-range-end=repeat-shutdown:3:async echo ok",
        "nsys profile -c nvtx --kill=\"$SIGNAL\" echo ok",
        "nsys profile -c nvtx --capture-range-end=\"$END\" echo ok",
    ] {
        let bound = resolve(command);
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ControlProcess && e.target == EffectTarget::None),
            "{command}"
        );
        assert!(
            !bound
                .bound_parameters
                .iter()
                .any(|p| matches!(p.semantic, SemanticType::ProcessTarget(_))),
            "{command}"
        );
    }
}

#[test]
fn only_proven_nontermination_removes_the_control_effect() {
    for command in [
        "nsys profile --duration=10 --kill=none echo ok",
        "nsys profile --kill none -c nvtx echo ok",
        "nsys profile -c none echo ok",
        "nsys profile -c nvtx --capture-range-end=stop echo ok",
        "nsys profile -c nvtx --capture-range-end=none echo ok",
        "nsys profile -c nvtx --capture-range-end=repeat:3:async echo ok",
        "nsys profile --capture-range-end=stop-shutdown echo ok",
        "nsys profile --kill=sigkill echo ok",
    ] {
        let bound = resolve(command);
        assert!(
            !bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ControlProcess),
            "{command}"
        );
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath)
        );
        assert_eq!(
            collect_dispatch_command_projection(&bound).resolved.len(),
            1
        );
    }
}

#[test]
fn no_kill_does_not_override_an_independent_duration_trigger() {
    let bound = resolve("nsys profile -d 10 -c nvtx --capture-range-end=stop echo ok");
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ControlProcess)
    );
}

#[test]
fn environment_csv_is_projected_as_assignments_not_shell_source() {
    let bound = resolve("nsys profile -e 'TARGET=/opt/example,MODE=lab,EMPTY=' echo ok");
    let child = collect_dispatch_command_projection(&bound)
        .resolved
        .remove(0);
    assert_eq!(
        child
            .environment
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["TARGET=/opt/example", "MODE=lab", "EMPTY="]
    );
    assert!(child.environment.iter().all(|a| a.runtime_data));
    let original = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "profile_environment_operand")
        .unwrap();
    assert!(original.projected_values.is_none());
    assert_eq!(original.values.len(), 1);
}

#[test]
fn profile_pure_help_has_no_child_report_or_control_effect() {
    for command in ["nsys profile --help", "nsys profile -h trace"] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), "profile_information");
        assert!(bound.effects.is_empty());
        assert!(
            collect_dispatch_command_projection(&bound)
                .resolved
                .is_empty()
        );
    }
}

#[test]
fn opaque_collection_forms_do_not_become_readonly_or_guessed_paths() {
    for command in [
        "nsys profile --command-file settings.conf echo ok",
        "nsys profile --after-report-ready 'rm -f /opt/example' echo ok",
        "nsys profile --session-new other echo ok",
        "nsys profile --enable custom echo ok",
        "nsys profile -o '%q{DEST}/report' echo ok",
        "nsys profile -o 'reports/%p' echo ok",
        "nsys profile --auto-report-name=true echo ok",
        "nsys profile --inherit-environment=false echo ok",
        "nsys profile --future-option value echo ok",
        "nsys profile --duration=10",
        "nsys profile --duration=10 --kill=none --kill=sigterm echo ok",
        "nsys profile --duration=10 --kill=sigterm --kill=none echo ok",
        "nsys profile -o reports/run -o '%q{DEST}/report' echo ok",
        "nsys profile --help --after-report-ready 'rm -rf /'",
        "nsys start --session existing",
        "nsys stop --session existing",
        "nsys launch echo ok",
        "nsys shutdown --kill=none --session existing",
        "nsys finalize",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        match resolve_invocation(
            &ProfileRegistry::built_in().unwrap(),
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
        ) {
            ResolveInvocationResult::SelectionError { gap_kind, .. } => assert_eq!(
                gap_kind,
                caushell_types::ResolveGapKind::OpaqueInvocation,
                "{command}"
            ),
            ResolveInvocationResult::Resolved(r) => assert!(
                r.bound.operation_semantics_unresolved,
                "{command}: {:?}",
                r.bound
            ),
            other => panic!("{command}: {other:?}"),
        }
    }
}
