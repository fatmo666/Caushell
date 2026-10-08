use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ShellJobOperationKind as Op, ShellKind};

fn bound(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(resolved) = resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
    ) else {
        panic!("{command}")
    };
    resolved.bound
}

#[test]
fn disown_declares_job_operations_without_process_control_or_paths() {
    for (command, operation) in [
        ("disown", Op::RemoveFromJobTable),
        ("disown %1", Op::RemoveFromJobTable),
        ("disown 123 456", Op::RemoveFromJobTable),
        ("disown -a", Op::RemoveFromJobTable),
        ("disown -r", Op::RemoveFromJobTable),
        ("disown -ar", Op::RemoveFromJobTable),
        ("disown -h", Op::SuppressSighup),
        ("disown -h %1", Op::SuppressSighup),
        ("disown -ah", Op::SuppressSighup),
        ("disown -hra %1", Op::SuppressSighup),
        ("disown -- %1", Op::RemoveFromJobTable),
    ] {
        let b = bound(command);
        assert!(
            !b.operation_semantics_unresolved,
            "{command}: {:?}",
            b.residuals
        );
        assert_eq!(b.effects.len(), 1, "{command}");
        assert_eq!(b.effects[0].kind, EffectKind::ShellJobOperation);
        assert_eq!(b.effects[0].shell_job_operation, Some(operation));
        assert_eq!(b.effects[0].target, EffectTarget::None);
    }
}

#[test]
fn job_operands_are_plain_values_and_unknown_jobs_are_not_analysis_gaps() {
    for command in [
        "disown -h \"$job\"",
        "disown $job",
        "disown -- -h",
        "disown %1 -h",
    ] {
        let b = bound(command);
        assert!(
            !b.operation_semantics_unresolved,
            "{command}: {:?}",
            b.residuals
        );
        let jobs = b
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "jobs")
            .unwrap();
        assert!(matches!(jobs.semantic, SemanticType::PlainValue));
        if command == "disown -- -h" || command == "disown %1 -h" {
            assert_eq!(
                b.effects[0].shell_job_operation,
                Some(Op::RemoveFromJobTable)
            );
            assert!(
                jobs.values
                    .iter()
                    .any(|v| matches!(v, BoundValue::Argument {text, ..} if text == "-h"))
            );
        }
    }
}

#[test]
fn help_has_no_job_effect_and_unknown_options_use_existing_resolution_policy() {
    assert!(bound("disown --help").effects.is_empty());
    assert!(bound("disown -h --help").effects.is_empty());
    let registry = ProfileRegistry::built_in().unwrap();
    for command in ["disown -x", "disown -hx", "disown --future"] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        match resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
        ) {
            ResolveInvocationResult::SelectionError { gap_kind, .. } => {
                assert_eq!(gap_kind, caushell_types::ResolveGapKind::OpaqueInvocation)
            }
            ResolveInvocationResult::Resolved(r) => {
                assert!(r.bound.operation_semantics_unresolved, "{command}")
            }
            other => panic!("{command}: {other:?}"),
        }
    }
}

fn profile(effect: &str) -> Result<CommandProfile, LoadProfileError> {
    load_command_profile_from_str(&format!(
        "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: arbitrary-job-tool}}\nforms:\n  - id: run\n    selector: {{kind: all, items: []}}\n    effects: [{effect}]\n"
    ))
}

#[test]
fn job_semantics_are_generic_and_metadata_is_validated() {
    for (name, operation) in [
        ("remove_from_job_table", Op::RemoveFromJobTable),
        ("suppress_sighup", Op::SuppressSighup),
    ] {
        let p = profile(&format!(
            "{{kind: shell_job_operation, shell_job_operation: {name}, target: {{kind: none}}}}"
        ))
        .unwrap();
        assert_eq!(p.forms[0].effects[0].shell_job_operation, Some(operation));
    }
    for effect in [
        "{kind: shell_job_operation, target: {kind: none}}",
        "{kind: read_path, shell_job_operation: suppress_sighup, target: {kind: none}}",
        "{kind: shell_job_operation, shell_job_operation: remove_from_job_table, target: {kind: slot, name: job}}",
        "{kind: shell_job_operation, shell_job_operation: invented, target: {kind: none}}",
    ] {
        assert!(profile(effect).is_err(), "{effect}");
    }
}
