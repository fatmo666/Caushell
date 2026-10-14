//! Native option operands and namespace semantics, with no command execution.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolved(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(result) = resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) else {
        panic!("{command}: unresolved invocation")
    };
    assert!(
        !result.bound.operation_semantics_unresolved,
        "{command}: {:?}",
        result.bound
    );
    result.bound
}

fn values(bound: &BoundInvocation, slot: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| p.semantic_values())
        .map(|v| match v {
            SemanticValueRef::Original(BoundValue::Argument { text, .. }) => text.clone(),
            other => panic!("{slot}: {other:?}"),
        })
        .collect()
}

#[test]
fn backup_control_is_an_option_value_and_disabled_backups_keep_content_open_semantics() {
    for (option, expected_form, content_open) in [
        ("", "default_copy", true),
        ("--backup=none", "default_copy", true),
        ("--backup=off", "default_copy", true),
        ("--backup", "default_copy_replacing_destination", false),
        ("-b", "default_copy_replacing_destination", false),
        (
            "--backup=numbered",
            "default_copy_replacing_destination",
            false,
        ),
        (
            "--backup=existing",
            "default_copy_replacing_destination",
            false,
        ),
        (
            "--backup=simple",
            "default_copy_replacing_destination",
            false,
        ),
    ] {
        let command = format!("cp input {option} output");
        let bound = resolved(&command);
        assert_eq!(bound.form_id.as_str(), expected_form, "{command}");
        assert_eq!(values(&bound, "source_paths"), ["input"]);
        assert_eq!(values(&bound, "destination_path"), ["output"]);
        let effect = bound
            .effects
            .iter()
            .find(|e| {
                e.kind == EffectKind::WritePath
                    && matches!(&e.target, EffectTarget::Slot(s) if s.as_str()=="destination_path")
            })
            .unwrap();
        assert_eq!(
            effect.path_access == Some(PathAccessKind::ContentOpen),
            content_open,
            "{command}: {effect:?}"
        );
        if let Some(value) = option.strip_prefix("--backup=") {
            assert_eq!(values(&bound, "backup_control"), [value]);
        }
    }
}

#[test]
fn optional_and_required_option_values_do_not_capture_or_drop_file_operands() {
    for (options, slots) in [
        ("--backup --preserve --reflink --context --update", vec![]),
        ("-bpu", vec![]),
        (
            "--sparse never --no-preserve links",
            vec![
                ("sparse_mode", "never"),
                ("excluded_preserve_attr_list", "links"),
            ],
        ),
        (
            "--sparse=never --no-preserve=links",
            vec![
                ("sparse_mode", "never"),
                ("excluded_preserve_attr_list", "links"),
            ],
        ),
        (
            "--preserve=all --update=none-fail --context=LABEL",
            vec![
                ("preserve_attr_list", "all"),
                ("update_control", "none-fail"),
                ("security_context", "LABEL"),
            ],
        ),
    ] {
        let command = format!("cp input {options} output");
        let bound = resolved(&command);
        assert_eq!(values(&bound, "source_paths"), ["input"], "{command}");
        assert_eq!(values(&bound, "destination_path"), ["output"], "{command}");
        for (slot, value) in slots {
            assert_eq!(values(&bound, slot), [value], "{command}");
        }
    }
}

#[test]
fn repeated_backup_controls_never_certify_a_disabled_backup_from_one_matching_value() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in [
        "cp --backup=none --backup=numbered input output",
        "cp --backup=numbered --backup=none input output",
        "cp --backup=off --backup input output",
        "cp -b --backup=off input output",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let result = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
        );
        let bound = match result {
            ResolveInvocationResult::Resolved(r) => r.bound,
            ResolveInvocationResult::SelectionError {
                partial_bound: Some(b),
                ..
            } => b,
            other => panic!("{command}: {other:?}"),
        };
        assert!(
            bound.effects.iter().any(|e| e.kind == EffectKind::WritePath
                && matches!(&e.target, EffectTarget::Slot(s) if s.as_str() == "destination_path")
                && e.path_access.is_none()),
            "{command}: {bound:?}"
        );
    }
}
