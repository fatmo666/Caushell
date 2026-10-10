//! Profile-only checks; the command strings below never execute.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolved(command: &str) -> ResolvedInvocationArtifact {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationResult::Resolved(value) => value.into_artifact(),
        value => panic!("{command}: {value:#?}"),
    }
}

#[test]
fn copy_pass_clusters_and_permuted_options_bind_one_real_destination() {
    for command in [
        "cpio -pdm /backup",
        "cpio -dump /backup",
        "cpio -pvd0 /backup",
        "cpio /backup -p -dm",
        "cpio --pass-through --make-directories /backup",
        "cpio -p -- /backup",
        "cpio -p -- -local",
    ] {
        let result = resolved(command);
        assert_eq!(
            result.bound.form_id.as_str(),
            "pass_through_archive",
            "{command}"
        );
        assert!(
            !result.bound.operation_semantics_unresolved,
            "{command}: {result:#?}"
        );
        assert!(result.bound.effects.iter().any(|effect| effect.kind == EffectKind::WritePath &&
            matches!(&effect.target, EffectTarget::Slot(slot) if slot.as_str() == "destination_path")));
        let parameter = result
            .bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "destination_path")
            .unwrap();
        assert_eq!(parameter.values.len(), 1);
    }
}

#[test]
fn option_operands_never_become_modes_or_the_destination() {
    let result = resolved("cpio -pdm -O -i -- /backup");
    assert_eq!(result.bound.form_id.as_str(), "pass_through_archive");
    let destination = result
        .bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "destination_path")
        .unwrap();
    assert!(
        matches!(&destination.values[0], BoundValue::Argument { text, .. } if text == "/backup")
    );
    assert!(
        !result
            .bound
            .applied_modifiers
            .iter()
            .any(|m| m.as_str() == "extract_mode")
    );
}

#[test]
fn archive_input_and_output_modes_still_bind_archive_file_operands() {
    for (command, form, slot) in [
        (
            "cpio -idmv -F archive.cpio",
            "extract_archive",
            "archive_path",
        ),
        (
            "cpio -ov -O archive.cpio",
            "create_archive",
            "output_archive_path",
        ),
    ] {
        let result = resolved(command);
        assert_eq!(result.bound.form_id.as_str(), form);
        assert!(
            result
                .bound
                .bound_parameters
                .iter()
                .any(|p| p.name.as_str() == slot && !p.values.is_empty())
        );
    }
}

#[test]
fn archive_format_is_a_value_not_a_mode_flag_or_destination() {
    for command in [
        "cpio -ov --format=ustar",
        "cpio -o -H ustar",
        "cpio -oHustar",
        "cpio -pdm -H -i -- /backup",
    ] {
        let result = resolved(command);
        assert!(
            !result.bound.operation_semantics_unresolved,
            "{command}: {result:#?}"
        );
        assert!(
            !result
                .bound
                .applied_modifiers
                .iter()
                .any(|m| m.as_str() == "extract_mode")
        );
        let format = result
            .bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "archive_format")
            .unwrap();
        assert!(
            matches!(&format.values[0], BoundValue::Argument { text, .. } if text == "ustar" || text == "-i")
        );
    }
}
