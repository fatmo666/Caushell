use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{DatabaseOperationKind, ShellKind};

fn profile(effect: &str, extras: &str) -> Result<CommandProfile, LoadProfileError> {
    load_command_profile_from_str(&format!(
        "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: state-tool}}\n{extras}\nforms:\n  - id: run\n    selector: {{kind: all, items: []}}\n    effects: [{effect}]\n"
    ))
}
#[test]
fn database_effect_classes_are_declared_not_inferred_from_tool_names() {
    for (name, kind) in [
        ("read", DatabaseOperationKind::Read),
        ("write", DatabaseOperationKind::Write),
        ("administration", DatabaseOperationKind::Administration),
        ("opaque", DatabaseOperationKind::Opaque),
    ] {
        let p = profile(
            &format!(
                "{{kind: database_operation, database_operation: {name}, target: {{kind: none}}}}"
            ),
            "",
        )
        .unwrap();
        assert_eq!(p.forms[0].effects[0].kind, EffectKind::DatabaseOperation);
        assert_eq!(p.forms[0].effects[0].database_operation, Some(kind));
    }
}
#[test]
fn incomplete_or_misplaced_database_metadata_is_rejected_at_load() {
    for effect in [
        "{kind: database_operation, target: {kind: none}}",
        "{kind: read_path, database_operation: write, target: {kind: none}}",
        "{kind: database_operation, database_operation: write, target: {kind: slot, name: key}}",
        "{kind: database_operation, database_operation: invent, target: {kind: none}}",
    ] {
        assert!(profile(effect, "").is_err(), "{effect}");
    }
}
#[test]
fn failure_effects_cannot_reference_unbound_form_operands() {
    let r = profile(
        "{kind: transform_data, target: {kind: none}}",
        "selection_failure_effects: [{kind: write_path, target: {kind: slot, name: output}}]",
    );
    assert!(matches!(
        r,
        Err(LoadProfileError::Normalize(
            NormalizeError::InvalidSelectionFailureEffects(_)
        ))
    ));
}
#[test]
fn declared_selection_failure_is_retained_but_not_invented_for_legacy_profiles() {
    for declared in [false, true] {
        let extras = if declared {
            "option_scope: leading_options\nselection_failure_effects: [{kind: database_operation, database_operation: opaque, target: {kind: none}}]"
        } else {
            "option_scope: leading_options"
        };
        let p = profile("{kind: transform_data, target: {kind: none}}", extras).unwrap();
        let registry = ProfileRegistry::from_profiles(vec![p]).unwrap();
        let parsed = parse_command("state-tool --unknown", ShellKind::Bash).unwrap();
        match resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
        ) {
            ResolveInvocationResult::SelectionError { partial_bound, .. } => {
                assert_eq!(partial_bound.is_some(), declared);
                if let Some(b) = partial_bound {
                    assert_eq!(
                        b.effects[0].database_operation,
                        Some(DatabaseOperationKind::Opaque)
                    );
                }
            }
            other => panic!("{other:?}"),
        }
    }
}
#[test]
fn literal_set_uses_exact_ascii_case_matching_without_regex_semantics() {
    let input = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: literal-tool}\nforms:\n  - id: exact\n    selector: {kind: has_positional_at_matching, index: 0, matcher: {kind: ascii_case_insensitive_literals, values: [READ, 'a+b']}}\n";
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(input).unwrap()])
            .unwrap();
    for value in ["READ", "read", "ReAd", "a+b", "A+B"] {
        let parsed = parse_command(&format!("literal-tool '{value}'"), ShellKind::Bash).unwrap();
        assert!(matches!(
            resolve_invocation(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new()
            ),
            ResolveInvocationResult::Resolved(_)
        ));
    }
    for value in ["READWRITE", "xREAD", "aaab", "RéAD"] {
        let parsed = parse_command(&format!("literal-tool '{value}'"), ShellKind::Bash).unwrap();
        assert!(matches!(
            resolve_invocation(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new()
            ),
            ResolveInvocationResult::SelectionError { .. }
        ));
    }
    for values in ["[]", "['']"] {
        assert!(load_command_profile_from_str(&input.replace("[READ, 'a+b']", values)).is_err());
    }
}
