use caushell_profile::*;
use caushell_types::TerminalSessionOperationKind as Op;

fn profile(effect: &str) -> Result<CommandProfile, LoadProfileError> {
    load_command_profile_from_str(&format!(
        "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: terminal-tool}}\nforms:\n  - id: run\n    selector: {{kind: all, items: []}}\n    effects: [{effect}]\n"
    ))
}
#[test]
fn terminal_classes_are_declarative_not_inferred_from_command_names() {
    for (name, kind) in [
        ("inspect", Op::Inspect),
        ("create", Op::Create),
        ("attach", Op::Attach),
        ("control", Op::Control),
        ("opaque", Op::Opaque),
    ] {
        let p = profile(&format!("{{kind: terminal_session_operation, terminal_session_operation: {name}, target: {{kind: none}}}}")).unwrap();
        assert_eq!(
            p.forms[0].effects[0].kind,
            EffectKind::TerminalSessionOperation
        );
        assert_eq!(p.forms[0].effects[0].terminal_session_operation, Some(kind));
    }
}
#[test]
fn missing_misplaced_or_path_shaped_terminal_metadata_is_rejected() {
    for effect in [
        "{kind: terminal_session_operation, target: {kind: none}}",
        "{kind: read_path, terminal_session_operation: control, target: {kind: none}}",
        "{kind: terminal_session_operation, terminal_session_operation: create, target: {kind: slot, name: session}}",
        "{kind: terminal_session_operation, terminal_session_operation: invented, target: {kind: none}}",
    ] {
        assert!(profile(effect).is_err(), "{effect}");
    }
}
