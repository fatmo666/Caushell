use caushell_profile::*;

fn profile(effect: &str, modifiers: &str) -> String {
    format!(
        "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: arbitrary_consumer}}\nforms:\n  - id: consume\n    selector: {{kind: all, items: []}}\n    effects: [{effect}]\nmodifiers: {modifiers}\n"
    )
}

#[test]
fn path_list_declarations_are_typed_and_command_independent() {
    let source = profile(
        "{kind: metadata_mutation, target: {kind: implicit_input, source: stdin_data}, path_list: {separator: newline, nul_modifier: zeros}}",
        "[{id: zeros, matcher: {kind: any_flag, flags: ['-0']}}]",
    );
    let profile = load_command_profile_from_str(&source).unwrap();
    let contract = profile.forms[0].effects[0].path_list.as_ref().unwrap();
    assert_eq!(contract.separator, PathListSeparator::Newline);
    assert_eq!(contract.nul_modifier.as_deref(), Some("zeros"));
    assert_eq!(profile.primary_name(), "arbitrary_consumer");
}

#[test]
fn path_list_contracts_reject_wrong_sources_and_unbound_mode_flags() {
    for effect in [
        "{kind: metadata_mutation, target: {kind: none}, path_list: {separator: nul}}",
        "{kind: metadata_mutation, target: {kind: implicit_input, source: stdin_payload}, path_list: {separator: nul}}",
        "{kind: transform_data, target: {kind: implicit_input, source: stdin_data}, path_list: {separator: nul}}",
        "{kind: metadata_mutation, target: {kind: implicit_input, source: stdin_data}, path_list: {separator: newline, nul_modifier: missing}}",
        "{kind: metadata_mutation, target: {kind: implicit_input, source: stdin_data}, path_list: {separator: newline, nul_modifier: ''}}",
        "{kind: metadata_mutation, target: {kind: implicit_input, source: stdin_data}, path_list: {separator: space}}",
    ] {
        assert!(
            load_command_profile_from_str(&profile(effect, "[]")).is_err(),
            "{effect}"
        );
    }
}
