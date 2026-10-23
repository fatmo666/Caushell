use caushell_profile::{ConfigurationSyntax, load_command_profile_from_str};

const CURL: &str = include_str!("../profiles/curl.yaml");
const CONTRACT: &str = "configuration_files: {syntax: curl, modifier: config_input, operand: config_operand, implicit_search: default_config}";

#[test]
fn normalizes_configuration_grammar_and_search_references() {
    let profile = load_command_profile_from_str(CURL).unwrap();
    let contract = profile.configuration_files.unwrap();
    assert_eq!(contract.syntax, ConfigurationSyntax::Curl);
    assert_eq!(contract.modifier, "config_input");
    assert_eq!(contract.operand, "config_operand");
    assert_eq!(contract.implicit_search.as_deref(), Some("default_config"));
}

#[test]
fn rejects_unbound_configuration_contracts() {
    for contract in [
        "configuration_files: {syntax: curl, modifier: missing, operand: config_operand}",
        "configuration_files: {syntax: curl, modifier: config_input, operand: missing}",
        "configuration_files: {syntax: curl, modifier: config_input, operand: config_operand, implicit_search: missing}",
        "configuration_files: {syntax: shell, modifier: config_input, operand: config_operand}",
        "configuration_files: {syntax: curl, modifier: config_input, operand: config_operand, extra: true}",
    ] {
        assert!(
            load_command_profile_from_str(&CURL.replacen(CONTRACT, contract, 1)).is_err(),
            "{contract}"
        );
    }
    assert!(
        load_command_profile_from_str(&CURL.replacen(
            "option_scope: permuted_options",
            "option_scope: leading_options",
            1
        ))
        .is_err()
    );
}
