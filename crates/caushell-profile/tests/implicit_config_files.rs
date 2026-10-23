use caushell_profile::{ImplicitConfigSource, load_command_profile_from_str};

fn profile(declaration: &str) -> String {
    format!(
        "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: fixture}}\nforms: [{{id: run}}]\nimplicit_config_files:\n{declaration}\n"
    )
}

#[test]
fn normalizes_ordered_sources_without_command_name_rules() {
    let profile = load_command_profile_from_str(&profile(
        r#"  - id: startup
    disabled_by_first_argument: {words: [--clean], prefixes: [-C]}
    sources:
      - {kind: environment_directory, name: FIXTURE_HOME, suffix: config}
      - {kind: account_home, suffix: .fixture}"#,
    ))
    .unwrap();
    let input = &profile.implicit_config_files[0];
    assert_eq!(input.id, "startup");
    assert!(
        matches!(&input.sources[0], ImplicitConfigSource::EnvironmentDirectory { name, .. } if name == "FIXTURE_HOME")
    );
    assert!(
        matches!(&input.sources[1], ImplicitConfigSource::AccountHome { suffix } if suffix == ".fixture")
    );
    assert_eq!(input.disabled_by_first_argument.prefixes, ["-C"]);
}

#[test]
fn rejects_invalid_and_unbounded_search_declarations() {
    for declaration in [
        "  - {id: startup, sources: []}".to_owned(),
        "  - {id: startup, sources: [{kind: account_home, suffix: /absolute}]}".to_owned(),
        "  - {id: startup, sources: [{kind: account_home, suffix: ../escape}]}".to_owned(),
        "  - {id: startup, sources: [{kind: environment_directory, name: 'X-Y', suffix: rc}]}".to_owned(),
        "  - {id: startup, sources: [{kind: environment_directory, name: X, suffix: rc, unless_environment_set: ''}]}".to_owned(),
        "  - {id: startup, sources: [{kind: account_home, suffix: rc}], disabled_by_first_argument: {prefixes: ['']}}".to_owned(),
        "  - {id: startup, sources: [{kind: analyzer_home, suffix: rc}]}".to_owned(),
        "  - {id: startup, sources: [{kind: account_home, suffix: rc}]}\n  - {id: startup, sources: [{kind: account_home, suffix: rc}]}".to_owned(),
        format!("  - id: startup\n    sources:\n{}", "      - {kind: account_home, suffix: rc}\n".repeat(33)),
    ] {
        assert!(load_command_profile_from_str(&profile(&declaration)).is_err(), "{declaration}");
    }
}
