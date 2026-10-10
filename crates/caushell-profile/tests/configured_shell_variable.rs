use caushell_profile::*;

fn profile(default: &str) -> String {
    format!(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: configured-fixture}}
forms:
  - id: run
    effects:
      - kind: write_path
        target:
          kind: configured_path
          sources: []
          missing: skip
          {default}
"#
    )
}

#[test]
fn shell_variable_default_is_opt_in_and_preserves_exported_environment_scope() {
    for (default, is_shell) in [
        (
            "shell_variable: {name: TOOL_STORE, empty_is_unset: true}",
            true,
        ),
        (
            "environment: {name: TOOL_STORE, empty_is_unset: true}",
            false,
        ),
    ] {
        let p = load_command_profile_from_str(&profile(default)).unwrap();
        let EffectTarget::ConfiguredPath(target) = &p.forms[0].effects[0].target else {
            panic!()
        };
        assert_eq!(target.shell_variable.is_some(), is_shell);
        assert_eq!(target.environment.is_some(), !is_shell);
        assert_eq!(target.missing, ConfiguredPathMissing::Skip);
    }
}

#[test]
fn invalid_names_and_ambiguous_variable_scopes_are_rejected() {
    for name in ["", "1STORE", "STORE-PATH", "STORE[0]", "$STORE"] {
        assert!(
            load_command_profile_from_str(&profile(&format!("shell_variable: {{name: '{name}'}}")))
                .is_err()
        );
    }
    let both = "shell_variable: {name: TOOL_STORE}\n          environment: {name: TOOL_STORE}";
    assert!(load_command_profile_from_str(&profile(both)).is_err());
}
