//! Command-independent declaration validation and projection; no execution.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const WRAPPER: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: wrapper-fixture}
option_scope: leading_options
forms:
  - id: run
    parameters:
      - {name: child, semantic: {kind: plain_value}, binding: {kind: next_positional}, cardinality: required_one}
      - {name: args, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}
    effects:
      - kind: dispatch_command
        target:
          kind: dispatch
          command: child
          argv: [args]
          unset_environment_when: [{modifier: omit, names: [FIXTURE_CACHE, FIXTURE_MODE]}]
modifiers:
  - {id: omit, matcher: {kind: any_flag, flags: [--omit]}}
"#;

#[test]
fn conditional_unsets_are_opt_in_literal_names_not_shell_data() {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(WRAPPER).unwrap()])
            .unwrap();
    for (command, expected) in [
        ("wrapper-fixture child --omit", false),
        ("wrapper-fixture --omit child data", true),
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
        ) else {
            panic!()
        };
        let original = r.bound.clone();
        let child = collect_dispatch_command_candidates(&r.bound).remove(0);
        assert_eq!(r.bound, original);
        assert!(!child.clear_environment);
        assert!(!child.unknown_environment);
        assert_eq!(child.unset_environment.len(), if expected { 2 } else { 0 });
        assert!(
            child
                .unset_environment
                .iter()
                .all(|a| a.runtime_data && a.text.starts_with("FIXTURE_"))
        );
        assert_eq!(child.argv[0].text, if expected { "data" } else { "--omit" });
    }
}

#[test]
fn conditional_unsets_validate_modifier_and_environment_names() {
    for yaml in [
        WRAPPER.replace("modifier: omit", "modifier: missing"),
        WRAPPER.replace("FIXTURE_CACHE", "9INVALID"),
        WRAPPER.replace("FIXTURE_CACHE", "A=B"),
        WRAPPER.replace("[FIXTURE_CACHE, FIXTURE_MODE]", "[]"),
        WRAPPER.replace(
            "[FIXTURE_CACHE, FIXTURE_MODE]",
            "[FIXTURE_CACHE, FIXTURE_CACHE]",
        ),
        WRAPPER.replace("modifier: omit", "modifier: ''"),
    ] {
        assert!(load_command_profile_from_str(&yaml).is_err(), "{yaml}");
    }
}

const OUTPUT: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: output-fixture}
forms:
  - id: run
    parameters:
      - {name: inputs, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}
    effects:
      - kind: write_path
        target: {kind: configured_path, sources: [], fallback_parent_slots: [inputs], missing: unknown}
"#;

#[test]
fn output_families_validate_references_and_effect_contract() {
    load_command_profile_from_str(OUTPUT).unwrap();
    for yaml in [
        OUTPUT.replace(
            "fallback_parent_slots: [inputs]",
            "fallback_parent_slots: [missing]",
        ),
        OUTPUT.replace(
            "fallback_parent_slots: [inputs]",
            "fallback_parent_slots: ['']",
        ),
        OUTPUT.replace("kind: write_path", "kind: delete_path"),
        OUTPUT.replace("kind: write_path", "kind: set_execution_working_directory"),
        OUTPUT.replace("missing: unknown", "missing: incidental_cache"),
        OUTPUT.replace(
            "missing: unknown",
            "missing: unknown, unresolved_relative_base: true",
        ),
        OUTPUT.replace(
            "missing: unknown",
            "missing: unknown, relative_to: {slot: inputs}",
        ),
    ] {
        assert!(load_command_profile_from_str(&yaml).is_err(), "{yaml}");
    }
}
