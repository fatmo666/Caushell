//! Command-name-independent conditional dispatch declarations.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const FIXTURE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-manager}
option_scope: leading_options
forms:
  - id: run
    effects:
      - kind: dispatch_command
        target:
          kind: dispatch
          command_literal: cat
          argv_prefix: [.env]
          unknown_environment: true
          stdin_from_parent_when: [pipe]
          stdout_to_parent_when: [pipe]
modifiers:
  - id: pipe
    matcher: {kind: any_flag, flags: [--pipe]}
"#;

fn project(profile: &str, command: &str) -> DispatchCommandProjection {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(profile).unwrap()])
            .unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(r) = resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) else {
        panic!("unresolved fixture")
    };
    collect_dispatch_command_projection(&r.bound)
}

#[test]
fn conditional_routing_and_unconditional_unknown_environment_are_opt_in() {
    for (command, enabled) in [
        ("arbitrary-manager", false),
        ("arbitrary-manager --pipe", true),
    ] {
        let p = project(FIXTURE, command);
        assert_eq!(p.resolved.len(), 1);
        let child = &p.resolved[0];
        assert!(child.unknown_environment);
        assert_eq!(child.stdin_from_parent, enabled);
        assert_eq!(child.stdout_to_parent, enabled);
    }
    let plain = FIXTURE
        .replace("          unknown_environment: true\n", "")
        .replace("          stdin_from_parent_when: [pipe]\n", "")
        .replace("          stdout_to_parent_when: [pipe]\n", "");
    let p = project(&plain, "arbitrary-manager --pipe");
    assert!(!p.resolved[0].unknown_environment);
    assert!(!p.resolved[0].stdin_from_parent);
    assert!(!p.resolved[0].stdout_to_parent);
}

#[test]
fn routing_mode_references_and_competing_stdin_sources_are_validated() {
    for bad in [
        FIXTURE.replace(
            "stdin_from_parent_when: [pipe]",
            "stdin_from_parent_when: [typo]",
        ),
        FIXTURE.replace(
            "stdout_to_parent_when: [pipe]",
            "stdout_to_parent_when: [typo]",
        ),
        FIXTURE.replace(
            "unknown_environment: true",
            "unknown_environment: true\n          stdin_from_tool: true",
        ),
    ] {
        assert!(load_command_profile_from_str(&bad).is_err(), "{bad}");
    }
}

#[test]
fn encoded_dispatch_obeys_the_same_routing_contract() {
    let encoded = FIXTURE.replace("          command_literal: cat\n          argv_prefix: [.env]", "          command_string: {slot: program, syntax: posix_shell}").replace("    effects:\n", "    parameters:\n      - {name: program, semantic: {kind: plain_value}, binding: {kind: next_positional}, cardinality: required_one}\n    effects:\n");
    let p = project(&encoded, "arbitrary-manager --pipe 'cat .env'");
    assert_eq!(p.resolved.len(), 1);
    assert!(p.resolved[0].unknown_environment);
    assert!(p.resolved[0].stdin_from_parent);
    assert!(p.resolved[0].stdout_to_parent);
}

#[test]
fn projection_branch_suppression_requires_a_known_last_control_value() {
    let fixture = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-projector}
option_scope: leading_options
forms:
  - id: input
    parameters:
      - name: data
        semantic: {kind: plain_value}
        binding: {kind: remaining_args}
        cardinality: optional_many
        structured_projection:
          branches:
            - matcher: {kind: prefix, value: 'dynamic:'}
              unless_parameter_matches: {name: mode_value, matcher: {kind: literal, value: no}}
              target: {name: opaque, semantic: {kind: plain_value}, unresolved: true}
modifiers:
  - id: mode
    matcher: {kind: any_flag, flags: [--mode]}
    parameters:
      - {name: mode_value, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}
"#;
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(fixture).unwrap()])
            .unwrap();
    for (args, suppressed) in [
        ("dynamic:VALUE", false),
        ("--mode=no dynamic:VALUE", true),
        ("--mode=yes dynamic:VALUE", false),
        ("--mode=no --mode=yes dynamic:VALUE", false),
        ("--mode=yes --mode=no dynamic:VALUE", true),
        ("--mode=\"$UNKNOWN\" dynamic:VALUE", false),
        ("--mode=no --mode=\"$UNKNOWN\" dynamic:VALUE", false),
    ] {
        let parsed =
            parse_command(&format!("arbitrary-projector {args}"), ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
        ) else {
            panic!("{args}")
        };
        assert_eq!(
            !r.bound
                .bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "opaque"),
            suppressed,
            "{args}: {r:#?}"
        );
    }
    assert!(
        load_command_profile_from_str(
            &fixture.replace("name: mode_value, matcher", "name: typo, matcher")
        )
        .is_err()
    );
}
