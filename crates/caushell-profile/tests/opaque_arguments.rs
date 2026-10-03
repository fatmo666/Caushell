use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: generic-argv-tool}
argument_files:
  - {prefix: '@', possible_effects: [read_path, write_path, delete_path]}
forms:
  - id: run
    parameters:
      - {name: args, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}
"#;

fn bound(profile: &str, command: &str) -> BoundInvocation {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(profile).unwrap()])
            .unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => r.bound,
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => bound,
        other => panic!("{other:?}"),
    }
}

#[test]
fn declaration_is_opt_in_and_not_command_specific() {
    assert!(
        bound(PROFILE, "generic-argv-tool normal.txt")
            .effects
            .is_empty()
    );
    assert_eq!(
        bound(PROFILE, "generic-argv-tool '@args.txt'")
            .effects
            .len(),
        3
    );
    let plain = PROFILE.replace("argument_files:\n  - {prefix: '@', possible_effects: [read_path, write_path, delete_path]}\n", "");
    assert!(
        bound(&plain, "generic-argv-tool @args.txt")
            .effects
            .is_empty()
    );
}

#[test]
fn unknown_and_empty_argfile_operands_cannot_be_proven_literal_paths() {
    for command in [
        "generic-argv-tool @",
        "generic-argv-tool \"$UNKNOWN\"",
        "generic-argv-tool -- @args.txt",
    ] {
        assert_eq!(bound(PROFILE, command).effects.len(), 3, "{command}");
    }
    assert!(
        bound(PROFILE, "generic-argv-tool '$LITERAL'")
            .effects
            .is_empty()
    );
}

#[test]
fn failed_form_selection_preserves_unknown_argfile_effects() {
    let profile = PROFILE.replace(
        "  - id: run\n",
        "  - id: run\n    selector: {kind: has_flag, flag: '--enabled'}\n",
    );
    assert_eq!(
        bound(&profile, "generic-argv-tool @args.txt").effects.len(),
        3
    );
}

#[test]
fn invalid_argument_file_rules_are_rejected() {
    for (from, to) in [
        ("prefix: '@'", "prefix: ''"),
        ("[read_path, write_path, delete_path]", "[]"),
        ("[read_path, write_path, delete_path]", "[execute_payload]"),
    ] {
        assert!(load_command_profile_from_str(&PROFILE.replace(from, to)).is_err());
    }
}

fn projection(text: &str) -> Option<SemanticValueResolution> {
    let parsed = parse_command("echo x", ShellKind::Bash).unwrap();
    let value = BoundValue::argument_with_node_kind(
        text,
        true,
        "raw_string",
        parsed.commands[0].tokens[0].span.clone(),
        ArgumentBindingSource::RemainingArg,
    );
    project_value(
        &ValueProjection::TomlString {
            key: "cache-dir".into(),
        },
        &value,
    )
}

#[test]
fn toml_strings_use_the_parser_not_string_splitting() {
    for (input, expected) in [
        ("cache-dir = '/etc/cache'", "/etc/cache"),
        (
            "\"cache-dir\" = \"/etc/c\\u0061che\" # comment",
            "/etc/cache",
        ),
        ("cache-dir = '''/etc/cache'''", "/etc/cache"),
        ("line-length=88\ncache-dir='/etc/cache'", "/etc/cache"),
        ("cache-dir='contains=equals'", "contains=equals"),
    ] {
        assert_eq!(
            projection(input),
            Some(SemanticValueResolution::Known(expected.into())),
            "{input}"
        );
    }
    for input in [
        "line-length=88",
        "other='cache-dir=/etc/cache'",
        "cfg.toml",
        "configuration",
        "./config",
    ] {
        assert_eq!(projection(input), None, "{input}");
    }
    for input in [
        "cache-dir =",
        "cache-dir=42",
        "cache-dir=''",
        "cache-dir=['/etc/cache']",
        "cache-dir='/etc/a'\ncache-dir='/etc/b'",
    ] {
        assert!(
            matches!(projection(input), Some(SemanticValueResolution::Unknown(_))),
            "{input}"
        );
    }
}
