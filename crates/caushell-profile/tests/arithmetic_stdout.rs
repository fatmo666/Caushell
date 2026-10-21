use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

#[test]
fn numeric_output_is_a_positive_contract_not_an_executable_name_rule() {
    let registry = ProfileRegistry::built_in().unwrap();
    for text in [
        "date +%s",
        "printf '%d' 42",
        "printf '%d' \"$unknown\"",
        "printf '%d' \"'$char\"",
        "printf '%d' \"'${data:$i:1}\"",
        "wc -l",
        "shuf -i 0-4 -n1",
    ] {
        let parsed = parse_command(text, ShellKind::Bash).unwrap();
        let r = resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default().with_shell_kind(ShellKind::Bash),
            &SessionBindings::new(),
        );
        assert!(
            matches!(&r, ResolveInvocationArtifactResult::Resolved(r) if r.proven_arithmetic_stdout()),
            "{text}: {r:#?}"
        );
    }
    for text in [
        "printf '%s' \"$unknown\"",
        "date +%A",
        "date -R +%s",
        "date -I +%s",
        "wc -l file",
        "wc --files0-from=list",
        "wc --total=always",
        "shuf -e '\"$unknown\"'",
    ] {
        let parsed = parse_command(text, ShellKind::Bash).unwrap();
        let r = resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default().with_shell_kind(ShellKind::Bash),
            &SessionBindings::new(),
        );
        assert!(
            !matches!(&r, ResolveInvocationArtifactResult::Resolved(r) if r.proven_arithmetic_stdout()),
            "{text}: {r:#?}"
        );
    }
}

#[test]
fn custom_profiles_and_contract_inputs_use_the_same_proof() {
    let profile = load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: counter, aliases: []}
trust: {tier: tier_a, source: built_in}
platform: {os_families: [], shell_families: [], requires_features: []}
forms:
  - id: numeric
    selector: {kind: all, items: []}
    parameters:
      - {name: format, semantic: {kind: plain_value}, binding: {kind: positional_at, index: 0}, cardinality: required_one}
    stream_contract: {stdin_mode: ignored, stdout_mode: data, stderr_mode: opaque}
    stdout_scalar: arithmetic_text
    stdout_scalar_inputs: [format]
modifiers: []
subcommands: null
"#).unwrap();
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    for (text, expected) in [("counter digits", true), ("counter \"$unknown\"", false)] {
        let parsed = parse_command(text, ShellKind::Bash).unwrap();
        let ResolveInvocationArtifactResult::Resolved(r) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::default(),
                &SessionBindings::new(),
            )
        else {
            panic!("{text}");
        };
        assert_eq!(r.proven_arithmetic_stdout(), expected, "{text}");
    }
}
