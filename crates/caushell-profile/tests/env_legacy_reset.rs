use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn resolve(command: &str) -> BoundInvocation {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(result) => {
            assert!(
                !result.bound.operation_semantics_unresolved,
                "{command}: {result:#?}"
            );
            result.bound
        }
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn consumes_one_reset_marker_before_the_assignment_prefix() {
    for (command, child, argv) in [
        ("env - touch /opt/out", "touch", vec!["/opt/out"]),
        ("env -- - touch /opt/out", "touch", vec!["/opt/out"]),
        ("env -i - touch /opt/out", "touch", vec!["/opt/out"]),
        (
            "env -u OLD - X=one Y=two touch /opt/out",
            "touch",
            vec!["/opt/out"],
        ),
        ("env - - /bin/sh", "-", vec!["/bin/sh"]),
        ("env - -- /bin/sh", "--", vec!["/bin/sh"]),
        ("env - --help", "--help", vec![]),
        ("env - -i /bin/sh", "-i", vec!["/bin/sh"]),
        ("env - NAME=value - /bin/sh", "-", vec!["/bin/sh"]),
        ("env - /bin/sh --help", "/bin/sh", vec!["--help"]),
        ("env - -S 'rm /opt/out'", "-S", vec!["rm /opt/out"]),
        ("env -u - - touch /opt/out", "touch", vec!["/opt/out"]),
    ] {
        let candidates = collect_dispatch_command_candidates(&resolve(command));
        assert_eq!(candidates.len(), 1, "{command}: {candidates:#?}");
        let candidate = &candidates[0];
        assert_eq!(candidate.command.text, child, "{command}: {candidate:#?}");
        assert_eq!(
            candidate
                .argv
                .iter()
                .map(|v| v.text.as_str())
                .collect::<Vec<_>>(),
            argv,
            "{command}"
        );
        assert!(candidate.clear_environment, "{command}");
    }
}

#[test]
fn empty_reset_environment_is_not_an_unknown_executable() {
    for command in ["env -", "env -- -", "env - X=value", "env -i - X=value"] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), "dispatch_with_empty_environment");
        assert!(
            collect_dispatch_command_candidates(&bound).is_empty(),
            "{command}"
        );
    }
}

#[test]
fn reset_marker_after_an_assignment_or_child_is_data() {
    for (command, child, args, clear) in [
        ("env X=value - /bin/sh", "-", vec!["/bin/sh"], false),
        ("env X=value printf -- -", "printf", vec!["--", "-"], false),
        ("env printf -- -", "printf", vec!["--", "-"], false),
        (
            "env -i X=value printf -- -",
            "printf",
            vec!["--", "-"],
            true,
        ),
        ("env -u - printf -- -", "printf", vec!["--", "-"], false),
    ] {
        let candidates = collect_dispatch_command_candidates(&resolve(command));
        assert_eq!(candidates.len(), 1, "{command}");
        let candidate = &candidates[0];
        assert_eq!(candidate.command.text, child, "{command}");
        assert_eq!(
            candidate
                .argv
                .iter()
                .map(|v| v.text.as_str())
                .collect::<Vec<_>>(),
            args,
            "{command}"
        );
        assert_eq!(candidate.clear_environment, clear, "{command}");
    }
}

#[test]
fn unconditional_environment_reset_is_a_command_independent_dispatch_contract() {
    for command_source in [
        "command_literal: printf",
        "command_string: {slot: program, syntax: posix_shell}",
    ] {
        let source = format!(
            r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: isolated_runner}}
forms:
  - id: run
    parameters:
      - {{name: program, semantic: {{kind: plain_value}}, binding: {{kind: next_positional}}, cardinality: optional_one}}
    effects:
      - kind: dispatch_command
        target:
          kind: dispatch
          {command_source}
          clear_environment: true
modifiers: []
"#
        );
        let registry =
            ProfileRegistry::from_profiles(vec![load_command_profile_from_str(&source).unwrap()])
                .unwrap();
        let parsed = parse_command("isolated_runner 'printf hello'", ShellKind::Bash).unwrap();
        let ResolveInvocationArtifactResult::Resolved(result) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new(),
                &SessionBindings::new(),
            )
        else {
            panic!("custom runner did not resolve")
        };
        let candidates = collect_dispatch_command_candidates(&result.bound);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].clear_environment);
    }
}

#[test]
fn prefix_boundaries_require_native_field_width_independently_of_command_name() {
    let source = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: prefix_runner}
option_scope: leading_options
opaque_on_unresolved: true
forms:
  - id: run
    parameters:
      - {name: marker, semantic: {kind: plain_value}, binding: {kind: positional_at, index: 0}, cardinality: required_one}
      - {name: assignments, semantic: {kind: structured_value, context: env_assignment}, binding: {kind: leading_positionals_while, matcher: {kind: structured_value_context, context: env_assignment}}, cardinality: optional_many}
      - {name: command, semantic: {kind: command_ref, dispatch: wrapper_command}, binding: {kind: next_positional}, cardinality: required_one}
    effects:
      - {kind: dispatch_command, target: {kind: dispatch, command: command, environment: [assignments]}}
modifiers: []
"#;
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(source).unwrap()])
            .unwrap();
    for (command, unresolved) in [
        ("prefix_runner START X=$unknown printf", true),
        ("prefix_runner START X=$(cat values) printf", true),
        ("prefix_runner START X=\"$unknown\" printf", false),
        ("prefix_runner START X=literal printf", false),
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationArtifactResult::Resolved(result) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new(),
                &SessionBindings::new(),
            )
        else {
            panic!("{command} did not resolve")
        };
        assert_eq!(
            result.bound.operation_semantics_unresolved, unresolved,
            "{command}: {result:#?}"
        );
        assert_eq!(
            result
                .bound
                .residuals
                .iter()
                .any(|r| r.surface == ResidualSurface::Control),
            unresolved,
            "{command}: {result:#?}"
        );
    }
}
