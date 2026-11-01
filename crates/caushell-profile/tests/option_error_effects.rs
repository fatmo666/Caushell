//! Error recovery records possible hazards without certifying argv ownership.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn partial(source: &str, scope: &str) -> BoundInvocation {
    let yaml = format!(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
option_scope: {scope}
option_matching: exact_names
opaque_on_unresolved: true
identity: {{canonical_name: native-worker, aliases: []}}
trust: {{tier: tier_a, source: built_in}}
platform: {{os_families: [posix], shell_families: [], requires_features: []}}
forms:
  - id: operate
    parameters: [{{name: operands, semantic: {{kind: plain_value}}, binding: {{kind: remaining_positionals}}, cardinality: optional_many}}]
    effects: [{{kind: dispatch_command, target: {{kind: dispatch, command_literal: /bin/sh, argv_suffix: [-s], stdin_from_parent: true, stdout_to_parent: true}}}}]
    stream_contract: {{stdin_mode: data_required, stdout_mode: data, stderr_mode: data}}
modifiers:
  - id: load
    matcher: {{kind: any_flag, flags: [--load]}}
    parameters: [{{name: library, semantic: {{kind: in_process_code_load, load_kind: library_path}}, binding: {{kind: following_matched_flag, operand_mode: next_arg}}, cardinality: required_many}}]
    effects: [{{kind: load_in_process_code, target: {{kind: slot, name: library}}}}]
  - id: data
    matcher: {{kind: any_flag, flags: [--data]}}
    parameters: [{{name: data, semantic: {{kind: plain_value}}, binding: {{kind: following_matched_flag, operand_mode: next_arg}}, cardinality: required_many}}]
  - id: flag
    matcher: {{kind: any_flag, flags: [--flag]}}
subcommands: null
extensions: {{}}
"#
    );
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(&yaml).unwrap()])
            .unwrap();
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(result) => {
            assert!(result.bound.operation_semantics_unresolved);
            assert!(result.proven_stream_contract().is_none());
            result.bound
        }
        ResolveInvocationArtifactResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => {
            assert!(bound.operation_semantics_unresolved);
            bound
        }
        other => panic!("{source}: {other:#?}"),
    }
}
#[test]
fn unknown_permuted_controls_retain_later_declared_risk() {
    for source in [
        "native-worker --unknown --load /outside/library.so",
        "native-worker --flag=invalid --load /outside/library.so",
        "native-worker --load /outside/library.so --unknown",
        "native-worker --unknown --data '--load /outside/fake.so' --load /outside/library.so",
        "native-worker --unknown --data --load /outside/library.so",
        "native-worker --unknown -- --load /outside/library.so",
    ] {
        let r = partial(source, "permuted_options");
        assert!(
            r.effects
                .iter()
                .any(|e| e.kind == EffectKind::LoadInProcessCode),
            "{source}: {r:#?}"
        );
        assert!(
            r.effects
                .iter()
                .any(|e| e.kind == EffectKind::DispatchCommand),
            "{source}: {r:#?}"
        );
        let paths: Vec<_> = r
            .bound_parameters
            .iter()
            .filter(|p| p.name.as_str() == "library")
            .flat_map(|p| &p.values)
            .filter_map(|v| match v {
                BoundValue::Argument { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(paths, ["/outside/library.so"], "{source}: {r:#?}");
    }
}
#[test]
fn error_recovery_does_not_scan_certified_data_or_terminator_tails() {
    for source in [
        "native-worker --unknown --data '--load /outside/fake.so'",
        "native-worker --data --load /outside/fake.so --unknown",
    ] {
        let r = partial(source, "permuted_options");
        assert!(
            !r.effects
                .iter()
                .any(|e| e.kind == EffectKind::LoadInProcessCode),
            "{source}: {r:#?}"
        );
    }
}
#[test]
fn leading_grammar_does_not_recover_effects_from_an_opaque_child_tail() {
    let r = partial(
        "native-worker --unknown child --load /outside/fake.so",
        "leading_options",
    );
    assert!(
        !r.effects
            .iter()
            .any(|e| e.kind == EffectKind::LoadInProcessCode)
    );
}
