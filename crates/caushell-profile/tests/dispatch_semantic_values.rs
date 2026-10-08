//! Tool-independent dispatch contract checks; no command strings are executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{
    ImplicitInputSource, RuntimeArgumentDomain, RuntimeProducedValueKind, ShellKind,
};

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: projection-fixture}
option_matching: exact_names
option_scope: leading_options
forms:
  - id: dispatch
    parameters:
      - name: encoded_command
        semantic: {kind: plain_value}
        binding: {kind: next_positional}
        cardinality: required_one
        structured_projection:
          branches:
            - matcher: {kind: prefix, value: 'cmd:'}
              target: {name: child_command, semantic: {kind: command_ref, dispatch: wrapper_command}}
      - name: encoded_args
        semantic: {kind: plain_value}
        binding: {kind: next_positional}
        cardinality: required_one
        structured_projection:
          separator: ';'
          branches: [{matcher: {kind: literal, value: skip}}]
          fallback: {name: child_args, semantic: {kind: plain_value}}
      - name: encoded_environment
        semantic: {kind: plain_value}
        binding: {kind: next_positional}
        cardinality: required_one
        structured_projection:
          separator: ';'
          branches: [{matcher: {kind: literal, value: skip}}]
          fallback: {name: child_environment, semantic: {kind: plain_value}}
      - name: encoded_unsets
        semantic: {kind: plain_value}
        binding: {kind: next_positional}
        cardinality: optional_one
        structured_projection:
          separator: ';'
          branches: []
          fallback: {name: child_unsets, semantic: {kind: plain_value}}
    effects:
      - kind: dispatch_command
        target: {kind: dispatch, command: child_command, argv: [child_args], environment: [child_environment], unset_environment: [child_unsets], clear_environment_when: [clear]}
modifiers:
  - id: clear
    matcher: {kind: any_flag, flags: [--clear]}
"#;

fn resolve(command: &str, bindings: &SessionBindings) -> BoundInvocation {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(PROFILE).unwrap()])
            .unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        bindings,
    ) {
        ResolveInvocationResult::Resolved(r) => {
            assert!(r.bound.residuals.is_empty(), "{:?}", r.bound.residuals);
            r.bound
        }
        r => panic!("{r:?}"),
    }
}

#[test]
fn projected_command_argv_environment_and_unsets_use_decoded_values() {
    let bound = resolve(
        "projection-fixture 'cmd:echo' 'one;$INNER;two words' 'TARGET=$OUT;EMPTY=' 'OLD;OTHER'",
        &SessionBindings::new(),
    );
    let projection = collect_dispatch_command_projection(&bound);
    assert!(projection.unresolved.is_empty());
    let child = &projection.resolved[0];
    assert_eq!(child.command.text, "echo");
    assert!(child.command.runtime_data);
    assert_eq!(
        child
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["one", "$INNER", "two words"]
    );
    assert_eq!(
        child
            .environment
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["TARGET=$OUT", "EMPTY="]
    );
    assert_eq!(
        child
            .unset_environment
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["OLD", "OTHER"]
    );
    assert!(
        child
            .argv
            .iter()
            .chain(&child.environment)
            .chain(&child.unset_environment)
            .all(|a| a.runtime_data)
    );
    let fact = child.to_command_fact();
    let materialized = materialize_projected_invocation(
        &project_invocation(&fact, InvocationRuntimeContext::new()),
        &SessionBindings::new().with_exact_scalar("INNER", "/opt/should-not-expand"),
    );
    assert_eq!(materialized.invocation.args[1].text, "$INNER");
    assert_eq!(materialized.invocation.args[2].text, "two words");
}

#[test]
fn projected_source_operands_and_spans_are_preserved() {
    let bound = resolve(
        "projection-fixture 'cmd:cat' 'a;b' 'A=1;B=2'",
        &SessionBindings::new(),
    );
    let untouched = bound.clone();
    let child = collect_dispatch_command_projection(&bound)
        .resolved
        .remove(0);
    assert_eq!(bound, untouched);
    for (slot, args) in [
        ("encoded_args", &child.argv),
        ("encoded_environment", &child.environment),
    ] {
        let original = bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == slot)
            .unwrap();
        let BoundValue::Argument {
            span,
            binding_source,
            text,
            ..
        } = &original.values[0]
        else {
            panic!()
        };
        assert!(text.contains(';'));
        assert!(
            args.iter()
                .all(|a| &a.span == span && &a.binding_source == binding_source)
        );
    }
}

#[test]
fn unknown_projected_command_never_falls_back_to_source_text() {
    let bound = resolve(
        "projection-fixture \"$COMMAND\" skip skip",
        &SessionBindings::new(),
    );
    let projection = collect_dispatch_command_projection(&bound);
    assert!(projection.resolved.is_empty());
    assert_eq!(projection.unresolved.len(), 1);
    assert_eq!(
        projection.unresolved[0].command_slot.as_str(),
        "child_command"
    );
}

#[test]
fn unknown_projected_argv_retains_known_effects_and_an_explicit_gap() {
    let bound = resolve(
        "projection-fixture 'cmd:rm' \"$ARGS\" skip",
        &SessionBindings::new(),
    );
    let projection = collect_dispatch_command_projection(&bound);
    assert_eq!(projection.resolved.len(), 1);
    assert_eq!(projection.unresolved.len(), 1);
    assert_eq!(
        projection.resolved[0].dispatch_index,
        projection.unresolved[0].dispatch_index
    );
    assert_eq!(projection.unresolved[0].command_slot.as_str(), "child_args");
    let unknown = &projection.resolved[0].argv[0];
    assert!(unknown.text.is_empty());
    assert!(!unknown.runtime_data);
    assert_eq!(
        unknown.implicit_input_source,
        Some(ImplicitInputSource::DispatchOutput)
    );
    assert_eq!(
        unknown.runtime_argument_domain,
        Some(RuntimeArgumentDomain::Unbounded)
    );
}

#[test]
fn unknown_environment_and_unsets_are_not_known_raw_words() {
    let bound = resolve(
        "projection-fixture --clear 'cmd:echo' skip \"$ENV\" \"$UNSETS\"",
        &SessionBindings::new(),
    );
    let child = collect_dispatch_command_projection(&bound)
        .resolved
        .remove(0);
    assert!(child.clear_environment);
    for unknown in [&child.environment[0], &child.unset_environment[0]] {
        assert!(unknown.text.is_empty());
        assert!(unknown.implicit_input_source.is_some());
        assert_eq!(
            unknown.runtime_argument_domain,
            Some(RuntimeArgumentDomain::Unbounded)
        );
    }
}

#[test]
fn proven_inapplicable_projection_is_not_an_unknown_operand() {
    let bound = resolve(
        "projection-fixture 'cmd:echo' skip skip",
        &SessionBindings::new(),
    );
    let projection = collect_dispatch_command_projection(&bound);
    assert!(projection.unresolved.is_empty());
    assert!(projection.resolved[0].argv.is_empty());
    assert!(projection.resolved[0].environment.is_empty());
}

#[test]
fn unknown_projection_does_not_inherit_a_source_path_bound() {
    let mut bound = resolve(
        "projection-fixture 'cmd:rm' file skip",
        &SessionBindings::new(),
    );
    let parameter = bound
        .bound_parameters
        .iter_mut()
        .find(|p| p.name.as_str() == "child_args")
        .unwrap();
    parameter.values[0] = BoundValue::ImplicitInput {
        source: caushell_profile::ImplicitInputSource::StdinData,
        domain: Some(RuntimeArgumentDomain::PathSet {
            roots: vec!["/workspace".into()],
            may_escape: false,
        }),
    };
    parameter.projected_values = Some(vec![ProjectedSemanticValue {
        source_index: 0,
        resolution: SemanticValueResolution::Unknown(ProjectionUnknownReason::DynamicArgument),
    }]);
    let child = collect_dispatch_command_projection(&bound)
        .resolved
        .remove(0);
    assert_eq!(
        child.argv[0].implicit_input_source,
        Some(ImplicitInputSource::StdinData)
    );
    assert_eq!(
        child.argv[0].runtime_argument_domain,
        Some(RuntimeArgumentDomain::Unbounded)
    );
}

#[test]
fn empty_semantic_view_does_not_reuse_raw_command_or_argv() {
    let mut bound = resolve(
        "projection-fixture 'cmd:echo' item skip",
        &SessionBindings::new(),
    );
    let argv = bound
        .bound_parameters
        .iter_mut()
        .find(|p| p.name.as_str() == "child_args")
        .unwrap();
    argv.projected_values = Some(Vec::new());
    assert!(
        collect_dispatch_command_projection(&bound).resolved[0]
            .argv
            .is_empty()
    );
    let cmd = bound
        .bound_parameters
        .iter_mut()
        .find(|p| p.name.as_str() == "child_command")
        .unwrap();
    cmd.projected_values = Some(Vec::new());
    let projection = collect_dispatch_command_projection(&bound);
    assert!(projection.resolved.is_empty());
    assert_eq!(projection.unresolved.len(), 1);
}

#[test]
fn materialized_scalar_is_not_expanded_again_while_attaching_binding_metadata() {
    let registry = ProfileRegistry::built_in().unwrap();
    for runtime_produced in [false, true] {
        let mut bindings =
            SessionBindings::new().with_exact_scalar("INNER", "/opt/should-not-expand");
        if runtime_produced {
            bindings.insert_runtime_produced("VALUE", "$INNER", RuntimeProducedValueKind::Scalar);
        } else {
            bindings.insert_exact_scalar("VALUE", "$INNER");
        }
        let parsed = parse_command("rm -f \"$VALUE\"", ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &bindings,
        ) else {
            panic!()
        };
        let target = r
            .bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "path_targets")
            .unwrap();
        assert!(matches!(&target.values[0], BoundValue::Argument {text, ..} if text == "$INNER"));
    }
}
