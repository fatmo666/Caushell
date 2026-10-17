use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(text: &str, scoped: bool) -> BoundInvocation {
    let policy = if scoped {
        "option_scope: permuted_options\nopaque_on_unresolved: true"
    } else {
        ""
    };
    let profile = load_command_profile_from_str(&format!(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: arbitrary-consumer}}
{policy}
forms:
  - id: files
    parameters:
      - {{name: paths, semantic: {{kind: path, role: write}}, binding: {{kind: remaining_positionals}}, cardinality: optional_many}}
modifiers:
  - id: output
    matcher: {{kind: any_flag, flags: [-o]}}
    parameters:
      - {{name: output, semantic: {{kind: path, role: write}}, binding: {{kind: following_matched_flag, operand_mode: next_arg}}, cardinality: required_one}}
"#)).unwrap();
    let parsed = parse_command(text, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(&profile, &projection).unwrap();
    bind_invocation(&profile, &projection, &selection)
}

#[test]
fn completed_scoped_ownership_is_retained_by_the_bound_value() {
    for text in [
        "arbitrary-consumer -- *.sh",
        "arbitrary-consumer ./dir/*",
        "arbitrary-consumer -o '*.sh'",
    ] {
        let bound = resolve(text, true);
        assert!(!bound.operation_semantics_unresolved, "{text}: {bound:?}");
        assert!(
            bound
                .bound_parameters
                .iter()
                .flat_map(|p| &p.values)
                .all(|v| matches!(
                    v,
                    BoundValue::Argument {
                        ownership: ArgumentOwnership::Operand,
                        ..
                    }
                )),
            "{text}: {bound:?}"
        );
    }
}

#[test]
fn semantic_slot_names_and_uncertain_boundaries_do_not_create_proofs() {
    for (text, scoped) in [
        ("arbitrary-consumer *", true),
        ("arbitrary-consumer -- *.sh", false),
        ("arbitrary-consumer -o $UNKNOWN *.sh", true),
        ("arbitrary-consumer -o *.sh", true),
    ] {
        let bound = resolve(text, scoped);
        assert!(
            bound
                .bound_parameters
                .iter()
                .flat_map(|p| &p.values)
                .all(|v| matches!(
                    v,
                    BoundValue::Argument {
                        ownership: ArgumentOwnership::Unproven,
                        ..
                    }
                )),
            "{text}: {bound:?}"
        );
    }
}

#[test]
fn argument_materialization_keeps_ownership_without_reclassifying_data() {
    let bound = resolve("arbitrary-consumer -- *.sh", true);
    let value = bound.bound_parameters[0].values[0]
        .clone()
        .with_materialization(BoundArgumentMaterialization::ResolvedExactScalar {
            variable_name: "input".into(),
        });
    assert!(matches!(
        value,
        BoundValue::Argument {
            ownership: ArgumentOwnership::Operand,
            ..
        }
    ));
}

#[test]
fn exact_lexical_words_become_native_data_once_before_option_selection() {
    for (source, expected) in [
        ("arbitrary -'c'", "-c"),
        ("arbitrary -\\\nc", "-c"),
        ("arbitrary \\-c", "-c"),
        ("arbitrary pre'$$'", "pre$$"),
        ("arbitrary a\\\nb", "ab"),
        ("arbitrary pre'\\\n'post", "pre\\\npost"),
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        let once = materialize_projected_invocation(&projection, &SessionBindings::new());
        assert_eq!(once.invocation.args.len(), 1, "{source}: {once:?}");
        assert_eq!(once.invocation.args[0].text, expected, "{source}: {once:?}");
        assert!(once.invocation.args[0].runtime_data, "{source}: {once:?}");
        let twice = materialize_projected_invocation(&once.invocation, &SessionBindings::new());
        assert_eq!(
            twice.invocation.args[0].text, expected,
            "{source}: {twice:?}"
        );
    }
    for source in [
        "arbitrary ./*",
        "arbitrary prefix$UNKNOWN",
        "arbitrary {}.tmp$$",
    ] {
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        let result = materialize_projected_invocation(&projection, &SessionBindings::new());
        assert!(
            !result.invocation.args[0].runtime_data,
            "{source}: {result:?}"
        );
    }
}

#[test]
fn exact_positional_count_is_an_argv_proof_not_a_count_of_source_words() {
    let profile = load_command_profile_from_str(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: any-name}
forms:
  - id: single
    selector: {kind: exact_positional_count, count: 1}
  - id: other
    selector: {kind: not, item: {kind: exact_positional_count, count: 1}}
"#,
    )
    .unwrap();
    for (command, expected) in [
        ("any-name file", "single"),
        ("any-name ./f*", "other"),
        ("any-name \"$value\"", "single"),
        ("any-name $value", "other"),
        ("any-name \"$@\"", "other"),
        ("any-name one two", "other"),
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        assert_eq!(
            select_invocation(&profile, &projection)
                .unwrap()
                .form
                .id
                .as_str(),
            expected,
            "{command}"
        );
    }
}

#[test]
fn explicit_modifier_policy_survives_post_materialization_projection_refresh() {
    for (id, suppress) in [
        ("ordinary-name", true),
        ("ordinary-name", false),
        ("show_help", true),
        ("show_help", false),
    ] {
        let source = format!(
            r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: arbitrary}}
option_scope: permuted_options
opaque_on_unresolved: true
forms:
  - id: {id}
    extensions: {{caushell.form/suppress_modifier_effects: {suppress}}}
modifiers:
  - id: output
    matcher: {{kind: any_flag, flags: [-o]}}
    parameters:
      - name: operand
        semantic: {{kind: plain_value}}
        binding: {{kind: following_matched_flag, operand_mode: next_arg}}
        cardinality: required_one
        structured_projection:
          branches:
            - {{matcher: {{kind: regex_capture, pattern: '^.+$', group: 0}}, target: {{name: output, semantic: {{kind: path, role: write}}}}}}
    effects: [{{kind: write_path, target: {{kind: slot, name: output}}}}]
"#
        );
        let profile = load_command_profile_from_str(&source).unwrap();
        let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
        let parsed = parse_command("arbitrary -o \"$OUT\"", ShellKind::Bash).unwrap();
        let result = resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &SessionBindings::new().with_exact_scalar("OUT", "/opt/out"),
        );
        let ResolveInvocationArtifactResult::Resolved(result) = result else {
            panic!("{result:?}");
        };
        assert_eq!(
            result.bound.effects.is_empty(),
            suppress,
            "{id}: {result:?}"
        );
        assert_eq!(
            !result
                .bound
                .bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "output"),
            suppress,
            "{id}: {result:?}"
        );
        assert!(
            load_command_profile_from_str(
                &source.replace(&format!("effects: {suppress}"), "effects: 'not-a-boolean'")
            )
            .is_err()
        );
    }
}
