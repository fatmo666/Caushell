use caushell_parse::parse_command;
use caushell_profile::{
    ArgumentFieldCount, ArgumentStructure, BoundInvocation, EffectKind, InvocationRuntimeContext,
    argument_structure, bind_invocation, load_command_profile_from_str, project_invocation,
    select_invocation,
};
use caushell_types::ShellKind;

fn shape(word: &str) -> ArgumentStructure {
    let parsed = parse_command(&format!("echo {word}"), ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    assert_eq!(projection.args.len(), 1, "{word}: {projection:?}");
    argument_structure(&projection.args[0])
}

fn bound_with(yaml: &str, command: &str) -> BoundInvocation {
    let profile = load_command_profile_from_str(yaml).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(&profile, &projection).unwrap();
    bind_invocation(&profile, &projection, &selection)
}

fn find(command: &str) -> BoundInvocation {
    bound_with(include_str!("../profiles/find.yaml"), command)
}

#[test]
fn exact_literals_preserve_shell_quoting_and_placeholder_values() {
    for (word, value) in [
        ("plain", "plain"),
        ("'./$dir'", "./$dir"),
        (r"./\*", "./*"),
        ("{}", "{}"),
        ("name{3}", "name{3}"),
        ("'-delete'", "-delete"),
        ("'a b'", "a b"),
        ("'./'\"literal\"", "./literal"),
    ] {
        let facts = shape(word);
        assert_eq!(
            facts.fields,
            ArgumentFieldCount::ExactlyOne,
            "{word}: {facts:?}"
        );
        assert_eq!(facts.exact_value(), Some(value), "{word}: {facts:?}");
    }
}

#[test]
fn resolved_field_data_preserves_recursive_payload_binding_origin() {
    use caushell_profile::{
        BoundArgumentMaterialization, ProfileRegistry, ResolveInvocationArtifactResult,
        SessionBindings, ValueMaterialization, collect_recursive_payload_candidates,
        materialize_recursive_payload_candidate, resolve_invocation_artifact_with_bindings,
    };
    let registry = ProfileRegistry::built_in().unwrap();
    for value in [r#"printf '%s' '$OTHER'"#, r#"echo \"{a,b}\""#] {
        let parsed = parse_command(r#"eval "$payload""#, ShellKind::Bash).unwrap();
        let bindings = SessionBindings::new().with_exact_scalar("payload", value);
        let ResolveInvocationArtifactResult::Resolved(resolved) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new(),
                &bindings,
            )
        else {
            panic!("expected resolved eval");
        };
        assert!(resolved.materialized_projection.invocation.args[0].runtime_data);
        assert!(
            resolved
                .bound
                .bound_parameters
                .iter()
                .flat_map(|p| &p.values)
                .any(|v| {
                    matches!(v, caushell_profile::BoundValue::Argument { text, materialization:
                BoundArgumentMaterialization::ResolvedExactScalar { variable_name }, .. }
                if text == value && variable_name == "payload")
                })
        );
        let candidate = collect_recursive_payload_candidates(&resolved.bound).remove(0);
        let materialized = materialize_recursive_payload_candidate(&candidate, &bindings);
        assert!(matches!(materialized.resolution,
            ValueMaterialization::ResolvedExactScalar { ref variable_name, value: ref text, .. }
            if variable_name == "payload" && text == value));
    }
}

#[test]
fn quoted_scalar_prefix_is_shared_by_its_single_field() {
    for word in [
        r#""./$dir""#,
        r#"./"$dir""#,
        r#""./${dir}""#,
        r#""./$1""#,
        r#""./$*""#,
    ] {
        let facts = shape(word);
        assert_eq!(
            facts.fields,
            ArgumentFieldCount::ExactlyOne,
            "{word}: {facts:?}"
        );
        assert_eq!(facts.static_prefix, "./", "{word}: {facts:?}");
        assert!(!facts.exact && !facts.may_start_with("-") && !facts.may_equal(";"));
    }
    let facts = shape(r#""$dir""#);
    assert_eq!(facts.fields, ArgumentFieldCount::ExactlyOne);
    assert!(facts.may_equal("-delete") && facts.may_equal(";"));
}

#[test]
fn pathname_generation_keeps_per_field_prefix_but_not_exact_width() {
    for (word, prefix) in [
        ("/home/*/public_html", "/home/"),
        ("./*", "./"),
        ("CACHE_?", "CACHE_"),
        ("/var/spool/{deferred,active}/", "/var/spool/"),
        ("/path/folder{1..50}", "/path/folder"),
    ] {
        let facts = shape(word);
        assert_eq!(
            facts.fields,
            ArgumentFieldCount::ZeroOrMore,
            "{word}: {facts:?}"
        );
        assert_eq!(facts.static_prefix, prefix);
        assert!(!facts.exact && !facts.may_start_with("-") && !facts.may_equal("-exec"));
    }
    assert!(shape("*.py").may_start_with("-"));
}

#[test]
fn splitting_arrays_and_complex_expansions_never_inherit_a_first_field_prefix() {
    for word in [
        "./$dir",
        "/tmp/${dir}",
        "./$@",
        r#""./$@""#,
        r#""./${@}""#,
        r#""./${array[@]}""#,
        r#""./${dir:-$@}""#,
        "/tmp/{one,$value}",
    ] {
        let facts = shape(word);
        assert_eq!(
            facts.fields,
            ArgumentFieldCount::Unknown,
            "{word}: {facts:?}"
        );
        assert!(
            facts.static_prefix.is_empty() && facts.may_equal("-exec"),
            "{word}: {facts:?}"
        );
    }
    let brace_controls = shape("--{delete,print}");
    assert_eq!(brace_controls.fields, ArgumentFieldCount::ZeroOrMore);
    assert!(brace_controls.may_start_with("-") && brace_controls.may_equal("--delete"));
}

#[test]
fn whole_quoted_scalar_syntax_proves_width_without_evaluating_substitutions() {
    for word in [
        r#""./$(printf foo)""#,
        r#""./`hostname`""#,
        r#""./${value:-fallback}""#,
        r#""./$(date -d @1494500000)""#,
    ] {
        let facts = shape(word);
        assert_eq!(
            facts.fields,
            ArgumentFieldCount::ExactlyOne,
            "{word}: {facts:?}"
        );
        assert_eq!(facts.static_prefix, "./");
        assert!(!facts.exact && !facts.may_equal(";"));
    }
    for word in [r#"".*\\.rb$""#, r#""^.*~$\\|^.*#$""#] {
        assert_eq!(shape(word).fields, ArgumentFieldCount::ExactlyOne, "{word}");
        assert!(shape(word).exact, "{word}");
    }
    for word in [
        r#""./${!name}""#,
        r#""./${array[$index]}""#,
        r#""./${value:-$@}""#,
    ] {
        assert_eq!(shape(word).fields, ArgumentFieldCount::Unknown, "{word}");
    }
}

#[test]
fn noncontrol_dynamic_roots_do_not_make_read_operations_opaque() {
    for command in [
        r#"find "./$dir" -print"#,
        r#"find ./"$dir" -print"#,
        "find /home/*/public_html -print",
        "find ./* -print",
        "find CACHE_* -print",
        "find /var/spool/{deferred,active}/ -print",
        "find /path/folder{1..50} -print",
        r#"find "./$dir" -exec echo {} \; -type f"#,
    ] {
        let bound = find(command);
        assert!(
            !bound.operation_semantics_unresolved,
            "{command}: {bound:?}"
        );
        assert!(bound.residuals.is_empty(), "{command}: {bound:?}");
    }
}

#[test]
fn owned_unknown_single_fields_cannot_supply_outer_control_words() {
    for command in [
        r#"find . -name "$pattern" -print"#,
        r#"find . -newer "/tmp/$stamp" -print"#,
    ] {
        let bound = find(command);
        assert!(
            !bound.operation_semantics_unresolved,
            "{command}: {bound:?}"
        );
        assert!(bound.argument_regions.is_empty());
        assert!(
            !bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::DeletePath)
        );
    }
}

#[test]
fn unknown_option_width_and_possible_root_controls_remain_unresolved() {
    for command in [
        r#"find "$dir" -print"#,
        "find ./$dir -print",
        "find * -print",
        "find . -name *.py -print",
        r#"find . -name "$@" -print"#,
        r#"find . -newer "$@" -delete"#,
        r#"find . -name "./${array[@]}" -print"#,
        "find {-delete,-print}",
    ] {
        let bound = find(command);
        assert!(bound.operation_semantics_unresolved, "{command}: {bound:?}");
    }
}

#[test]
fn child_single_data_field_cannot_end_parent_region_but_potential_delimiters_can() {
    let bound = find(r#"find . -exec echo "./$value" \; -delete"#);
    assert!(!bound.operation_semantics_unresolved, "{bound:?}");
    assert_eq!(bound.argument_regions.len(), 1);
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DeletePath)
    );
    for command in [
        r#"find . -exec echo "$value" \;"#,
        r#"find . -exec echo "{}$value" + extra \;"#,
        "find . -exec echo /tmp/* + -delete \\;",
    ] {
        let bound = find(command);
        assert!(bound.operation_semantics_unresolved, "{command}: {bound:?}");
    }
}

const GENERIC: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-region-tool}
option_matching: exact_names
opaque_on_unresolved: true
argument_regions:
  - id: worker
    start_flags: [--worker]
    terminators: [{value: END}]
forms:
  - id: run
    parameters:
      - {name: worker, semantic: {kind: plain_value}, binding: {kind: argument_region_command, region: worker}, cardinality: optional_many}
      - {name: argv, semantic: {kind: plain_value}, binding: {kind: argument_region_args, region: worker}, cardinality: optional_many}
      - {name: roots, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}
modifiers:
  - id: action
    matcher: {kind: any_flag, flags: [--action]}
"#;

#[test]
fn structural_query_uses_declared_grammar_not_find_or_path_exceptions() {
    let command = r#"arbitrary-region-tool "/root/$dir" --worker echo "/tmp/$arg" END --action"#;
    let bound = bound_with(GENERIC, command);
    assert!(!bound.operation_semantics_unresolved, "{bound:?}");
    assert_eq!(bound.argument_regions.len(), 1);
    let yaml = GENERIC.replace("[--action]", "[/root/action]");
    let bound = bound_with(&yaml, r#"arbitrary-region-tool "/root/$dir""#);
    assert!(bound.operation_semantics_unresolved, "{bound:?}");
    let bound = bound_with(
        GENERIC,
        r#"arbitrary-region-tool --worker echo "END$arg" END"#,
    );
    assert!(bound.operation_semantics_unresolved, "{bound:?}");
}

#[test]
fn materialization_distinguishes_unknown_positionals_from_known_empty_or_known_fields() {
    use caushell_profile::{SessionBindings, materialize_projected_invocation};
    let parsed = parse_command(r#"echo "$@""#, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let unknown = materialize_projected_invocation(&projection, &SessionBindings::new());
    assert_eq!(unknown.invocation.args.len(), 1);
    assert_eq!(unknown.invocation.args[0].text, "$@");
    assert_eq!(
        argument_structure(&unknown.invocation.args[0]).fields,
        ArgumentFieldCount::Unknown
    );
    let mut bindings = SessionBindings::new();
    bindings.replace_positional_parameters_with_exact_scalars(Vec::<String>::new());
    assert!(
        materialize_projected_invocation(&projection, &bindings)
            .invocation
            .args
            .is_empty()
    );
    bindings.replace_positional_parameters_with_exact_scalars(["*.py", "-delete"]);
    let known = materialize_projected_invocation(&projection, &bindings);
    assert_eq!(
        known
            .invocation
            .args
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["*.py", "-delete"]
    );
}

#[test]
fn resolved_fields_are_data_not_shell_source_for_a_second_expansion() {
    use caushell_profile::{SessionBindings, materialize_projected_invocation};
    let parsed = parse_command(r#"echo "$value""#, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    for value in ["./$literal", "./{a,b}", "./*.py", "./'quoted'"] {
        let bindings = SessionBindings::new().with_exact_scalar("value", value);
        let known = materialize_projected_invocation(&projection, &bindings);
        assert_eq!(known.invocation.args.len(), 1);
        assert!(known.invocation.args[0].runtime_data);
        assert_eq!(
            argument_structure(&known.invocation.args[0]).exact_value(),
            Some(value)
        );
    }
}
