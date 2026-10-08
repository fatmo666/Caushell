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
        ("[]", "[]"),
        ("name[", "name["),
        ("'s/.*('\"x)/\"", "s/.*(x)/"),
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
fn glob_and_scalar_spelling_bounds_include_suffixes_and_literal_fallbacks() {
    let glob = shape("report*.log");
    assert_eq!(glob.static_suffix, ".log");
    assert!(glob.may_equal("report-x.LOG")); // nocaseglob may be enabled
    assert!(glob.may_equal("report*.log")); // noglob / unmatched glob
    assert!(!glob.may_equal("-delete") && !glob.may_start_with("-"));
    assert!(!shape("*.log").may_equal("-delete"));
    assert!(shape("*.log").may_start_with("-")); // undeclared options still possible
    assert!(shape("*DELETE").may_equal("-delete"));
    let class = shape("[ab]*");
    assert!(!class.may_start_with("-"));
    assert!(class.may_equal("[ab]*") && class.may_start_with("[ab]"));
    assert!(shape("[!a]*").may_start_with("-"));
    assert!(shape("[a-z]*").may_start_with("-")); // unknown collation
    let posix = shape("file[[:digit:]]");
    assert_eq!(posix.fields, ArgumentFieldCount::ZeroOrMore);
    assert!(!posix.may_start_with("-") && posix.may_equal("file123"));
    assert_eq!(
        shape("file[[:digit:]]$value").fields,
        ArgumentFieldCount::Unknown
    );
    let scalar = shape(r#""$HOME/""#);
    assert_eq!(scalar.fields, ArgumentFieldCount::ExactlyOne);
    assert_eq!(scalar.static_suffix, "/");
    assert!(!scalar.may_equal("-delete") && scalar.may_equal("/home/user/"));
    assert!(scalar.may_start_with("-")); // a suffix is NOT a prefix guarantee
    let brace = shape("/path/folder{?,[1-4]?,50}");
    assert_eq!(brace.fields, ArgumentFieldCount::ZeroOrMore);
    assert!(!brace.may_start_with("-") && !brace.may_equal(";"));
}

#[test]
fn standalone_process_substitution_is_one_unknown_path_not_its_shell_body() {
    for word in ["<(cat stamp)", ">(cat)"] {
        let facts = shape(word);
        assert_eq!(facts.fields, ArgumentFieldCount::ExactlyOne);
        assert!(!facts.exact);
        assert!(!facts.may_equal(";") && !facts.may_equal("{}"));
    }
    assert!(!find("find . -newer <(cat stamp) -print").operation_semantics_unresolved);
}

fn slot_values<'a>(bound: &'a BoundInvocation, name: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            caushell_profile::BoundValue::Argument { text, .. } => text.as_str(),
            _ => panic!("{v:?}"),
        })
        .collect()
}

#[test]
fn bounded_operand_width_checks_zero_one_many_and_respects_positional_order() {
    for command in [
        "find . -name report*.log -print",
        "find . -name [ab]* -type f -print",
        "find . -name report*.log -name other*.log -print",
    ] {
        let bound = find(command);
        assert!(
            !bound.operation_semantics_unresolved,
            "{command}: {bound:?}"
        );
        assert_eq!(slot_values(&bound, "search_roots"), vec!["."], "{bound:?}");
        assert!(bound.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    }
    let bound = find("find /outside -name report*.log -delete");
    assert!(bound.operation_semantics_unresolved); // zero fields can swallow -delete
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DeletePath)
    );
}

#[test]
fn shifted_controls_and_mutation_operands_never_lose_structural_approval() {
    for command in [
        "find /outside -name *.zip -printf '-delete'",
        "find /outside -name report*.zip -printf '-delete'",
        "find . -fprint ./output* /outside/new-target",
        "find . -name -d* -print",
        "find . -name * -print",
    ] {
        let bound = find(command);
        assert!(bound.operation_semantics_unresolved, "{command}: {bound:?}");
    }
}

#[test]
fn declared_control_vocabulary_bounds_globs_without_guessing_unknown_options() {
    for command in [
        "find . -name *.py -print",
        "find -name *.xml",
        "find -name met* -print",
        "find . -name *.py -type f -exec md5sum {} '+'",
    ] {
        let bound = find(command);
        assert!(
            !bound.operation_semantics_unresolved,
            "{command}: {bound:?}"
        );
    }
    let mut profile = load_command_profile_from_str(include_str!("../profiles/find.yaml")).unwrap();
    profile.argument_control_vocabulary = None;
    let parsed = parse_command("find . -name *.py -print", ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(&profile, &projection).unwrap();
    assert!(bind_invocation(&profile, &projection, &selection).operation_semantics_unresolved);
    for command in [
        r#"find "$HOME/" -name myfile.txt -print"#,
        "find *.py -print",
        "find *.. -delete",
        "find . -name * -print",
        "find . -name *DELETE -print",
        "find . -name *ok -print",
        "find . -name *files0-from -print",
        "find . -name *newer* -print",
        "find . -name *sX -print", // valid BSD option clusters are not guessed
    ] {
        assert!(find(command).operation_semantics_unresolved, "{command}");
    }
}

#[test]
fn finite_control_vocabulary_is_command_independent_and_validated() {
    let yaml = include_str!("../profiles/find.yaml")
        .replace("canonical_name: find", "canonical_name: probe");
    assert!(!bound_with(&yaml, "probe . -name *.py -print").operation_semantics_unresolved);
    assert!(bound_with(&yaml, "probe . -name *ok -print").operation_semantics_unresolved);
    assert!(
        load_command_profile_from_str(&yaml.replace(
            "unmodeled_short_clusters: [\"EHLPXdsx\"]",
            "unmodeled_short_clusters: [\"-s\"]"
        ))
        .is_err()
    );
    assert!(
        load_command_profile_from_str(&yaml.replace(
            "unmodeled_words: [\"-ok\"",
            "unmodeled_words: [\"bad control\""
        ))
        .is_err()
    );
}

#[test]
fn bounded_ownership_retains_defaults_children_and_effectful_target_coverage() {
    let bound = find("find -name met* -print");
    assert!(!bound.operation_semantics_unresolved, "{bound:?}");
    assert!(slot_values(&bound, "search_roots").is_empty());
    assert!(bound.effects.iter().any(|e| matches!(&e.target,
        caushell_profile::EffectTarget::ConfiguredPath(p)
        if p.default_value.as_deref() == Some("."))));
    let yaml = include_str!("../profiles/find.yaml");
    let start = yaml.find("  positional_boundary_words:").unwrap();
    let end = start + yaml[start..].find('\n').unwrap();
    let open = format!(
        "{}  positional_boundary_words: []{}",
        &yaml[..start],
        &yaml[end..]
    );
    let bound = bound_with(&open, "find -name met* -print");
    assert!(!bound.operation_semantics_unresolved);
    assert!(slot_values(&bound, "search_roots").contains(&"met*"));
    assert!(bound.effects.iter().any(|e| matches!(&e.target,
        caushell_profile::EffectTarget::ConfiguredPath(p)
        if p.sources.is_empty() && p.default_value.as_deref() == Some("."))));
    let bound = find("find . -name *.py -type f -exec rm {} ';'");
    assert!(!bound.operation_semantics_unresolved, "{bound:?}");
    assert_eq!(bound.argument_regions.len(), 1);
    assert_eq!(slot_values(&bound, "exec_command"), vec!["rm"]);
    assert_eq!(slot_values(&bound, "exec_args"), vec!["{}"]);
    assert_eq!(slot_values(&bound, "search_roots"), vec!["."]);
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DispatchCommand)
    );
    for command in ["find /outside -name *.py -printf '-delete'"] {
        assert!(find(command).operation_semantics_unresolved, "{command}");
    }
}

#[test]
fn dead_expression_branches_do_not_hide_live_writes_or_exposed_controls() {
    let bound = find("find . -name *.py -fprint /outside/target");
    assert!(!bound.operation_semantics_unresolved, "{bound:?}");
    assert_eq!(slot_values(&bound, "output_paths"), vec!["/outside/target"]);
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    let bound = find("find . -name *.py -exec echo '-delete' ';'");
    assert!(!bound.operation_semantics_unresolved, "{bound:?}");
    assert_eq!(slot_values(&bound, "exec_args"), vec!["-delete"]);
    for command in [
        "find . -name *.py -exec -delete ';'",
        "find . -name *.py -fprint '-delete'",
        "find . -name *.py -printf '-ok'",
        "find . -name *.py -type '-delete'",
    ] {
        assert!(find(command).operation_semantics_unresolved, "{command}");
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
fn bounded_width_coverage_is_declarative_and_preserves_cross_modifier_targets() {
    let yaml = format!(
        "{GENERIC}\n  - id: pattern\n    matcher: {{kind: any_flag, flags: [--pattern]}}\n    parameters:\n      - {{name: filters, semantic: {{kind: plain_value}}, binding: {{kind: following_matched_flag, operand_mode: next_arg}}, cardinality: required_many}}\n"
    );
    let command = "arbitrary-region-tool root --pattern item* --action";
    let bound = bound_with(&yaml, command);
    assert!(!bound.operation_semantics_unresolved, "{bound:?}");
    assert_eq!(slot_values(&bound, "roots"), ["root", "item*"]);
    // A different modifier consuming that slot makes its role effectful,
    // even when the modifier owning --pattern itself has no effects.
    let yaml = yaml.replace("matcher: {kind: any_flag, flags: [--action]}",
        "matcher: {kind: any_flag, flags: [--action]}\n    effects: [{kind: write_path, target: {kind: slot, name: filters}}]");
    assert!(bound_with(&yaml, command).operation_semantics_unresolved);
    let command = "arbitrary-region-tool root --pattern item* --worker echo END";
    assert!(bound_with(&yaml, command).operation_semantics_unresolved);
}

#[test]
fn configured_targets_require_same_form_companions_and_active_effect_metadata() {
    let yaml = format!(
        "{GENERIC}\n  - id: pattern\n    matcher: {{kind: any_flag, flags: [--pattern]}}\n    parameters:\n      - {{name: filters, semantic: {{kind: plain_value}}, binding: {{kind: following_matched_flag, operand_mode: next_arg}}, cardinality: required_many}}\n"
    ).replace("name: roots, semantic: {kind: plain_value}",
        "name: roots, semantic: {kind: path, role: read, purpose: generic_operand}")
    .replace("modifiers:\n", "    effects:\n      - {kind: read_path, target: {kind: slot, name: roots}}\n      - kind: read_path\n        target: {kind: configured_path, sources: [{slot: roots, projection: {kind: identity}}], default_value: '.', purpose: generic_operand}\nmodifiers:\n");
    let command = "arbitrary-region-tool root --pattern item* --action";
    assert!(!bound_with(&yaml, command).operation_semantics_unresolved);
    // Different access metadata does not prove target coverage, even when
    // the two effects' kinds and slots agree.
    let different = yaml.replace(
        "{kind: read_path, target: {kind: slot, name: roots}}",
        "{kind: read_path, path_access: content_open, target: {kind: slot, name: roots}}",
    );
    assert!(bound_with(&different, command).operation_semantics_unresolved);
    let inactive = format!(
        "{yaml}\n  - id: other\n    matcher: {{kind: any_flag, flags: [--other]}}\n    effects:\n      - kind: write_path\n        target: {{kind: configured_path, sources: [{{slot: roots, projection: {{kind: identity}}}}], purpose: generic_operand}}\n"
    );
    assert!(!bound_with(&inactive, command).operation_semantics_unresolved);
    assert!(bound_with(&inactive, &format!("{command} --other")).operation_semantics_unresolved);
    // An effect from a different form cannot cover the configured target.
    let other_form = yaml.replace("      - {kind: read_path, target: {kind: slot, name: roots}}\n", "")
        .replace("modifiers:\n", "  - id: companion_elsewhere\n    selector: {kind: has_flag, flag: --worker}\n    parameters:\n      - {name: roots, semantic: {kind: path, role: read, purpose: generic_operand}, binding: {kind: remaining_positionals}, cardinality: optional_many}\n    effects: [{kind: read_path, target: {kind: slot, name: roots}}]\nmodifiers:\n");
    assert!(bound_with(&other_form, command).operation_semantics_unresolved);
}

#[test]
fn bounded_pid_fields_do_not_inherit_prefixes_or_ignore_ifs() {
    let facts = shape("/tmp/stamp$$");
    assert_eq!(facts.fields, ArgumentFieldCount::ZeroOrMore);
    assert!(facts.static_prefix.is_empty());
    assert!(facts.may_equal("/tmp/stamp123") && facts.may_equal("23"));
    assert!(!facts.may_start_with("-") && !facts.may_equal(";"));
    assert!(!find("find /usr -newer /tmp/stamp$$").operation_semantics_unresolved);
    assert!(find("find . -newer /tmp/stamp$$ -delete").operation_semantics_unresolved);
    assert_eq!(shape("/tmp/$unknown").fields, ArgumentFieldCount::Unknown);
    assert!(shape("'$$'").exact);
}

#[test]
fn second_operand_arity_is_covered_but_effectful_second_targets_are_not_guessed() {
    let yaml = format!(
        "{GENERIC}\n  - id: pair\n    matcher: {{kind: any_flag, flags: [--pair]}}\n    parameters:\n      - {{name: second, semantic: {{kind: plain_value}}, binding: {{kind: following_matched_flag, operand_mode: second_arg}}, cardinality: required_many}}\n"
    );
    let command = "arbitrary-region-tool root --pair item* value --action";
    let bound = bound_with(&yaml, command);
    assert!(!bound.operation_semantics_unresolved, "{bound:?}");
    assert_eq!(slot_values(&bound, "roots"), ["root", "item*", "value"]);
    let effectful = yaml.replace(
        "name: second, semantic: {kind: plain_value}",
        "name: second, semantic: {kind: path, role: write}",
    );
    assert!(bound_with(&effectful, command).operation_semantics_unresolved);
    let excluded = yaml.replace("name: roots, semantic: {kind: plain_value}",
        "name: roots, value_constraints: [{kind: exclude_literal, value: value}], semantic: {kind: plain_value}");
    assert!(bound_with(&excluded, command).operation_semantics_unresolved);
}

#[test]
fn form_shape_selection_and_modifier_constraints_cannot_be_changed_by_width_proofs() {
    let yaml = format!(
        "{GENERIC}\n  - id: pattern\n    matcher: {{kind: any_flag, flags: [--pattern]}}\n    parameters:\n      - {{name: filters, semantic: {{kind: plain_value}}, binding: {{kind: following_matched_flag, operand_mode: next_arg}}, cardinality: required_many}}\n"
    );
    let command = "arbitrary-region-tool root --pattern item* --action";
    let by_shape = yaml.replace(
        "- id: run",
        "- id: run\n    selector: {kind: has_positional_at, index: 0}",
    );
    assert!(bound_with(&by_shape, command).operation_semantics_unresolved);
    let constrained=yaml.replace("matcher: {kind: any_flag, flags: [--action]}",
        "matcher: {kind: any_flag, flags: [--action]}\n    constraints: [{kind: requires_modifier, modifier: pattern}]");
    assert!(bound_with(&constrained, command).operation_semantics_unresolved);
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
