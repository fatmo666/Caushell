use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, CommandProfile, EffectKind, InvocationRuntimeContext, ModifierId,
    bind_invocation, load_command_profile_from_str, project_invocation, select_invocation,
};
use caushell_types::ShellKind;

fn find_profile() -> CommandProfile {
    load_command_profile_from_str(include_str!("../profiles/find.yaml")).unwrap()
}

fn bind(profile: &CommandProfile, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(profile, &projection)
        .unwrap_or_else(|error| panic!("{command}: {error}"));
    let bound = bind_invocation(profile, &projection, &selection);
    assert!(bound.residuals.is_empty(), "{command}: {bound:?}");
    bound
}

fn values<'a>(bound: &'a BoundInvocation, slot: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.as_str(),
            _ => panic!("{v:?}"),
        })
        .collect()
}

#[test]
fn child_flags_and_dashdash_never_become_outer_modifiers_or_roots() {
    let profile = find_profile();
    for command in [
        r"find . -exec printf %s -delete -type b -name /etc -exec -- {} \;",
        r"find . -execdir printf %s -delete -type b -name /etc -exec -- {} \;",
    ] {
        let bound = bind(&profile, command);
        assert_eq!(values(&bound, "search_roots"), ["."]);
        assert!(bound.applied_modifiers.is_empty(), "{bound:?}");
        assert!(
            !bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::DeletePath)
        );
        let slot = if command.contains("-execdir") {
            "execdir_args"
        } else {
            "exec_args"
        };
        assert_eq!(
            values(&bound, slot),
            [
                "%s", "-delete", "-type", "b", "-name", "/etc", "-exec", "--", "{}"
            ]
        );
        assert_eq!(bound.argument_regions.len(), 1);
    }
}

#[test]
fn outer_flags_before_between_and_after_regions_remain_owned() {
    let bound = bind(
        &find_profile(),
        r"find /opt/shared -name '*.txt' -exec printf %s -delete {} \; -type f -execdir echo -- {} \; -delete",
    );
    assert_eq!(values(&bound, "search_roots"), ["/opt/shared"]);
    assert_eq!(values(&bound, "patterns"), ["*.txt"]);
    assert_eq!(values(&bound, "file_types"), ["f"]);
    assert!(
        bound
            .applied_modifiers
            .contains(&ModifierId::new("delete_action"))
    );
    assert_eq!(
        bound
            .argument_regions
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        ["exec", "execdir"]
    );
    assert_eq!(values(&bound, "exec_args"), ["%s", "-delete", "{}"]);
    assert_eq!(values(&bound, "execdir_args"), ["--", "{}"]);
}

#[test]
fn opener_and_risky_flag_spelling_can_be_plain_outer_option_operands() {
    for word in ["-exec", "-execdir", "-delete", ";", "+"] {
        let bound = bind(&find_profile(), &format!("find . -name '{word}' -print"));
        assert!(bound.argument_regions.is_empty());
        assert_eq!(bound.form_id.as_str(), "enumerate_paths");
        assert!(
            !bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::DeletePath)
        );
        assert_eq!(values(&bound, "patterns"), [word]);
    }
}

#[test]
fn plus_is_data_unless_the_declared_previous_argv_word_matches() {
    let bound = bind(&find_profile(), r"find . -exec printf %s + -delete {} \;");
    assert_eq!(values(&bound, "exec_args"), ["%s", "+", "-delete", "{}"]);
    let bound = bind(&find_profile(), "find . -exec echo '{}' '+' -delete");
    assert_eq!(values(&bound, "exec_args"), ["{}"]);
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DeletePath)
    );
}

#[test]
fn quoted_outer_options_and_delimiters_use_argv_not_shell_spelling() {
    let bound = bind(
        &find_profile(),
        "find . '-name' '-exec' '-exec' printf %s '-delete' ';' '-delete'",
    );
    assert_eq!(values(&bound, "patterns"), ["-exec"]);
    assert_eq!(values(&bound, "search_roots"), ["."]);
    assert_eq!(values(&bound, "exec_args"), ["%s", "-delete"]);
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DeletePath)
    );
}

#[test]
fn incomplete_or_unknown_ownership_is_an_explicit_selection_error() {
    for command in [
        "find . -exec",
        "find . -exec echo",
        "find . -exec echo ;",
        "find . -exec ';'",
        "find . -exec echo {} + -execdir printf",
        "find . -unsupported -exec echo ';'",
        "find . -name",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        assert!(
            select_invocation(&find_profile(), &projection).is_err(),
            "{command}"
        );
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
  - id: delete
    matcher: {kind: any_flag, flags: [--delete]}
  - id: pattern
    matcher: {kind: any_flag, flags: [--pattern]}
    parameters:
      - {name: patterns, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}}
"#;

#[test]
fn declaration_works_without_any_find_command_name() {
    let profile = load_command_profile_from_str(GENERIC).unwrap();
    let bound = bind(
        &profile,
        "arbitrary-region-tool root --pattern --worker --worker echo --delete -- --worker END --worker printf END --delete",
    );
    assert_eq!(values(&bound, "patterns"), ["--worker"]);
    assert_eq!(values(&bound, "worker"), ["echo", "printf"]);
    assert_eq!(values(&bound, "argv"), ["--delete", "--", "--worker"]);
    assert_eq!(values(&bound, "roots"), ["root"]);
    assert_eq!(bound.argument_regions.len(), 2);
    assert_eq!(bound.applied_modifiers.len(), 2);
}

#[test]
fn unknown_argv_preserves_partial_children_but_is_never_complete_ownership() {
    for command in [
        "find $unknown -exec rm {} ';'",
        "find . -exec rm $unknown ';'",
        "find . -exec sh -c \"$unknown\" _ {} ';'",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        let profile = find_profile();
        let selection = select_invocation(&profile, &projection).unwrap();
        let bound = bind_invocation(&profile, &projection, &selection);
        assert!(bound.operation_semantics_unresolved, "{command}: {bound:?}");
        assert_eq!(bound.argument_regions.len(), 1);
        assert!(!values(&bound, "exec_command").is_empty());
    }
}

#[test]
fn invalid_declarations_fail_at_load_time() {
    for yaml in [
        GENERIC.replace("region: worker", "region: absent"),
        GENERIC.replace("id: worker", "id: ''"),
        GENERIC.replace("[--worker]", "[]"),
        GENERIC.replace("[--worker]", "[--worker, --worker]"),
        GENERIC.replace("[--worker]", "[--delete]"),
        GENERIC.replace("[{value: END}]", "[]"),
        GENERIC.replace("[{value: END}]", "[{value: ''}]"),
        GENERIC.replace("[{value: END}]", "[{value: END, preceding: ''}]"),
        GENERIC.replace("exact_names", "short_clusters"),
        GENERIC.replace("opaque_on_unresolved: true", "opaque_on_unresolved: false"),
        format!("{GENERIC}\noption_scope: leading_options\n"),
        format!("{GENERIC}\nsubcommands: {{roots: []}}\n"),
        GENERIC.replace("operand_mode: next_arg", "operand_mode: optional_next_arg"),
    ] {
        assert!(load_command_profile_from_str(&yaml).is_err(), "{yaml}");
    }
}

#[test]
fn subcommand_bindings_cannot_reference_an_absent_root_region() {
    let yaml = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-region-tool}
subcommands:
  roots:
    - name: worker
      forms:
        - id: run
          parameters:
            - {name: child, semantic: {kind: plain_value}, binding: {kind: argument_region_command, region: absent}, cardinality: optional_one}
"#;
    assert!(load_command_profile_from_str(yaml).is_err());
}
