use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> ResolvedInvocationArtifact {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    )
    .into_artifact()
    {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}
fn values(bound: &BoundInvocation, slot: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .filter_map(|v| match v {
            BoundValue::Argument { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

const GROUPED: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-paired-tool}
option_scope: leading_options
opaque_on_unresolved: true
forms:
  - id: convert
    parameters:
      - {name: sources, semantic: {kind: path, role: read}, binding: {kind: positional_groups, group_size: 2, member: 0}, cardinality: required_many}
      - {name: destinations, semantic: {kind: path, role: write}, binding: {kind: positional_groups, group_size: 2, member: 1}, cardinality: required_many}
    effects: [{kind: read_path, target: {kind: slot, name: sources}}, {kind: write_path, target: {kind: slot, name: destinations}}]
modifiers:
  - id: format
    matcher: {kind: any_flag, flags: [--format]}
    parameters: [{name: format, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_one}]
"#;

fn grouped(command: &str) -> BoundInvocation {
    grouped_with_profile(GROUPED, command)
}

fn grouped_with_profile(source: &str, command: &str) -> BoundInvocation {
    let profile = load_command_profile_from_str(source).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(&profile, &projection).unwrap();
    bind_invocation(&profile, &projection, &selection)
}

#[test]
fn generic_groups_keep_original_member_order_and_source_metadata() {
    for command in [
        "arbitrary-paired-tool in1 out1 in2 out2",
        "arbitrary-paired-tool --format ascii in1 out1 in2 out2",
    ] {
        let b = grouped(command);
        assert!(!b.operation_semantics_unresolved, "{b:#?}");
        assert_eq!(values(&b, "sources"), ["in1", "in2"]);
        assert_eq!(values(&b, "destinations"), ["out1", "out2"]);
        for p in &b.bound_parameters {
            for v in &p.values {
                if let BoundValue::Argument { text, span, .. } = v {
                    assert_eq!(&command[span.start_byte..span.end_byte], text);
                }
            }
        }
    }
    let b = grouped("arbitrary-paired-tool -- -source -destination");
    assert_eq!(values(&b, "sources"), ["-source"]);
    assert_eq!(values(&b, "destinations"), ["-destination"]);
    assert!(!b.operation_semantics_unresolved);
}

#[test]
fn incomplete_and_variable_width_groups_never_invent_later_roles() {
    for command in [
        "arbitrary-paired-tool in1 out1 orphan",
        "arbitrary-paired-tool in1 out1 ./cache/* out2",
        "arbitrary-paired-tool in1 out1 $UNKNOWN out2",
        "arbitrary-paired-tool in1 out1 --format ascii in2 out2",
        "arbitrary-paired-tool in1 out1 \"--format\" ascii in2 out2",
        "arbitrary-paired-tool in1 out1 \"$UNKNOWN\" out2",
    ] {
        let b = grouped(command);
        assert!(b.operation_semantics_unresolved, "{command}: {b:#?}");
        assert_eq!(values(&b, "destinations"), ["out1"]);
        assert!(!b.residuals.is_empty());
    }
    let b = grouped("arbitrary-paired-tool -- \"$UNKNOWN\" out1 in2 out2");
    assert!(
        !b.operation_semantics_unresolved,
        "quoted unknown is exactly one field: {b:#?}"
    );
    assert_eq!(values(&b, "destinations"), ["out1", "out2"]);
}

#[test]
fn group_declarations_are_validated_without_affecting_legacy_bindings() {
    for invalid in [
        GROUPED.replace("group_size: 2", "group_size: 0"),
        GROUPED.replace("group_size: 2", "group_size: 257"),
        GROUPED.replace("member: 1", "member: 2"),
        GROUPED.replace("cardinality: required_many", "cardinality: required_one"),
        GROUPED.replace(
            "option_scope: leading_options",
            "option_scope: all_arguments",
        ),
    ] {
        assert!(load_command_profile_from_str(&invalid).is_err());
    }
    let reversed=GROUPED.replace("member: 0","member: 1").replace("name: destinations, semantic: {kind: path, role: write}, binding: {kind: positional_groups, group_size: 2, member: 1}","name: destinations, semantic: {kind: path, role: write}, binding: {kind: positional_groups, group_size: 2, member: 0}");
    let p = load_command_profile_from_str(&reversed).unwrap();
    let parsed = parse_command("arbitrary-paired-tool in out", ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let s = select_invocation(&p, &projection).unwrap();
    let b = bind_invocation(&p, &projection, &s);
    assert_eq!(values(&b, "sources"), ["out"]);
    assert_eq!(values(&b, "destinations"), ["in"]);
    let nonopaque = GROUPED.replace("opaque_on_unresolved: true", "opaque_on_unresolved: false");
    let b = grouped_with_profile(&nonopaque, "arbitrary-paired-tool --format ascii in out");
    assert!(!b.operation_semantics_unresolved, "{b:#?}");
    assert_eq!(values(&b, "sources"), ["in"]);
    assert_eq!(values(&b, "destinations"), ["out"]);
    let b = grouped_with_profile(&nonopaque, "arbitrary-paired-tool in out orphan");
    assert!(b.operation_semantics_unresolved, "{b:#?}");
}

#[test]
fn dos2unix_information_and_multiple_pairs_bind_exact_roles() {
    for command in [
        "dos2unix -i cache/file",
        "dos2unix -idu cache/file",
        "dos2unix --info=b cache/file",
    ] {
        let r = resolve(command);
        assert_eq!(r.bound.form_id.as_str(), "inspect_files");
        assert!(!r.bound.operation_semantics_unresolved, "{r:#?}");
        assert!(
            r.bound
                .effects
                .iter()
                .all(|e| e.kind != EffectKind::WritePath)
        );
        assert_eq!(values(&r.bound, "input_files"), ["cache/file"]);
    }
    for command in ["dos2unix --help", "dos2unix -V", "dos2unix --license"] {
        assert!(resolve(command).bound.effects.is_empty());
    }
    let r = resolve("dos2unix -k -n cache/in1 cache/out1 cache/in2 /opt/shared/out2");
    assert!(!r.bound.operation_semantics_unresolved, "{r:#?}");
    assert_eq!(values(&r.bound, "input_file"), ["cache/in1", "cache/in2"]);
    assert_eq!(
        values(&r.bound, "output_file"),
        ["cache/out1", "/opt/shared/out2"]
    );
    let r = resolve("dos2unix -- --help");
    assert_eq!(r.bound.form_id.as_str(), "convert_in_place");
    assert_eq!(values(&r.bound, "literal_files"), ["--help"]);
}

#[test]
fn code_tunnel_queries_have_inspection_not_control_effects() {
    for command in [
        "code tunnel status",
        "code tunnel user show",
        "code tunnel service log",
    ] {
        let r = resolve(command);
        assert_eq!(r.bound.form_id.as_str(), "tunnel_inspect", "{command}");
        assert!(!r.bound.operation_semantics_unresolved, "{r:#?}");
    }
    for command in [
        "code tunnel --help",
        "code tunnel user --help",
        "code tunnel service install --help",
    ] {
        let r = resolve(command);
        assert_eq!(r.bound.form_id.as_str(), "tunnel_help");
        assert!(r.bound.effects.is_empty(), "{r:#?}");
    }
    let r = resolve("code tunnel --name=status");
    assert_eq!(r.bound.form_id.as_str(), "remote_tunnel");
}
