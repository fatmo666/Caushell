use caushell_parse::parse_command;
use caushell_profile::{
    ArgumentBindingSource, BoundInvocation, BoundValue, InvocationRuntimeContext, bind_invocation,
    load_command_profile_from_str, project_invocation, select_invocation,
};
use caushell_types::ShellKind;

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
option_scope: permuted_options
opaque_on_unresolved: true
identity: {canonical_name: fixture, aliases: []}
trust: {tier: tier_a, source: built_in}
platform: {os_families: [posix], shell_families: [], requires_features: []}
forms:
  - id: run
    parameters:
      - {name: form_input, semantic: {kind: plain_value}, binding: {kind: following_flag, flag: --input, operand_mode: next_arg}, cardinality: required_many}
      - {name: operands, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}
modifiers:
  - id: input
    matcher: {kind: any_flag, flags: [-i, --input]}
    parameters:
      - {name: modifier_input, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}
      - {name: modifier_copy, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}
  - id: alternate
    matcher: {kind: any_flag, flags: [-i, --input]}
    parameters:
      - {name: alternate_input, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}
  - {id: verbose, matcher: {kind: any_flag, flags: [-v]}}
"#;

fn bind(profile: &str, command: &str) -> BoundInvocation {
    let profile = load_command_profile_from_str(profile).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(&profile, &projection).unwrap();
    bind_invocation(&profile, &projection, &selection)
}

fn values<'a>(bound: &'a BoundInvocation, slot: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot)
        .flat_map(|parameter| &parameter.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("{other:?}"),
        })
        .collect()
}

fn assert_views(bound: &BoundInvocation, input: &[&str], operands: &[&str]) {
    assert!(bound.residuals.is_empty(), "{bound:?}");
    assert!(!bound.operation_semantics_unresolved, "{bound:?}");
    for slot in [
        "form_input",
        "modifier_input",
        "modifier_copy",
        "alternate_input",
    ] {
        assert_eq!(values(bound, slot), input, "{slot}: {bound:?}");
    }
    assert_eq!(values(bound, "operands"), operands, "{bound:?}");
    for parameter in &bound.bound_parameters {
        for value in &parameter.values {
            let BoundValue::Argument { binding_source, .. } = value else {
                panic!("{value:?}");
            };
            match parameter.name.as_str() {
                "form_input" => assert!(matches!(
                    binding_source,
                    ArgumentBindingSource::FollowingFlag { .. }
                )),
                "modifier_input" | "modifier_copy" => assert!(matches!(binding_source,
                    ArgumentBindingSource::MatchedModifierFlag { modifier_id, .. } if modifier_id.as_str() == "input")),
                "alternate_input" => assert!(matches!(binding_source,
                    ArgumentBindingSource::MatchedModifierFlag { modifier_id, .. } if modifier_id.as_str() == "alternate")),
                _ => {}
            }
        }
    }
}

#[test]
fn form_and_modifiers_project_the_same_owned_operand() {
    for command in [
        "fixture --input first output",
        "fixture --input=first output",
        "fixture output --input first",
        "fixture --input --opaque output",
    ] {
        let bound = bind(PROFILE, command);
        let input = if command.contains("--opaque") {
            "--opaque"
        } else {
            "first"
        };
        assert_views(&bound, &[input], &["output"]);
    }
}

#[test]
fn repeated_occurrences_keep_order_without_duplicate_values() {
    let bound = bind(
        PROFILE,
        "fixture --input first output --input=second --input third",
    );
    assert_views(&bound, &["first", "second", "third"], &["output"]);
}

#[test]
fn short_clusters_keep_the_owned_operand_and_each_binding_source() {
    let profile = PROFILE.replace("flag: --input", "flag: '-i'");
    for command in ["fixture -vifirst output", "fixture -vi first output"] {
        assert_views(&bind(&profile, command), &["first"], &["output"]);
    }
}

#[test]
fn each_view_keeps_its_own_constraints_and_operand_audit() {
    let profile = PROFILE.replace(
        "name: modifier_copy,",
        "name: modifier_copy, value_constraints: [{kind: exclude_literal, value: ignored}],",
    );
    let bound = bind(&profile, "fixture --input ignored --input kept output");
    assert!(bound.operation_semantics_unresolved, "{bound:?}");
    assert!(!bound.residuals.is_empty(), "{bound:?}");
    assert_eq!(values(&bound, "form_input"), ["ignored", "kept"]);
    assert_eq!(values(&bound, "modifier_input"), ["ignored", "kept"]);
    assert_eq!(values(&bound, "modifier_copy"), ["kept"]);
    assert_eq!(values(&bound, "alternate_input"), ["ignored", "kept"]);
    assert_eq!(values(&bound, "operands"), ["output"]);
}

#[test]
fn required_filtered_view_stays_unresolved() {
    let profile = PROFILE.replace(
        "name: modifier_copy,",
        "name: modifier_copy, value_constraints: [{kind: exclude_literal, value: ignored}],",
    );
    let bound = bind(&profile, "fixture --input ignored");
    assert_eq!(values(&bound, "form_input"), ["ignored"]);
    assert!(values(&bound, "modifier_copy").is_empty());
    assert!(bound.operation_semantics_unresolved);
    assert!(bound.residuals.iter().any(|residual| {
        residual
            .slot
            .as_ref()
            .is_some_and(|slot| slot.as_str() == "modifier_copy")
    }));
}

#[test]
fn shared_views_do_not_reinterpret_words_after_the_terminator() {
    let bound = bind(PROFILE, "fixture --input first -- --input second");
    assert_views(&bound, &["first"], &["--input", "second"]);
}

#[test]
fn root_and_child_views_keep_separate_option_scopes() {
    let profile = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: fixture}
option_scope: leading_options
modifiers:
  - id: root_input
    matcher: {kind: any_flag, flags: [--input]}
    parameters: [{name: root_input, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_one}]
subcommands:
  roots:
    - name: run
      option_scope: permuted_options
      modifiers:
        - id: child_input
          matcher: {kind: any_flag, flags: [--input]}
          parameters: [{name: child_input, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_one}]
      forms:
        - id: run
          parameters:
            - {name: form_input, semantic: {kind: plain_value}, binding: {kind: following_flag, flag: --input, operand_mode: next_arg}, cardinality: required_one}
            - {name: operands, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}
"#;
    let bound = bind(profile, "fixture --input root run --input child output");
    assert!(bound.residuals.is_empty(), "{bound:?}");
    assert_eq!(values(&bound, "root_input"), ["root"]);
    assert_eq!(values(&bound, "child_input"), ["child"]);
    assert_eq!(values(&bound, "form_input"), ["child"]);
    assert_eq!(values(&bound, "operands"), ["output"]);
}

#[test]
fn unknown_control_and_missing_operand_are_not_certified() {
    let profile = load_command_profile_from_str(PROFILE).unwrap();
    for command in ["fixture --unknown --input first", "fixture --input"] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        if let Ok(selection) = select_invocation(&profile, &projection) {
            let bound = bind_invocation(&profile, &projection, &selection);
            assert!(bound.operation_semantics_unresolved, "{command}: {bound:?}");
            assert!(!bound.residuals.is_empty(), "{command}: {bound:?}");
        }
    }
}

#[test]
fn curl_explicit_upload_keeps_both_endpoint_views() {
    let bound = bind(
        include_str!("../profiles/curl.yaml"),
        "curl -q --noproxy '*' --silent --show-error --fail --connect-timeout 2 --max-time 4 --request PATCH --data-binary @/bench/workspace/support/payload.txt --url http://127.0.0.1:18080/ingest/example",
    );
    assert_eq!(bound.form_id.as_str(), "upload_explicit_url");
    assert!(bound.residuals.is_empty(), "{bound:?}");
    assert!(!bound.operation_semantics_unresolved, "{bound:?}");
    for slot in ["upload_endpoints", "endpoint"] {
        assert_eq!(
            values(&bound, slot),
            ["http://127.0.0.1:18080/ingest/example"]
        );
    }
}
