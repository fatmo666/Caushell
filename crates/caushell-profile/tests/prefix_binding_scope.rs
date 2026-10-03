use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: prefix-scope-tool}
forms:
  - id: run
    parameters:
      - name: tagged
        semantic: {kind: plain_value}
        binding: {kind: args_with_prefix, prefix: 'tag=' SCOPE}
        cardinality: optional_many
      - name: tail
        semantic: {kind: plain_value}
        binding: {kind: remaining_args}
        cardinality: optional_many
modifiers:
  - id: value
    matcher: {kind: any_flag, flags: [--value]}
    parameters:
      - name: value
        semantic: {kind: plain_value}
        binding: {kind: following_matched_flag, operand_mode: next_arg}
        cardinality: required_one
"#;

fn profile(scope: &str) -> CommandProfile {
    load_command_profile_from_str(&PROFILE.replace(" SCOPE", scope)).unwrap()
}

fn bound(profile: &CommandProfile, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(profile, &projection).unwrap();
    let bound = bind_invocation(profile, &projection, &selected);
    assert!(bound.residuals.is_empty(), "{command}: {bound:?}");
    bound
}

fn values<'a>(bound: &'a BoundInvocation, name: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("{other:?}"),
        })
        .collect()
}

#[test]
fn omission_and_explicit_false_preserve_legacy_prefix_binding() {
    for scope in ["", ", before_dash_dash: false"] {
        let profile = profile(scope);
        assert_eq!(
            profile.forms[0].parameters[0].binding,
            BindingSpec::ArgsWithPrefix("tag=".into())
        );
        let bound = bound(&profile, "prefix-scope-tool tag=first -- tag=last");
        assert_eq!(values(&bound, "tagged"), ["first", "last"]);
    }
}

#[test]
fn opt_in_preserves_pre_marker_values_and_leaves_post_marker_data_untouched() {
    let profile = profile(", before_dash_dash: true");
    assert_eq!(
        profile.forms[0].parameters[0].binding,
        BindingSpec::ArgsWithPrefixBeforeDashDash("tag=".into())
    );
    let bound = bound(
        &profile,
        "prefix-scope-tool tag=first tag=second -- tag=last",
    );
    assert_eq!(values(&bound, "tagged"), ["first", "second"]);
    assert_eq!(values(&bound, "tail"), ["--", "tag=last"]);
    let tagged = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "tagged")
        .unwrap();
    assert!(tagged.values.iter().all(|value| matches!(value,
        BoundValue::Argument { binding_source: ArgumentBindingSource::ArgumentPrefix { prefix }, .. } if prefix == "tag=")));
}

#[test]
fn no_marker_and_attached_dash_text_keep_normal_prefix_semantics() {
    let bound = bound(
        &profile(", before_dash_dash: true"),
        "prefix-scope-tool tag=-- tag=first tag=second tail",
    );
    assert_eq!(values(&bound, "tagged"), ["--", "first", "second"]);
    assert_eq!(values(&bound, "tail"), ["tail"]);
}

#[test]
fn literal_marker_used_as_an_option_operand_does_not_end_prefix_binding() {
    let bound = bound(
        &profile(", before_dash_dash: true"),
        "prefix-scope-tool --value -- tag=first -- tag=last",
    );
    assert_eq!(values(&bound, "value"), ["--"]);
    assert_eq!(values(&bound, "tagged"), ["first"]);
    assert_eq!(values(&bound, "tail"), ["--", "tag=last"]);
}

#[test]
fn leading_options_retains_marker_boundary_after_the_scanner_consumes_it() {
    let mut profile = profile(", before_dash_dash: true");
    profile.option_scope = OptionScopePolicy::LeadingOptions;
    let bound = bound(&profile, "prefix-scope-tool --value data -- tag=last");
    assert_eq!(values(&bound, "value"), ["data"]);
    assert!(values(&bound, "tagged").is_empty());
    assert_eq!(values(&bound, "tail"), ["tag=last"]);
}

#[test]
fn empty_prefix_remains_invalid_with_or_without_scope_declaration() {
    for scope in ["", ", before_dash_dash: false", ", before_dash_dash: true"] {
        let source = PROFILE
            .replace(" SCOPE", scope)
            .replace("prefix: 'tag='", "prefix: ''");
        assert!(load_command_profile_from_str(&source).is_err());
    }
}
