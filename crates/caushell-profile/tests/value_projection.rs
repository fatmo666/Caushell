use caushell_parse::{SourceSpan, parse_command};
use caushell_profile::{
    ArgumentBindingSource, BoundArgumentMaterialization, BoundInvocation, BoundParameter,
    BoundValue, CommandProfile, ImplicitInputSource, InvocationRuntimeContext, PathPurpose,
    PathRole, PathSemantic, ProfileRegistry, ProjectionAbsentPolicy, ProjectionUnknownReason,
    ResolveInvocationResult, SemanticType, SemanticValueRef, SemanticValueResolution,
    SessionBindings, SlotName, ValueProjection, bind_invocation, load_command_profile_from_str,
    project_invocation, refresh_parameter_semantic_values, resolve_invocation_with_bindings,
    select_invocation,
};
use caushell_types::{RuntimeProducedValueKind, ShellKind};

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: projection-tool}
forms:
  - id: run
    parameters:
      - name: cache
        semantic: {kind: path, role: write, purpose: generic_operand}
        binding: {kind: following_flag, flag: '--override', operand_mode: next_arg}
        cardinality: optional_many
        value_projection: {kind: key_value, separator: '=', key: cache_dir}
      - name: selectors
        semantic: {kind: path, role: read, purpose: generic_operand}
        binding: {kind: remaining_positionals}
        cardinality: optional_many
        value_projection: {kind: prefix_before, delimiter: '::', if_absent: original}
"#;

fn bind(profile: &CommandProfile, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(profile, &projection).unwrap();
    let result = bind_invocation(profile, &projection, &selection);
    assert!(
        result.residuals.is_empty(),
        "{command}: {:?}",
        result.residuals
    );
    result
}

fn bound(command: &str) -> BoundInvocation {
    bind(&load_command_profile_from_str(PROFILE).unwrap(), command)
}

fn parameter<'a>(bound: &'a BoundInvocation, name: &str) -> &'a BoundParameter {
    bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == name)
        .unwrap()
}

fn projected(parameter: &BoundParameter) -> Vec<(usize, SemanticValueResolution)> {
    parameter
        .semantic_values()
        .map(|value| match value {
            SemanticValueRef::Projected { source, value } => {
                assert!(std::ptr::eq(source, &parameter.values[value.source_index]));
                (value.source_index, value.resolution.clone())
            }
            other => panic!("expected projected value, got {other:?}"),
        })
        .collect()
}

fn known(value: &str) -> SemanticValueResolution {
    SemanticValueResolution::Known(value.to_string())
}

fn unknown(reason: ProjectionUnknownReason) -> SemanticValueResolution {
    SemanticValueResolution::Unknown(reason)
}

#[test]
fn declared_views_preserve_original_arguments_and_provenance() {
    let profile = load_command_profile_from_str(PROFILE).unwrap();
    let mut legacy = profile.clone();
    for parameter in &mut legacy.forms[0].parameters {
        parameter.value_projection = None;
    }
    let command =
        "projection-tool --override cache_dir=/etc/pytest-cache tests/test_api.py::test_login";
    let result = bind(&profile, command);
    let original = bind(&legacy, command);
    for name in ["cache", "selectors"] {
        assert_eq!(
            parameter(&result, name).values,
            parameter(&original, name).values
        );
        assert!(parameter(&original, name).projected_values.is_none());
        assert!(
            parameter(&original, name)
                .semantic_values()
                .all(|v| matches!(v, SemanticValueRef::Original(_)))
        );
    }
    assert_eq!(
        projected(parameter(&result, "cache")),
        [(0, known("/etc/pytest-cache"))]
    );
    assert_eq!(
        projected(parameter(&result, "selectors")),
        [(0, known("tests/test_api.py"))]
    );
}

#[test]
fn prefix_uses_first_delimiter_and_default_original_policy() {
    let profile =
        load_command_profile_from_str(&PROFILE.replace(", if_absent: original", "")).unwrap();
    assert_eq!(
        profile.forms[0].parameters[1].value_projection,
        Some(ValueProjection::PrefixBefore {
            delimiter: "::".into(),
            if_absent: ProjectionAbsentPolicy::Original,
        })
    );
    let result = bind(
        &profile,
        "projection-tool tests/test_api.py::Class::test_login README.md 测试/案例.py::方法",
    );
    assert_eq!(
        projected(parameter(&result, "selectors")),
        [
            (0, known("tests/test_api.py")),
            (1, known("README.md")),
            (2, known("测试/案例.py")),
        ]
    );
}

#[test]
fn strict_missing_delimiter_and_empty_prefix_are_explicitly_unknown() {
    let profile = load_command_profile_from_str(
        &PROFILE.replace("if_absent: original", "if_absent: unknown"),
    )
    .unwrap();
    let result = bind(&profile, "projection-tool README.md ::test_login");
    assert_eq!(
        projected(parameter(&result, "selectors")),
        [
            (0, unknown(ProjectionUnknownReason::MissingDelimiter)),
            (1, unknown(ProjectionUnknownReason::EmptyValue)),
        ]
    );
}

#[test]
fn keyed_projection_matches_whole_key_and_retains_extra_separators() {
    let result = bound(
        "projection-tool --override cache_dir=/tmp/cache=a --override console_output_style=classic --override cache_directory=/etc/other",
    );
    let parameter = parameter(&result, "cache");
    assert_eq!(parameter.values.len(), 3);
    assert_eq!(projected(parameter), [(0, known("/tmp/cache=a"))]);
    assert!(!parameter.semantic_values_are_inapplicable());
}

#[test]
fn proven_nonmatching_keys_are_inapplicable_not_unknown() {
    let result = bound(
        "projection-tool --override console_output_style=classic --override \"unrelated=$UNKNOWN\"",
    );
    let parameter = parameter(&result, "cache");
    assert_eq!(parameter.values.len(), 2);
    assert!(parameter.semantic_values_are_inapplicable());
    assert_eq!(parameter.projected_values, Some(vec![]));
    assert!(parameter.semantic_values().next().is_none());
}

#[test]
fn malformed_keyed_operands_do_not_disappear() {
    let result = bound(
        "projection-tool --override cache_dir --override cache_dir= --override $KEY=/etc/cache --override cache_dir=$ROOT/cache",
    );
    assert_eq!(
        projected(parameter(&result, "cache")),
        [
            (0, unknown(ProjectionUnknownReason::MissingDelimiter)),
            (1, unknown(ProjectionUnknownReason::EmptyValue)),
            (2, unknown(ProjectionUnknownReason::DynamicArgument)),
            (3, unknown(ProjectionUnknownReason::DynamicArgument)),
        ]
    );
}

#[test]
fn a_completed_prefix_delimiter_is_valid_despite_dynamic_selector_suffix() {
    let result =
        bound("projection-tool \"tests/test_api.py::$TEST\" $ROOT/test_api.py::test_login");
    assert_eq!(
        projected(parameter(&result, "selectors")),
        [
            (0, known("tests/test_api.py")),
            (1, unknown(ProjectionUnknownReason::DynamicArgument)),
        ]
    );
}

#[test]
fn shell_quoting_is_decoded_before_projection_without_execution() {
    for (argument, expected) in [
        ("'tests/test api.py::login'", "tests/test api.py"),
        ("\"tests/test api.py::login\"", "tests/test api.py"),
        ("tests/'test api.py'::login", "tests/test api.py"),
        ("tests/test\\ api.py\\:\\:login", "tests/test api.py"),
        ("'tests/$literal.py::login'", "tests/$literal.py"),
        ("\"tests/\\$literal.py::login\"", "tests/$literal.py"),
        ("'tests/`literal`.py::login'", "tests/`literal`.py"),
        ("'tests/*.py::login'", "tests/*.py"),
    ] {
        let result = bound(&format!("projection-tool {argument}"));
        assert_eq!(
            projected(parameter(&result, "selectors")),
            [(0, known(expected))],
            "{argument}"
        );
    }
    for (argument, expected) in [
        (
            "'cache_dir=/tmp/cache with spaces'",
            "/tmp/cache with spaces",
        ),
        ("cache_'dir'='/tmp/cache'", "/tmp/cache"),
        ("cache_dir\\=/tmp/cache", "/tmp/cache"),
        ("'cache_dir=/tmp/$literal'", "/tmp/$literal"),
        ("\"cache_dir=/tmp/\\$literal\"", "/tmp/$literal"),
        ("cache_dir=\"/tmp/quoted*\"", "/tmp/quoted*"),
    ] {
        let result = bound(&format!("projection-tool --override {argument}"));
        assert_eq!(
            projected(parameter(&result, "cache")),
            [(0, known(expected))],
            "{argument}"
        );
    }
}

#[test]
fn unresolved_unquoted_suffix_does_not_hide_possible_additional_argv_fields() {
    let result = bound("projection-tool tests/test.py::$SUFFIX --override unrelated=$VALUE");
    assert_eq!(
        projected(parameter(&result, "selectors")),
        [(0, unknown(ProjectionUnknownReason::DynamicArgument))]
    );
    assert_eq!(
        projected(parameter(&result, "cache")),
        [(0, unknown(ProjectionUnknownReason::DynamicArgument))]
    );
}

#[test]
fn globs_command_substitution_and_tilde_are_not_guessed() {
    for argument in ["*.py::login", "$(printf path)::login", "~/test.py::login"] {
        let result = bound(&format!("projection-tool {argument}"));
        assert_eq!(
            projected(parameter(&result, "selectors")),
            [(0, unknown(ProjectionUnknownReason::DynamicArgument))],
            "{argument}"
        );
    }
    for argument in [
        "cache_dir=~/cache",
        "cache_dir=$(printf /etc/cache)",
        "cache_dir=/tmp/*",
    ] {
        let result = bound(&format!("projection-tool --override {argument}"));
        assert_eq!(
            projected(parameter(&result, "cache")),
            [(0, unknown(ProjectionUnknownReason::DynamicArgument))],
            "{argument}"
        );
    }
}

fn resolve_with_bindings(command: &str, bindings: &SessionBindings) -> BoundInvocation {
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
        ResolveInvocationResult::Resolved(result) => result.bound,
        other => panic!("{command}: {other:?}"),
    }
}

#[test]
fn resolved_session_values_refresh_projection_and_keep_materialization_provenance() {
    let bindings = SessionBindings::new()
        .with_exact_scalar("OVERRIDE", "cache_dir=/tmp/$literal")
        .with_runtime_produced(
            "SELECTOR",
            "tests/$literal.py::login",
            RuntimeProducedValueKind::Scalar,
        );
    let result = resolve_with_bindings(
        "projection-tool --override \"$OVERRIDE\" \"$SELECTOR\"",
        &bindings,
    );
    assert_eq!(
        projected(parameter(&result, "cache")),
        [(0, known("/tmp/$literal"))]
    );
    assert_eq!(
        projected(parameter(&result, "selectors")),
        [(0, known("tests/$literal.py"))]
    );
    assert!(
        matches!(&parameter(&result, "cache").values[0], BoundValue::Argument {
        materialization: BoundArgumentMaterialization::ResolvedExactScalar { variable_name }, ..
    } if variable_name == "OVERRIDE")
    );
    assert!(
        matches!(&parameter(&result, "selectors").values[0], BoundValue::Argument {
        materialization: BoundArgumentMaterialization::ResolvedRuntimeProduced { variable_name }, ..
    } if variable_name == "SELECTOR")
    );
}

#[test]
fn a_resolved_nonmatching_key_is_skipped_but_unresolved_key_stays_unknown() {
    let bindings =
        SessionBindings::new().with_exact_scalar("OVERRIDE", "console_output_style=classic");
    let resolved = resolve_with_bindings("projection-tool --override \"$OVERRIDE\"", &bindings);
    assert!(parameter(&resolved, "cache").semantic_values_are_inapplicable());
    let unresolved = resolve_with_bindings("projection-tool --override \"$UNKNOWN\"", &bindings);
    assert_eq!(
        projected(parameter(&unresolved, "cache")),
        [(0, unknown(ProjectionUnknownReason::DynamicArgument))]
    );
}

fn manual_parameter(value: BoundValue) -> BoundParameter {
    let mut parameter = BoundParameter::new(
        SlotName::new("cache"),
        SemanticType::Path(PathSemantic {
            role: PathRole::Write,
            purpose: Some(PathPurpose::GenericOperand),
        }),
    );
    parameter.value_projection = Some(ValueProjection::KeyValue {
        separator: "=".into(),
        key: "cache_dir".into(),
    });
    parameter.with_value(value)
}

fn argument(text: &str) -> BoundValue {
    BoundValue::argument(
        text,
        false,
        SourceSpan {
            start_byte: 10,
            end_byte: 30,
            start_row: 0,
            start_column: 10,
            end_row: 0,
            end_column: 30,
        },
        ArgumentBindingSource::RemainingArg,
    )
}

#[test]
fn runtime_data_is_not_reinterpreted_as_shell_source() {
    let parameter = manual_parameter(
        argument("cache_dir=/tmp/$HOME*`cmd`")
            .with_materialization(BoundArgumentMaterialization::RuntimeData),
    );
    assert_eq!(projected(&parameter), [(0, known("/tmp/$HOME*`cmd`"))]);
}

#[test]
fn implicit_runtime_operand_has_unknown_substring_not_inherited_path_bounds() {
    let parameter = manual_parameter(BoundValue::implicit_input(ImplicitInputSource::StdinData));
    assert_eq!(
        projected(&parameter),
        [(0, unknown(ProjectionUnknownReason::DynamicArgument))]
    );
    assert!(!parameter.semantic_values_are_inapplicable());
}

#[test]
fn projection_does_not_inherit_a_runtime_domain_for_the_whole_operand() {
    let original = BoundValue::ImplicitInput {
        source: ImplicitInputSource::DispatchOutput,
        domain: Some(caushell_types::RuntimeArgumentDomain::PathSet {
            roots: vec!["/tmp/project".into()],
            may_escape: false,
        }),
    };
    let parameter = manual_parameter(original.clone());
    assert_eq!(parameter.values, [original]);
    assert_eq!(
        projected(&parameter),
        [(0, unknown(ProjectionUnknownReason::DynamicArgument))]
    );
}

#[test]
fn refresh_and_builder_keep_views_current_without_editing_raw_values() {
    let mut parameter = manual_parameter(argument("cache_dir=/tmp/one"));
    parameter = parameter.with_value(argument("cache_dir=/etc/two"));
    assert_eq!(
        projected(&parameter),
        [(0, known("/tmp/one")), (1, known("/etc/two"))]
    );
    parameter.values[0] = argument("unrelated=classic");
    refresh_parameter_semantic_values(&mut parameter);
    assert_eq!(projected(&parameter), [(1, known("/etc/two"))]);
    let originals = parameter.values.clone();
    parameter.value_projection = None;
    refresh_parameter_semantic_values(&mut parameter);
    assert_eq!(parameter.values, originals);
    assert!(parameter.projected_values.is_none());
    assert!(!parameter.semantic_values_are_inapplicable());
    assert_eq!(parameter.semantic_values().count(), 2);
}

fn declaration(semantic: &str, projection: &str) -> String {
    format!(
        "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: declaration-tool}}\nforms:\n  - id: run\n    parameters:\n      - name: value\n        semantic: {semantic}\n        binding: {{kind: next_positional}}\n        value_projection: {projection}\n"
    )
}

#[test]
fn invalid_projection_declarations_fail_loading() {
    let semantic = "{kind: path, role: read, purpose: generic_operand}";
    for projection in [
        "{kind: prefix_before, delimiter: ''}",
        "{kind: prefix_before, delimiter: '::', if_absent: allow}",
        "{kind: prefix_before, delimiter: '::', unexpected: true}",
        "{kind: key_value, separator: '', key: cache_dir}",
        "{kind: key_value, separator: '=', key: ''}",
        "{kind: key_value, separator: '=', key: 'cache=dir'}",
        "{kind: key_value, key: cache_dir}",
        "{kind: arbitrary_regex, pattern: '.*'}",
    ] {
        assert!(
            load_command_profile_from_str(&declaration(semantic, projection)).is_err(),
            "{projection}"
        );
    }
    for semantic in [
        "{kind: plain_value}",
        "{kind: path, role: cwd_anchor, purpose: working_directory}",
    ] {
        assert!(
            load_command_profile_from_str(&declaration(
                semantic,
                "{kind: prefix_before, delimiter: '::'}"
            ))
            .is_err(),
            "{semantic}"
        );
    }
}

#[test]
fn generic_multichar_separator_and_unicode_key_are_supported() {
    let mut parameter = manual_parameter(argument("缓存=>/tmp/路径=>suffix"));
    parameter.value_projection = Some(ValueProjection::KeyValue {
        separator: "=>".into(),
        key: "缓存".into(),
    });
    refresh_parameter_semantic_values(&mut parameter);
    assert_eq!(projected(&parameter), [(0, known("/tmp/路径=>suffix"))]);
}

#[test]
fn unknown_modifier_selection_keeps_resolved_path_projection() {
    let profile = load_command_profile_from_str(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: partial-tool}
forms:
  - id: run
    selector: {kind: no_positional_args}
modifiers:
  - id: override
    matcher: {kind: any_flag, flags: ['--override']}
    parameters:
      - name: cache
        semantic: {kind: path, role: write, purpose: generic_operand}
        binding: {kind: following_matched_flag, operand_mode: next_arg}
        value_projection: {kind: key_value, separator: '=', key: cache_dir}
"#,
    )
    .unwrap();
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    let bindings = SessionBindings::new().with_exact_scalar("VALUE", "cache_dir=/etc/cache");
    let parsed = parse_command(
        "partial-tool --override \"$VALUE\" unsupported",
        ShellKind::Bash,
    )
    .unwrap();
    match resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &bindings,
    ) {
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(partial),
            ..
        } => {
            assert_eq!(
                projected(parameter(&partial, "cache")),
                [(0, known("/etc/cache"))]
            );
        }
        other => panic!("expected partial selection error, got {other:?}"),
    }
}
