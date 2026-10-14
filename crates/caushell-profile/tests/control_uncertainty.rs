use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn profile(readonly: bool) -> CommandProfile {
    load_command_profile_from_str(&format!(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: synthetic-query}}
option_scope: permuted_options
opaque_on_unresolved: true
read_only_control_surface: {readonly}
forms:
  - id: query
    parameters:
      - {{name: paths, semantic: {{kind: path, role: read, purpose: generic_operand}}, binding: {{kind: remaining_positionals}}, cardinality: optional_many}}
    effects: [{{kind: read_path, target: {{kind: slot, name: paths}}}}]
    stream_contract: {{stdin_mode: ignored, stdout_mode: data, stderr_mode: opaque}}
modifiers: [{{id: quiet, matcher: {{kind: any_flag, flags: [-q]}}}}]
"#)).unwrap()
}

#[test]
fn declaration_separates_control_ownership_from_operation_risk_without_erasing_residuals() {
    for command in ["synthetic-query \"$UNKNOWN\"", "synthetic-query *"] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        for readonly in [false, true] {
            let p = profile(readonly);
            let selection = select_invocation(&p, &projected).unwrap();
            let bound = bind_invocation(&p, &projected, &selection);
            assert!(
                bound
                    .residuals
                    .iter()
                    .any(|r| r.kind == ResidualKind::UnboundControlSurface)
            );
            assert_eq!(bound.operation_semantics_unresolved, !readonly);
            let materialized_projection =
                materialize_projected_invocation(&projected, &SessionBindings::new());
            let artifact = ResolvedInvocationArtifact {
                normalized_command_name: "synthetic-query".into(),
                projection: projected.clone(),
                materialized_projection,
                bound,
            };
            assert!(artifact.proven_stream_contract().is_none());
        }
    }
}

#[test]
fn read_only_declaration_rejects_risky_or_opaque_profiles() {
    let query = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: synthetic}
read_only_control_surface: true
forms: [{id: query, effects: [{kind: read_path, target: {kind: none}}]}]
"#;
    for kind in [
        "write_path",
        "delete_path",
        "execute_payload",
        "load_config",
        "dispatch_command",
        "privilege_modifier",
    ] {
        assert!(
            load_command_profile_from_str(
                &query.replace("kind: read_path", &format!("kind: {kind}"))
            )
            .is_err(),
            "{kind}"
        );
    }
    assert!(
        load_command_profile_from_str(&query.replace(
            "id: query",
            "id: query, operation_semantics_unresolved: true"
        ))
        .is_err()
    );
    assert!(
        load_command_profile_from_str(&format!(
            "{query}\nselection_failure_effects: [{{kind: read_path, target: {{kind: none}}}}]"
        ))
        .is_err()
    );
}

#[test]
fn bounded_native_batch_is_not_an_unknown_option_just_because_its_width_varies() {
    let mut p = profile(false);
    p.option_scope = OptionScopePolicy::LeadingOptions;
    let parsed = parse_command("synthetic-query paths", ShellKind::Bash).unwrap();
    let mut projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let arg = &mut projected.args[0];
    arg.node_kind = "runtime_argument_list".into();
    arg.text.clear();
    arg.implicit_input_source = Some(caushell_types::ImplicitInputSource::StdinData);
    arg.runtime_argument_domain = Some(caushell_types::RuntimeArgumentDomain::PathSet {
        roots: vec!["htdocs".into(), "cgi-bin".into()],
        may_escape: false,
    });
    assert!(!argument_structure(arg).may_start_with("-"));
    let selection = select_invocation(&p, &projected).unwrap();
    assert!(selection.residuals.is_empty());
    // If the batch disappears, a later -q may become a control; do not certify
    // identical ownership when at least one native item would end options.
    let next = parse_command("synthetic-query -q", ShellKind::Bash).unwrap();
    projected
        .args
        .extend(project_invocation(&next.commands[0], InvocationRuntimeContext::new()).args);
    let selection = select_invocation(&p, &projected).unwrap();
    assert!(
        selection
            .residuals
            .iter()
            .any(|r| r.kind == ResidualKind::UnboundControlSurface)
    );
}

#[test]
fn concatenated_static_and_quoted_scalar_words_keep_exact_field_proofs() {
    assert_eq!(
        caushell_parse::decode_static_shell_argument("{}", false, "concatenation").as_deref(),
        Some("{}")
    );
    assert!(
        caushell_parse::decode_static_shell_argument("{left,right}", false, "concatenation")
            .is_none()
    );
    for (text, exact) in [
        (r"-t$'\t'", true),
        (r#"hostname="$(hostname)""#, false),
        (r#"-d"$(date --date="@$old_time")""#, false),
        (r#"prefix"$(printf '%s' "$@")""#, false),
    ] {
        let structure = shell_word_structure(text, false, "concatenation");
        assert_eq!(
            structure.fields,
            ArgumentFieldCount::ExactlyOne,
            "{text}: {structure:?}"
        );
        assert_eq!(structure.exact, exact, "{text}");
    }
    let tab = shell_word_structure(r"-t$'\t'", false, "concatenation");
    assert_eq!(tab.exact_value(), Some("-t\t"));
    for text in [
        r#"prefix"$@""#,
        r#"prefix"${items[@]}""#,
        r#"prefix"$(hostname)"$MORE"#,
        r#"prefix"$(hostname)"*"#,
    ] {
        assert_ne!(
            shell_word_structure(text, false, "concatenation").fields,
            ArgumentFieldCount::ExactlyOne,
            "{text}"
        );
    }
    for text in [r"-t$'\c@'", r"-t$'\x00'", r"-t$'\777'"] {
        assert!(
            caushell_parse::decode_static_shell_argument(text, false, "concatenation").is_none(),
            "{text}"
        );
    }
}

#[test]
fn supplied_home_proves_only_tilde_field_spelling_not_values_or_containment() {
    let mut bindings = SessionBindings::new();
    bindings.insert_inherited_exact_scalar("HOME", "/home/a user/[literal]");
    for (command, fields) in [
        ("synthetic-query ~/files/*", ArgumentFieldCount::ZeroOrMore),
        ("synthetic-query ~/files", ArgumentFieldCount::ExactlyOne),
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        let materialized = materialize_projected_invocation(&projected, &bindings);
        assert_eq!(materialized.invocation.args[0].text, projected.args[0].text);
        let shape = argument_structure(&materialized.invocation.args[0]);
        assert_eq!(shape.fields, fields);
        assert!(!shape.may_start_with("-"));
        assert!(!shape.exact);
        let mut exact = materialized.invocation.args[0].clone();
        exact.text = "/home/a user/[literal]/known".into();
        exact.runtime_data = true;
        assert_eq!(
            argument_structure(&exact).exact_value(),
            Some(exact.text.as_str())
        );
    }
    for command in [
        "synthetic-query ~/$UNKNOWN",
        r"synthetic-query \~/files",
        r"synthetic-query '~/files'",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        assert!(
            materialize_projected_invocation(&projected, &bindings)
                .invocation
                .args[0]
                .lexical_field_prefix
                .is_none()
        );
    }
}
