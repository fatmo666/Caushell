//! Analysis proof scope, completeness and native option binding are independent.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
fn resolve(
    text: &str,
    fields: Vec<Vec<String>>,
    invalid: Option<&str>,
) -> ResolveInvocationArtifactResult {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(text, ShellKind::Bash).unwrap();
    let command = &parsed.commands[0];
    let mut proofs = command
        .tokens
        .iter()
        .filter(|t| !t.command_substitutions.is_empty())
        .zip(fields)
        .map(|(t, fields)| ArgumentFieldsProof {
            span: t.span.clone(),
            source_word: t.text.clone(),
            fields,
        })
        .collect::<Vec<_>>();
    if let Some(proof) = proofs.first_mut() {
        match invalid {
            Some("span") => proof.span.start_byte += 1,
            Some("source") => proof.source_word.push('x'),
            Some("nul") => proof.fields = vec!["a\0b".into()],
            Some("budget") => proof.fields = vec!["x".repeat(262145)],
            _ => (),
        }
    }
    if invalid == Some("duplicate") {
        proofs.push(proofs[0].clone());
    }
    resolve_invocation_artifact_with_argument_proofs(
        &registry,
        command,
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
        &[],
        &proofs,
    )
}
fn resolved(result: ResolveInvocationArtifactResult) -> ResolvedInvocationArtifact {
    match result {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{other:?}"),
    }
}
#[test]
fn a_complete_source_word_binds_the_original_invocation() {
    let r = resolved(resolve(
        r#"touch "$(printf safe)""#,
        vec![vec!["safe".into()]],
        None,
    ));
    assert!(
        !r.bound.operation_semantics_unresolved,
        "{:?}",
        r.bound.residuals
    );
    assert!(r.projection.args[0].text.contains("$(printf"));
    assert_eq!(r.materialized_projection.invocation.args[0].text, "safe");
    assert!(r.materialized_projection.invocation.args[0].runtime_data);
}
#[test]
fn mismatched_duplicate_or_overbudget_proofs_cannot_close_the_gap() {
    for invalid in ["span", "source", "duplicate", "nul", "budget"] {
        let r = resolved(resolve(
            r#"touch "$(printf safe)""#,
            vec![vec!["safe".into()]],
            Some(invalid),
        ));
        assert!(r.bound.operation_semantics_unresolved, "{invalid}");
    }
}
#[test]
fn empty_and_multiple_fields_are_native_argv_not_a_shell_string() {
    let r = resolved(resolve(
        r#"touch $(printf '') "$(printf literal)""#,
        vec![vec![], vec!["$target;*".into()]],
        None,
    ));
    assert_eq!(r.materialized_projection.invocation.args.len(), 1);
    assert_eq!(
        r.materialized_projection.invocation.args[0].text,
        "$target;*"
    );
    assert!(!r.bound.operation_semantics_unresolved);
}
#[test]
fn fields_are_reclassified_before_native_option_and_terminator_selection() {
    let r = resolved(resolve(
        r#"rm "$(printf flags)" /"#,
        vec![vec!["-rf".into()]],
        None,
    ));
    assert!(!r.bound.operation_semantics_unresolved);
    assert!(
        r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DeletePath)
    );
    assert_eq!(
        r.materialized_projection.invocation.args[0].kind,
        ProjectedArgKind::Flag
    );
    let r = resolved(resolve(
        r#"touch "$(printf delimiter)" -rf"#,
        vec![vec!["--".into()]],
        None,
    ));
    assert_eq!(
        r.materialized_projection.invocation.args[0].kind,
        ProjectedArgKind::DashDash
    );
    assert_eq!(
        r.materialized_projection.invocation.args[1].kind,
        ProjectedArgKind::Positional
    );
}
#[test]
fn other_unknown_fields_and_configuration_keep_their_own_uncertainty() {
    for text in [
        r#"touch "$(printf safe)" "$other""#,
        r#"tar -cf "$(printf archive.tar)" file"#,
    ] {
        let r = resolved(resolve(text, vec![vec!["safe".into()]], None));
        assert!(r.bound.operation_semantics_unresolved, "{text}");
    }
}
