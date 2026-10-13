//! Command-independent tests for explicitly declared attached-or-next operands.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: word-tool}
option_scope: leading_options
option_matching: exact_names
opaque_on_unresolved: true
forms:
  - id: run
    parameters: [{name: files, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}]
    stream_contract: {stdin_mode: ignored, stdout_mode: data, stderr_mode: opaque}
modifiers:
  - id: count
    matcher: {kind: any_flag, flags: [-c, -cols, -p]}
    parameters: [{name: count, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: word_attached_or_next_arg}, cardinality: required_many}]
  - {id: format, matcher: {kind: any_flag, flags: [-ps]}}
"#;

fn result(source: &str, command: &str) -> ResolveInvocationArtifactResult {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(source).unwrap()])
            .unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    )
}

fn resolved(command: &str) -> ResolvedInvocationArtifact {
    match result(PROFILE, command) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}

fn values<'a>(r: &'a ResolvedInvocationArtifact, name: &str) -> Vec<&'a str> {
    r.bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("{other:#?}"),
        })
        .collect()
}

#[test]
fn attached_and_following_values_share_the_explicit_option_owner() {
    for (command, counts, files) in [
        ("word-tool -c8 input", vec!["8"], vec!["input"]),
        ("word-tool -c 8 input", vec!["8"], vec!["input"]),
        ("word-tool -cols8 input", vec!["8"], vec!["input"]),
        ("word-tool -cols 8 input", vec!["8"], vec!["input"]),
        (
            "word-tool -c8 -cols 16 -p32 input",
            vec!["8", "16", "32"],
            vec!["input"],
        ),
        ("word-tool -c -ps input", vec!["-ps"], vec!["input"]),
        ("word-tool -c -- input", vec!["--"], vec!["input"]),
        ("word-tool -c '' input", vec![""], vec!["input"]),
    ] {
        let r = resolved(command);
        assert!(r.bound.residuals.is_empty(), "{command}: {r:#?}");
        assert_eq!(values(&r, "count"), counts, "{command}");
        assert_eq!(values(&r, "files"), files, "{command}");
    }
}

#[test]
fn exact_names_win_and_option_scope_keeps_the_native_data_tail() {
    let r = resolved("word-tool -ps -c8 input -c16");
    assert_eq!(values(&r, "count"), ["8"]);
    assert_eq!(values(&r, "files"), ["input", "-c16"]);
    assert!(
        r.bound
            .applied_modifiers
            .iter()
            .any(|m| m.as_str() == "format")
    );
    let r = resolved("word-tool -- -c8");
    assert!(values(&r, "count").is_empty());
    assert_eq!(values(&r, "files"), ["-c8"]);
    let permuted = PROFILE.replace("leading_options", "permuted_options");
    match result(&permuted, "word-tool input -c8 -- -c16") {
        ResolveInvocationArtifactResult::Resolved(r) => {
            assert_eq!(values(&r, "count"), ["8"]);
            assert_eq!(values(&r, "files"), ["input", "-c16"]);
        }
        other => panic!("{other:#?}"),
    }
}

#[test]
fn missing_or_uncertain_operands_never_prove_a_stream_contract() {
    for command in ["word-tool -c", "word-tool -cols"] {
        assert!(
            matches!(
                result(PROFILE, command),
                ResolveInvocationArtifactResult::SelectionError { .. }
            ),
            "{command}"
        );
    }
    for command in [
        "word-tool -c\"$unknown\" input",
        "word-tool -c \"$unknown\" input",
        "word-tool -c $unknown input",
    ] {
        match result(PROFILE, command) {
            ResolveInvocationArtifactResult::Resolved(r) => {
                assert!(r.proven_stream_contract().is_none(), "{command}: {r:#?}")
            }
            ResolveInvocationArtifactResult::SelectionError { .. } => {}
            other => panic!("{command}: {other:#?}"),
        }
    }
}

#[test]
fn older_operand_modes_and_invalid_grammars_are_not_reinterpreted() {
    let legacy = PROFILE.replace("word_attached_or_next_arg", "next_arg");
    assert!(matches!(
        result(&legacy, "word-tool -c8 input"),
        ResolveInvocationArtifactResult::SelectionError { .. }
    ));
    let attached = PROFILE.replace("word_attached_or_next_arg", "word_attached");
    match result(&attached, "word-tool -c 8 input") {
        ResolveInvocationArtifactResult::Resolved(r) => {
            assert!(r.proven_stream_contract().is_none())
        }
        ResolveInvocationArtifactResult::SelectionError { .. } => {}
        other => panic!("{other:#?}"),
    }
    for invalid in [
        PROFILE.replace("leading_options", "all_arguments"),
        PROFILE.replace("exact_names", "short_clusters"),
        PROFILE.replace("flags: [-c, -cols, -p]", "flags: [--count]"),
    ] {
        assert!(load_command_profile_from_str(&invalid).is_err());
    }
}
