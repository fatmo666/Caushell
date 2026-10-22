use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const SOURCE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary_formatter}
forms:
  - id: formatted
    parameters:
      - name: roots
        semantic: {kind: path, role: read}
        binding: {kind: remaining_positionals}
        cardinality: optional_many
    stream_contract: {stdin_mode: ignored, stdout_mode: data, stderr_mode: opaque}
    stdout_records:
      projection: {kind: formatted_paths, roots_slot: roots, default_root: '.', formats_slot: formats, syntax: find_printf}
      required_modifiers: [format]
      excluded_modifiers: [other_output]
modifiers:
  - id: format
    matcher: {kind: any_flag, flags: ['--format']}
    parameters:
      - name: formats
        semantic: {kind: structured_value, context: format_string}
        binding: {kind: following_matched_flag, operand_mode: next_arg}
        cardinality: required_many
  - id: other_output
    matcher: {kind: any_flag, flags: ['--other']}
"#;

fn proof(source: &str, args: &str, roots: &[&str]) -> Option<Vec<String>> {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(source).unwrap()])
            .unwrap();
    let parsed = parse_command(&format!("arbitrary_formatter {args}"), ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(resolved) =
        resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &SessionBindings::new(),
        )
    else {
        panic!("{args}")
    };
    resolved.formatted_stdout_path_roots(&roots.iter().map(|r| r.to_string()).collect::<Vec<_>>())
}

#[test]
fn declared_grammar_projects_native_records_without_command_name_checks() {
    assert_eq!(
        proof(
            SOURCE,
            r#"--format '%p\0' olddir"#,
            &["olddir", "/opt/input"]
        ),
        Some(vec!["olddir".into(), "/opt/input".into()])
    );
    assert_eq!(
        proof(SOURCE, r#"--format 'newdir/%P\0' olddir"#, &["/opt/input"]),
        Some(vec!["newdir/".into()])
    );
    assert_eq!(
        proof(
            SOURCE,
            r#"--format '%p\0' --format 'newdir/%P\0' olddir"#,
            &["olddir"]
        ),
        Some(vec!["olddir".into(), "newdir/".into()])
    );
    // Concatenate bytes, never Path::join (which would discard the prefix).
    assert_eq!(
        proof(
            SOURCE,
            r#"--format 'newdir/%p\0' /opt/input"#,
            &["/opt/input"]
        ),
        Some(vec!["newdir//opt/input".into()])
    );
    assert_eq!(
        proof(SOURCE, r#"--format '%p\0' olddir"#, &["./a/../b/"]),
        Some(vec!["./a/../b/".into()])
    );
}

#[test]
fn all_actions_must_prove_complete_records_and_the_contract_must_apply() {
    for args in [
        r#"--format "$FORMAT" olddir"#,
        r#"--format '%p\0' --format '%p' olddir"#,
        r#"--format '%p' --format '\0' olddir"#,
        r#"--format '%p\0' --other olddir"#,
        r#"--format '%p\0' "$ROOT""#,
        "olddir",
    ] {
        assert_eq!(proof(SOURCE, args, &["olddir"]), None, "{args}");
    }
    assert_eq!(proof(SOURCE, r#"--format '%p\0' olddir"#, &[]), None);
    assert_eq!(proof(SOURCE, r#"--format '%p\0' olddir"#, &[""]), None);
    assert_eq!(
        proof(SOURCE, r#"--format '%p\0' olddir"#, &vec!["x"; 65]),
        None
    );
    let many = format!("--format '{}%p\\0' olddir", "a/".repeat(2048));
    assert_eq!(proof(SOURCE, &many, &["olddir"]), None);
}

#[test]
fn loader_validates_format_slots_streams_and_modifier_references() {
    for invalid in [
        SOURCE.replace("roots_slot: roots", "roots_slot: typo"),
        SOURCE.replace("formats_slot: formats", "formats_slot: typo"),
        SOURCE.replace("context: format_string", "context: free_text"),
        SOURCE.replace("stdout_mode: data", "stdout_mode: opaque"),
        SOURCE.replace("syntax: find_printf", "syntax: unknown"),
        SOURCE.replace("required_modifiers: [format]", "required_modifiers: [typo]"),
        SOURCE.replace("default_root: '.'", "default_root: ''"),
    ] {
        assert!(
            load_command_profile_from_str(&invalid).is_err(),
            "{invalid}"
        );
    }
}
