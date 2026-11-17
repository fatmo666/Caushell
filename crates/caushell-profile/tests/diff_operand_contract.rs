use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn resolve(text: &str) -> ResolveInvocationArtifactResult {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(text, ShellKind::Bash).unwrap();
    resolve_invocation_artifact_with_bindings(REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0], InvocationRuntimeContext::new(), &SessionBindings::new())
}
fn resolved(text: &str) -> ResolvedInvocationArtifact {
    match resolve(text) { ResolveInvocationArtifactResult::Resolved(r) => {
        assert!(!r.bound.operation_semantics_unresolved, "{text}: {r:#?}"); r
    }, r => panic!("{text}: {r:#?}") }
}
fn values(r: &ResolvedInvocationArtifact, slot: &str) -> Vec<String> {
    r.bound.bound_parameters.iter().filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values).map(|v| match v {
            BoundValue::Argument {text, ..} => text.clone(), x => panic!("{x:#?}")
        }).collect()
}

#[test]
fn output_templates_are_owned_data_not_paths_options_or_code() {
    for flag in ["--line-format", "--old-line-format", "--new-line-format", "--unchanged-line-format",
                 "--old-group-format", "--new-group-format", "--changed-group-format", "--unchanged-group-format"] {
        for arg in [format!("{flag}=''"), format!("{flag} '--help'"), format!("{flag}='system(42):%L'")] {
            let r = resolved(&format!("diff {arg} left right"));
            assert_eq!(r.bound.form_id.as_str(), "compare_paths");
            assert_eq!(values(&r, "input_paths"), ["left", "right"]);
            assert_eq!(values(&r, "output_templates").len(), 1);
            assert!(!r.bound.effects.iter().any(|e| matches!(e.kind,
                EffectKind::ExecutePayload | EffectKind::DispatchCommand | EffectKind::WritePath | EffectKind::LoadConfig)));
        }
    }
    assert_eq!(values(&resolved("diff -dbU0 left right"), "context_lines"), ["0"]);
}

#[test]
fn exclusion_files_are_separate_content_inputs_and_dash_reads_stdin() {
    for text in ["diff -X patterns left right", "diff left right --exclude-from=patterns", "diff -Xpatterns left right"] {
        let r = resolved(text);
        assert_eq!(values(&r, "input_paths"), ["left", "right"]);
        assert_eq!(values(&r, "exclude_files"), ["patterns"]);
        assert!(r.bound.effects.iter().any(|e| e.kind == EffectKind::ReadPath
            && matches!(&e.target, EffectTarget::Slot(s) if s.as_str()=="exclude_files")
            && e.path_access == Some(PathAccessKind::ContentOpen)));
        assert_eq!(r.proven_stream_contract().unwrap().stdin_mode, StreamInputMode::Ignored);
    }
    let r = resolved("diff -X first -X second left right");
    assert_eq!(values(&r, "exclude_files"), ["first", "second"]);
    let r = resolved("diff -X --help left right");
    assert_eq!(r.bound.form_id.as_str(), "compare_paths");
    assert_eq!(values(&r, "exclude_files"), ["--help"]);
    for text in ["diff -X- left right", "diff --exclude-from=- left right"] {
        let r = resolved(text);
        assert_eq!(values(&r, "exclude_stdin"), ["-"]);
        assert!(values(&r, "exclude_files").is_empty());
        assert_eq!(r.proven_stream_contract().unwrap().stdin_mode, StreamInputMode::DataOptional);
    }
}

#[test]
fn missing_operands_unknown_modes_and_pagination_do_not_gain_authority() {
    for text in ["diff -X", "diff left right --line-format", "diff --unmodeled left right", "diff -l left right", "diff --paginate left right"] {
        let r = resolve(text);
        assert!(!matches!(r, ResolveInvocationArtifactResult::Resolved(ref r) if !r.bound.operation_semantics_unresolved), "{text}: {r:#?}");
    }
}
