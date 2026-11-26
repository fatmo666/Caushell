//! Check native Zip form selection and effects without running the arguments.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn resolve(command: &str) -> ResolveInvocationArtifactResult {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation_artifact_with_bindings(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    )
}

fn complete(command: &str, form: &str) -> BoundInvocation {
    let ResolveInvocationArtifactResult::Resolved(resolved) = resolve(command) else {
        panic!("did not resolve {command}");
    };
    let bound = resolved.bound;
    assert_eq!(bound.form_id.as_str(), form, "{command}");
    assert!(
        !bound.operation_semantics_unresolved,
        "{command}: {bound:#?}"
    );
    assert!(bound.residuals.is_empty(), "{command}: {bound:#?}");
    bound
}

fn values<'a>(bound: &'a BoundInvocation, slot: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot)
        .flat_map(|parameter| &parameter.values)
        .filter_map(|value| match value {
            BoundValue::Argument { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

fn has_effect(bound: &BoundInvocation, kind: EffectKind) -> bool {
    bound.effects.iter().any(|effect| effect.kind == kind)
}

#[test]
fn native_pattern_lists_keep_their_values_out_of_archive_operands() {
    for (command, patterns, sources) in [
        (
            "zip -x '*.tmp' '*.log' -q notes.zip a b",
            vec!["*.tmp", "*.log"],
            vec!["a", "b"],
        ),
        ("zip -x'*.tmp' notes.zip a b", vec!["*.tmp"], vec!["a", "b"]),
        (
            "zip --exclude '*.tmp' '*.log' @ notes.zip a b",
            vec!["*.tmp", "*.log"],
            vec!["a", "b"],
        ),
        ("zip -x -v @ notes.zip a b", vec!["-v"], vec!["a", "b"]),
        (
            "zip notes.zip a b -x '*.tmp' '*.log'",
            vec!["*.tmp", "*.log"],
            vec!["a", "b"],
        ),
        (
            "zip notes.zip a --include='*.txt' b",
            vec!["*.txt"],
            vec!["a", "b"],
        ),
    ] {
        let bound = complete(command, "add_files_to_archive");
        assert_eq!(
            values(&bound, "member_selection_patterns"),
            patterns,
            "{command}"
        );
        assert_eq!(values(&bound, "input_paths"), sources, "{command}");
    }
}

#[test]
fn drop_members_edits_archive_contents_and_move_deletes_host_sources() {
    for command in ["zip -d notes.zip '*.tmp'", "zip --delete notes.zip -- -v"] {
        let bound = complete(command, "delete_archive_members");
        assert_eq!(values(&bound, "archive_path"), ["notes.zip"]);
        assert!(has_effect(&bound, EffectKind::WritePath));
        assert!(!has_effect(&bound, EffectKind::DeletePath));
        assert!(values(&bound, "input_paths").is_empty());
    }

    let bound = complete("zip -dv notes.zip a", "add_files_to_archive");
    assert_eq!(values(&bound, "input_paths"), ["a"]);
    let bound = complete("zip -m notes.zip a", "add_files_to_archive");
    assert!(has_effect(&bound, EffectKind::DeletePath));
}

#[test]
fn standalone_test_reads_but_test_after_a_write_still_writes() {
    for (command, form) in [
        ("zip -Tv ./notes.zip", "test_archive"),
        ("zip --test notes", "test_archive_implicit_extension"),
        ("zip -Tv .notes", "test_archive"),
        ("zip -Tv notes.", "test_archive"),
    ] {
        let bound = complete(command, form);
        assert!(has_effect(&bound, EffectKind::ReadPath));
        assert!(!has_effect(&bound, EffectKind::WritePath));
    }
    for command in [
        "zip -Tv notes.zip a",
        "zip -Tu notes.zip",
        "zip -Tf notes.zip",
        "zip -T -@ notes.zip",
    ] {
        let bound = complete(command, "add_files_to_archive");
        assert!(has_effect(&bound, EffectKind::WritePath), "{command}");
    }
    let bound = complete("zip -T -TT true notes.zip", "test_archive");
    assert!(has_effect(&bound, EffectKind::ExecutePayload));
    let bound = complete("zip -TT true notes.zip a", "add_files_to_archive");
    assert!(!has_effect(&bound, EffectKind::ExecutePayload));
}

#[test]
fn dashdash_only_ends_parsing_after_the_archive() {
    for command in ["zip -Tv -- notes.zip", "zip -u -- notes.zip a"] {
        let bound = complete(command, "missing_archive_before_dashdash");
        assert!(bound.effects.is_empty(), "{command}");
    }
    let bound = complete("zip notes.zip -- -v", "add_files_to_archive");
    assert_eq!(values(&bound, "input_paths"), ["-v"]);
    assert!(
        !bound
            .applied_modifiers
            .iter()
            .any(|m| m.as_str() == "diagnostics")
    );
}

#[test]
fn unmodeled_write_controls_do_not_form_a_complete_test_only_operation() {
    for command in [
        "zip -T notes.zip -O new.zip",
        "zip -T notes.zip -lf log.txt",
        "zip -mf notes.zip",
        "zip -m -- notes.zip a",
        "zip -m -@ notes.zip a",
    ] {
        if let ResolveInvocationArtifactResult::Resolved(resolved) = resolve(command) {
            assert!(resolved.bound.operation_semantics_unresolved, "{command}");
        }
    }
}
