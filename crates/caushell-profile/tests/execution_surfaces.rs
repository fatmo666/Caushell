//! Profiles only: all commands are parsed as data and never executed.
use caushell_profile::*;
use caushell_types::{DatabaseOperationKind, ShellKind};
use std::sync::OnceLock;

fn resolved(command: &str, stdin: bool) -> ResolvedInvocationArtifact {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap());
    let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
    let mut context = InvocationRuntimeContext::new();
    if stdin {
        context = context.with_stdin_payload_available();
    }
    match resolve_invocation_artifact_with_bindings(
        registry,
        &parsed.commands[0],
        context,
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}

fn effect(r: &ResolvedInvocationArtifact, kind: EffectKind) -> bool {
    r.bound.effects.iter().any(|e| e.kind == kind)
}

#[test]
fn supported_interactive_entry_points_declare_their_escape_surface() {
    for command in [
        "psql",
        "psql -X",
        "links input.html",
        "links",
        "links -anonymous input.html",
        "alpine -F input.txt",
        "alpine",
        "alpine -r -o -F input.txt",
        "w3m input.html",
    ] {
        let r = resolved(command, false);
        assert!(
            !r.bound.operation_semantics_unresolved,
            "{command}: {:?}",
            r.bound.residuals
        );
        assert!(
            effect(&r, EffectKind::OpenInteractiveEscapeSurface),
            "{command}"
        );
    }
}

#[test]
fn psql_repeated_and_mixed_actions_remain_native_opaque_programs() {
    let r = resolved(
        r#"psql -X -c 'SELECT 1' --command='\! /bin/sh' -f local.sql --file=/opt/more.sql"#,
        false,
    );
    assert_eq!(r.bound.form_id.as_str(), "execute_actions");
    assert!(
        !r.bound.operation_semantics_unresolved,
        "{:?}",
        r.bound.residuals
    );
    let candidates = collect_recursive_payload_candidates(&r.bound);
    assert_eq!(candidates.len(), 2, "{candidates:?}");
    for candidate in &candidates {
        assert_eq!(candidate.language, PayloadLanguage::Opaque);
        assert!(
            matches!(&candidate.input, RecursivePayloadInput::ArgumentFragments {fragments} if fragments.len() == 2)
        );
    }
    assert!(
        candidates
            .iter()
            .any(|c| c.source == PayloadSource::InlineString)
    );
    assert!(
        candidates
            .iter()
            .any(|c| c.source == PayloadSource::ScriptFileRef)
    );
    assert!(
        r.bound
            .effects
            .iter()
            .any(|e| e.database_operation == Some(DatabaseOperationKind::Opaque))
    );
    assert!(!effect(&r, EffectKind::OpenInteractiveEscapeSurface));
    assert_eq!(
        r.proven_stream_contract().unwrap().stdin_mode,
        StreamInputMode::Ignored
    );
}

#[test]
fn psql_file_stdin_has_no_fabricated_dash_path() {
    let r = resolved("psql -X -f local.sql -f - -c 'SELECT 1'", false);
    assert_eq!(r.bound.form_id.as_str(), "execute_actions_with_stdin_file");
    assert!(
        !r.bound.operation_semantics_unresolved,
        "{:?}",
        r.bound.residuals
    );
    let candidates = collect_recursive_payload_candidates(&r.bound);
    assert!(candidates.iter().any(|c| c.source == PayloadSource::Stdin));
    let files = r
        .bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "file_operands")
        .unwrap();
    assert_eq!(files.values.len(), 2);
    let paths = r
        .bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "sql_file")
        .unwrap();
    assert_eq!(paths.values.len(), 1);
    assert!(effect(&r, EffectKind::ConsumeStdin));
    assert!(!effect(&r, EffectKind::OpenInteractiveEscapeSurface));
    let r = resolved("psql -X", true);
    assert_eq!(r.bound.form_id.as_str(), "execute_stdin");
    assert!(
        collect_recursive_payload_candidates(&r.bound)
            .iter()
            .any(|c| c.source == PayloadSource::Stdin)
    );
}

#[test]
fn psql_information_and_listing_do_not_execute_queued_actions() {
    for command in [
        r"psql --help -c '\! /bin/sh' -f /opt/input.sql",
        r"psql --version -c '\! /bin/sh'",
        r"psql --help=commands",
        r"psql -X -l -c '\! /bin/sh' -f /opt/input.sql",
    ] {
        let r = resolved(command, false);
        assert!(
            !r.bound.operation_semantics_unresolved,
            "{command}: {:?}",
            r.bound.residuals
        );
        assert!(
            collect_recursive_payload_candidates(&r.bound).is_empty(),
            "{command}"
        );
        assert!(!effect(&r, EffectKind::ReadPath), "{command}");
        assert!(!effect(&r, EffectKind::ExecutePayload), "{command}");
        assert!(
            !effect(&r, EffectKind::OpenInteractiveEscapeSurface),
            "{command}"
        );
    }
}

#[test]
fn output_programs_are_not_fabricated_filenames_or_suppressed_by_help() {
    for command in [
        "psql -o '|/bin/sh' -c 'SELECT 1'",
        "psql -o '|/bin/sh' --help",
    ] {
        let r = resolved(command, false);
        let candidates = collect_recursive_payload_candidates(&r.bound);
        assert!(candidates.iter().any(|c| matches!(&c.origin, RecursivePayloadOrigin::Parameter {slot} if slot.as_str() == "output_programs")), "{command}: {candidates:?}");
        assert!(
            !r.bound
                .bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "output_path" && !p.values.is_empty()),
            "{command}: {:?}",
            r.bound.bound_parameters
        );
    }
    let r = resolved(
        "psql -o local.out -o /opt/other.out -L /opt/log -c 'SELECT 1'",
        false,
    );
    let paths = r
        .bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "output_path")
        .unwrap();
    assert_eq!(paths.values.len(), 2);
    assert!(effect(&r, EffectKind::WritePath));
    let r = resolved("psql -o '' --version", false);
    assert!(collect_recursive_payload_candidates(&r.bound).is_empty());
    assert!(
        !r.bound
            .bound_parameters
            .iter()
            .any(|p| p.name.as_str() == "output_path" && !p.values.is_empty())
    );
}

#[test]
fn explicit_dump_modes_keep_reads_without_interactive_effects() {
    for command in [
        "links -dump input.html",
        "links -source input.html",
        "links -width 80 -dump input.html",
        "w3m -dump input.html",
    ] {
        let r = resolved(command, false);
        assert!(
            !r.bound.operation_semantics_unresolved,
            "{command}: {:?}",
            r.bound.residuals
        );
        assert!(effect(&r, EffectKind::ReadPath), "{command}");
        assert!(
            !effect(&r, EffectKind::OpenInteractiveEscapeSurface),
            "{command}"
        );
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_mode,
            StreamOutputMode::Data
        );
    }
}
