//! Exercise profile binding through the static guard. Shell text never executes.
use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_types::*;

fn check_with_core(core: &mut ShellQueryCore, command: &str, zip_defaults: bool) -> CheckResponse {
    let mut state = ShellStateSnapshot::new("/bench/workspace");
    if zip_defaults {
        state = state
            .with_environment_observation("ZIPINFO", ShellEnvironmentValue::Absent)
            .with_environment_observation("ZIPINFOOPT", ShellEnvironmentValue::Absent);
    }
    core.check(CheckRequest {
        command: command.into(),
        session_id: SessionId::new("find-native-file-profiles"),
        sequence_no: CommandSequenceNo(1),
        shell_state_before: state,
        shell_kind: ShellKind::Bash,
        workspace_root: Some("/bench/workspace".into()),
        home: Some("/home/test".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

fn check(command: &str, zip_defaults: bool) -> CheckResponse {
    check_with_core(&mut ShellQueryCore::new(), command, zip_defaults)
}

fn assert_file_effect(core: &ShellQueryCore, path: &str, expected: ResolvedPathRole) {
    let graph = core
        .session_graph(&SessionId::new("find-native-file-profiles"))
        .unwrap();
    assert!(
        graph.nodes().any(|node| matches!(&node.kind,
            NodeKind::PathFact { role, resolution, .. }
            if *role == expected && resolution.concrete_path() == Some(path)
        )),
        "{expected:?}: {path}"
    );
}

#[test]
fn pdfunite_binds_every_input_and_the_final_destination() {
    let mut core = ShellQueryCore::new();
    let result = check_with_core(
        &mut core,
        "pdfunite ./first.pdf ./second.pdf ./merged.pdf",
        false,
    );
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
    for input in ["/bench/workspace/first.pdf", "/bench/workspace/second.pdf"] {
        assert_file_effect(&core, input, ResolvedPathRole::Read);
    }
    assert_file_effect(
        &core,
        "/bench/workspace/merged.pdf",
        ResolvedPathRole::Write,
    );
    let outside = check("pdfunite ./first.pdf /opt/shared/merged.pdf", false);
    assert_eq!(
        outside.decision,
        Decision::NeedApproval,
        "{:?}",
        outside.reasons
    );
}

#[test]
fn pdfunite_diagnostic_has_no_output_write() {
    let diagnostic = check("pdfunite /opt/shared/merged.pdf", false);
    assert_eq!(
        diagnostic.decision,
        Decision::Allow,
        "{:?}",
        diagnostic.reasons
    );
    assert!(
        diagnostic
            .decision_trace
            .path_targets
            .iter()
            .all(|target| target.slot_name != "output_file")
    );
    for command in [
        "pdfunite -- ./input.pdf ./merged.pdf",
        "pdfunite - ./merged.pdf",
    ] {
        let result = check(command, false);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn zipinfo_uses_a_read_only_listing_persona_with_both_suffix_fallbacks() {
    let mut core = ShellQueryCore::new();
    let result = check_with_core(&mut core, "zipinfo -T ./report 'folder/*.txt'", true);
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
    for input in [
        "/bench/workspace/report",
        "/bench/workspace/report.zip",
        "/bench/workspace/report.ZIP",
    ] {
        assert_file_effect(&core, input, ResolvedPathRole::Read);
    }
    assert_ne!(
        check("unzip -T /opt/shared/report.zip", true).decision,
        Decision::Allow
    );
}

#[test]
fn zipinfo_keeps_unproved_archive_controls_in_approval() {
    for (command, zip_defaults) in [
        ("zipinfo ./report.zip", false),
        ("ZIPINFO=other.zip zipinfo ./report.zip", true),
        ("zipinfo 'reports/*.zip'", true),
        ("zipinfo -M ./report.zip", true),
        ("zipinfo ./report.zip > /opt/shared/listing.txt", true),
    ] {
        let result = check(command, zip_defaults);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn pdfgrep_searches_explicit_files_and_preserves_the_read_effect() {
    let mut core = ShellQueryCore::new();
    let result = check_with_core(&mut core, "pdfgrep -i keyword ./report.pdf", false);
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
    assert_file_effect(&core, "/bench/workspace/report.pdf", ResolvedPathRole::Read);

    let command = "find . -iname '*.pdf' -exec pdfgrep -i keyword {} +";
    let result = check(command, false);
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
}

#[test]
fn pdfgrep_unmodeled_file_selection_and_cache_stay_guarded() {
    for command in [
        "pdfgrep --cache keyword ./report.pdf",
        "pdfgrep -R keyword .",
        "pdfgrep -f patterns.txt ./report.pdf",
        "pdfgrep keyword",
        "pdfgrep keyword ./report.pdf > /opt/shared/report",
    ] {
        let result = check(command, false);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}: {:?}", result.reasons);
    }
}
