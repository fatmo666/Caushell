//! Exercise profile binding through the static guard. Shell text never executes.
use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_profile::{
    BoundArgumentMaterialization, BoundInvocation, BoundValue, EffectKind, EffectTarget,
    InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult, SessionBindings,
    resolve_invocation_artifact_with_bindings,
};
use caushell_types::*;

fn request(command: &str, zip_defaults: bool) -> CheckRequest {
    let mut state = ShellStateSnapshot::new("/bench/workspace");
    if zip_defaults {
        state = state
            .with_environment_observation("ZIPINFO", ShellEnvironmentValue::Absent)
            .with_environment_observation("ZIPINFOOPT", ShellEnvironmentValue::Absent);
    }
    CheckRequest {
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
    }
}

fn check_with_core(core: &mut ShellQueryCore, command: &str, zip_defaults: bool) -> CheckResponse {
    core.check(request(command, zip_defaults))
}

fn check_info_zip(core: &mut ShellQueryCore, command: &str, zip_defaults: bool) -> CheckResponse {
    core.try_judge_static_shell_with_native_variants(
        request(command, zip_defaults),
        &[("zipinfo".into(), "info_zip_3_0_debian".into())].into(),
    ).unwrap()
}

fn bind_info_zip(command: &str) -> BoundInvocation {
    let mut summary = SessionSummary::default();
    summary.set_protected_native_variants(
        [("zipinfo".into(), "info_zip_3_0_debian".into())].into(),
    );
    let request = request(command, true);
    let bindings = SessionBindings::from_summary_and_shell_state(&summary, &request.shell_state_before);
    let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
    let resolved = resolve_invocation_artifact_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
        &bindings,
    );
    let ResolveInvocationArtifactResult::Resolved(resolved) = resolved else {
        panic!("{resolved:?}");
    };
    resolved.bound
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
    let command = "zipinfo -T ./report 'folder/*.txt'";
    let result = check_info_zip(&mut core, command, true);
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
    let bound = bind_info_zip(command);
    assert_eq!(bound.form_id.as_str(), "list_members");
    let reads: Vec<_> = bound.effects.iter()
        .filter(|effect| effect.kind == EffectKind::ReadPath)
        .map(|effect| &effect.target)
        .collect();
    assert!(matches!(reads.as_slice(), [
        EffectTarget::Slot(slot), EffectTarget::DerivedPath(lower), EffectTarget::DerivedPath(upper),
    ] if slot.as_str() == "archive_file"
        && matches!(&lower.rule, DerivedPathRule::AppendSuffix { suffix } if suffix == ".zip")
        && matches!(&upper.rule, DerivedPathRule::AppendSuffix { suffix } if suffix == ".ZIP")));
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
fn zipinfo_only_closes_listing_effects_for_protected_lookup() {
    let command = "find . -name '*.jar' -exec zipinfo {} \\;";
    let result = check_info_zip(&mut ShellQueryCore::new(), command, false);
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
    let result = check(command, false);
    assert_eq!(result.decision, Decision::NeedApproval, "{:?}", result.reasons);
    for command in [
        "find . -name '*.jar' -exec zipinfo {} \\; > /opt/shared/listing",
        "PATH=./bin:$PATH find . -name '*.jar' -exec zipinfo {} \\;",
        "find . -name '*.jar' | PATH=./bin:$PATH xargs zipinfo",
    ] {
        let result = check_info_zip(&mut ShellQueryCore::new(), command, false);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}: {:?}", result.reasons);
    }
}

#[test]
fn zipinfo_keeps_an_unexpanded_archive_read_symbolic() {
    let bound = bind_info_zip(r#"zipinfo "$archive""#);
    assert_eq!(bound.native_argv_effect_envelope, Some(NativeArgvEffectEnvelope::ContentRead));
    assert!(bound.bound_parameters.iter().any(|parameter| {
        parameter.name.as_str() == "possible_archive_inputs"
            && matches!(&parameter.values[..], [BoundValue::Argument {
                materialization: BoundArgumentMaterialization::Literal, ..
            }])
    }));
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
