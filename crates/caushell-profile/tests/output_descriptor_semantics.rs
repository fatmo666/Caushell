use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{DerivedPathRule, ShellKind, StreamDataDependency};
use std::sync::OnceLock;

fn resolved(command: &str) -> ResolvedInvocationArtifact {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn explicit_opaque_operation_is_opt_in_and_preserves_declared_effects() {
    let source = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: custom}\nforms:\n  - id: configured\n    operation_semantics_unresolved: true\n    selector: {kind: all, items: []}\n    parameters: [{name: output, semantic: {kind: path, role: write}, binding: {kind: next_positional}, cardinality: required_one}]\n    effects: [{kind: write_path, target: {kind: slot, name: output}}]\n";
    let profile = load_command_profile_from_str(source).unwrap();
    let legacy = load_command_profile_from_str(
        &source.replace("    operation_semantics_unresolved: true\n", ""),
    )
    .unwrap();
    assert!(profile.forms[0].operation_semantics_unresolved);
    assert!(!legacy.forms[0].operation_semantics_unresolved);
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    let parsed = parse_command("custom /opt/shared/out", ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(r) = resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) else {
        panic!("expected shape to resolve");
    };
    assert!(r.bound.operation_semantics_unresolved);
    assert!(
        r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
}

#[test]
fn filename_prefix_targets_have_no_fictitious_prefix_write() {
    for command in [
        "csplit -s -f cache/part public 1",
        "csplit -s public 1",
        "csplit -s -f '' public 1",
    ] {
        let r = resolved(command);
        assert!(!r.bound.operation_semantics_unresolved, "{command}");
        let writes = r
            .bound
            .effects
            .iter()
            .filter(|e| e.kind == EffectKind::WritePath)
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 1);
        assert!(
            matches!(&writes[0].target, EffectTarget::DerivedPath(t) if t.rule == DerivedPathRule::FileNamePrefix)
        );
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
            StreamDataDependency::Independent
        );
    }
    assert!(
        resolved("csplit -b /../../../out%02d public 1")
            .bound
            .operation_semantics_unresolved
    );
}

#[test]
fn descriptor_projection_keeps_raw_argv_and_only_declared_reads_consume_it() {
    let r = resolved("read -u03 token");
    let parameter = r
        .bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "descriptor")
        .unwrap();
    assert!(matches!(&parameter.values[0], BoundValue::Argument { text, .. } if text == "03"));
    assert!(
        matches!(&parameter.projected_values.as_ref().unwrap()[0].resolution, SemanticValueResolution::Known(path) if path == "/dev/fd/3")
    );
    assert!(
        r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath
                && e.path_access == Some(PathAccessKind::ContentOpen))
    );
    let r = resolved("read -u3 -t0 token");
    assert!(
        !r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath
                || e.kind == EffectKind::BindVariableFromRuntimeInput)
    );
    let r = resolved("read -u\"$FD\" token");
    let parameter = r
        .bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "descriptor")
        .unwrap();
    assert!(matches!(
        &parameter.projected_values.as_ref().unwrap()[0].resolution,
        SemanticValueResolution::Unknown(_)
    ));
}

#[test]
fn configuration_and_interpreter_boundaries_remain_distinct() {
    assert!(
        resolved("curl -K cache/curl.conf https://example.test")
            .bound
            .operation_semantics_unresolved
    );
    assert!(
        !resolved("curl -q https://example.test")
            .bound
            .operation_semantics_unresolved
    );
    for command in ["awk '{print}'", "awk -e '{print}'", "awk -f program.awk"] {
        assert!(
            resolved(command)
                .bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ExecutePayload),
            "{command}"
        );
    }
    for tool in ["md5sum", "sha256sum"] {
        assert_eq!(
            resolved(&format!("{tool} --status -c .env"))
                .proven_stream_contract()
                .unwrap()
                .stdout_dependency,
            StreamDataDependency::Independent
        );
    }
}
