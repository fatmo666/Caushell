//! Static decision/Graph tests; command strings are never executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;
fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("sed-embedded"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn expect(command: &str, expected: Decision) {
    let r = ShellQueryCore::new().check(request(command));
    assert_eq!(r.decision, expected, "{command}: {r:#?}");
}
fn paths(command: &str) -> Vec<(ResolvedPathRole, PathResolution)> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(command));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    staged
        .graph()
        .nodes()
        .filter_map(|n| match &n.kind {
            NodeKind::PathFact {
                role, resolution, ..
            } => Some((*role, resolution.clone())),
            _ => None,
        })
        .collect()
}
#[test]
fn real_embedded_writes_use_the_existing_workspace_guard() {
    for cmd in ["sed 'w output' input", "sed -n 's/a/b/w cache/out' input"] {
        expect(cmd, Decision::Allow);
    }
    for cmd in [
        "sed -n '1s/.*/DATA/w /opt/shared/output' /etc/hosts",
        "sed 'W /opt/shared/output' input",
        "sed -e p -e 'w /opt/shared/output' input",
        "sed 'q;w /opt/shared/output' input",
    ] {
        expect(cmd, Decision::NeedApproval);
    }
}
#[test]
fn execution_and_unavailable_programs_are_opaque() {
    for cmd in [
        "sed e",
        "sed '1e exec /bin/sh 1>&0' input",
        "sed 's/a/b/e' input",
        "sed -f program input",
        "printf CODE | sed -f - input",
        "sed \"$PROGRAM\" input",
        "sed 'w output\nunknown' input",
        "sed --unmodeled 's/a/b/' input",
    ] {
        expect(cmd, Decision::NeedApproval);
    }
}
#[test]
fn normal_data_and_literal_effect_letters_are_not_execution() {
    for cmd in [
        "sed 's/e/w/g' input",
        "sed -n '/e;w/p' input",
        "sed 'a e;w /opt/file' input",
        "sed '# e;w /opt/file' input",
        "sed -e 'a\\' -e 'w /opt/output' input",
        "sed -E 's/(a|b)/c/g' input",
        "sed --help",
        "sed --version",
        "sed '' input",
        "sed \"s/^$//;t;p;\" input",
    ] {
        expect(cmd, Decision::Allow);
    }
    let result = ShellQueryCore::new().check(request("sed 's/e/w/g' input"));
    assert!(
        result
            .decision_trace
            .execution_semantics
            .iter()
            .all(|s| !s.executes_payload && s.payload_mode.is_none()),
        "{result:#?}"
    );
}
#[test]
fn graph_keeps_real_paths_not_program_as_input_file_or_shell_expansion() {
    let p = paths("sed -e 'r /etc/hosts' -e 'w /opt/output' input");
    for (role, path) in [
        (ResolvedPathRole::Read, "/tmp/project/input"),
        (ResolvedPathRole::Read, "/etc/hosts"),
        (ResolvedPathRole::Write, "/opt/output"),
    ] {
        assert!(
            p.iter()
                .any(|(r, v)| *r == role && v.concrete_path() == Some(path)),
            "{p:#?}"
        );
    }
    let p = paths("sed 'w $DEST' input");
    assert!(
        p.iter().any(|(r, v)| *r == ResolvedPathRole::Write
            && v.concrete_path() == Some("/tmp/project/$DEST")),
        "{p:#?}"
    );
    assert!(
        !paths("sed -n 's/a/b/' -")
            .iter()
            .any(|(_, v)| v.concrete_path() == Some("/tmp/project/-"))
    );
    let p = paths("sed -f - -f program.sed input");
    assert!(
        !p.iter()
            .any(|(_, v)| v.concrete_path() == Some("/tmp/project/-")),
        "{p:#?}"
    );
    assert!(
        p.iter().any(|(r, v)| *r == ResolvedPathRole::Read
            && v.concrete_path() == Some("/tmp/project/program.sed")),
        "{p:#?}"
    );
}
#[test]
fn nested_sed_does_not_erase_known_embedded_effects() {
    expect(
        r"find . -type f -exec sed 'w /opt/shared/out' {} \;",
        Decision::NeedApproval,
    );
    expect(
        r"find . -type f -exec sed 's/a/b/e' {} \;",
        Decision::NeedApproval,
    );
    expect(r"find . -type f -exec sed 's/a/b/' {} \;", Decision::Allow);
    expect(
        "find . -type f -print0 | xargs -0 sed 'w /opt/shared/out'",
        Decision::NeedApproval,
    );
    expect("sed -i 's/a/b/' /opt/shared/input", Decision::NeedApproval);
    expect("sed -i.bak 's/a/b/' input", Decision::Allow);
    expect("sed -i'/opt/*' 's/a/b/' input", Decision::NeedApproval);
    expect("sed -i\"$SUFFIX\" 's/a/b/' input", Decision::NeedApproval);
}
