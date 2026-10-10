//! Static decisions and staged Graph only; no sample commands execute.
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
        session_id: SessionId::new("selection-boundary"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
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

#[test]
fn ordinary_queries_and_local_archive_writes_are_allowed() {
    for command in [
        "last",
        "last -w",
        "last -i root",
        "last -a -f input root",
        "dpkg --get-selections",
        "dpkg -S /bin/ls",
        "dpkg -I package.deb",
        "rpm -qf /bin/ls",
        "rpm -qfi /bin/ls",
        "readelf -a -W input.a",
        "cat foo.md | pandoc -f markdown_github",
        "pandoc --from=markdown+smart --to=html5 input.md",
        "pandoc -r gfm -w plain input.md",
        "systemctl --type=service",
        "systemctl list-units --type=service --all",
        "systemctl list-unit-files --type=service --no-pager",
        "printf '%s\\n' input | cpio -p --owner user:group cache",
        "find . -name '*.txt' | xargs zip -9 txt.zip",
        "find . -name '*.html' | zip -j all-html-files -@",
        r"find . -exec echo 'report*' \;",
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn child_cardinality_proof_preserves_child_effects_and_unknown_controls() {
    for command in [
        r"find . -exec chmod 755 '{}/*' \;",
        r"find . -execdir tar -cvf filename.tar 'RS*' \;",
    ] {
        let r = ShellQueryCore::new().check(request(command));
        assert!(
            !r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError
                    && p.reason.starts_with("command find ")),
            "{command}: {r:#?}"
        );
        assert!(!r.decision_trace.derived_invocations.is_empty(), "{r:#?}");
    }
    for command in [
        r"find . -exec echo report* \;",
        r"find . -exec cp -t target* /opt/shared/output {} \;",
        r"find /opt/shared -exec convert -thumbnail x80 {}[0] {}-thumb.png \;",
        r"find . -exec chmod 755 {}/* \;",
        r"find . -execdir tar -cvf filename.tar RS* \;",
        r"find . -exec cp report* /opt/shared/output \;",
        r"find . -exec tar -cvf /opt/shared/archive.tar RS* \;",
        r"find /opt/shared -exec chmod 755 {}/* \;",
        r"find . -exec echo * \;",
        r"find . -exec echo $args \;",
        r#"find . -exec echo "$arg" \;"#,
        "find ${DIRECTORY} -type f -print",
        "find \"$path\" -type f -print",
        "find $(pwd) -type f -print",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn archive_outputs_and_opaque_payloads_keep_existing_approval() {
    for command in [
        "cpio -p --owner user:group /opt/shared/cache",
        "cpio -p --owner user:group \"$destination\"",
        "cpio -p --owner",
        "zip -9 /opt/shared/archive.zip input",
        "zip -j /opt/shared/archive -@",
        "zip -9 archive.zip -T -TT 'touch /opt/shared/marker' input",
        "zip -m archive.zip input",
        "cat input | pandoc -f markdown -o /opt/shared/output",
        "pandoc -f markdown --lua-filter /opt/shared/filter.lua",
        "pandoc -f ./reader.lua",
        "pandoc --from=/opt/shared/reader.lua -t html input.md",
        "pandoc -t ./writer.lua input.md",
        "pandoc -f markdown -t /opt/shared/writer.lua input.md",
        "pandoc -f markdown -f ./reader.lua input.md",
        "pandoc -t html -t ./writer.lua input.md",
        "pandoc -f \"$format\" input.md",
        "pandoc -f unmodeled_format input.md",
        "pandoc -t pdf input.md",
        "pandoc -f markdown --unknown",
        "readelf -a --unknown input",
        "last --unsupported root",
        "dpkg --set-selections",
        "dpkg -i package.deb",
        "dpkg --install package.deb",
        "rpm -ivh package.rpm",
        "rpm -q --eval '%{lua:os.execute(\"touch /opt/shared/marker\")}'",
        "rpm -q --pipe 'touch /opt/shared/marker'",
        "systemctl link /opt/shared/unit.service",
        "systemctl list-units --unknown",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn graph_has_real_destination_not_owner_or_format_value() {
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
    let mut ctx = RunnerContext::new(request("cpio -p --owner user:group /opt/shared/cache"));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    let writes: Vec<_> = staged
        .graph()
        .nodes()
        .filter_map(|n| match &n.kind {
            NodeKind::PathFact {
                role: ResolvedPathRole::Write | ResolvedPathRole::Target,
                resolution,
                ..
            } => Some(resolution),
            _ => None,
        })
        .collect();
    assert!(!writes.is_empty());
    assert!(
        writes
            .iter()
            .all(|p| p.concrete_path() == Some("/opt/shared/cache")),
        "{writes:#?}"
    );
}
