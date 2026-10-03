//! Samples are statically checked; no source edits/deletions are executed.
use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PathResolution, ResolvedPathPurpose,
    ResolvedPathRole, RuntimeMetadata, SessionId, ShellKind, ShellRuntimeCapabilities,
    ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    let mut state = ShellStateSnapshot::new("/tmp/project");
    state.observability.variables = caushell_types::ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("ruff-profile-test"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: state,
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}

fn check(command: &str, expected: Decision) {
    let result = ShellQueryCore::new().check(request(command));
    assert_eq!(
        result.decision, expected,
        "{command}: {:?}",
        result.decision_trace.findings
    );
}

fn facts(
    command: &str,
) -> Vec<(
    ResolvedPathRole,
    Option<ResolvedPathPurpose>,
    PathResolution,
)> {
    let mut core = ShellQueryCore::new();
    let req = request(command);
    let result = core.check(req.clone());
    assert_eq!(
        result.decision,
        Decision::Allow,
        "{command}: {:?}",
        result.decision_trace.findings
    );
    core.session_graph(&req.session_id)
        .unwrap()
        .nodes()
        .filter_map(|n| match &n.kind {
            NodeKind::PathFact {
                role,
                purpose,
                resolution,
                ..
            } => Some((*role, *purpose, resolution.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn unknown_environment_does_not_prove_optional_report_absent() {
    let mut req = request("ruff check --diff src/a.py");
    req.shell_state_before.observability.variables = caushell_types::ShellStateKnowledge::Unknown;
    let result = ShellQueryCore::new().check(req);
    assert_eq!(result.decision, Decision::NeedApproval);
    // A known absent variable skips optional output; an explicit CLI destination
    // also wins over unknown environment values.
    check("ruff check --diff src/a.py", Decision::Allow);
    let mut req = request("ruff check --diff --no-cache -o report.json src/a.py");
    req.shell_state_before.observability.variables = caushell_types::ShellStateKnowledge::Unknown;
    assert_eq!(ShellQueryCore::new().check(req).decision, Decision::Allow);
}

#[test]
fn source_mutations_use_existing_workspace_rules() {
    for command in [
        "ruff check src/a.py",
        "ruff check --fix src/a.py",
        "ruff format src/a.py",
        "ruff",
        "ruff check",
        "ruff format",
        "ruff check --config 'fix=true' src/a.py",
    ] {
        check(command, Decision::Allow);
    }
    for command in [
        "ruff check /etc/a.py",
        "ruff format /etc/a.py",
        "ruff check --no-fix /etc/a.py",
        "ruff check --config 'fix-only=true' --no-fix /etc/a.py",
        "ruff check --no-cache /etc/a.py",
        "ruff check --add-noqa /etc/a.py",
        "ruff check --diff --add-noqa /etc/a.py",
        "ruff check --diff --add-ignore /etc/a.py",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn explicitly_nonwriting_source_modes_allow_external_reads() {
    for command in [
        "ruff check --diff /etc/a.py",
        "ruff check --no-fix --no-fix-only /etc/a.py",
        "ruff check --show-files /etc/a.py",
        "ruff check --show-files --add-noqa /etc/a.py",
        "ruff check --show-settings --cache-dir /etc/cache /etc/a.py",
        "ruff format --check /etc/a.py",
        "ruff format --diff /etc/a.py",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn graph_keeps_source_reads_and_potential_writes() {
    let paths = facts("ruff check src/a.py");
    for role in [ResolvedPathRole::Read, ResolvedPathRole::Write] {
        assert!(
            paths
                .iter()
                .any(|(r, _, p)| *r == role && p.concrete_path() == Some("/tmp/project/src/a.py")),
            "{paths:?}"
        );
    }
    let paths = facts("ruff format --check src/a.py");
    assert!(!paths.iter().any(|(r, _, p)| *r == ResolvedPathRole::Write
        && p.concrete_path() == Some("/tmp/project/src/a.py")));
    assert!(
        paths
            .iter()
            .any(|(r, purpose, p)| *r == ResolvedPathRole::Write
                && *purpose == Some(ResolvedPathPurpose::IncidentalCache)
                && p.concrete_path().is_none())
    );
}

#[test]
fn cache_unknown_default_is_allowed_but_explicit_targets_are_not_exempt() {
    check(
        "ruff check --cache-dir /tmp/project/cache src/a.py",
        Decision::Allow,
    );
    for command in [
        "ruff check --cache-dir /etc/cache src/a.py",
        "ruff format --check --cache-dir /etc/cache src/a.py",
        "ruff check --cache-dir= src/a.py",
        "ruff check src/a.py --cache-dir",
        "ruff check --cache-dir \"$UNKNOWN\" src/a.py",
        "RUFF_CACHE_DIR=/etc/cache ruff check src/a.py",
    ] {
        check(command, Decision::NeedApproval);
    }
    check(
        "ruff check --no-cache --cache-dir /etc/cache src/a.py",
        Decision::Allow,
    );
    check(
        "ruff format -n --cache-dir /etc/cache src/a.py",
        Decision::Allow,
    );
}

#[test]
fn inline_toml_cache_paths_are_decoded_and_independent_of_source_mode() {
    for command in [
        "ruff check --config \"cache-dir = '/etc/cache'\" src/a.py",
        "ruff check --diff --config \"cache-dir='/etc/cache'\" src/a.py",
        "ruff format --check --config '\"cache-dir\" = \"/etc/c\\u0061che\"' src/a.py",
        "ruff check --config $'line-length=88\ncache-dir=\"/etc/cache\"' src/a.py",
        "ruff check --config 'cache-dir=' src/a.py",
        "ruff check --config 'cache-dir=42' src/a.py",
    ] {
        check(command, Decision::NeedApproval);
    }
    for command in [
        "ruff check --config 'line-length=88' src/a.py",
        "ruff check --config cfg.toml src/a.py",
        "ruff check --config \"cache-dir='cache'\" src/a.py",
        "ruff check --cache-dir cache --config \"cache-dir='/etc/cache'\" src/a.py",
        "ruff check --no-cache --config \"cache-dir='/etc/cache'\" src/a.py",
    ] {
        check(command, Decision::Allow);
    }
    let paths = facts("ruff check --config \"cache-dir='cache'\" src/a.py");
    assert!(paths.iter().any(|(r, _, p)| *r == ResolvedPathRole::Write
        && p.concrete_path() == Some("/tmp/project/cache")));
}

#[test]
fn independent_output_is_not_bypassed_by_readonly_or_stdin_modes() {
    for command in [
        "ruff check --diff -o /etc/out src/a.py",
        "ruff check --show-files -o /etc/out src/a.py",
        "ruff check --fix - -o /etc/out",
        "RUFF_OUTPUT_FILE=/etc/out ruff check --no-cache src/a.py",
        "ruff check -o \"$UNKNOWN\" src/a.py",
        "ruff check src/a.py --output-file",
    ] {
        check(command, Decision::NeedApproval);
    }
    check(
        "ruff check --diff -o out/report.json src/a.py",
        Decision::Allow,
    );
    check(
        "RUFF_OUTPUT_FILE=/etc/out ruff check --output-file result.json src/a.py",
        Decision::Allow,
    );
}

#[test]
fn stdin_identity_is_not_a_disk_mutation_target() {
    for command in [
        "ruff check --fix --stdin-filename /etc/a.py src/ignored.py",
        "printf 'import os' | ruff check --fix -",
        "ruff format --stdin-filename /etc/a.py",
        "ruff format --check -",
    ] {
        check(command, Decision::Allow);
    }
    let paths = facts("ruff format --stdin-filename /etc/a.py");
    assert!(
        !paths
            .iter()
            .any(|(role, _, _)| *role == ResolvedPathRole::Write)
    );
    check(
        "ruff check --watch --stdin-filename ignored.py /etc/a.py",
        Decision::NeedApproval,
    );
}

#[test]
fn argfiles_never_silently_downgrade_to_plain_paths() {
    for command in [
        "ruff @args.txt",
        "ruff check @args.txt",
        "ruff check --diff -- @args.txt",
        "ruff format --check @args.txt",
        "ruff check --select @args.txt src/a.py",
        "ruff check --no-cache --config @args.txt src/a.py",
        "ruff format --stdin-filename @args.txt",
        "env ruff check --diff @args.txt",
        "timeout 1 ruff check --diff @args.txt",
        "ARG=@args.txt; ruff check --diff \"$ARG\"",
        "ruff check --diff \"$UNKNOWN\"",
    ] {
        check(command, Decision::NeedApproval);
    }
    check("ruff check --diff '$LITERAL'", Decision::Allow);
}

#[test]
fn nested_forms_and_redirections_retain_separate_effects() {
    check("env ruff check /etc/a.py", Decision::NeedApproval);
    check("env ruff format --check /etc/a.py", Decision::Allow);
    check(
        "ruff check --diff src/a.py >/etc/output",
        Decision::NeedApproval,
    );
    check("cd /etc && ruff format", Decision::NeedApproval);
}

#[test]
fn clean_unknown_deletions_and_information_are_not_conflated() {
    check("ruff clean", Decision::NeedApproval);
    for command in [
        "ruff clean --help",
        "ruff check --help --output-file /etc/out --cache-dir /etc/cache /etc/a.py",
        "ruff rule --all",
        "ruff config cache-dir",
        "ruff linter",
        "ruff version",
        "ruff help format",
    ] {
        check(command, Decision::Allow);
    }
}
