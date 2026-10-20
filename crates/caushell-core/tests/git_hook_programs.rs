use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("git-hook-programs"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(request(command, 1))
}
fn expect(command: &str, expected: Decision) -> CheckResponse {
    let r = check(command);
    assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    r
}
fn installed(stage: &str, body: &str, call: &str) -> String {
    format!(
        "git init .; printf '%s\\n' '{}' >.git/hooks/{stage}; chmod +x .git/hooks/{stage}; {call}",
        body.replace('\'', "'\\''")
    )
}

#[test]
fn known_hooks_enter_the_graph_and_existing_guards() {
    for (body, expected, child) in [
        ("rm -rf /", Decision::Deny, "rm"),
        ("touch /opt/out", Decision::NeedApproval, "touch"),
        ("exec /bin/sh 0<&2 1>&2", Decision::NeedApproval, "sh"),
        ("printf SAFE", Decision::Allow, "printf"),
    ] {
        let r = expect(
            &installed("pre-commit", body, "git commit --allow-empty -m x"),
            expected,
        );
        assert!(
            r.decision_trace
                .derived_invocations
                .iter()
                .any(|i| i.command_name.as_deref() == Some(child)),
            "{:?}",
            r.decision_trace.derived_invocations
        );
        assert!(r.decision_trace.nested_payloads.iter().any(|p| matches!(&p.origin, NestedPayloadOrigin::ConfigDefinedTask {config_path, task_name} if config_path == "/bench/workspace/.git/hooks/pre-commit" && task_name == "git-hook:pre-commit")));
    }
}

#[test]
fn no_verify_skips_only_the_applicable_commit_events() {
    for stage in ["pre-commit", "commit-msg"] {
        expect(
            &installed(
                stage,
                "rm -rf /",
                "git commit --no-verify --allow-empty -m x",
            ),
            Decision::Allow,
        );
    }
    for stage in ["prepare-commit-msg", "post-commit"] {
        expect(
            &installed(
                stage,
                "rm -rf /",
                "git commit --no-verify --allow-empty -m x",
            ),
            Decision::Deny,
        );
    }
    expect(
        &installed("post-rewrite", "rm -rf /", "git commit --amend --no-edit"),
        Decision::Deny,
    );
    expect(
        &installed(
            "post-rewrite",
            "rm -rf /",
            "git commit --amend --no-post-rewrite --allow-empty -m x",
        ),
        Decision::Allow,
    );
}

#[test]
fn commit_and_am_have_distinct_hook_stages() {
    for stage in ["applypatch-msg", "pre-applypatch", "post-applypatch"] {
        expect(
            &installed(stage, "rm -rf /", "git am /tmp/patch"),
            Decision::Deny,
        );
    }
    expect(
        &installed(
            "pre-applypatch",
            "rm -rf /",
            "git am --no-verify /tmp/patch",
        ),
        Decision::Allow,
    );
    expect(
        &installed(
            "post-applypatch",
            "rm -rf /",
            "git am --no-verify /tmp/patch",
        ),
        Decision::Deny,
    );
    expect(
        &installed("pre-commit", "rm -rf /", "git status"),
        Decision::Allow,
    );
}

#[test]
fn only_the_latest_observed_hook_content_is_used() {
    let prefix = installed("pre-commit", "rm -rf /", "");
    expect(
        &format!("{prefix} echo 'printf SAFE' >.git/hooks/pre-commit; git commit -m x"),
        Decision::Allow,
    );
    let prefix = installed("pre-commit", "printf SAFE", "");
    expect(
        &format!("{prefix} echo 'rm -rf /' >.git/hooks/pre-commit; git commit -m x"),
        Decision::Deny,
    );
    expect(
        &format!("{prefix} cat /opt/input >.git/hooks/pre-commit; git commit -m x"),
        Decision::Allow,
    );
}

#[test]
fn hook_paths_follow_inline_overrides_and_process_cwd() {
    expect(
        "mkdir -p /tmp/hooks; echo 'rm -rf /' >/tmp/hooks/pre-commit; chmod +x /tmp/hooks/pre-commit; git -c core.hooksPath=/tmp/hooks commit --allow-empty -m x",
        Decision::Deny,
    );
    expect(
        "mkdir -p /tmp/hooks; echo 'rm -rf /' >/tmp/hooks/pre-commit; chmod +x /tmp/hooks/pre-commit; git -c core.hooksPath=/tmp/hooks -c core.hooksPath=.git/hooks commit --allow-empty -m x",
        Decision::Allow,
    );
    expect(
        "mkdir -p /tmp/repo/.git/hooks; echo 'rm -rf /' >/tmp/repo/.git/hooks/pre-commit; chmod +x /tmp/repo/.git/hooks/pre-commit; git -C /tmp/repo commit --allow-empty -m x",
        Decision::Deny,
    );
    expect(
        "mkdir -p /tmp/hooks; echo 'touch local' >/tmp/hooks/pre-commit; chmod +x /tmp/hooks/pre-commit; git -C /tmp -c core.hooksPath=/tmp/hooks commit --allow-empty -m x",
        Decision::Allow,
    );
}

#[test]
fn hook_shell_frames_and_nested_invocations_do_not_share_caller_locals() {
    for call in [
        "env git commit -m x",
        "sh -c 'git commit -m x'",
        "f() { git commit -m x; }; f",
    ] {
        expect(&installed("pre-commit", "rm -rf /", call), Decision::Deny);
    }
    let r = expect(
        &installed(
            "pre-commit",
            "rm -rf /",
            "sh -c 'echo '\''printf SAFE'\'' >.git/hooks/pre-commit; git commit -m x'",
        ),
        Decision::Allow,
    );
    assert!(
        !r.decision_trace
            .derived_invocations
            .iter()
            .any(|i| i.command_name.as_deref() == Some("rm"))
    );
    expect(
        &installed(
            "pre-commit",
            "touch \"$TARGET\"",
            "TARGET=local; git commit -m x",
        ),
        Decision::NeedApproval,
    );
}

#[test]
fn opaque_shebangs_are_not_misread_as_shell() {
    expect(
        &installed("pre-commit", "#!/bin/bash\nrm -rf /", "git commit -m x"),
        Decision::Deny,
    );
    expect(
        &installed(
            "pre-commit",
            "#!/usr/bin/env sh\nprintf SAFE",
            "git commit -m x",
        ),
        Decision::Allow,
    );
    expect(
        &installed(
            "pre-commit",
            "#!/usr/bin/python3\nprint('safe')",
            "git commit -m x",
        ),
        Decision::NeedApproval,
    );
    expect(
        &installed("pre-commit", "#!/bin/sh -c\nprintf SAFE", "git commit -m x"),
        Decision::NeedApproval,
    );
}

#[test]
fn prior_action_hook_content_is_available_without_host_reads() {
    let mut core = ShellQueryCore::new();
    let setup = installed("pre-commit", "rm -rf /", "printf READY");
    assert_eq!(core.check(request(&setup, 1)).decision, Decision::Allow);
    assert_eq!(
        core.check(request("git commit -m x", 2)).decision,
        Decision::Deny
    );
}

#[test]
fn unobserved_local_hooks_do_not_make_every_commit_an_approval() {
    for command in [
        "git commit --allow-empty -m x",
        "git -c core.hooksPath=/tmp/hooks commit -m x",
        "git commit --no-verify --allow-empty -m x",
        "git status",
        "git commit -h",
        "git -c core.hooksPath=/dev/null commit -m x",
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn explicit_disabled_hooks_and_reenable_are_respected() {
    for mode in ["a-x", "000", "644"] {
        expect(
            &installed(
                "pre-commit",
                "rm -rf /",
                &format!("chmod {mode} .git/hooks/pre-commit; git commit -m x"),
            ),
            Decision::Allow,
        );
    }
    expect(
        &installed(
            "pre-commit",
            "rm -rf /",
            "chmod 000 .git/hooks/pre-commit; chmod +x .git/hooks/pre-commit; git commit -m x",
        ),
        Decision::Deny,
    );
    expect(
        &installed(
            "pre-commit",
            "rm -rf /",
            "if test \"$x\"; then chmod 000 .git/hooks/pre-commit; fi; git commit -m x",
        ),
        Decision::Deny,
    );
    let mut core = ShellQueryCore::new();
    assert_eq!(
        core.check(request(
            &installed("pre-commit", "rm -rf /", "chmod 000 .git/hooks/pre-commit"),
            1
        ))
        .decision,
        Decision::Allow
    );
    assert_eq!(
        core.check(request("git commit -m x", 2)).decision,
        Decision::Allow
    );
}

#[test]
fn observed_configuration_and_repository_roots_drive_hook_paths() {
    expect(
        "git init .; mkdir -p .githooks; printf '[core]\\n hooksPath = .githooks\\n' >.git/config; echo 'rm -rf /' >.githooks/pre-commit; chmod +x .githooks/pre-commit; git commit -m x",
        Decision::Deny,
    );
    let command = installed(
        "pre-commit",
        "touch local",
        "mkdir -p sub; cd /bench/workspace/sub; git commit -m x",
    );
    let r = expect(&command, Decision::Allow);
    let touch = r
        .decision_trace
        .execution_units
        .iter()
        .find(|u| u.raw_text == "touch local")
        .unwrap();
    let _ = touch;
    let mut core = ShellQueryCore::new();
    core.check(request(&command, 1));
    let graph = core
        .session_graph(&SessionId::new("git-hook-programs"))
        .unwrap();
    assert!(graph.nodes().any(|n| matches!(&n.kind, caushell_graph::NodeKind::PathFact {resolution, slot_name, ..} if slot_name == "git_hook_pre_commit" && resolution.concrete_path() == Some("/bench/workspace/.git/hooks/pre-commit"))));
    assert!(graph.nodes().any(|n| matches!(&n.kind, caushell_graph::NodeKind::PathFact {resolution, slot_name, ..} if slot_name == "path_targets" && resolution.concrete_path() == Some("/bench/workspace/local"))));
}
