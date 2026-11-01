use caushell_core::{SessionState, ShellQueryCore};
use caushell_types::*;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "caushell-frame-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::write(path.join("report.data"), "data\n").unwrap();
        Self(path)
    }
    fn request(&self, sequence: u64, command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("frame-session"),
            sequence_no: CommandSequenceNo(sequence),
            command: command.into(),
            shell_state_before: ShellStateSnapshot::new(self.0.to_str().unwrap()),
            shell_kind: ShellKind::Bash,
            home: None,
            workspace_root: Some(self.0.to_str().unwrap().into()),
            runtime: RuntimeMetadata {
                runtime_name: "frame-test".into(),
                tool_name: Some("Bash".into()),
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
        }
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn options() -> ShellPathnameSnapshot {
    ShellPathnameSnapshot {
        noglob: false,
        nullglob: false,
        failglob: false,
        dotglob: false,
        nocaseglob: false,
        globstar: false,
        extglob: false,
        globskipdots: true,
        globignore: ShellEnvironmentValue::Absent,
        lc_all: ShellEnvironmentValue::Present { value: "C".into() },
        lc_collate: ShellEnvironmentValue::Absent,
        lc_ctype: ShellEnvironmentValue::Absent,
        lang: ShellEnvironmentValue::Absent,
    }
}
fn observed(mut request: CheckRequest) -> CheckRequest {
    request.shell_state_before.execution_frame = Some(ExecutionFrameObservation {
        binding: ExecutionFrameBinding::for_request(&request, "executor-a"),
        variables: Vec::new(),
        environment: vec![
            ShellEnvironmentSnapshot {
                name: "LC_ALL".into(),
                value: ShellEnvironmentValue::Present { value: "C".into() },
            },
            ShellEnvironmentSnapshot {
                name: "TAR_OPTIONS".into(),
                value: ShellEnvironmentValue::Absent,
            },
        ],
        pathname: Some(options()),
    });
    request
}
fn accepted(response: &CheckResponse) -> bool {
    response.decision_trace.evidence.iter().any(|e| {
        matches!(&e.kind,
        EvidenceKind::ExecutionFrame(frame) if frame.accepted)
    })
}
fn rejected(response: &CheckResponse) -> bool {
    response.decision_trace.evidence.iter().any(|e| {
        matches!(&e.kind,
        EvidenceKind::ExecutionFrame(frame) if !frame.accepted)
    })
}

#[test]
fn frame_supplies_native_locale_and_pathname_inputs_without_command_special_cases() {
    let w = Workspace::new();
    for command in [
        "find . -iname '*.DATA' | xargs -n1 chmod g+w",
        "tar -cf out.tar -- *",
    ] {
        let missing = ShellQueryCore::new().check(w.request(1, command));
        assert_eq!(missing.decision, Decision::NeedApproval, "{missing:#?}");
        let complete = ShellQueryCore::new().check(observed(w.request(1, command)));
        assert_eq!(complete.decision, Decision::Allow, "{complete:#?}");
        assert!(accepted(&complete));
    }
}

#[test]
fn frame_is_bound_to_session_sequence_runtime_command_shell_and_cwd() {
    let w = Workspace::new();
    for field in 0..8 {
        let mut request = observed(w.request(1, "printf ok"));
        let frame = request.shell_state_before.execution_frame.as_mut().unwrap();
        match field {
            0 => frame.binding.session_id = SessionId::new("other"),
            1 => frame.binding.sequence_no = CommandSequenceNo(2),
            2 => frame.binding.command_sha256 = "0".repeat(64),
            3 => frame.binding.cwd = "/elsewhere".into(),
            4 => frame.binding.runtime_name = "other".into(),
            5 => frame.binding.shell_kind = ShellKind::Sh,
            6 => frame.binding.protocol = 2,
            _ => frame.binding.executor_instance_id.clear(),
        }
        let response = ShellQueryCore::new().check(request);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{field}: {response:#?}"
        );
        assert!(rejected(&response));
    }
}

#[test]
fn missing_or_replayed_frames_do_not_reuse_saved_observations() {
    let w = Workspace::new();
    let command = "tar -cf out.tar -- report.data";
    let mut backdated = SessionState::new();
    backdated
        .summary_mut()
        .observe_sequence(CommandSequenceNo(5));
    backdated.observe_request(&observed(w.request(3, command)));
    assert!(backdated.summary().execution_frame_executor().is_none());
    let mut core = ShellQueryCore::new();
    let first = observed(w.request(1, command));
    assert_eq!(core.check(first.clone()).decision, Decision::Allow);
    let snapshot = core.session_snapshot(&first.session_id, 0).unwrap();
    assert!(snapshot.summary.variable_binding("TAR_OPTIONS").is_none());
    let snapshot = serde_json::from_slice(&serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let mut restored = ShellQueryCore::new();
    restored.insert_session_state(
        first.session_id.clone(),
        SessionState::from_snapshot(snapshot).unwrap(),
    );
    let mut replay = w.request(2, command);
    replay.shell_state_before.execution_frame = first.shell_state_before.execution_frame;
    let r = restored.check(replay);
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(rejected(&r));
    assert_eq!(
        restored.check(w.request(3, command)).decision,
        Decision::NeedApproval
    );
    assert_eq!(
        restored.check(observed(w.request(4, command))).decision,
        Decision::Allow
    );
}

#[test]
fn executor_replacement_requires_a_new_persistent_session() {
    let w = Workspace::new();
    let mut core = ShellQueryCore::new();
    core.check(observed(w.request(1, "printf first")));
    let mut next = observed(w.request(2, "printf second"));
    next.shell_state_before
        .execution_frame
        .as_mut()
        .unwrap()
        .binding
        .executor_instance_id = "executor-b".into();
    assert!(rejected(&core.check(next)));
    let mut fresh = w.request(3, "printf third");
    fresh.runtime.shell_runtime_capabilities = ShellRuntimeCapabilities::request_only();
    let mut fresh = observed(fresh);
    fresh
        .shell_state_before
        .execution_frame
        .as_mut()
        .unwrap()
        .binding
        .executor_instance_id = "executor-c".into();
    assert_eq!(core.check(fresh).decision, Decision::Allow);
}

#[test]
fn frame_conflicts_and_unknown_environment_cannot_resurrect_a_prior_value() {
    let w = Workspace::new();
    let mut core = ShellQueryCore::new();
    assert_eq!(
        core.check(w.request(1, "export TAR_OPTIONS=--verbose"))
            .decision,
        Decision::Allow
    );
    let mut r = observed(w.request(2, "printf observed"));
    r.shell_state_before
        .execution_frame
        .as_mut()
        .unwrap()
        .environment
        .iter_mut()
        .find(|v| v.name == "TAR_OPTIONS")
        .unwrap()
        .value = ShellEnvironmentValue::Unknown;
    core.check(r);
    assert_eq!(
        core.check(w.request(3, "tar -cf out.tar -- report.data"))
            .decision,
        Decision::NeedApproval
    );
    let mut r = observed(w.request(1, "printf ok"));
    r.shell_state_before
        .environment
        .push(ShellEnvironmentSnapshot {
            name: "LC_ALL".into(),
            value: ShellEnvironmentValue::Present {
                value: "other".into(),
            },
        });
    assert!(rejected(&ShellQueryCore::new().check(r)));
}

#[test]
fn valid_frame_does_not_override_same_action_uncertainty_script_approval_or_deny() {
    let w = Workspace::new();
    for command in [
        "shopt -s nullglob; tar -cf out.tar *",
        "python3 -c pass",
        "tar -cf out.tar --checkpoint=1 --checkpoint-action='exec=python3 -c pass' -- report.data",
    ] {
        let r = ShellQueryCore::new().check(observed(w.request(1, command)));
        assert_eq!(r.decision, Decision::NeedApproval, "{r:#?}");
    }
    for invalid in [false, true] {
        for command in [
            "rm -rf /",
            r#"python3 -c 'import shutil; shutil.rmtree("/etc")'"#,
        ] {
            let mut r = observed(w.request(1, command));
            if invalid {
                r.shell_state_before
                    .execution_frame
                    .as_mut()
                    .unwrap()
                    .binding
                    .protocol = 2;
            }
            assert_eq!(ShellQueryCore::new().check(r).decision, Decision::Deny);
        }
    }
}

#[test]
fn frame_planning_is_read_only_and_racing_plans_do_not_authorize_later_checks() {
    let w = Workspace::new();
    let mut core = ShellQueryCore::new();
    let context = w.request(1, "printf hello");
    let runtime = RuntimeCheckRequest {
        intent: CheckIntent::JudgeOnly,
        session_id: context.session_id.clone(),
        command: context.command.clone(),
        shell_state_before: context.shell_state_before.clone(),
        shell_kind: context.shell_kind,
        runtime: context.runtime.clone(),
        home: context.home.clone(),
        workspace_root: context.workspace_root.clone(),
    };
    let plan_request = ExecutionFramePlanRequest {
        request: runtime,
        executor_instance_id: "executor-a".into(),
    };
    let a = core.execution_frame_plan(plan_request.clone()).unwrap();
    let b = core.execution_frame_plan(plan_request.clone()).unwrap();
    assert_eq!(a, b);
    assert_eq!(core.session_count(), 0);
    let mut first = observed(context);
    first
        .shell_state_before
        .execution_frame
        .as_mut()
        .unwrap()
        .binding = a.binding;
    assert_eq!(core.check(first).decision, Decision::Allow);
    let mut racing = observed(w.request(2, "printf hello"));
    racing
        .shell_state_before
        .execution_frame
        .as_mut()
        .unwrap()
        .binding = b.binding;
    assert_eq!(core.check(racing).decision, Decision::NeedApproval);
    let next = core.execution_frame_plan(plan_request).unwrap();
    assert_eq!(next.binding.sequence_no, CommandSequenceNo(3));
}

#[test]
fn planning_reuses_static_requirements_but_binds_each_request_independently() {
    let w = Workspace::new();
    let mut core = ShellQueryCore::new();
    let requirements = caushell_profile::execution_frame_requirements(
        caushell_profile::ProfileRegistry::built_in()
            .unwrap()
            .profiles(),
    );
    for index in 0..16 {
        let mut request = w.request(1, &format!("printf value_{index}"));
        request.session_id = SessionId::new(format!("session-{index}"));
        request.runtime.runtime_name = format!("runtime-{index}");
        request.shell_state_before.cwd = w.0.join(format!("dir-{index}")).display().to_string();
        let expected = ExecutionFrameBinding::for_request(&request, format!("executor-{index}"));
        let runtime = RuntimeCheckRequest {
            intent: CheckIntent::JudgeOnly,
            session_id: request.session_id,
            command: request.command,
            shell_state_before: request.shell_state_before,
            shell_kind: request.shell_kind,
            runtime: request.runtime,
            home: request.home,
            workspace_root: request.workspace_root,
        };
        let plan_request = ExecutionFramePlanRequest {
            request: runtime,
            executor_instance_id: format!("executor-{index}"),
        };
        let mut plan = core.execution_frame_plan(plan_request.clone()).unwrap();
        assert_eq!(plan.requirements, requirements);
        assert_eq!(plan.binding, expected);
        plan.requirements.environment_names.clear();
        plan.requirements.pathname = false;
        core.replace_policy(PolicyConfig::default());
        let next = core.execution_frame_plan(plan_request).unwrap();
        assert_eq!(next.requirements, requirements);
        assert_eq!(next.binding, expected);
    }
    assert_eq!(core.session_count(), 0);
}

#[test]
fn cached_requirements_do_not_cache_observed_environment_or_decisions() {
    let w = Workspace::new();
    let mut core = ShellQueryCore::new();
    let command = "find . -iname '*.DATA' | xargs -n1 chmod g+w";
    assert_eq!(
        core.check(observed(w.request(1, command))).decision,
        Decision::Allow
    );
    let mut unknown = observed(w.request(2, command));
    let frame = unknown.shell_state_before.execution_frame.as_mut().unwrap();
    frame.environment[0].value = ShellEnvironmentValue::Unknown;
    frame.pathname.as_mut().unwrap().lc_all = ShellEnvironmentValue::Unknown;
    let response = core.check(unknown);
    assert!(accepted(&response));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert_eq!(
        core.check(observed(w.request(3, command))).decision,
        Decision::Allow
    );
}

#[test]
fn frame_scalar_names_and_values_are_partial_expiring_and_not_environment_grants() {
    let work = Workspace::new();
    let mut request =
        observed(work.request(1, "ln -s \"$PWD/report.data\" /usr/local/bin/frame-fixture"));
    request
        .shell_state_before
        .execution_frame
        .as_mut()
        .unwrap()
        .variables
        .push(ShellEnvironmentSnapshot {
            name: "PWD".into(),
            value: ShellEnvironmentValue::Present {
                value: work.0.to_str().unwrap().into(),
            },
        });
    let mut core = ShellQueryCore::new();
    let response = core.check(request.clone());
    assert!(accepted(&response));
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(response.decision_trace.path_targets.iter().any(|t| t.slot_name == "link_path" &&
        matches!(&t.lexical,PathResolution::Concrete {path} if path=="/usr/local/bin/frame-fixture")));
    assert!(
        !response
            .reasons
            .iter()
            .any(|r| r.contains("argument region ownership")),
        "{:?}",
        response.reasons
    );
    let later = core.check(work.request(2, "printf x > \"$PWD/new.data\""));
    assert_eq!(
        later.decision,
        Decision::NeedApproval,
        "{:?}",
        later.reasons
    );

    let mut frame = request.shell_state_before.execution_frame.unwrap();
    frame.variables.push(frame.variables[0].clone());
    assert!(frame.validate(&request_without_frame(&work), None).is_err());
}
fn request_without_frame(work: &Workspace) -> CheckRequest {
    work.request(1, "ln -s \"$PWD/report.data\" /usr/local/bin/frame-fixture")
}
