use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("bash-evaluation"),
        sequence_no: CommandSequenceNo::new(1),
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

fn check(command: &str, expected: Decision) -> CheckResponse {
    let response = ShellQueryCore::new().check(request(command));
    assert_eq!(response.decision, expected, "{command}: {:#?}", response);
    response
}

#[test]
fn hidden_substitutions_enter_the_execution_graph() {
    for command in [
        "declare -a a=(one); unset 'a[$(touch /opt/out)]'",
        "declare -a a=(one); name='a[$(touch /opt/out)]'; unset \"$name\"",
        "declare -a a=(one); x='a[$(touch /opt/out)]'; echo $((x))",
        "declare -a a=(one); x='a[$(touch /opt/out)]'; echo ${a[x]}",
        "declare -a a=(one); x='a[$(touch /opt/out)]'; ((x))",
        "declare -a a=(one); x='a[$(touch /opt/out)]'; let 'x'",
        "declare -a a=(one); x='a[$(touch /opt/out)]'; declare -i n=x",
        "a[0]='b[$(touch /opt/out)]'; echo $((a[0]))",
        "a=(1); a[0]='b[$(touch /opt/out)]'; echo $((a))",
        "a=('b[$(touch /opt/out)]'); echo $((a[0]))",
        "a=(one); x='a[$(touch /opt/out)]'; declare -i n; n=x",
        "(( a[$(touch /opt/out)]=2 ))",
        "a=(1); x='a[`touch /opt/out`]'; echo $((x))",
        "i='a[$(touch /opt/out)]'; ((flag ? i=0 : 0, i))",
        "i='a[$(touch /opt/out)]'; ((flag && (i=0), i))",
    ] {
        let response = check(command, Decision::NeedApproval);
        assert!(
            response
                .decision_trace
                .derived_invocations
                .iter()
                .any(|d| d.command_name.as_deref() == Some("touch")),
            "{command}: {:#?}",
            response.decision_trace.derived_invocations
        );
    }
    check("a=(one); x='a[$(rm -rf /)]'; echo $((x))", Decision::Deny);
}

#[test]
fn data_and_numeric_controls_are_not_executable() {
    for command in [
        "s='$(touch /opt/out)'; echo \"$s\"",
        "s='a[$(touch /opt/out)]'; echo \"$s\"",
        "a=(1 2); unset 'a[0]'",
        "a=(1 2); i=1; echo ${a[i]}",
        "x=2; echo $((x + 1))",
        "a=(1 2); echo $((a[0] + a[1]))",
        "a=(one); unset -f 'a[$(touch /opt/out)]'",
        "a=(one); unset -n 'a[$(touch /opt/out)]'",
        "declare -A a=([key]=value); echo ${a[key]}",
        "a=(1 2); echo ${a[@]}",
        "((x=2))",
        "for ((i=0;i<3;i++)); do echo ok; done",
        "x='$(touch /opt/out)'; echo $((x))",
        "let() { :; }; let 'a[$(touch /opt/out)]'",
        "let() { :; }; let\t'a[$(touch /opt/out)]'",
        "let '$(touch /opt/out)'",
        "declare -i n='$(touch /opt/out)'",
        "a=(1); unset -f `printf f`",
        "a=(1); a[1]='b[$(touch /opt/out)]'; echo $((a[0]))",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn unknown_recursive_and_cyclic_values_require_approval() {
    for command in [
        "echo $((unknown))",
        "unset \"$unknown\"",
        "x=y; y=x; echo $((x))",
        "a=\"$unknown\"; echo $((a[0]))",
        "x=2; read x; echo $((x))",
        "for ((i=0;i<3;i++)); do read i; done",
        "for ((i=0;i<3;i++)); do read i; echo $((i)); done",
        "echo $(( $(printf 'a[$(touch /opt/out)]') ))",
        "a[0]='b[$(rm -rf /)]'; a[0]=2; echo $((a[0]))",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn evaluation_uses_source_cwd_and_nested_shell_scopes() {
    for command in [
        "cd /etc; a=(one); unset 'a[$(touch result)]'",
        "bash -c \"a=(one); unset 'a[\u{24}(touch /opt/out)]'\"",
        "f() { a=(one); unset 'a[$(touch /opt/out)]'; }; f",
        "unset $(touch /opt/out)",
        "unset -- 'a[$(touch /opt/out)]'",
    ] {
        check(command, Decision::NeedApproval);
    }
    let r = check(
        "cd /tmp; a=(one); unset 'a[$(touch result)]'",
        Decision::NeedApproval,
    );
    assert!(
        !r.reasons
            .iter()
            .any(|r| r.contains("write target") || r.contains("outside workspace")),
        "{r:#?}"
    );
}

#[test]
fn native_arguments_do_not_create_shell_evaluation_sites() {
    let r = check(
        "printf '%s' 'a[$(touch /opt/out)]' | xargs -0 printf '%s'",
        Decision::Allow,
    );
    assert!(
        !r.decision_trace
            .derived_invocations
            .iter()
            .any(|d| d.command_name.as_deref() == Some("touch"))
    );
}

#[test]
fn evaluation_respects_the_shared_depth_budget() {
    for depth in [0, 1, 2, 8] {
        let mut policy = PolicyConfig::default();
        policy.semantic_expansion.max_nested_parse_depth = depth;
        let response = ShellQueryCore::try_with_policy(policy)
            .unwrap()
            .check(request("a=(one); x='a[$(rm -rf /)]'; echo $((x))"));
        assert_ne!(
            response.decision,
            Decision::Allow,
            "depth={depth}: {response:#?}"
        );
        assert!(response.decision_trace.derived_invocations.len() < 8);
    }
}
