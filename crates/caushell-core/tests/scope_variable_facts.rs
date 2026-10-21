use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(source: &str, expected: Decision) -> CheckResponse {
    let request = CheckRequest {
        session_id: SessionId::new("scope-variable-facts"),
        sequence_no: CommandSequenceNo::new(1),
        command: source.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    };
    let response = ShellQueryCore::new().check(request);
    assert_eq!(response.decision, expected, "{source}: {response:#?}");
    response
}

#[test]
fn positive_facts_follow_visible_function_and_substitution_frames() {
    for source in [
        "declare -A m=([key]=1); f() { echo \"${m[key]}\"; }; f",
        "declare -A m=([key]=text); f() { local value=${m[key]}; echo \"$value\"; }; f",
        "declare -A m=([key]=1); f() { local -A scores=([one]=1 [two]=2); local score=${scores[${m[key]}]}; echo $((score)); }; f",
        "f() { local ord=$(printf '%d' \"'a\"); local result=$(printf '%d' \"$((ord-1))\"); }; f",
        "f() { local ord=$(printf '%d' \"'a\"); g() { printf '%d' \"$((ord-1))\"; }; g; }; f",
        "f() { x=$(printf '%d' 1); }; f; g() { printf '%d' \"$((x-1))\"; }; g",
        "f() { local data=$1; local length=${#data}; local result=$(printf '%d' \"$((length+1))\"); }; f abc",
        "f() { local data=$1; for ((i=0;i<${#data};i++)); do local ord=$(printf '%d' \"'${data:$i:1}\"); local result=$(printf '%d' \"$((ord-1))\"); done; }; f abc",
        "ord=$(printf '%d' 1); ignored=$(ord=$unknown); f() { printf '%d' \"$((ord+1))\"; }; f",
        "ord=$(printf '%d' 1); f() { declare ord=$unknown; }; f; g() { printf '%d' \"$((ord+1))\"; }; g",
        "ord=$(printf '%d' 1); f() { declare -p ord; }; f; g() { printf '%d' \"$((ord+1))\"; }; g",
        "f() { export ord=$(printf '%d' 1); local result=$(printf '%d' \"$((ord+1))\"); }; f",
        "f() { local input=$1; if [[ -n $input ]]; then local ord=$(printf '%d' \"'${input:0:1}\"); echo \"$((ord+${#input}))\"; fi; }; f a",
    ] {
        check(source, Decision::Allow);
    }
}

#[test]
fn writes_shadowing_and_unknown_operations_do_not_retain_old_proofs() {
    for source in [
        "ord=$(printf '%d' 1); ord=$unknown; f() { printf '%d' \"$((ord))\"; }; f",
        "ord=$(printf '%d' 1); read ord; f() { printf '%d' \"$((ord))\"; }; f",
        "ord=$(printf '%d' 1); unset \"$target\"; f() { printf '%d' \"$((ord))\"; }; f",
        "ord=$(printf '%d' 1); g() { unset \"$target\"; }; g; f() { printf '%d' \"$((ord))\"; }; f",
        "ord=$(printf '%d' 1); g() { read \"$target\"; }; g; f() { printf '%d' \"$((ord))\"; }; f",
        "ord=$(printf '%d' 1); g() { ord=$unknown; }; g; f() { printf '%d' \"$((ord))\"; }; f",
        "ord=$(printf '%d' 1); g() { declare -g ord=$unknown; }; g; f() { printf '%d' \"$((ord))\"; }; f",
        "ord=$(printf '%d' 1); g() { declare -p ord; ord=$unknown; }; g; f() { printf '%d' \"$((ord))\"; }; f",
        "x=$unknown; value=$((x)) x=1",
        "n=$unknown; f() { local n=1 value=$((n)); }; f",
        "payload='a[$(touch /opt/out)]'; ord=$(shuf -i 1-1 -n 0); value=${ord:=$payload}; f() { echo $((ord)); }; f",
        "ord='a[$(touch /opt/out)]'; function local { :; }; f() { local ord=$(printf '%d' 1); echo $((ord)); }; f",
        "ord=$(printf '%d' 1); function local { ord=$unknown; }; f() { local ord; }; f; g() { echo $((ord)); }; g",
        "ord=$(printf '%d' 1); f() { local ord; echo $((ord)); }; f",
        "ord=$(printf '%d' 1); f() { local -n ref=ord; ref=$unknown; echo $((ord)); }; f",
        "x=$unknown; ignored=$(x=$(printf '%d' 1)); f() { echo $((x)); }; f",
        "f() { printf() { echo \"$unknown\"; }; local ord=$(printf '%d' 1); local result=$(echo $((ord))); }; f",
        "f() { local ord=$unknown; if test -f flag; then ord=$(printf '%d' 1); fi; local result=$(echo $((ord))); }; f",
        "f() { local ord=$(printf '%d' 1 2>&1); local result=$(echo $((ord))); }; f",
        "f() { local ord=$(printf '%d' 1; echo \"$unknown\"); local result=$(echo $((ord))); }; f",
    ] {
        check(source, Decision::NeedApproval);
    }
}

#[test]
fn array_type_shadowing_and_redeclaration_preserve_hidden_execution() {
    for source in [
        "declare -A m=([key]=1); key='a[$(touch /opt/out)]'; f() { local m; echo \"${m[key]}\"; }; f",
        "declare -A m=([key]=1); key='a[$(touch /opt/out)]'; f() { local -a m=(1); echo \"${m[key]}\"; }; f",
        "key='a[$(touch /opt/out)]'; f() { declare -A m=([key]=1); }; f; echo \"${m[key]}\"",
        "declare -A m=([key]=1); unset m; declare -a m=(1); key='a[$(touch /opt/out)]'; f() { echo \"${m[key]}\"; }; f",
        "declare -a m=(1); declare -Ap m; key='a[$(touch /opt/out)]'; f() { echo \"${m[key]}\"; }; f",
    ] {
        let response = check(source, Decision::NeedApproval);
        assert!(
            response
                .decision_trace
                .derived_invocations
                .iter()
                .any(|d| d.command_name.as_deref() == Some("touch")),
            "{source}: {response:#?}"
        );
    }
}

#[test]
fn changed_array_elements_cannot_borrow_old_numeric_element_facts() {
    check(
        "declare -a m=(1); f() { m[0]='a[$(touch /opt/out)]'; }; f; g() { echo $((m[0])); }; g",
        Decision::NeedApproval,
    );
}

#[test]
fn explicit_substitutions_in_associative_keys_still_enter_graph() {
    let response = check(
        "declare -A m=([key]=1); f() { echo \"${m[$(touch /opt/out)]}\"; }; f",
        Decision::NeedApproval,
    );
    assert!(
        response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|d| d.command_name.as_deref() == Some("touch"))
    );
}
