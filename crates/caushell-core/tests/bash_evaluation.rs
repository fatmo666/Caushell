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
fn bash_scalar_conditions_preserve_state_and_substitution_effects() {
    for source in [
        "[[ $unknown == a* ]]",
        "[[ $unknown =~ ^[a-z]+$ ]]",
        "i=0; idx=-1; for item in a b; do if [[ $item == a* ]]; then idx=$i; break; fi; ((i+=2)); done; echo ${a[$((idx+2))]}",
        "f() { local i; for ((i=0;i<3;i++)); do [[ x == y ]]; done; }; f",
        "BASH_REMATCH=1; [[ $unknown == a* ]]; echo $((BASH_REMATCH))",
        "BASH_REMATCH=1; [[ '=~' == $unknown ]]; echo $((BASH_REMATCH))",
    ] {
        check(source, Decision::Allow);
    }
    check(
        "BASH_REMATCH=1; [[ x =~ x ]]; echo $((BASH_REMATCH))",
        Decision::NeedApproval,
    );
    let response = check("[[ $(touch /opt/out) == a* ]]", Decision::NeedApproval);
    assert!(
        response
            .decision_trace
            .derived_invocations
            .iter()
            .any(|d| d.command_name.as_deref() == Some("touch"))
    );
    check("[[ $(rm -rf /) == a* ]]", Decision::Deny);
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

#[test]
fn numeric_shapes_do_not_require_a_concrete_value() {
    for command in [
        "unset array[2]",
        "unset array[$RANDOM%4]",
        "unset array[`shuf -i 0-4 -n1`]",
        "shift $(($#-1))",
        "echo $(( ${#unknown} + 1 ))",
        "echo $(($RANDOM % 4))",
        "n=$(printf '%d' 42); echo $((n+1))",
        "echo $(($(date +%s) / 86400))",
        "f() { for ((i=0;i<3;i++)); do local other=1; echo ok; done; }; f",
        "f() { for ((i=0;i<${#signature};i++)); do if [ x != y ]; then break; fi; done; }; f",
        "f() { for ((i=0;i<3;i++)); do continue; done; }; f",
        "f() { a=(x y); for ((i=0;i<2;i++)); do echo ${a[$i]}; done; }; f",
        "f() { for ((i=0;i<3;i++)); do local n=$(printf '%d' \"$unknown\"); echo $((n+1)); done; }; f",
        "f() { for ((i=0;i<${#data};i++)); do local ord=$(printf '%d' \"'${data:$i:1}\"); echo $((ord+1)); done; }; f",
        "f() { local n; case x in x) n=1;; *) n=2;; esac; echo $((n+1)); }; f",
        "declare -A a=([x]=1 [y]=2); n=${a[x]:-0}; echo $((n+1))",
        "a=(1 2 3); i=0; echo ${a[$((i+1))]}",
    ] {
        let r = check(command, Decision::Allow);
        assert!(
            !r.decision_trace
                .derived_invocations
                .iter()
                .any(|d| matches!(d.command_name.as_deref(), Some("i+1" | "index" | "idx+2"))),
            "{r:#?}"
        );
    }
}

#[test]
fn numeric_shell_proof_does_not_hide_an_unmatched_native_option() {
    let result = check(
        "head -$((${RANDOM} % `wc -l < file` + 1)) file | tail -1",
        Decision::NeedApproval,
    );
    assert!(
        result
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::SelectionError)
    );
    assert!(
        !result
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::MissingCommandName)
    );
}

#[test]
fn inert_arithmetic_bytes_do_not_authorize_an_unprofiled_builtin() {
    let result = check("let '$(touch /opt/out)'", Decision::NeedApproval);
    assert!(
        result
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::NoProfile)
    );
    assert!(
        !result
            .decision_trace
            .derived_invocations
            .iter()
            .any(|call| call.command_name.as_deref() == Some("touch"))
    );
}

#[test]
fn numeric_proofs_do_not_survive_unknown_or_non_numeric_writes() {
    for command in [
        "data=a; echo $((data*10000))",
        "echo ${a[$i]}",
        "f() { local n; case x in x) n=1; read n;; *) n=2;; esac; echo $((n)); }; f",
        "f() { local n; case x in x) n=1;; esac; echo $((n)); }; f",
        "n=2; read n; echo $((n+1))",
        "n=2; n[0]='a[$(touch /opt/out)]'; echo $((n))",
        "f() { for ((i=0;i<3;i++)); do read i; done; }; f",
        "printf() { echo 'a[$(touch /opt/out)]'; }; n=$(printf '%d' 42); echo $((n+1))",
        "alias printf='cat .env'; n=$(printf '%d' 42); echo $((n+1))",
        "declare -A a=([x]=1); if test x; then a=([x]='b[$(touch /opt/out)]'); fi; n=${a[x]}; echo $((n))",
        "declare -A a=([x]=1); f() { a[x]='b[$(touch /opt/out)]'; }; f; n=${a[x]}; echo $((n))",
        "n=1; f() { local -n ref=n; ref='a[$(touch /opt/out)]'; }; f; echo $((n))",
        "break() { read i; }; for ((i=0;i<3;i++)); do break; done",
        "n=\"$unknown\"; n+=1; echo $((n))",
        "n=\"$unknown\"; case x in x) n+=1;; *) n+=2;; esac; echo $((n))",
        "f() { for ((i=0;i<3;i++)); do if test x; then local n=1; fi; echo $((n)); done; }; f",
    ] {
        assert_ne!(
            ShellQueryCore::new().check(request(command)).decision,
            Decision::Allow,
            "{command}"
        );
    }
    check(
        "a=(1); x='a[$(rm -rf /)]'; echo ${a[$((x))]}",
        Decision::Deny,
    );
}

#[test]
fn lexical_arithmetic_words_and_loop_initializers_preserve_safety() {
    for command in [
        "echo $(($(printf '%d' 1)0))",
        "sleep $(($(date -f - +%s- <<< $'tomorrow 21:30\\nnow')0))",
        "for ((i=${#data}-2;i>=0;i--)); do echo ${a[$i]}; done",
        "for ((i=0;i<3;i++)); do i[0]=2; done",
        "f() { for ((i=0;i<3;i++)); do echo ok; done; local -n ref=i; }; f",
    ] {
        check(command, Decision::Allow);
    }
    for command in [
        "echo $((x$(printf '%d' 1)y))",
        "x=0; echo $((x$(printf '%d' 1)y))",
        "echo $(($(printf '%s' 'a[$(touch /opt/out)]')0))",
        "for ((i=i;i<3;i++)); do echo ok; done",
        "for ((i=unknown;i<3;i++)); do echo ok; done",
        "for ((i=0;i<3;i++)); do i[0]='a[$(touch /opt/out)]'; echo $((i)); done",
        "local -n ref=i; for ((i=0;i<3;i++)); do ref='a[$(touch /opt/out)]'; echo $((i)); done",
    ] {
        assert_ne!(
            ShellQueryCore::new().check(request(command)).decision,
            Decision::Allow,
            "{command}"
        );
    }
}

#[test]
fn arithmetic_word_grammar_recovery_preserves_approval_and_denial_effects() {
    for command in [
        "echo $((0$(printf '%d' 1)))",
        "echo $(($(printf '%d' 1)$(printf '%d' 2)))",
        "echo $(( $(printf '%d' 1)0 ))",
        "(( $(printf '%d' 1)0 ))",
    ] {
        check(command, Decision::Allow);
    }
    for command in [
        "echo $(($(cat /tmp/unknown-arithmetic-input)0))",
        "echo $(($(touch /opt/out)0))",
        "bash -c 'echo $(($(touch /opt/out)0))'",
        "cd /etc; echo $(($(touch result)0))",
        "printf() { echo 'a[$(touch /opt/out)]'; }; echo $(($(printf '%d' 1)0))",
        "echo $(($(printf '%s' 'a[$(touch /opt/out)]')0))",
    ] {
        check(command, Decision::NeedApproval);
    }
    let touch = check("echo $(($(touch /opt/out)0))", Decision::NeedApproval);
    assert!(
        touch
            .decision_trace
            .derived_invocations
            .iter()
            .any(|d| { d.command_name.as_deref() == Some("touch") })
    );
    for command in [
        "echo $(($(rm -rf /)0))",
        "bash -c 'echo $(($(rm -rf /)0))'",
        "echo $(($(printf '%d' 1)0)); rm -rf /",
    ] {
        check(command, Decision::Deny);
    }
    assert_ne!(
        ShellQueryCore::new()
            .check(request("echo $(( $(rm -rf /)0 + ))"))
            .decision,
        Decision::Allow,
    );
    for depth in [0, 1, 2] {
        let mut policy = PolicyConfig::default();
        policy.semantic_expansion.max_nested_parse_depth = depth;
        let response = ShellQueryCore::try_with_policy(policy)
            .unwrap()
            .check(request("echo $(($(rm -rf /)0))"));
        assert_ne!(
            response.decision,
            Decision::Allow,
            "depth={depth}: {response:#?}"
        );
    }
}

#[test]
fn known_array_nameref_does_not_invalidate_unrelated_loop_counter() {
    check(
        r#"pick() {
    local -n items=$1
    local needle=$2 result=''
    for (( idx=${#items[@]}-2; idx>=0; idx-=2 )); do
        if [[ ${items[idx]} == "$needle" ]]; then
            result=${items[idx+1]}
            break
        fi
    done
    printf '%s' "$result"
}
declare -a entries=(word other)
result=$(pick entries word)
printf '%s' "$result""#,
        Decision::Allow,
    );
}

#[test]
fn uncertain_namerefs_keep_loop_counter_approvals() {
    for command in [
        "f() { local -n ref=$1; for ((i=0;i<3;i++)); do echo ok; done; }; f i",
        "f() { local -n ref=$1; for ((i=0;i<3;i++)); do echo ok; done; }; f \"$target\"",
        "f() { local -n ref='a[0]'; for ((i=0;i<3;i++)); do echo ok; done; }; declare -a a=(1); f",
        "f() { local -n ref=$1; for ((i=0;i<3;i++)); do unset a; done; }; declare -a a=(1); f a",
        "f() { for ((i=0;i<3;i++)); do local -n ref=$1; done; }; declare -a a=(1); f a",
        "f() { local -n ref=$1; for ((i=0;i<3;i++)); do printf -v inherited '%s' 1; done; }; declare -a a=(1); declare -n inherited=i; f a",
    ] {
        check(command, Decision::NeedApproval);
    }
}
#[test]
fn whole_numeric_capture_does_not_add_a_second_arithmetic_gap() {
    let source = r#"f() {
        local data=K
        local -i code=$(printf "%d" "'$data")
        echo "$code"
    }; f"#;
    let result = check(source, Decision::Allow);
    assert_eq!(
        result
            .decision_trace
            .derived_invocations
            .iter()
            .filter(|call| call.command_name.as_deref() == Some("printf"))
            .count(),
        1,
    );

    for source in [
        r#"declare -i number=$(printf '%s' "$runtime_value")"#,
        r#"declare -i number=$(printf '%d' 74)other"#,
        r#"printf() { echo "$runtime_value"; }; declare -i number=$(printf '%d' 74)"#,
    ] {
        let result = check(source, Decision::NeedApproval);
        assert!(
            result
                .reasons
                .iter()
                .any(|reason| reason == "shell arithmetic/index expression is unresolved")
        );
    }
}

#[test]
fn numeric_pipeline_capture_preserves_upstream_policy_checks() {
    let source = r#"number=$(printf '%s\n' peach | wc -l)
        let number--
        printf '%d\n' "$number""#;
    check(source, Decision::Allow);

    let source = r#"number=$(find "$runtime_directory" -type d | wc -l)
        let number--
        printf '%d\n' "$number""#;
    let result = check(source, Decision::NeedApproval);
    assert!(result.reasons.iter().any(|reason| {
        reason.starts_with("command find has unresolved operation semantics")
    }));
    assert!(!result.reasons.iter().any(|reason| {
        reason == "shell arithmetic/index expression is unresolved"
    }));

    for source in [
        r#"number=$(printf '%s\n' peach | wc -l sample.txt); let number--"#,
        r#"number=$(printf '%s\n' peach | wc -l; printf '%s' unknown); let number--"#,
        r#"wc() { printf '%s' unknown; }; number=$(printf '%s\n' peach | wc -l); let number--"#,
    ] {
        let result = check(source, Decision::NeedApproval);
        assert!(result.reasons.iter().any(|reason| {
            reason == "shell arithmetic/index expression is unresolved"
        }));
    }
}
