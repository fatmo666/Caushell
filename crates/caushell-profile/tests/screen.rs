//! Static Profile inputs only; no terminal session is launched or controlled.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ShellKind, TerminalSessionOperationKind as Op};
use std::sync::OnceLock;

fn result(command: &str) -> ResolveInvocationResult<'static> {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap());
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    )
}
fn operation(command: &str, expected: Op) -> BoundInvocation {
    let bound = match result(command) {
        ResolveInvocationResult::Resolved(r) => {
            assert!(r.bound.residuals.is_empty(), "{command}: {:?}", r.bound);
            r.bound
        }
        other => panic!("{command}: {other:?}"),
    };
    let ops: Vec<_> = bound
        .effects
        .iter()
        .filter_map(|e| e.terminal_session_operation)
        .collect();
    assert_eq!(ops, [expected], "{command}: {bound:?}");
    bound
}

#[test]
fn registers_native_screen_with_exact_leading_options() {
    let registry = ProfileRegistry::built_in().unwrap();
    for name in ["screen", "/usr/bin/screen"] {
        let p = registry.lookup(name).profile.unwrap();
        assert_eq!(p.primary_name(), "screen");
        assert!(p.identity.aliases.is_empty());
        assert_eq!(p.option_matching, OptionMatchingPolicy::ExactNames);
        assert_eq!(p.option_scope, OptionScopePolicy::LeadingOptions);
    }
}
#[test]
fn explicit_inspection_forms_and_option_operands_are_not_launches() {
    for command in [
        "screen -v",
        "screen -ls",
        "screen -list",
        "screen -ls build",
        "screen -q -ls build",
        "screen -S build -Q windows",
        "screen -Q info",
        "screen -S build -p 0 -Q title",
        "screen -Q number",
        "screen -Q lastmsg",
    ] {
        let b = operation(command, Op::Inspect);
        assert!(
            b.effects
                .iter()
                .all(|e| e.kind == EffectKind::TerminalSessionOperation)
        );
    }
}
#[test]
fn query_admission_is_case_sensitive_and_argumentless() {
    for command in [
        "screen -Q title new-title",
        "screen -Q number 1",
        "screen -Q select 1",
        "screen -Q echo hi",
        "screen -Q Info",
        "screen -Q future",
        "screen -Q time",
        "screen -Q",
        "screen -Q title -X stuff",
        "screen -ls build -wipe",
        "screen -ls -wipe",
        "screen -v -X quit",
        "screen -c config -ls",
        "screen -L -Q windows",
        "screen -ls -Q windows",
    ] {
        operation(command, Op::Opaque);
    }
}
#[test]
fn launches_and_common_detached_spellings_are_explicit_operations() {
    for command in [
        "screen",
        "screen bash -c 'echo ok'",
        "screen -m",
        "screen -dm sleep 1",
        "screen -Dm sleep 1",
        "screen -dmS build sleep 1",
        "screen -DmS build sleep 1",
        "screen -d -m -S build sleep 1",
        "screen -c config -L -Logfile 'log.%n' bash",
        "screen -s /bin/bash -t build",
        "screen -fn -U -T xterm sleep 1",
    ] {
        operation(command, Op::Create);
    }
}
#[test]
fn attachment_and_remote_control_are_not_bash_payloads() {
    for command in [
        "screen -r build",
        "screen -RR",
        "screen -x",
        "screen -dr build",
        "screen -D -RR build",
    ] {
        operation(command, Op::Attach);
    }
    for command in [
        "screen -d build",
        "screen -D build",
        "screen -wipe build",
        "screen -S build -X stuff 'rm -f /etc/a\n'",
        "screen -X source /etc/screenrc",
        "screen -X eval 'stuff hi' 'screen bash'",
        "screen -X screen bash -c 'echo hi'",
        "screen -X hardcopy /etc/output",
        "screen -X quit",
    ] {
        let b = operation(command, Op::Control);
        assert!(collect_recursive_payload_candidates(&b).is_empty());
        assert!(
            b.effects
                .iter()
                .all(|e| e.kind == EffectKind::TerminalSessionOperation)
        );
        assert!(
            b.bound_parameters
                .iter()
                .all(|p| p.semantic == SemanticType::PlainValue)
        );
    }
}
#[test]
fn unsupported_or_incomplete_options_keep_explicit_opaque_effects() {
    for command in [
        "screen --version",
        "screen --future",
        "screen -S",
        "screen -c",
        "screen -Logfile",
        "screen -dmS",
        "screen -lsS build",
        "screen -Q -S",
    ] {
        match result(command) {
            ResolveInvocationResult::SelectionError {
                partial_bound: Some(b),
                ..
            } => {
                assert!(
                    b.effects
                        .iter()
                        .any(|e| e.terminal_session_operation == Some(Op::Opaque)),
                    "{command}: {b:?}"
                );
            }
            other => panic!("{command}: {other:?}"),
        }
    }
}
#[test]
fn flags_inside_child_argv_or_control_text_do_not_become_screen_options() {
    operation("screen printf -ls", Op::Create);
    operation("screen bash -c 'screen -ls'", Op::Create);
    operation("screen -X stuff '-ls'", Op::Control);
    operation("screen -X screen -Q info", Op::Control);
}

#[test]
fn inspection_does_not_certify_dynamic_expansion_or_repeated_option_ownership() {
    for command in [
        "screen -ls $PATTERN",
        "screen -ls *",
        "screen -ls 'name with spaces'",
        "screen -S $SESSION -Q info",
        "screen -S \"$SESSION\" -Q info",
        "screen -p $WINDOW -Q title",
        "screen -S $SESSION -v",
        "screen -S first -S second -Q windows",
        "screen -p 0 -p 1 -Q title",
    ] {
        operation(command, Op::Opaque);
    }
    operation("screen -S 1234.build -p 0 -Q windows", Op::Inspect);
    operation("screen -list 1234.build", Op::Inspect);
}
