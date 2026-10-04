//! Static inputs only; no Redis command is executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{DatabaseOperationKind as Operation, ShellKind};
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
fn bound(command: &str) -> BoundInvocation {
    match result(command) {
        ResolveInvocationResult::Resolved(r) => {
            assert!(r.bound.residuals.is_empty(), "{command}: {:?}", r.bound);
            r.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}
fn operation(command: &str, expected: Operation) -> BoundInvocation {
    let b = bound(command);
    let operations: Vec<_> = b
        .effects
        .iter()
        .filter(|e| e.kind == EffectKind::DatabaseOperation)
        .filter_map(|e| e.database_operation)
        .collect();
    assert_eq!(operations, [expected], "{command}: {b:?}");
    b
}
fn values(b: &BoundInvocation, slot: &str) -> Vec<String> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .filter_map(|v| match v {
            BoundValue::Argument { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn registers_native_cli_without_invented_aliases() {
    let r = ProfileRegistry::built_in().unwrap();
    for name in ["redis-cli", "/usr/bin/redis-cli"] {
        let p = r.lookup(name).profile.unwrap();
        assert_eq!(p.primary_name(), "redis-cli");
        assert!(p.identity.aliases.is_empty());
        assert_eq!(p.option_scope, OptionScopePolicy::LeadingOptions);
        assert_eq!(p.option_matching, OptionMatchingPolicy::ExactNames);
    }
}
#[test]
fn queries_are_case_insensitive_complete_names_not_prefixes() {
    for c in [
        "redis-cli GET /etc/a",
        "redis-cli get key",
        "redis-cli GeT key",
        "redis-cli DBSIZE",
        "redis-cli EXISTS key",
        "redis-cli CONFIG get dir",
        "redis-cli CLIENT LIST",
        "redis-cli CLUSTER INFO",
        "redis-cli COMMAND INFO GET",
        "redis-cli MEMORY USAGE key",
        "redis-cli SORT_RO key",
        "redis-cli XREAD STREAMS x 0",
        "redis-cli LATENCY LATEST",
    ] {
        operation(c, Operation::Read);
    }
    for c in [
        "redis-cli GETDEL key",
        "redis-cli GETEX key EX 30",
        "redis-cli GETSET key v",
        "redis-cli ZRANGESTORE target source 0 -1",
    ] {
        let b = bound(c);
        assert!(
            !b.effects
                .iter()
                .any(|e| e.database_operation == Some(Operation::Read)),
            "{c}"
        );
    }
}
#[test]
fn writes_management_and_opaque_commands_are_distinct() {
    for c in [
        "redis-cli SET key value",
        "redis-cli DEL key",
        "redis-cli flushall ASYNC",
        "redis-cli HSET map k v",
        "redis-cli SORT list STORE output",
        "redis-cli --lru-test 10",
    ] {
        operation(c, Operation::Write);
    }
    for c in [
        "redis-cli CONFIG SET dir /etc",
        "redis-cli SHUTDOWN NOSAVE",
        "redis-cli ACL SETUSER user on",
        "redis-cli CLIENT KILL ID 5",
        "redis-cli --cluster check 127.0.0.1:6379",
        "redis-cli --replica",
    ] {
        operation(c, Operation::Administration);
    }
    for c in [
        "redis-cli EVAL 'return 1' 0",
        "redis-cli EVAL_RO 'return 1' 0",
        "redis-cli FCALL_RO f 0",
        "redis-cli EXEC",
        "redis-cli CUSTOM.DO value",
        "redis-cli \"$CMD\" value",
    ] {
        operation(c, Operation::Opaque);
    }
}
#[test]
fn keys_and_options_after_command_remain_plain_argv() {
    let b = operation("redis-cli GET --eval /etc/not-a-script", Operation::Read);
    assert_eq!(
        values(&b, "command_arguments"),
        ["GET", "--eval", "/etc/not-a-script"]
    );
    assert!(b.bound_parameters.iter().all(|p| p.semantic_values().next().is_none() || p.semantic == SemanticType::PlainValue));
    assert!(!b.effects.iter().any(|e| matches!(
        e.kind,
        EffectKind::ReadPath | EffectKind::WritePath | EffectKind::ExecutePayload
    )));
    operation("redis-cli --eval local.lua GET key", Operation::Opaque);
}
#[test]
fn connection_operands_do_not_become_commands_or_help() {
    let b = operation(
        "redis-cli -h localhost -p 6380 -n 2 -a --help --user test --raw -r 1 GET /etc/key",
        Operation::Read,
    );
    assert_eq!(values(&b, "command_arguments"), ["GET", "/etc/key"]);
    assert_eq!(values(&b, "host"), ["localhost"]);
    operation(
        "redis-cli -s /tmp/project/db.sock SET key v",
        Operation::Write,
    );
    operation(
        "redis-cli -u redis://localhost:6379/2 --json CONFIG GET dir",
        Operation::Read,
    );
}
#[test]
fn input_reinterpretation_and_special_modes_cannot_hide_under_get() {
    for c in [
        "redis-cli -x GET",
        "redis-cli -X GET GET key",
        "redis-cli --quoted-input GET key",
        "redis-cli --pipe GET key",
        "redis-cli --eval script.lua GET key",
        "redis-cli --ldb --eval script.lua",
        "redis-cli --test_hint_file hints GET key",
    ] {
        operation(c, Operation::Opaque);
    }
    operation(
        "redis-cli --cluster fix localhost:6379 GET key",
        Operation::Administration,
    );
}
#[test]
fn interactive_stdin_and_script_file_keep_non_bash_contracts() {
    let b = operation("redis-cli", Operation::Opaque);
    assert_eq!(b.bound_implicit_inputs.len(), 1);
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::ConsumeStdin));
    let b = operation("redis-cli --eval script.lua k , v", Operation::Opaque);
    assert_eq!(values(&b, "lua_file"), ["script.lua"]);
    assert!(
        !b.effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecutePayload)
    );
    assert!(collect_recursive_payload_candidates(&b).is_empty());
}
#[test]
fn backups_have_real_file_targets_and_stdout_has_none() {
    let b = operation("redis-cli --rdb /backup/dump.rdb", Operation::Read);
    assert_eq!(values(&b, "backup_operands"), ["/backup/dump.rdb"]);
    let paths: Vec<_> = b
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == "backup_paths")
        .flat_map(|p| p.semantic_values())
        .collect();
    assert_eq!(paths.len(), 1);
    let b = operation("redis-cli --functions-rdb -", Operation::Read);
    assert!(
        b.bound_parameters
            .iter()
            .filter(|p| p.name.as_str() == "backup_paths")
            .all(|p| p.semantic_values().next().is_none())
    );
}
#[test]
fn unsupported_leading_options_retain_declared_opaque_effects() {
    for c in [
        "redis-cli --new-option GET key",
        "redis-cli -h",
        "redis-cli -p6379 GET key",
        "redis-cli --eval",
        "redis-cli --rdb",
        "redis-cli -abc GET key",
    ] {
        match result(c) {
            ResolveInvocationResult::SelectionError {
                partial_bound: Some(b),
                ..
            } => assert!(
                b.effects
                    .iter()
                    .any(|e| e.database_operation == Some(Operation::Opaque)),
                "{c}: {b:?}"
            ),
            other => panic!("{c}: {other:?}"),
        }
    }
}
#[test]
fn information_modes_are_not_database_execution() {
    for c in [
        "redis-cli --help",
        "redis-cli --version",
        "redis-cli -v",
        "redis-cli --help --eval missing.lua",
        "redis-cli --version FLUSHALL",
    ] {
        let b = bound(c);
        assert_eq!(b.form_id.as_str(), "information");
        assert!(
            !b.effects
                .iter()
                .any(|e| e.kind == EffectKind::DatabaseOperation)
        );
    }
}
#[test]
fn diagnostic_modes_and_supported_output_switches_are_queries() {
    for c in [
        "redis-cli --scan --pattern 'item:*' --count 50",
        "redis-cli --latency",
        "redis-cli --stat",
        "redis-cli --bigkeys",
        "redis-cli --keystats --top 5",
        "redis-cli --intrinsic-latency 1",
        "redis-cli --tls --cacert ca.pem --cert cert.pem --key key.pem --csv -3 GET k",
    ] {
        operation(c, Operation::Read);
    }
}
