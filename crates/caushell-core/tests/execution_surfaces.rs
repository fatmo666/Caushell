//! Static Graph/policy checks only: no client, database or browser is run.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str, expected: Decision) -> CheckResponse {
    let r = ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("execution-surfaces"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    });
    assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    r
}
fn rule(r: &CheckResponse, rule: RuleId) -> bool {
    r.decision_trace
        .decision_proposals
        .iter()
        .any(|p| p.rule_id == rule)
}

#[test]
fn benchmark_interactive_misses_and_related_entry_points_are_approved_by_existing_guard() {
    for command in [
        "psql\n\\?",
        "psql\n\\! /bin/sh",
        "psql",
        "psql -X -w",
        "links /path/to/input-file",
        "links",
        "links -anonymous /tmp/input.html",
        "alpine -F /path/to/input-file",
        "alpine",
        "alpine -r -o -F /tmp/input.txt",
        "w3m /tmp/input.html",
        "env links /tmp/input.html",
        "find . -type f -exec links '{}' \\;",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(
            rule(&r, RuleId::InteractiveEscapeSurface),
            "{command}: {:?}",
            r.reasons
        );
    }
}

#[test]
fn psql_sql_client_commands_files_and_streams_are_not_readonly_data() {
    for command in [
        r"psql -c 'SELECT 1'",
        r"psql -c '\! /bin/sh'",
        "psql -c 'DROP TABLE example'",
        "psql -X -f ./script.sql",
        "psql -f /tmp/script.sql",
        "psql --file=-",
        "psql -f local.sql -f - -c 'SELECT 1'",
        "psql -c 'SELECT 1' -f local.sql -c 'SELECT 2'",
        "printf '%s\\n' 'SELECT 1' | psql -X",
        "cat local.sql | psql",
        "psql <<'SQL'\nSELECT 1;\nSQL",
        "env psql -c 'SELECT 1'",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(
            rule(&r, RuleId::DatabaseOpaqueExecution),
            "{command}: {:?}",
            r.reasons
        );
        assert_eq!(
            rule(&r, RuleId::NestedPayloadExpansion),
            !matches!(
                command,
                "psql -X -f ./script.sql" | "psql -f /tmp/script.sql"
            ),
            "{command}: {:?}",
            r.reasons
        );
        assert!(
            !r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "DROP"
                    || s.normalized_command_name == "SELECT"),
            "{command}"
        );
    }
}

#[test]
fn information_and_explicit_local_dumps_keep_allow() {
    for command in [
        "psql --help",
        "psql --help=commands",
        "psql --version",
        "psql -V",
        "psql '-?'",
        "psql -c 'SELECT 1' --help",
        "psql -f /opt/not-read.sql --version",
        "psql -o '' --version",
        "links -help",
        "links -version",
        "alpine -h",
        "alpine -v",
        "alpine -version",
        "alpine -supported",
        "links -dump /opt/input.html",
        "links -source /opt/input.html",
        "links -dump -width 80 /opt/input.html",
        "w3m -dump /opt/input.html",
    ] {
        let r = check(command, Decision::Allow);
        assert!(!rule(&r, RuleId::InteractiveEscapeSurface), "{command}");
        assert!(!rule(&r, RuleId::NestedPayloadExpansion), "{command}");
    }
}

#[test]
fn option_operands_do_not_turn_into_information_or_dump_flags() {
    for command in [
        "psql -c --help",
        "psql -f --version",
        "psql --command",
        "psql -c",
        "psql -f",
        "psql --unknown",
        "psql -P --help",
        "psql -?",
        "alpine -F -h",
        "alpine -F",
        "alpine -pinerc /opt/output -h",
        "links -width -dump input.html",
        "links -dump /opt/input.html extra.html",
        "links --unknown -help",
        "links -dumpfile.html",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn output_pipes_and_files_keep_independent_effects_even_on_information_calls() {
    for command in [
        "psql -o '|/bin/sh' --help",
        "psql -o '|/bin/sh' -c 'SELECT 1'",
        "psql -o '|/bin/sh' -l",
        "psql -o '/opt/output' --version",
        "psql -L /opt/log --help",
    ] {
        check(command, Decision::NeedApproval);
    }
    let r = check("psql -o '|/bin/sh' --help", Decision::NeedApproval);
    assert!(rule(&r, RuleId::NestedPayloadExpansion));
    let r = check("psql -o /opt/output --version", Decision::NeedApproval);
    assert!(rule(&r, RuleId::OutsideWorkspaceMutation));
}

#[test]
fn database_listing_does_not_execute_queued_client_programs() {
    let r = check(
        r"psql -X -l -c '\! /bin/sh' -f /opt/script.sql",
        Decision::NeedApproval,
    );
    assert!(rule(&r, RuleId::DatabaseOpaqueExecution));
    assert!(!rule(&r, RuleId::NestedPayloadExpansion));
}
