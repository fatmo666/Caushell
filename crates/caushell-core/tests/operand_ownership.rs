//! Static guard checks only. No sample command is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("operand-ownership"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "isolated-bash".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn certified_glob_data_retains_local_scope_for_direct_and_derived_effects() {
    for command in [
        "chmod +x -- *.sh",
        "chown alice -- *.txt",
        "chgrp staff -- *.txt",
        "touch -- *.txt",
        "mkdir -- dir*",
        "cp -- *.txt ./backup/",
        "mv -- *.txt ./backup/",
        "gzip -k -- *cache.html",
        "bzip2 -kv -- */*",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:#?}");
    }
}

#[test]
fn proof_does_not_waive_external_paths_or_deletion() {
    for command in [
        "chmod +x -- /opt/shared/*.sh",
        "touch -- /opt/shared/*.txt",
        "chmod +x -- ../*.sh",
        "gzip -k -- ../*.txt",
        "rm -- *.txt",
        "gzip -- *.txt",
        "bzip2 -- *.txt",
        "chmod +x -- ./../*.sh",
        "chmod +x -- $UNKNOWN",
        "touch -- \"$UNKNOWN\"",
    ] {
        let result = check(command);
        assert_ne!(result.decision, Decision::Allow, "{command}: {result:#?}");
    }
}

#[test]
fn ownership_is_local_to_the_actual_consumer_and_never_a_wrapper_waiver() {
    for command in [
        "env chmod +x -- *.sh",
        "bash -c 'chmod +x -- *.sh'",
        "find . -exec chmod +x -- '*.sh' ';'",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:#?}");
    }
    for command in [
        "chmod +x *.sh",
        "env -- chmod +x *.sh",
        "env -- chmod +x /opt/shared/*.sh",
        "chmod +x -- *.sh; rm /opt/shared/file",
        "chmod +x -- ./.[.]*/*.sh",
    ] {
        let result = check(command);
        assert_ne!(result.decision, Decision::Allow, "{command}: {result:#?}");
    }
}

#[test]
fn literal_program_words_share_the_same_quote_proof_in_every_consumer() {
    for command in [
        "df . -B MB | tail -1 | awk {'print $4'} | cut -d'%' -f1",
        "df . -B MB | tail -1 | awk {'print substr($5, 1, length($5)-1)'}",
        "awk {'print \"a,b\"'} file",
        "sed {'s/a/b/'} file",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:#?}");
    }
    for command in [
        "awk {'system(\"rm /opt/file\")'} file",
        "awk {'print > \"/opt/out\"'} file",
        "sed {'s/a/b/w /opt/out'} file",
        "bash -c r\\\nm' /opt/file'",
        "r\\\nm /opt/file",
        "bash -\\\nc 'rm /opt/file'",
        "bash -'c' 'rm /opt/file'",
        "bash \\-c 'rm /opt/file'",
    ] {
        let result = check(command);
        assert_ne!(result.decision, Decision::Allow, "{command}: {result:#?}");
    }
}

#[test]
fn provably_incomplete_native_copy_move_calls_do_not_invent_side_effects() {
    for command in [
        "cp",
        "cp one",
        "cp -t /opt/output",
        "mv",
        "mv -n",
        "mv one",
        "mv -t /opt/output",
        "cp --help -t /opt/output",
        "mv --help -t /opt/output",
        "find . -name '*c' -print0 | xargs -0 -n1 cp xyz.c",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:#?}");
        assert!(
            !result
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation)
        );
    }
    for command in [
        "cp ./*",
        "mv ./*",
        "cp -- ./*",
        "mv -- ./*",
        "cp -- $UNKNOWN",
        "cp one /opt/out",
        "mv -t /opt/out one",
        "cp -t /opt/out ./*",
        "cp --help $(touch /opt/out)",
    ] {
        let result = check(command);
        assert_ne!(result.decision, Decision::Allow, "{command}: {result:#?}");
    }
}
