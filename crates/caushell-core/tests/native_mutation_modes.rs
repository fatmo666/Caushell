//! End-to-end static guard checks; no sample command is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("native-mutation-modes"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

fn expect(command: &str, decision: Decision) {
    let r = check(command);
    assert_eq!(r.decision, decision, "{command}: {r:#?}");
}

#[test]
fn perl_in_place_external_targets_need_approval() {
    for command in [
        "perl -pi -e 's/a/b/' /opt/shared/file",
        "perl -i.bak -pe 's/a/b/' /opt/shared/file",
        r"find /opt/shared -type f -exec perl -pi -e 's/a/b/' {} \;",
        "find /opt/shared -print0 | xargs -0 perl -pi -e 's/a/b/'",
        "perl -pi -e 's/a/b/' \"$target\"",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn perl_local_in_place_and_no_filename_do_not_invent_external_writes() {
    for command in [
        "perl -pi -e 's/a/b/' cache/file",
        "perl -i.bak -pe 's/a/b/' cache/file",
        "perl -i -e 1",
        "perl -e 'print 1' -- -i",
        "perl -c -pi -e 1 /opt/shared/file",
        "perl -V",
        "perl -lnE'print $_'",
        "perl -F'(.{1,3})' -anE'print @F'",
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn perl_backup_templates_unknown_options_and_runtime_sources_keep_approval() {
    for command in [
        "perl -i'/opt/shared/*' -pe 's/a/b/' file",
        "perl -i'../*' -pe 's/a/b/' file",
        "perl --unmodeled -pi -e 1 file",
        "perl -i\"$suffix\" -pe 1 file",
        "perl -e\"$code\"",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn rsync_external_dry_run_is_allowed_but_real_writes_are_not() {
    for command in [
        "rsync -an --delete input /opt/shared",
        "rsync --dry-run input /opt/shared",
        "rsync --list-only input /opt/shared",
        "rsync -n --remove-source-files /opt/shared/file cache",
        "rsync input /opt/shared --dry-run",
        "rsync /opt/shared",
        "rsync -a -f\"+ */\" -f\"- *\" source/ destination/",
    ] {
        expect(command, Decision::Allow);
    }
    for command in [
        "rsync -a --delete input /opt/shared",
        "rsync --remove-source-files /opt/shared/file cache",
        "rsync -an --log-file=/opt/shared/log input cache",
        "rsync --exclude -n input /opt/shared",
        "rsync -a -- input --dry-run",
        "rsync -n --unknown input /opt/shared",
        "rsync --read-batch=batch /opt/shared/output",
    ] {
        // '--dry-run' after '--' is a literal local destination; not preview.
        let expected = if command == "rsync -a -- input --dry-run" {
            Decision::Allow
        } else {
            Decision::NeedApproval
        };
        expect(command, expected);
    }
}

#[test]
fn split_filter_shell_effects_reach_existing_guards() {
    for command in [
        "split --filter='cat > /opt/shared/output' input",
        "split --filter='touch /opt/shared/output' input",
        "split --filter='/bin/sh -i 0<&2 1>&2' input",
        "split --filter='cat > \"$FILE\"' input",
        "export FILE=cache/safe; split --filter='cat > \"$FILE\"' input /opt/shared/chunk",
    ] {
        expect(command, Decision::NeedApproval);
    }
    let r = check("split --filter='touch /opt/shared/output' input");
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "touch"),
        "{r:#?}"
    );
    assert!(
        r.decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation),
        "{r:#?}"
    );
}

#[test]
fn split_filter_does_not_write_the_named_prefix_itself() {
    for command in [
        "split --filter='cat' input /opt/shared/chunk",
        "split --filter='cat > cache/output' input",
        "split -n 1/3 input /opt/shared/chunk",
        "split -d -b 1000 - cache/chunk",
        "split --help",
        "split --numeric-suffixes=1 --additional-suffix=.csv -l100 data.csv data_",
        "split -b 10 input -",
        "split --filter=cat - -",
    ] {
        expect(command, Decision::Allow);
    }
    for command in [
        "split -b 1000 input /opt/shared/chunk",
        "split --additional-suffix=/../../bad input cache/chunk",
        "split --unmodeled input",
        "split --filter='echo ok' --additional-suffix=../bad input",
        "split --additional-suffix=\"$suffix\" input cache/chunk",
    ] {
        expect(command, Decision::NeedApproval);
    }
}
