//! Static command analysis only; none of these copy commands are executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("cp-argv"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        workspace_root: Some("/workspace".into()),
        home: Some("/home/alice".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

fn expect(command: &str, expected: Decision) -> CheckResponse {
    let response = check(command);
    assert_eq!(response.decision, expected, "{command}: {response:#?}");
    response
}

#[test]
fn dynamic_words_cannot_silently_override_the_explicit_copy_destination() {
    for command in [
        "cp * .hiddendir -R",
        "cp -f \"$project_dir\"/input cache/output",
        "cp -Rp \"$appname.app\" Payload/",
        "cp --remove-destination `readlink file` file",
        "cp -rv $(ls -A) targetDir",
        "find /testbed -type f -path '*FooBar*' | xargs -i cp -p \"{}\" .",
        "find . -name '*.txt' | xargs -I{} cp {} ./cache/",
        "cat args | xargs -0 cp -t ./cache/",
        "find dir/ -name '*.txt' | xargs cp -a --target-directory=cache/ --parents",
    ] {
        let response = expect(command, Decision::NeedApproval);
        assert!(
            response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError),
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "cp" && s.operation_semantics_unresolved),
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn explicit_terminators_and_proven_non_option_paths_keep_local_copies_allowed() {
    for command in [
        "cp -R -- * .hiddendir",
        "cp ./* .hiddendir -R",
        "cp -f -- \"$project_dir\"/input cache/output",
        "cp -f ./\"$project_dir\"/input cache/output",
        "cp -a /opt/shared/input cache/output",
        "find ./input -type f -print0 | xargs -0 cp -t ./cache/",
        "find ./input -type f -print0 | xargs -0 -I{} cp {} ./cache/",
        "cat args | xargs -0 cp -t ./cache/ --",
        "cp -v -- --target-directory=.. ./cache/",
    ] {
        let response = expect(command, Decision::Allow);
        assert!(
            !response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError),
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn native_permutation_option_operands_and_short_clusters_remain_supported() {
    for command in [
        "cp -av input cache/output",
        "cp input cache/output -av",
        "cp input -tcache -av",
        "cp input --target-directory=cache -av",
        "cp input -t cache -S --help -b",
        "cp --preserve=all --no-preserve=links input cache/output",
        "cp --backup=numbered --suffix=.bak --reflink=always --sparse=never input cache/output",
        "cp --backup input cache/output",
        "cp -bu input cache/output",
        "cp --update=none --context input cache/output",
        "cp --update=all --context=some_context input cache/output",
    ] {
        expect(command, Decision::Allow);
    }
    for command in [
        "cp input cache/output --unmodeled-option",
        "cp input -t",
        "cp --no-preserve input cache/output",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn explicit_and_statically_reconstructed_external_options_preserve_real_targets() {
    for command in [
        "cp input ./cache --target-directory=/opt/shared",
        "cp input ./cache -t/opt/shared",
        r"printf '%s\0' '--target-directory=/opt/shared' input | xargs -0 cp ./cache",
        r"printf '%s\n' '--target-directory=/opt/shared' | xargs -I{} cp -R {} ./cache",
    ] {
        let response = expect(command, Decision::NeedApproval);
        assert!(
            response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation
                    && p.reason.contains("/opt/shared")),
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn information_flags_are_effect_free_but_option_shaped_values_are_not_help() {
    for command in [
        "cp --help -t /opt/shared input",
        "cp input --version -t /opt/shared",
    ] {
        expect(command, Decision::Allow);
    }
    let response = expect("cp input -t --help", Decision::Allow);
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "cp" && s.form_id == "target_directory")
    );
    let response = expect(
        "cp --target-directory=/opt/shared -- --help",
        Decision::NeedApproval,
    );
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "cp" && s.form_id == "target_directory")
    );
}
