//! GNU tar aliases go through the same analysis and approval checks as tar.
use caushell_core::ShellQueryCore;
use caushell_types::{
    CheckRequest, CheckResponse, CommandSequenceNo, Decision, RuntimeMetadata, SessionId,
    ShellEnvironmentValue, ShellKind, ShellRuntimeCapabilities, ShellStateKnowledge,
    ShellStateSnapshot,
};

const ALIASES: [&str; 2] = ["gnutar", "gtar"];

fn check(program: &str, args: &str, options_observed_absent: bool) -> CheckResponse {
    let mut state = ShellStateSnapshot::new("/tmp/project");
    if options_observed_absent {
        state = state.with_environment_observation("TAR_OPTIONS", ShellEnvironmentValue::Absent);
    }
    state.observability.aliases = ShellStateKnowledge::Complete;
    state.observability.functions = ShellStateKnowledge::Complete;
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("gnutar-profile-alias"),
        sequence_no: CommandSequenceNo::new(1),
        command: format!("{program} {args}"),
        shell_state_before: state,
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-tar".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    })
}

#[test]
fn aliases_resolve_the_same_local_archive_form() {
    let args = "-cf ./fixture.tar ./fixture.txt";
    let canonical = check("tar", args, true);
    assert_eq!(
        canonical.decision,
        Decision::Allow,
        "{:?}",
        canonical.reasons
    );
    for alias in ALIASES {
        let response = check(alias, args, true);
        assert_eq!(
            response.decision, canonical.decision,
            "{alias}: {:?}",
            response.reasons
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|fact| {
                    fact.form_id == "create_archive" && !fact.operation_semantics_unresolved
                }),
            "{alias}: {:?}",
            response.reasons
        );
    }
}

#[test]
fn aliases_require_the_same_tar_options_evidence() {
    for program in ["tar", "gnutar", "gtar"] {
        let response = check(program, "-cf ./fixture.tar ./fixture.txt", false);
        assert_eq!(response.decision, Decision::NeedApproval);
        assert!(
            response.reasons.iter().any(|reason| {
                reason.contains("TAR_OPTIONS option environment is not observed")
            }),
            "{program}: {:?}",
            response.reasons
        );
    }
}

#[test]
fn aliases_preserve_path_and_unresolved_archive_checks() {
    for program in ["tar", "gnutar", "gtar"] {
        for args in [
            "-cf /opt/fixture/out.tar ./fixture.txt",
            "-xf ./fixture.tar",
        ] {
            let response = check(program, args, true);
            assert_eq!(
                response.decision,
                Decision::NeedApproval,
                "{program} {args}: {:?}",
                response.reasons
            );
        }
    }
}
