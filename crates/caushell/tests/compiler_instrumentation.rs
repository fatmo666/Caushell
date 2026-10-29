//! Real transport/runtime/store roundtrips; submitted compiler programs are not executed.
#![cfg(unix)]
use caushell_types::*;
use std::{fs, io::Cursor};

#[test]
fn instrumentation_checks_restore_authority_and_reject_unknown_or_stale_evidence() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("caushell-instrumentation-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let work = root.join("work");
    fs::create_dir_all(work.join("build")).unwrap();
    fs::write(work.join("input.c"), "not compiled\n").unwrap();
    fs::write(work.join("build/program"), "not executed\n").unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    let round_with_modes = |command: &str, modes: Option<&str>| {
        let mut shell = ShellStateSnapshot::new(work.to_str().unwrap())
            .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
            .with_environment_observation("ENV", ShellEnvironmentValue::Absent);
        shell.observability.variables = ShellStateKnowledge::Complete;
        shell.observability.aliases = ShellStateKnowledge::Complete;
        shell.observability.functions = ShellStateKnowledge::Complete;
        if let Some(modes) = modes {
            shell = shell.with_exact_scalar_variable("SANITIZERS", modes, false);
        }
        let request = RuntimeTransportRequest::Check(RuntimeCheckRequest {
            intent: CheckIntent::JudgeOnly,
            session_id: SessionId::new("instrumentation-stdio"),
            command: command.into(),
            shell_state_before: shell,
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "stdio-test".into(),
                tool_name: Some("Bash".into()),
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
            home: None,
            workspace_root: Some(work.to_str().unwrap().into()),
        });
        let mut runtime =
            caushell::create_runtime(Some(&root.join("defaults.yaml")), Some(&root.join("store")))
                .unwrap();
        let mut output = Vec::new();
        caushell::serve_stdio(
            &mut runtime,
            Cursor::new(serde_json::to_string(&request).unwrap() + "\n"),
            &mut output,
        )
        .unwrap();
        let RuntimeTransportResponse::Check(result) = serde_json::from_slice(&output).unwrap()
        else {
            panic!()
        };
        result.response
    };
    let round = |command: &str| round_with_modes(command, None);
    for (flags, expected) in [
        ("-std=c17", Decision::Allow),
        ("-std=gnu++20 -g", Decision::Allow),
        (
            "-std=iso9899:2018 -fsanitize=address,undefined",
            Decision::Allow,
        ),
        ("-std=unknown -std=c17", Decision::NeedApproval),
    ] {
        let response = round(&format!(
            "gcc {flags} input.c -o build/program && ./build/program"
        ));
        assert_eq!(
            response.decision, expected,
            "{flags}: {:?}",
            response.reasons
        );
    }
    let first =
        round("gcc -g3 -fsanitize=address,undefined input.c -o build/program && ./build/program");
    assert_eq!(first.decision, Decision::Allow, "{:?}", first.reasons);
    assert!(
        first
            .decision_trace
            .path_targets
            .iter()
            .any(|p| !p.namespace_proofs.is_empty())
    );
    let dynamic_command =
        "gcc -g -fsanitize=\"$SANITIZERS\" input.c -o build/program && ./build/program";
    for (modes, expected) in [
        ("address,undefined", Decision::Allow),
        ("unknown", Decision::NeedApproval),
        ("undefined,address", Decision::Allow),
    ] {
        let response = round_with_modes(dynamic_command, Some(modes));
        assert_eq!(
            response.decision, expected,
            "{modes}: {:?}",
            response.reasons
        );
        assert_eq!(
            response
                .decision_trace
                .path_targets
                .iter()
                .any(|p| !p.namespace_proofs.is_empty()),
            expected == Decision::Allow
        );
    }
    let unknown = round("gcc -g -fsanitize=unknown input.c -o build/program && ./build/program");
    assert_eq!(
        unknown.decision,
        Decision::NeedApproval,
        "{:?}",
        unknown.reasons
    );
    assert!(
        unknown
            .decision_trace
            .path_targets
            .iter()
            .all(|p| p.namespace_proofs.is_empty())
    );
    assert_eq!(
        round("gcc -g -fsanitize=address input.c -o build/program; rm -rf /").decision,
        Decision::Deny
    );
    let deletion = round(
        "rm -f build/program; gcc -g -fsanitize=address input.c -o build/program && ./build/program",
    );
    assert_eq!(deletion.decision, Decision::NeedApproval);
    assert!(
        deletion
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::FileDeletion)
    );
    assert_eq!(
        fs::read_to_string(work.join("build/program")).unwrap(),
        "not executed\n"
    );
    fs::remove_file(work.join("build/program")).unwrap();
    std::os::unix::fs::symlink("/outside/program", work.join("build/program")).unwrap();
    let stale = round("gcc -g -fsanitize=address input.c -o build/program && ./build/program");
    assert_eq!(
        stale.decision,
        Decision::NeedApproval,
        "{:?}",
        stale.reasons
    );
    assert!(
        stale
            .decision_trace
            .path_targets
            .iter()
            .all(|p| p.namespace_proofs.is_empty())
    );
    fs::remove_dir_all(root).unwrap();
}
