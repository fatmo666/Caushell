//! Static checks for getconf integer-limit queries.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("getconf-integer-limits"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-fixture".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(request(command))
}

#[test]
fn integer_limit_queries_keep_unproved_default_abi_selection_visible() {
    for command in [
        "getconf WORD_BIT",
        "/usr/bin/getconf LONG_BIT",
        "GETCONF_DIR=./fixture-directory getconf WORD_BIT",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
        let query = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "getconf")
            .expect("known getconf form");
        assert_eq!(query.form_id, "print_integer_width");
        assert!(query.loads_tool_config);
        assert!(query.executes_payload && query.operation_semantics_unresolved);
    }
}

#[test]
fn helper_selection_unknown_input_and_other_effects_keep_their_own_checks() {
    for command in [
        "getconf",
        "getconf -a",
        "getconf -v POSIX_V7_LP64_OFF64 LONG_BIT",
        "getconf LONG_BIT -v POSIX_V7_LP64_OFF64",
        "getconf PATH",
        "getconf NAME_MAX .",
        "getconf LONG_BIT .",
        "getconf \"$unknown\"",
        "getconf $unknown",
        "getconf LONG_BIT > /outside/fixture.txt",
        "getconf LONG_BIT | sh",
    ] {
        let result = check(command);
        assert_ne!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn enumeration_forms_expose_path_queries_without_assuming_a_trusted_helper() {
    use caushell_parse::parse_command;
    use caushell_profile::{
        EffectKind, EffectTarget, InvocationRuntimeContext, ProfileRegistry,
        ResolveInvocationArtifactResult, SessionBindings,
        resolve_invocation_artifact_with_bindings,
    };

    let registry = ProfileRegistry::built_in().unwrap();
    for (command, form) in [
        ("getconf -a", "list_configuration"),
        ("getconf -a ./fixture-directory", "list_path_configuration"),
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        let query = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| entry.normalized_command_name == "getconf")
            .expect("getconf enumeration should resolve to a named form");
        assert_eq!(query.form_id, form);
        assert!(query.loads_tool_config && query.executes_payload);
        assert!(query.operation_semantics_unresolved);

        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationArtifactResult::Resolved(resolved) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash),
                &SessionBindings::new(),
            )
        else {
            panic!("{command}: expected resolved getconf");
        };
        let effect = resolved
            .bound
            .effects
            .iter()
            .find(|effect| effect.kind == EffectKind::ReadPath)
            .expect("metadata lookup should have a source path");
        assert_eq!(effect.path_access, None);
        match &effect.target {
            EffectTarget::ToolConventionPath(target) if form == "list_configuration" => {
                assert_eq!(target.path, "/");
            }
            EffectTarget::Slot(slot) if form == "list_path_configuration" => {
                assert_eq!(slot.as_str(), "pathname");
            }
            other => panic!("{command}: unexpected path target {other:?}"),
        }
        assert!(resolved.bound.stdout_records.is_none());
        assert!(resolved.bound.stdout_scalar.is_none());
    }
}

#[test]
fn malformed_or_dynamic_enumeration_stays_unresolved() {
    for command in [
        "getconf WORD_BIT -a",
        "getconf -a -a",
        "getconf -a -- ./fixture-directory",
        "getconf -a ./fixture-directory ./other-directory",
        "getconf -a -v POSIX_V7_LP64_OFF64",
        "getconf -a \"$unknown\"",
    ] {
        let result = check(command);
        assert_ne!(result.decision, Decision::Allow, "{command}");
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .all(|entry| {
                    entry.normalized_command_name != "getconf"
                        || !entry.form_id.starts_with("list_")
                }),
            "{command}: {:?}",
            result.decision_trace.execution_semantics
        );
    }
}

#[test]
fn attested_binary_only_closes_complete_read_only_queries() {
    use Decision::{Allow, NeedApproval};

    let verified = Some("debian_getconf_2_36_deb12u14");
    let width = Some("attested_integer_width");
    let enumeration = Some("attested_list_configuration");
    for (command, identity, expected, form) in [
        ("getconf LONG_BIT", verified, Allow, width),
        ("getconf WORD_BIT", verified, Allow, width),
        ("getconf -a", verified, Allow, enumeration),
        ("getconf -a | wc -l", verified, Allow, enumeration),
        ("getconf WORD_BIT", None, NeedApproval, None),
        ("getconf -a", Some("unknown_getconf"), NeedApproval, None),
        (
            "PATH=./bin:$PATH getconf WORD_BIT",
            verified,
            NeedApproval,
            None,
        ),
        (
            "export PATH=./bin:$PATH; getconf WORD_BIT",
            verified,
            NeedApproval,
            None,
        ),
        ("/usr/bin/getconf LONG_BIT", verified, NeedApproval, None),
        (
            "getconf -v POSIX_V7_LP64_OFF64 WORD_BIT",
            verified,
            NeedApproval,
            None,
        ),
        (
            "getconf WORD_BIT -v POSIX_V7_LP64_OFF64",
            verified,
            NeedApproval,
            None,
        ),
        ("getconf -a ./fixture", verified, NeedApproval, None),
        ("getconf -a -a", verified, NeedApproval, None),
        ("getconf \"$QUERY\"", verified, NeedApproval, None),
        (
            "getconf WORD_BIT > /outside/fixture.txt",
            verified,
            NeedApproval,
            width,
        ),
        ("getconf WORD_BIT | sh", verified, NeedApproval, width),
    ] {
        let inventory = identity
            .map(|identity| ("getconf".into(), identity.into()))
            .into_iter()
            .collect();
        let result = ShellQueryCore::new()
            .try_judge_static_shell_with_native_variants(request(command), &inventory)
            .unwrap();
        assert_eq!(result.decision, expected, "{command}: {:?}", result.reasons);
        let selected = result
            .decision_trace
            .execution_semantics
            .iter()
            .find(|entry| {
                entry.normalized_command_name == "getconf" && entry.form_id.starts_with("attested_")
            });
        assert_eq!(
            selected.map(|entry| entry.form_id.as_str()),
            form,
            "{command}"
        );
        if let Some(entry) = selected {
            assert!(!entry.executes_payload && !entry.loads_tool_config);
            assert!(!entry.operation_semantics_unresolved);
        }
    }
}
