use caushell_profile::{
    EffectKind, InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult,
    SessionBindings, load_command_profile_from_str, resolve_invocation_artifact_with_bindings,
};
use caushell_types::{ShellKind, StateOperationDomain, StateOperationKind};

#[test]
fn smbstatus_share_mode_models_configured_reads_and_messaging_paths() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in ["smbstatus -S", "smbstatus --shares"] {
        let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationArtifactResult::Resolved(resolved) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new(),
                &SessionBindings::new(),
            )
        else {
            panic!("{command}: missing profile");
        };
        assert!(resolved.bound.operation_semantics_unresolved);
        assert!(resolved.proven_stream_contract().is_none());
        for kind in [
            EffectKind::LoadConfig,
            EffectKind::ReadPath,
            EffectKind::WritePath,
            EffectKind::DeletePath,
        ] {
            assert!(
                resolved.bound.effects.iter().any(|effect| {
                    effect.kind == kind
                        && matches!(
                            effect.target,
                            caushell_profile::EffectTarget::ConfiguredPath(_)
                        )
                }),
                "{command}: missing {kind:?}"
            );
        }
    }
}

#[test]
fn native_service_contracts_do_not_depend_on_command_names_in_the_engine() {
    let source = include_str!("../profiles/postfix.yaml").replace(
        "canonical_name: postfix",
        "canonical_name: arbitrary_service_frontend",
    );
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(&source).unwrap()])
            .unwrap();
    let parsed =
        caushell_parse::parse_command("arbitrary_service_frontend start", ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(resolved) =
        resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &SessionBindings::new(),
        )
    else {
        panic!("generic Profile did not resolve")
    };
    assert!(resolved.bound.effects.iter().any(|e| {
        e.kind == EffectKind::StateOperation
            && e.state_operation.is_some_and(|op| {
                op.domain == StateOperationDomain::ServiceManager
                    && op.operation == StateOperationKind::Control
            })
    }));
}

#[test]
fn service_name_and_action_bind_in_order_without_losing_child_options() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in [
        "service arbitrary-service status",
        "service arbitrary-service start --help",
    ] {
        let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationArtifactResult::Resolved(resolved) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new(),
                &SessionBindings::new(),
            )
        else {
            panic!("{command}")
        };
        assert!(
            !resolved.bound.operation_semantics_unresolved,
            "{command}: {resolved:#?}"
        );
        let action = resolved
            .bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "action")
            .unwrap();
        assert!(
            matches!(&action.values[0], caushell_profile::BoundValue::Argument { text, .. } if text == if command.ends_with("status") { "status" } else { "start" })
        );
        if command.ends_with("--help") {
            assert!(resolved.bound.effects.iter().any(|e| {
                e.state_operation
                    .is_some_and(|op| op.operation == StateOperationKind::Control)
            }));
        }
    }
}

#[test]
fn configuration_operands_keep_their_native_argv_ownership() {
    let registry = ProfileRegistry::built_in().unwrap();
    for (command, slot) in [
        (
            "postfix -c /workspace/config start",
            "configuration_directory",
        ),
        (
            "postfix -c/workspace/config start",
            "configuration_directory",
        ),
        ("mailman -C /workspace/config start", "configuration_file"),
        ("mailman -C/workspace/config start", "configuration_file"),
        (
            "mailman --config=/workspace/config start",
            "configuration_file",
        ),
    ] {
        let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationArtifactResult::Resolved(resolved) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new(),
                &SessionBindings::new(),
            )
        else {
            panic!("{command}")
        };
        assert!(
            !resolved.bound.operation_semantics_unresolved,
            "{command}: {resolved:#?}"
        );
        for (name, expected) in [(slot, "/workspace/config"), ("operation", "start")] {
            let parameter = resolved
                .bound
                .bound_parameters
                .iter()
                .find(|p| p.name.as_str() == name)
                .unwrap();
            assert_eq!(parameter.values.len(), 1, "{command}");
            assert!(
                matches!(&parameter.values[0], caushell_profile::BoundValue::Argument { text, .. } if text == expected),
                "{command}: {parameter:#?}"
            );
        }
    }
}
