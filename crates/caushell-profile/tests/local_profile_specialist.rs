use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{
    ShellKind, StateOperationDomain, StateOperationKind, TerminalSessionOperationKind,
};

fn resolve(command: &str) -> ResolvedInvocationArtifact {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(result) => result,
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn native_local_forms_have_complete_owned_arguments() {
    for command in [
        "file -In source",
        "file -m magic",
        "file -- -In",
        "uniq --all-repeat=separate",
        "uniq --a=separate input output",
        "uniq --group=prepend input",
        "sort +1 -2 input",
        "sort +0.2n -1.4 input",
        "sort +1 -2",
        "sort -- -1",
        "sort -o result -- -1",
        "ffmpeg -i input -f flv %f",
        "ffmpeg -i input frame-%03d.jpg",
        "kubectl --context ctx exec pod -- cat /etc/hosts",
        "kubectl exec -n ns -it pod -- sh -c 'echo ok'",
        "kubectl --kubeconfig=/tmp/config get pods",
        "kubectl proxy --address=127.0.0.1 --port 8001",
        "gzip -kr .",
        "gzip -kr ./data/",
        "gzip -kr input",
        "gzip -r input",
        "gzip -kr . -",
        "rsync -avz -e ssh user@host:/src/ dst/",
        "rsync --list-only --rsh=/usr/bin/ssh user@host:/src/ dst/",
        "openvt -- true",
        "openvt -c 2 true",
        "openvt --help",
        "systemd-run --scope true",
        "systemd-run --same-dir true",
    ] {
        let result = resolve(command);
        assert!(
            !result.bound.operation_semantics_unresolved,
            "{command}: {result:#?}"
        );
        assert!(result.bound.residuals.is_empty(), "{command}: {result:#?}");
    }
}

#[test]
fn service_and_terminal_effects_are_explicit() {
    for command in [
        "fail2ban-client add jail",
        "fail2ban-client set jail action x actionban 'echo ok'",
        "systemd-run true",
        "systemd-run --scope true",
    ] {
        let result = resolve(command);
        assert!(
            result
                .bound
                .effects
                .iter()
                .any(|effect| effect
                    .state_operation
                    .is_some_and(|operation| operation.domain
                        == StateOperationDomain::ServiceManager
                        && matches!(
                            operation.operation,
                            StateOperationKind::Mutate | StateOperationKind::Control
                        ))),
            "{command}: {result:#?}"
        );
    }
    let result = resolve("openvt -- true");
    assert!(
        result
            .bound
            .effects
            .iter()
            .any(|e| e.terminal_session_operation == Some(TerminalSessionOperationKind::Create))
    );
}

#[test]
fn standard_transport_is_not_a_fabricated_incomplete_child() {
    let attached = resolve("rsync --list-only -exclude '*.xml' host::module/");
    let transport = attached
        .bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "remote_shell")
        .unwrap();
    assert!(matches!(&transport.values[0], BoundValue::Argument {text, ..} if text == "xclude"));
    for transport in ["ssh", "/usr/bin/ssh", "/bin/ssh"] {
        let result = resolve(&format!("rsync -e {transport} host:/src dst"));
        assert!(
            !result
                .bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::DispatchCommand)
        );
        assert!(!result.bound.effects.iter().any(|e| {
            e.state_operation.is_some_and(|s| {
                s.domain == StateOperationDomain::RemoteAccess
                    && s.operation == StateOperationKind::Opaque
            })
        }));
    }
    for (command, expected) in [
        ("rsync -e 'ssh -oProxyCommand=evil' host:/src dst", true),
        ("rsync -e 'arbitrary transport' src/ dst/", false),
    ] {
        let result = resolve(command);
        assert_eq!(
            result.bound.effects.iter().any(|e| e
                .state_operation
                .is_some_and(|s| s.domain == StateOperationDomain::RemoteAccess
                    && s.operation == StateOperationKind::Opaque)),
            expected,
            "{command}"
        );
    }
}

#[test]
fn remote_command_tail_is_not_owned_by_kubectl_options() {
    let result = resolve("kubectl --context ctx exec pod -- cat --kubeconfig /etc/secret --help");
    assert_eq!(result.bound.form_id.as_str(), "remote_pod_command");
    assert!(
        !result
            .bound
            .applied_modifiers
            .iter()
            .any(|m| m.as_str() == "config_kubeconfig" || m.as_str() == "information")
    );
    let args = result
        .bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "remote_command")
        .unwrap();
    assert_eq!(args.values.len(), 4);
}
