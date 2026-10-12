//! Static boundary checks for the audited Profile gaps. No command is executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use caushell_types::{StateOperation, StateOperationDomain, StateOperationKind};
use std::sync::OnceLock;

fn resolve(command: &str) -> ResolvedInvocationArtifact {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap());
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => r.into_artifact(),
        other => panic!("{command}: {other:#?}"),
    }
}

fn complete(command: &str) -> ResolvedInvocationArtifact {
    let result = resolve(command);
    assert!(
        !result.bound.operation_semantics_unresolved && result.bound.residuals.is_empty(),
        "{command}: {result:#?}"
    );
    result
}

fn has(command: &str, kind: EffectKind) -> bool {
    resolve(command)
        .bound
        .effects
        .iter()
        .any(|effect| effect.kind == kind)
}

fn unresolved(command: &str) -> Option<BoundInvocation> {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationResult::SelectionError { partial_bound, .. } => partial_bound,
        other => panic!("expected unresolved native invocation: {command}: {other:#?}"),
    }
}

fn has_state_operation(
    command: &str,
    domain: StateOperationDomain,
    operation: StateOperationKind,
) -> bool {
    resolve(command).bound.effects.iter().any(|effect| {
        effect.kind == EffectKind::StateOperation
            && effect.state_operation == Some(StateOperation { domain, operation })
            && effect.target == EffectTarget::None
    })
}

#[test]
fn systemctl_inspection_retains_pager_surface_independently_of_state_control() {
    for operation in ["status", "show", "list-dependencies"] {
        let paged = complete(&format!("systemctl {operation} example.service"));
        assert!(
            paged
                .bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
        );
        let plain = complete(&format!("systemctl --no-pager {operation} example.service"));
        assert!(
            !plain
                .bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
        );
    }
    for operation in ["is-active", "is-failed"] {
        let query = complete(&format!("systemctl {operation} example.service"));
        assert!(
            !query
                .bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
        );
    }
}

#[test]
fn chmod_reporting_and_reference_options_never_erase_mutation_targets() {
    for command in [
        "chmod -Rf u+w /opt/file",
        "chmod --reference=source /opt/file",
        "chmod -R --reference source /opt/file",
    ] {
        let result = complete(command);
        assert!(result.bound.effects.iter().any(|e| e.kind == EffectKind::ChangeMode
            && matches!(&e.target, EffectTarget::Slot(slot) if slot.as_str() == "path_targets")));
    }
    let reference = complete("chmod --reference=source /opt/file");
    assert!(
        !reference
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath)
    );
    let unknown = unresolved("chmod --unsupported u+w /opt/file").unwrap();
    assert!(unknown.operation_semantics_unresolved);
    let help = complete("chmod --help -R u+w /opt/file");
    assert!(!help.bound.effects.iter().any(|e| matches!(
        e.kind,
        EffectKind::ChangeMode | EffectKind::MetadataMutation
    )));
    let fingerprint = complete("ssh-keygen -l -E md5 -f /etc/ssh/ssh_host_ecdsa_key.pub");
    assert!(
        fingerprint
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath)
    );
    assert!(
        !fingerprint
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
}

#[test]
fn shell_entry_points_keep_script_stdin_and_interactive_context_distinct() {
    assert!(has("sh ./script.sh arg", EffectKind::ReadPath));
    assert!(has("sh -s", EffectKind::ConsumeStdin));
    assert!(has("sh -c 'echo fixed'", EffectKind::ExecutePayload));
    // With no script, known stdin, or known interactive session, entry is unresolved.
    // The Profile must not manufacture an interactive-session fact.
    let bare = resolve("sh");
    assert!(
        bare.bound.effects.iter().any(|effect| {
            effect.kind == EffectKind::ExecutePayload
                && effect.target == EffectTarget::ImplicitInput(ImplicitInputSource::StdinPayload)
        }),
        "{bare:#?}"
    );
    assert!(
        bare.bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ConsumeStdin),
        "{bare:#?}"
    );
    assert!(
        !bare.bound.effects.iter().any(|effect| matches!(
            effect.target,
            EffectTarget::ImplicitInput(ImplicitInputSource::InteractiveSession)
        )),
        "{bare:#?}"
    );
    assert!(has("ksh ./script.ksh arg", EffectKind::ReadPath));
    assert!(has("ksh -s", EffectKind::ConsumeStdin));
}

#[test]
fn exact_utility_operand_grammars_preserve_targets_without_accepting_arbitrary_flags() {
    let chmod = complete("chmod -x /tmp/target");
    assert!(
        chmod
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ChangeMode)
    );
    assert!(
        !chmod
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    let chmod = complete("chmod -x+r /tmp/target");
    assert!(
        chmod
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ChangeMode)
    );
    unresolved("chmod -not-a-mode /tmp/target");

    for command in ["perl -0777ne 'print' input", "perl -l40pe0"] {
        let result = complete(command);
        assert!(
            result
                .bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ExecutePayload),
            "{command}: {result:#?}"
        );
    }
    let numeric = resolve("perl -0777ne 'print' input");
    let script = numeric
        .bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "payload")
        .unwrap();
    assert!(
        matches!(&script.values[0], BoundValue::Argument { text, .. } if text == "print"),
        "{numeric:#?}"
    );
}

#[test]
fn utility_queries_and_legacy_forms_do_not_become_mutations_or_children() {
    for command in ["nice", "command"] {
        let result = complete(command);
        assert!(result.bound.effects.is_empty(), "{command}: {result:#?}");
    }
    let adjusted = complete("nice -10 true");
    assert!(
        adjusted
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DispatchCommand)
    );
    for command in ["service --status-all", "service -e"] {
        let result = complete(command);
        assert!(
            !result
                .bound
                .effects
                .iter()
                .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::DeletePath))
        );
        assert!(has_state_operation(
            command,
            StateOperationDomain::ServiceManager,
            StateOperationKind::Inspect
        ));
    }
    assert!(has_state_operation(
        "service nginx status",
        StateOperationDomain::ServiceManager,
        StateOperationKind::Inspect
    ));
    assert!(has_state_operation(
        "service nginx restart",
        StateOperationDomain::ServiceManager,
        StateOperationKind::Control
    ));
}

#[test]
fn shell_entry_wrappers_preserve_redirections_and_opaque_code_boundaries() {
    let result = resolve("exec > /tmp/out");
    assert!(
        !result
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DispatchCommand),
        "{result:#?}"
    );
    assert!(has(
        "csh -c 'echo fixed' arg0 arg1",
        EffectKind::ExecutePayload
    ));
    assert!(!has(
        "csh -c 'echo fixed' arg0 arg1",
        EffectKind::ExecuteRemoteCommand
    ));
    assert!(
        unresolved("systemd-run --shell")
            .unwrap()
            .operation_semantics_unresolved
    );
    assert!(has("passwd --stdin alice", EffectKind::ConsumeStdin));
}

#[test]
fn terminal_and_remote_file_forms_keep_native_boundaries() {
    let screen = resolve("screen -Rd build");
    assert!(
        screen
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::TerminalSessionOperation),
        "{screen:#?}"
    );
    assert!(
        !screen
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DispatchCommand)
    );

    let sftp = resolve("sftp user@host:/remote/file /tmp/local-file");
    assert!(sftp.bound.operation_semantics_unresolved, "{sftp:#?}");
    assert!(
        sftp.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::NetworkEndpoint)
    );
    assert!(
        !sftp
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath),
        "{sftp:#?}"
    );
    let loginctl = complete("loginctl enable-linger alice");
    assert!(!loginctl.bound.effects.iter().any(|e| matches!(
        e.kind,
        EffectKind::ReadPath | EffectKind::WritePath | EffectKind::DeletePath
    )));
    assert!(has_state_operation(
        "loginctl enable-linger alice",
        StateOperationDomain::ServiceManager,
        StateOperationKind::Mutate
    ));
    assert!(has_state_operation(
        "systemctl start example.service",
        StateOperationDomain::ServiceManager,
        StateOperationKind::Control
    ));
    assert!(has_state_operation(
        "systemctl enable example.service",
        StateOperationDomain::ServiceManager,
        StateOperationKind::Mutate
    ));
    assert!(has_state_operation(
        "systemctl --no-pager status example.service",
        StateOperationDomain::ServiceManager,
        StateOperationKind::Inspect
    ));
    let password = complete("passwd --stdin alice");
    assert!(
        password
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ConsumeStdin),
        "{password:#?}"
    );
    assert!(
        password
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath),
        "{password:#?}"
    );
    let journal = complete("journalctl --vacuum-time=1d");
    assert!(
        journal
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DeletePath)
    );
}

#[test]
fn archive_cloud_and_cluster_controls_use_accurate_target_domains() {
    let archive = complete("7z a -psecret -mhe=on /tmp/archive.7z /tmp/input");
    assert!(
        archive
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    assert!(
        archive
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath)
    );

    let aws = resolve("aws ec2 run-instances --image-id ami-123 --instance-type t3.micro");
    assert!(
        !aws.bound.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::ReadPath | EffectKind::WritePath | EffectKind::DeletePath
        )),
        "{aws:#?}"
    );
    assert!(has_state_operation(
        "aws ec2 run-instances --image-id ami-123 --instance-type t3.micro",
        StateOperationDomain::CloudResource,
        StateOperationKind::Mutate
    ));
    let aws_data =
        resolve("aws ec2 run-instances --image-id ami-123 --user-data file://./userdata.sh");
    assert!(
        aws_data
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath),
        "{aws_data:#?}"
    );
    assert!(has_state_operation(
        "aws ec2 create-launch-template --launch-template-name demo --launch-template-data file://./template.json",
        StateOperationDomain::CloudResource,
        StateOperationKind::Mutate
    ));

    let run = resolve("kubectl run nginx --image=nginx");
    assert!(
        !run.bound.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::ReadPath | EffectKind::WritePath | EffectKind::DeletePath
        )),
        "{run:#?}"
    );
    assert!(has_state_operation(
        "kubectl run nginx --image=nginx",
        StateOperationDomain::CloudResource,
        StateOperationKind::Mutate
    ));
    let remote = resolve("kubectl exec pod -- sh -c 'echo fixed'");
    assert!(
        !remote.bound.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::ReadPath | EffectKind::WritePath | EffectKind::DeletePath
        )),
        "{remote:#?}"
    );
    assert!(has_state_operation(
        "kubectl exec pod -- sh -c 'echo fixed'",
        StateOperationDomain::RemoteAccess,
        StateOperationKind::Control
    ));
}

#[test]
fn job_and_terminal_protocols_are_not_replayed_as_shell_source() {
    let dry = complete("parallel --dry-run echo ::: one two");
    assert!(
        !dry.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DispatchCommand),
        "{dry:#?}"
    );
    let parallel = complete("parallel rm -rf ::: /tmp/a /tmp/b").bound;
    assert!(!parallel.operation_semantics_unresolved, "{parallel:#?}");
    assert!(
        parallel
            .effects
            .iter()
            .any(|e| matches!(&e.target, EffectTarget::Dispatch(target) if matches!(
                &target.command,
                caushell_profile::DispatchCommandSource::CommandString { syntax: caushell_profile::DispatchStringSyntax::GnuParallel, .. }
            ))),
        "native template declaration, not invented literal job argv: {parallel:#?}"
    );

    let tmux = resolve("tmux new-window -c /tmp/project 'echo fixed'");
    assert!(
        !tmux
            .bound
            .effects
            .iter()
            .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::DeletePath)),
        "{tmux:#?}"
    );
    let send_keys = resolve("tmux send-keys 'rm -rf /tmp/a'");
    assert!(
        !send_keys
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DispatchCommand),
        "{send_keys:#?}"
    );
    assert!(
        !send_keys
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecutePayload),
        "{send_keys:#?}"
    );

    for command in [
        "tmux new-session -s vims -n vim0 -d 'vim foo'",
        "tmux new-window -t vims -c /tmp/project -n win0 'vim foo'",
    ] {
        let result = complete(command);
        assert!(
            result
                .bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ExecutePayload),
            "{command}: {result:#?}"
        );
        // A declared local start directory is context, not an archive/write target.
        assert!(
            !result
                .bound
                .effects
                .iter()
                .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::DeletePath)),
            "{command}: {result:#?}"
        );
    }
    assert!(has("tmux -c '/bin/sh'", EffectKind::ExecutePayload));
    let socket = complete("tmux -S /tmp/tmux-sock");
    assert!(
        !socket.bound.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::ReadPath | EffectKind::WritePath | EffectKind::DeletePath
        )),
        "{socket:#?}"
    );
}

#[test]
fn remote_helpers_and_clock_settings_do_not_claim_local_file_effects() {
    let rsync = resolve("rsync -e 'ssh -i key' local remote:/dest");
    assert!(
        !rsync
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecutePayload),
        "{rsync:#?}"
    );
    assert!(
        rsync
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DispatchCommand),
        "{rsync:#?}"
    );
    let rsync_path = resolve("rsync --rsync-path='sudo rsync' local remote:/dest");
    assert!(
        !rsync_path.bound.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::ReadPath | EffectKind::WritePath
        ) && e.target == EffectTarget::None),
        "{rsync_path:#?}"
    );
    assert!(
        rsync_path
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecuteRemoteCommand),
        "{rsync_path:#?}"
    );

    let date = resolve("date --set '2030-01-01 00:00:00'");
    assert!(
        !date.bound.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::ReadPath | EffectKind::WritePath | EffectKind::DeletePath
        )),
        "{date:#?}"
    );
    assert!(has_state_operation(
        "date --set '2030-01-01 00:00:00'",
        StateOperationDomain::SystemClock,
        StateOperationKind::Mutate
    ));
    assert!(has_state_operation(
        "code tunnel --name demo",
        StateOperationDomain::RemoteAccess,
        StateOperationKind::Control
    ));
}
