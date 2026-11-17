use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn attempt(command: &str) -> ResolveInvocationArtifactResult {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation_artifact_with_bindings(
        &ProfileRegistry::built_in().unwrap(), &parsed.commands[0],
        InvocationRuntimeContext::new(), &SessionBindings::new(),
    )
}
fn known(command: &str) -> BoundInvocation {
    match attempt(command) {
        ResolveInvocationArtifactResult::Resolved(r) => {
            assert!(!r.bound.operation_semantics_unresolved && r.bound.residuals.is_empty(), "{command}: {r:#?}");
            r.bound
        }
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn finite_queries_have_no_global_argv_or_exact_output_certificate() {
    for command in ["swapon --show", "swapon -s", "swapon", "csrutil status", "kmod list",
        "kmod help", "localectl status", "localectl", "sockstat -4", "sockstat -6 -l",
        "findmnt -t nfs", "findmnt --json -o SOURCE,TARGET", "inotifywait -e attrib watched",
        "colrm 34 39"] {
        let bound = known(command);
        assert!(bound.native_argv_effect_envelope.is_none());
        assert!(bound.stdout_records.is_none() && bound.stdout_scalar.is_none() && bound.stdout_growth.is_none());
        assert!(!bound.effects.iter().any(|e| matches!(e.kind,
            EffectKind::WritePath | EffectKind::ExecutePayload | EffectKind::DispatchCommand)));
    }
}

#[test]
fn mutation_remote_pager_list_and_unknown_controls_do_not_select_a_query() {
    for command in ["swapon -a", "swapon /dev/sda", "swapon --show -p 3 /dev/sda",
        "csrutil disable", "csrutil enable", "csrutil clear", "csrutil authenticated-root disable",
        "kmod static-nodes --output=/etc/owned", "localectl set-locale LANG=C", "localectl list-locales",
        "localectl -H remote status", "localectl -M container status", "findmnt --tab-file .env",
        "findmnt --task 1", "inotifywait --fromfile .env", "inotifywait --daemon -o out watched",
        "sockstat --unknown", "colrm --output=/etc/owned", "colrm 1 2 3",
        "inotifywait -m watched", "inotifywait --monitor --outfile log watched"] {
        if let ResolveInvocationArtifactResult::Resolved(r) = attempt(command) {
            assert!(r.bound.operation_semantics_unresolved || !r.bound.residuals.is_empty(), "{command}: {r:#?}");
        }
    }
}

#[test]
fn inotify_watches_metadata_and_declares_real_output_writes() {
    let bound = known("inotifywait -e attrib --outfile /etc/owned watched");
    assert!(bound.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    assert!(bound.effects.iter().any(|e| e.kind == EffectKind::TargetPath));
    assert!(!bound.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    assert!(bound.bound_parameters.iter().any(|p| p.name.as_str() == "output_file" && !p.values.is_empty()));
}

#[test]
fn colrm_consumes_real_stdin_without_certifying_empty_output() {
    let bound = known("colrm 1 999999");
    assert!(bound.effects.iter().any(|e| e.kind == EffectKind::ConsumeStdin));
    let stream = bound.stream_contract.unwrap();
    assert_eq!(stream.stdin_mode, StreamInputMode::DataRequired);
    assert_eq!(stream.stdout_dependency, caushell_types::StreamDataDependency::Inputs);
    assert!(bound.stdout_records.is_none() && bound.stdout_scalar.is_none());
}

#[test]
fn every_new_profile_keeps_unknown_native_argv_under_resolution() {
    for name in ["swapon", "csrutil", "kmod", "localectl", "sockstat", "findmnt", "colrm", "inotifywait"] {
        if let ResolveInvocationArtifactResult::Resolved(r) = attempt(&format!("{name} $OPTIONS")) {
            assert!(r.bound.operation_semantics_unresolved || !r.bound.residuals.is_empty(), "{name}: {r:#?}");
            assert!(r.bound.native_argv_effect_envelope.is_none());
        }
    }
}
