//! Static Profile binding only; never invoke the scheduler or its editor.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> ResolveInvocationArtifactResult {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    )
    .into_artifact()
}

fn bound(command: &str) -> BoundInvocation {
    match resolve(command) {
        ResolveInvocationArtifactResult::Resolved(result) => {
            assert!(
                !result.bound.operation_semantics_unresolved,
                "{command}: {result:#?}"
            );
            result.bound
        }
        result => panic!("{command}: {result:#?}"),
    }
}

#[test]
fn installation_edit_and_removal_retain_scheduler_storage_effects() {
    for (command, form, effect) in [
        (
            "crontab ./jobs",
            "install_crontab_file",
            EffectKind::WritePath,
        ),
        (
            "crontab -u alice ./jobs",
            "install_crontab_file",
            EffectKind::WritePath,
        ),
        ("crontab -", "install_crontab_stdin", EffectKind::WritePath),
        ("crontab", "install_crontab_stdin", EffectKind::WritePath),
        ("crontab -e", "edit_crontab", EffectKind::WritePath),
        ("crontab -r", "remove_crontab", EffectKind::DeletePath),
        ("crontab -ir", "remove_crontab", EffectKind::DeletePath),
    ] {
        let b = bound(command);
        assert_eq!(b.form_id.as_str(), form, "{command}");
        assert!(
            b.effects.iter().any(|e| e.kind == effect
                && matches!(&e.target,
            EffectTarget::ConfiguredPath(t) if t.sources.is_empty()
                && t.default_value.is_none() && t.missing == ConfiguredPathMissing::Unknown)),
            "{command}: {b:#?}"
        );
    }
}

#[test]
fn query_information_and_syntax_test_have_no_scheduling_mutation() {
    for command in [
        "crontab -l",
        "crontab -lu alice",
        "crontab -u alice -l",
        "crontab -h",
        "crontab -V",
        "crontab -T ./jobs",
        "crontab -T -",
    ] {
        let b = bound(command);
        assert!(
            !b.effects.iter().any(|e| matches!(
                e.kind,
                EffectKind::WritePath
                    | EffectKind::DeletePath
                    | EffectKind::ExecuteConfigDefinedTask
            )),
            "{command}: {b:#?}"
        );
    }
}

#[test]
fn flag_ownership_and_dash_dash_decide_the_actual_operation() {
    for (command, form) in [
        ("crontab -u -r -l", "list_crontab"),
        ("crontab -u -l ./jobs", "install_crontab_file"),
        ("crontab -u-l ./jobs", "install_crontab_file"),
        ("crontab -- -l", "install_crontab_file"),
        ("crontab ./jobs -u alice", "install_crontab_file"),
    ] {
        assert_eq!(bound(command).form_id.as_str(), form, "{command}");
    }
}

#[test]
fn stdin_task_text_is_not_a_filename_or_immediate_shell_payload() {
    for command in ["crontab", "crontab -", "crontab -ualice -", "crontab -T -"] {
        let b = bound(command);
        assert!(
            b.bound_implicit_inputs
                .iter()
                .any(|i| i.source == ImplicitInputSource::StdinData),
            "{command}: {b:#?}"
        );
        assert!(
            !b.bound_parameters
                .iter()
                .any(|p| matches!(p.semantic, SemanticType::Path(_))),
            "{command}: {b:#?}"
        );
        assert!(
            !b.effects
                .iter()
                .any(|e| e.kind == EffectKind::ExecutePayload),
            "{command}: {b:#?}"
        );
    }
}

#[test]
fn ambiguous_invalid_and_unknown_forms_do_not_claim_complete_semantics() {
    for command in [
        "crontab -n ./jobs",
        "crontab -lr",
        "crontab -le",
        "crontab -Tr",
        "crontab -l ./jobs",
        "crontab -u",
        "crontab --unknown ./jobs",
        "crontab ./one ./two",
    ] {
        match resolve(command) {
            ResolveInvocationArtifactResult::SelectionError { .. } => {}
            ResolveInvocationArtifactResult::Resolved(r)
                if r.bound.operation_semantics_unresolved => {}
            r => panic!("{command}: {r:#?}"),
        }
    }
}

#[test]
fn unresolved_file_operand_does_not_erase_possible_task_table_write() {
    let b = bound("crontab \"$file\"");
    assert!(
        b.effects.iter().any(|e| e.kind == EffectKind::WritePath
            && matches!(e.target, EffectTarget::ConfiguredPath(_)))
    );
}
