//! Declarative binding checks only; these shell strings are not executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => {
            assert!(
                !r.bound.operation_semantics_unresolved,
                "{command}: {:#?}",
                r.bound
            );
            assert!(r.bound.residuals.is_empty(), "{command}: {:#?}", r.bound);
            r.bound
        }
        other => panic!("{command}: {other:#?}"),
    }
}

fn has_effect(bound: &BoundInvocation, kind: EffectKind, slot: &str) -> bool {
    bound
        .effects
        .iter()
        .any(|e| e.kind == kind && matches!(&e.target, EffectTarget::Slot(n) if n.as_str() == slot || n.as_str() == format!("old_{slot}")))
}

#[test]
fn declared_operations_include_appending_updating_and_member_deletion() {
    for (command, form) in [
        ("tar -rf a.tar input", "append_or_update_archive"),
        (
            "tar --update --file=a.tar input",
            "append_or_update_archive",
        ),
        ("tar rvf a.tar input", "append_or_update_archive_old_style"),
        ("tar uf a.tar input", "append_or_update_archive_old_style"),
        ("tar -Af a.tar other.tar", "concatenate_archives"),
        ("tar Avf a.tar other.tar", "concatenate_archives_old_style"),
        (
            "tar --delete --file=a.tar /etc/passwd",
            "delete_archive_members",
        ),
        ("tar -df a.tar input", "compare_archive"),
        ("tar dvf a.tar input", "compare_archive_old_style"),
    ] {
        let b = resolve(command);
        assert_eq!(b.form_id.as_str(), form, "{command}");
        assert!(
            has_effect(&b, EffectKind::ReadPath, "archive_file"),
            "{command}"
        );
        assert_eq!(
            has_effect(&b, EffectKind::WritePath, "archive_file"),
            !form.starts_with("compare"),
            "{command}"
        );
        assert!(
            !b.effects.iter().any(|e| e.kind == EffectKind::DeletePath),
            "{command}"
        );
    }
}

#[test]
fn option_ownership_works_after_prior_operands_and_with_compact_clusters() {
    for command in [
        "tar -C my_dir -zcvf my_dir.tar.gz .[^.]* ..?* *",
        "tar -I pbzip2 -cf OUTPUT.tar.bz2 /DIR_TO_ZIP/",
        "tar -I pbzip2 -cfOUTPUT.tar.bz2 paths_to_archive",
        "tar -N '2014-02-01 18:00:00' -jcvf archive.tar.bz2 files",
        "tar --mtime='2023-01-01' --owner=0 --group=0 -zcf archive.tgz /system/folder",
        "tar -cf archive.tar --exclude='*.o' --strip-components=1 input",
    ] {
        let b = resolve(command);
        assert!(has_effect(&b, EffectKind::WritePath, "archive_file"));
        assert_eq!(
            b.bound_parameters
                .iter()
                .filter(|p| p.name.as_str() == "archive_file")
                .count(),
            1
        );
    }
}

#[test]
fn filename_lists_are_file_selection_not_shell_payloads() {
    for command in [
        "tar --null -T - --create -f archive.tar",
        "tar -T - --null --create -f archive.tar",
        "tar -cf archive.tar -T-",
        "tar cf archive.tar --files-from=- --no-recursion",
        "tar -rf archive.tar --files-from=list.txt --null -T second.txt",
    ] {
        let b = resolve(command);
        assert!(has_effect(&b, EffectKind::WritePath, "archive_file"));
        assert!(!b.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::ExecutePayload | EffectKind::DispatchCommand
        )));
    }
    let file = resolve("tar -cf archive.tar -T list.txt");
    assert!(has_effect(&file, EffectKind::ReadPath, "name_list_files"));
    assert!(
        !file
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ConsumeStdin)
    );
    let stdin = resolve("tar -cf archive.tar -T -");
    assert!(has_effect(&stdin, EffectKind::ConsumeStdin, "stdin_names"));
    assert!(!has_effect(&stdin, EffectKind::ReadPath, "name_list_files"));
}

#[test]
fn dash_archive_is_a_stream_not_a_file_named_dash() {
    for command in ["tar -cf - input", "tar cf - input", "tar -tf -", "tar tf -"] {
        let b = resolve(command);
        assert!(
            !b.bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "archive_file"),
            "{command}: {b:#?}"
        );
        assert!(!has_effect(&b, EffectKind::WritePath, "archive_file"));
    }
    assert!(has_effect(
        &resolve("tar -tf -"),
        EffectKind::ConsumeStdin,
        "archive_stream"
    ));
}

#[test]
fn stdout_and_callback_extraction_do_not_claim_host_member_writes() {
    for command in [
        "tar -xOf archive.tar",
        "tar xOf archive.tar",
        "tar xvf archive.tar --to-stdout",
        "tar xf archive.tar --to-command='cat'",
    ] {
        let b = resolve(command);
        assert!(
            !b.effects.iter().any(|e| e.kind == EffectKind::WritePath),
            "{command}: {b:#?}"
        );
    }
    for command in [
        "tar -xf archive.tar",
        "tar xf archive.tar",
        "tar -xf -",
        "tar xf -",
        "tar x",
    ] {
        let b = resolve(command);
        assert!(
            b.effects.iter().any(|e| e.kind == EffectKind::WritePath),
            "{command}: {b:#?}"
        );
    }
}

#[test]
fn default_archive_is_unknown_not_assumed_to_be_stdout() {
    for command in ["tar -c input", "tar c input", "tar cv --files-from=-"] {
        let b = resolve(command);
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath && matches!(&e.target, EffectTarget::ConfiguredPath(p) if p.missing == ConfiguredPathMissing::Unknown)), "{command}: {b:#?}");
    }
    for command in ["tar t", "tar -t", "tar xO", "tar -xO"] {
        let b = resolve(command);
        assert!(
            !b.effects.iter().any(|e| e.kind == EffectKind::WritePath),
            "{command}: {b:#?}"
        );
    }
}

#[test]
fn information_forms_suppress_real_callbacks_and_file_mutations() {
    for command in [
        "tar --help --checkpoint-action='exec=rm /opt/file'",
        "tar --version --remove-files -cf archive.tar input",
    ] {
        let b = resolve(command);
        assert!(b.effects.is_empty(), "{command}: {b:#?}");
    }
}
