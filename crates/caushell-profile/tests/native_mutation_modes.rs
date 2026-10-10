//! Native CLI semantics only. No sample command is executed.
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
            assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
            assert!(r.bound.residuals.is_empty(), "{command}: {r:#?}");
            r.bound
        }
        r => panic!("{command}: {r:#?}"),
    }
}

fn values(bound: &BoundInvocation, name: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.clone(),
            other => panic!("{name}: {other:#?}"),
        })
        .collect()
}

fn has_effect(bound: &BoundInvocation, kind: EffectKind, slot: &str) -> bool {
    bound
        .effects
        .iter()
        .any(|e| e.kind == kind && matches!(&e.target, EffectTarget::Slot(s) if s.as_str() == slot))
}

#[test]
fn perl_inline_code_is_not_mistaken_for_a_script_or_a_filename() {
    for command in [
        "perl -pi -e 's/a/b/' /opt/shared/file",
        "perl -i.bak -pe 's/a/b/' /opt/shared/file",
        "perl -p -i -e 's/a/b/' /opt/shared/file",
        "perl -E 'say 1' -i /opt/shared/file",
    ] {
        let b = resolve(command);
        assert_eq!(b.form_id.as_str(), "command_string_in_place");
        assert_eq!(values(&b, "input_paths"), ["/opt/shared/file"]);
        assert!(has_effect(&b, EffectKind::WritePath, "input_paths"));
        assert!(has_effect(&b, EffectKind::ExecutePayload, "payload"));
    }
    let b = resolve("perl -e 'print 1' -e 'print 2' one two");
    assert_eq!(values(&b, "payload"), ["print 1", "print 2"]);
    assert_eq!(values(&b, "script_args"), ["one", "two"]);
    assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
}

#[test]
fn perl_script_boundary_and_dash_dash_are_not_interpreter_options() {
    let b = resolve("perl script.pl -i -e anything");
    assert_eq!(b.form_id.as_str(), "script_file");
    assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    let b = resolve("perl -e 'print 1' -- -i -n");
    assert_eq!(b.form_id.as_str(), "command_string");
    assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    let b = resolve("perl -i script.pl data");
    assert_eq!(values(&b, "script_path"), ["script.pl"]);
    assert_eq!(values(&b, "input_paths"), ["data"]);
    assert!(has_effect(&b, EffectKind::WritePath, "input_paths"));
}

#[test]
fn perl_inline_option_payload_cannot_enable_an_in_place_switch() {
    let b = resolve("perl -e '-i' data");
    assert_eq!(b.form_id.as_str(), "command_string");
    assert_eq!(values(&b, "payload"), ["-i"]);
    assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    assert!(values(&resolve("perl -i -e 1"), "input_paths").is_empty());
}

#[test]
fn perl_compilation_and_configuration_do_not_invent_in_place_runtime_writes() {
    for command in [
        "perl -c -pi -e 1 /opt/shared/file",
        "perl -ci script.pl /opt/shared/file",
    ] {
        let b = resolve(command);
        assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
        assert!(
            b.effects
                .iter()
                .any(|e| e.kind == EffectKind::ExecutePayload)
        );
    }
    assert_eq!(
        resolve("perl -V").form_id.as_str(),
        "configuration_information"
    );
    assert_eq!(
        resolve("perl -V:version -e 1").form_id.as_str(),
        "command_string"
    );
    let b = resolve("perl -F -ane 'print 1' file");
    assert_eq!(b.form_id.as_str(), "command_string");
    assert_eq!(values(&b, "payload"), ["print 1"]);
}

#[test]
fn rsync_preview_has_no_transfer_or_source_delete_effects() {
    for command in [
        "rsync -an --delete input /opt/shared",
        "rsync -av --list-only input /opt/shared",
        "rsync -n --remove-source-files /opt/shared/input cache",
        "rsync input /opt/shared --dry-run",
    ] {
        let b = resolve(command);
        assert_eq!(
            b.form_id.as_str(),
            "preview_local_sync",
            "{command}: {b:#?}"
        );
        assert!(
            !b.effects
                .iter()
                .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::DeletePath))
        );
    }
    let b = resolve("rsync -a --delete input /opt/shared");
    assert!(has_effect(&b, EffectKind::WritePath, "destination_path"));
    assert!(has_effect(&b, EffectKind::DeletePath, "destination_path"));
}

#[test]
fn rsync_preview_retains_the_independent_log_write() {
    let b = resolve("rsync -an --log-file=/opt/shared/log input cache");
    assert_eq!(values(&b, "log_file"), ["/opt/shared/log"]);
    assert!(has_effect(&b, EffectKind::WritePath, "log_file"));
    assert!(!has_effect(&b, EffectKind::WritePath, "destination_path"));
    let b = resolve("rsync -an --exclude '*.tmp' input /opt/shared");
    assert_eq!(values(&b, "source_paths"), ["input"]);
    assert_eq!(values(&b, "destination_path"), ["/opt/shared"]);
}

#[test]
fn rsync_preview_flag_inside_an_option_operand_does_not_enable_preview() {
    for command in [
        "rsync --exclude=-n input /opt/shared",
        "rsync --exclude -n input /opt/shared",
        "rsync --rsh '-n' input /opt/shared",
        "rsync --out-format=-n input /opt/shared",
        "rsync --filter '-n' input /opt/shared",
    ] {
        let b = resolve(command);
        assert_eq!(b.form_id.as_str(), "local_sync", "{command}: {b:#?}");
        assert!(has_effect(&b, EffectKind::WritePath, "destination_path"));
    }
}

#[test]
fn rsync_remote_preview_keeps_endpoints_and_single_source_is_a_listing() {
    for (command, form) in [
        (
            "rsync -n host:/data /opt/shared",
            "preview_import_from_remote",
        ),
        (
            "rsync --list-only data host:/backup",
            "preview_export_to_remote",
        ),
        ("rsync /opt/shared", "list_single_source_local"),
        ("rsync host:/data", "list_single_source_remote"),
    ] {
        let b = resolve(command);
        assert_eq!(b.form_id.as_str(), form);
        assert!(
            !b.effects
                .iter()
                .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::DeletePath))
        );
    }
}

#[test]
fn split_filters_use_a_shell_child_with_a_tool_generated_file_variable() {
    let b = resolve("split --filter='cat > /opt/shared/output' - cache/chunk");
    assert_eq!(b.form_id.as_str(), "filter_with_prefix");
    assert!(values(&b, "input_paths").is_empty());
    assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    let children = collect_dispatch_command_candidates(&b);
    assert_eq!(children.len(), 1);
    let child = &children[0];
    assert_eq!(child.command.text, "/bin/sh");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["-c", "cat > /opt/shared/output"]
    );
    assert_eq!(child.unknown_environment_names, ["FILE"]);
    assert!(child.stdin_from_tool && child.stdout_to_parent);
    for command in ["split -b 1000 - cache/chunk", "split -n 1/3 - cache/chunk"] {
        let b = resolve(command);
        assert!(values(&b, "input_paths").is_empty(), "{command}: {b:#?}");
    }
}

#[test]
fn split_kth_chunk_is_stdout_not_a_prefix_write() {
    for command in [
        "split -n 1/3 input",
        "split --number=l/1/3 input /opt/shared/prefix",
        "split -n r/2/3 -",
    ] {
        let b = resolve(command);
        assert_eq!(b.form_id.as_str(), "stdout_chunk");
        assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
        assert_eq!(
            b.stream_contract.unwrap().stdout_mode,
            StreamOutputMode::Data
        );
    }
    assert!(
        resolve("split -n r/3 input cache/chunk")
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
}

#[test]
fn split_option_operands_and_dash_dash_do_not_activate_a_filter() {
    let b = resolve("split --additional-suffix=--filter=cat input cache/chunk");
    assert_eq!(b.form_id.as_str(), "split_with_prefix");
    let b = resolve("split -- input --filter=cat");
    assert_eq!(b.form_id.as_str(), "split_with_prefix");
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    let b = resolve("split -b 10 input -");
    assert_eq!(values(&b, "output_prefix"), ["-"]);
    assert_eq!(values(&b, "input_paths"), ["input"]);
    let b = resolve("split --filter=cat - -");
    assert_eq!(values(&b, "output_prefix"), ["-"]);
    assert!(values(&b, "input_paths").is_empty());
    let b = resolve("split --numeric-suffixes=1 --additional-suffix=.csv -l100 data.csv data_");
    assert_eq!(values(&b, "input_paths"), ["data.csv"]);
    assert_eq!(values(&b, "output_prefix"), ["data_"]);
    assert!(
        !resolve("split --help")
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
}
