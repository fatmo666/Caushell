use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, EffectTarget, InvocationRuntimeContext,
    ProfileRegistry, ResolveInvocationResult, load_command_profile_from_str, resolve_invocation,
};
use caushell_types::ShellKind;

const PROFILES: [&str; 10] = [
    include_str!("../profiles/troff.yaml"),
    include_str!("../profiles/nroff.yaml"),
    include_str!("../profiles/pic.yaml"),
    include_str!("../profiles/m4.yaml"),
    include_str!("../profiles/msgfilter.yaml"),
    include_str!("../profiles/dvips.yaml"),
    include_str!("../profiles/enscript.yaml"),
    include_str!("../profiles/zgrep.yaml"),
    include_str!("../profiles/rustfmt.yaml"),
    include_str!("../profiles/tsc.yaml"),
];

fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        PROFILES
            .into_iter()
            .map(|source| load_command_profile_from_str(source).unwrap())
            .collect(),
    )
    .unwrap()
}

fn bind(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry(),
        parsed.commands.last().expect("outer command"),
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(resolved) => resolved.bound,
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => bound,
        other => panic!("{command}: {other:?}"),
    }
}

fn values<'a>(bound: &'a BoundInvocation, name: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == name)
        .flat_map(|parameter| &parameter.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("unexpected {name}: {other:?}"),
        })
        .collect()
}

fn effect(bound: &BoundInvocation, kind: EffectKind, slot: &str) -> bool {
    bound.effects.iter().any(|item| {
        item.kind == kind
            && matches!(&item.target, EffectTarget::Slot(name) if name.as_str() == slot)
    })
}

fn dispatches_to(bound: &BoundInvocation, slot: &str) -> bool {
    bound.effects.iter().any(|item| {
        item.kind == EffectKind::DispatchCommand
            && matches!(&item.target, EffectTarget::Dispatch(target)
                if matches!(&target.command, caushell_profile::DispatchCommandSource::Slot(actual)
                    | caushell_profile::DispatchCommandSource::CommandString { slot: actual, .. }
                    if actual.as_str() == slot))
    })
}

#[test]
fn roff_tools_distinguish_safe_reads_from_unsafe_opaque_documents() {
    for (command, form, path_slot) in [
        (
            "troff /tmp/input.roff",
            "typeset_input_files",
            "input_paths",
        ),
        ("nroff /tmp/input.roff", "format_input_files", "input_paths"),
        (
            "pic /tmp/input.pic",
            "translate_picture_files",
            "input_paths",
        ),
    ] {
        let bound = bind(command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
        let expected_path = if command.starts_with("pic ") {
            "/tmp/input.pic"
        } else {
            "/tmp/input.roff"
        };
        assert_eq!(values(&bound, path_slot), [expected_path]);
        assert!(
            effect(&bound, EffectKind::ReadPath, path_slot),
            "{bound:#?}"
        );
        assert!(
            !bound
                .effects
                .iter()
                .any(|item| item.kind == EffectKind::ExecutePayload)
        );
    }

    for (command, form) in [
        ("troff -U /tmp/input.roff", "unsafe_typeset_input_files"),
        ("nroff -U /tmp/input.roff", "unsafe_format_input_files"),
        ("pic -U /tmp/input.pic", "unsafe_picture_files"),
    ] {
        let bound = bind(command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
        assert!(
            bound
                .effects
                .iter()
                .any(|item| item.kind == EffectKind::ExecutePayload)
        );
    }

    let pic_stdin = bind("pic -U <<'PIC'\n.PS\nsh X sh X\n.PE\nPIC");
    assert_eq!(pic_stdin.form_id.as_str(), "unsafe_picture_stdin");
    assert!(
        pic_stdin
            .effects
            .iter()
            .any(|item| item.kind == EffectKind::ConsumeStdin)
    );
    assert!(
        pic_stdin
            .effects
            .iter()
            .any(|item| item.kind == EffectKind::ExecutePayload)
    );
}

#[test]
fn m4_macro_sources_are_opaque_and_file_inputs_remain_concrete_reads() {
    let stdin = bind("printf '%s\\n' 'esyscmd(/bin/true)' | m4");
    assert_eq!(stdin.form_id.as_str(), "process_macro_stdin");
    assert!(
        stdin
            .effects
            .iter()
            .any(|item| item.kind == EffectKind::ConsumeStdin)
    );
    assert!(
        stdin
            .effects
            .iter()
            .any(|item| item.kind == EffectKind::ExecutePayload)
    );

    let file = bind("m4 /tmp/source.m4");
    assert_eq!(file.form_id.as_str(), "process_macro_files");
    assert_eq!(values(&file, "macro_files"), ["/tmp/source.m4"]);
    assert!(effect(&file, EffectKind::ReadPath, "macro_paths"));
    assert!(effect(&file, EffectKind::ExecutePayload, "macro_files"));
}

#[test]
fn msgfilter_dispatches_filter_with_separate_argv_and_models_catalog_file_io() {
    let shell = bind("printf x | msgfilter -P /bin/sh -c 'printf SAFE'");
    assert_eq!(shell.form_id.as_str(), "filter_catalog");
    assert_eq!(values(&shell, "filter_command"), ["/bin/sh"]);
    assert_eq!(values(&shell, "filter_args"), ["-c", "printf SAFE"]);
    assert!(dispatches_to(&shell, "filter_command"), "{shell:#?}");

    let input = bind("msgfilter -P -i /tmp/catalog.po /bin/cat");
    assert_eq!(values(&input, "input_file"), ["/tmp/catalog.po"]);
    assert!(effect(&input, EffectKind::ReadPath, "input_path"));
    assert_eq!(input.form_id.as_str(), "filter_catalog_from_file");
    assert_eq!(values(&input, "filter_command"), ["/bin/cat"]);
}

#[test]
fn dvips_unsafe_specials_are_attached_to_the_dvi_artifact() {
    let safe = bind("dvips document.dvi");
    assert_eq!(safe.form_id.as_str(), "translate_dvi");
    assert_eq!(values(&safe, "dvi_path"), ["document.dvi"]);
    assert!(effect(&safe, EffectKind::ReadPath, "dvi_path"));
    assert!(
        !safe
            .effects
            .iter()
            .any(|item| item.kind == EffectKind::ExecutePayload)
    );

    let unsafe_dvi = bind("dvips -R0 texput.dvi");
    assert_eq!(unsafe_dvi.form_id.as_str(), "unsafe_translate_dvi");
    assert!(effect(
        &unsafe_dvi,
        EffectKind::ExecutePayload,
        "dvi_payload"
    ));
}

#[test]
fn enscript_interpreter_uses_nested_posix_shell_dispatch() {
    let command = bind("enscript /dev/null -qo /dev/null -I '/bin/sh >&2'");
    assert_eq!(command.form_id.as_str(), "interpret_input_files");
    assert_eq!(values(&command, "interpreter_command"), ["/bin/sh >&2"]);
    assert!(
        dispatches_to(&command, "interpreter_command"),
        "{command:#?}"
    );
    assert!(
        command
            .effects
            .iter()
            .any(|item| item.kind == EffectKind::DispatchCommand)
    );
    assert_eq!(values(&command, "output_path"), ["/dev/null"]);
}

#[test]
fn zgrep_adaptation_binds_pattern_and_path_without_claiming_grep_is_zgrep() {
    let command = bind("zgrep '' /tmp/input.gz");
    assert_eq!(command.form_id.as_str(), "search_explicit_files");
    assert_eq!(values(&command, "pattern"), [""]);
    assert_eq!(values(&command, "input_paths"), ["/tmp/input.gz"]);
    assert!(effect(&command, EffectKind::ReadPath, "input_paths"));
}

#[test]
fn rustfmt_named_input_is_both_read_and_rewritten() {
    let command = bind("rustfmt /tmp/invalid.rs");
    assert_eq!(command.form_id.as_str(), "format_named_files");
    assert_eq!(values(&command, "input_paths"), ["/tmp/invalid.rs"]);
    assert!(effect(&command, EffectKind::ReadPath, "input_paths"));
    assert!(effect(&command, EffectKind::WritePath, "input_paths"));
}

#[test]
fn tsc_binds_explicit_source_and_outfile_as_distinct_graph_effects() {
    let command = bind("tsc /tmp/input.ts --outFile /tmp/output.js");
    assert_eq!(command.form_id.as_str(), "compile_explicit_sources_to_file");
    assert_eq!(values(&command, "source_paths"), ["/tmp/input.ts"]);
    assert_eq!(values(&command, "output_path"), ["/tmp/output.js"]);
    assert!(effect(&command, EffectKind::ReadPath, "source_paths"));
    assert!(
        command
            .effects
            .iter()
            .any(|item| item.kind == EffectKind::WritePath
                && matches!(&item.target, EffectTarget::ConfiguredPath(path)
            if path.sources.iter().any(|source| source.slot.as_str() == "output_path")))
    );

    let invalid = bind("tsc /tmp/input.ts --unknown-option");
    assert!(
        invalid.operation_semantics_unresolved
            || invalid.form_id.as_str() == "compile_explicit_sources"
    );
}
