use caushell_parse::parse_command;
use caushell_profile::{
    load_command_profile_from_str, resolve_invocation, BoundInvocation, BoundValue, EffectKind,
    EffectTarget, InvocationRuntimeContext, ProfileRegistry, ResolveInvocationResult,
    StreamOutputMode,
};
use caushell_types::{ShellKind, StreamDataDependency};

const PROFILES: [&str; 10] = [
    include_str!("../profiles/xz.yaml"),
    include_str!("../profiles/chattr.yaml"),
    include_str!("../profiles/setcap.yaml"),
    include_str!("../profiles/setfacl.yaml"),
    include_str!("../profiles/wall.yaml"),
    include_str!("../profiles/dialog.yaml"),
    include_str!("../profiles/whiptail.yaml"),
    include_str!("../profiles/eqn.yaml"),
    include_str!("../profiles/tbl.yaml"),
    include_str!("../profiles/soelim.yaml"),
];

fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        PROFILES
            .into_iter()
            .map(|yaml| load_command_profile_from_str(yaml).unwrap())
            .collect(),
    )
    .unwrap()
}

fn bind(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => r.bound,
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => bound,
        other => panic!("{command}: {other:?}"),
    }
}

fn values<'a>(bound: &'a BoundInvocation, slot: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.as_str(),
            _ => panic!("{v:?}"),
        })
        .collect()
}

fn effect_targets(bound: &BoundInvocation, kind: EffectKind, slot: &str) -> bool {
    bound.effects.iter().any(|effect| {
        effect.kind == kind
            && matches!(&effect.target, EffectTarget::Slot(name) if name.as_str() == slot)
    })
}

#[test]
fn gtfo_source_forms_bind_actual_file_and_metadata_targets() {
    let b = bind("xz -c /opt/secret | xz -d");
    assert_eq!(b.form_id.as_str(), "compress_stdout_files");
    assert_eq!(values(&b, "input_paths"), ["/opt/secret"]);
    assert!(effect_targets(&b, EffectKind::ReadPath, "input_paths"));
    assert_eq!(
        b.stream_contract.unwrap().stdout_mode,
        StreamOutputMode::Data
    );

    for command in ["chattr +i /opt/secret", "chattr -i /opt/secret"] {
        let b = bind(command);
        assert_eq!(values(&b, "targets"), ["/opt/secret"]);
        assert!(effect_targets(&b, EffectKind::MetadataMutation, "targets"));
    }
    let b = bind("setcap cap_setuid+ep /opt/secret");
    assert_eq!(values(&b, "capability_spec"), ["cap_setuid+ep"]);
    assert_eq!(values(&b, "executable_path"), ["/opt/secret"]);
    assert!(effect_targets(
        &b,
        EffectKind::MetadataMutation,
        "executable_path"
    ));

    let b = bind("setfacl -m u:alice:rwx /opt/secret");
    assert_eq!(values(&b, "acl_spec"), ["u:alice:rwx"], "{b:?}");
    assert_eq!(values(&b, "targets"), ["/opt/secret"], "{b:?}");
    assert!(effect_targets(&b, EffectKind::MetadataMutation, "targets"));

    let b = bind("wall --nobanner /opt/secret");
    assert_eq!(values(&b, "message_file"), ["/opt/secret"]);
    assert!(effect_targets(&b, EffectKind::ReadPath, "message_file"));
    assert_eq!(
        b.stream_contract.unwrap().stdout_mode,
        StreamOutputMode::Opaque
    );
}

#[test]
fn tui_textbox_dimensions_are_data_and_ui_streams_are_not_stdout() {
    for command in [
        "dialog --textbox /opt/secret 24 80",
        "whiptail --textbox --scrolltext /opt/secret 24 80",
    ] {
        let b = bind(command);
        assert_eq!(values(&b, "text_file"), ["/opt/secret"], "{command}: {b:?}");
        assert_eq!(values(&b, "height"), ["24"]);
        assert_eq!(values(&b, "width"), ["80"]);
        assert!(effect_targets(&b, EffectKind::ReadPath, "text_file"));
        assert_eq!(
            b.stream_contract.unwrap().stdout_mode,
            StreamOutputMode::Opaque
        );
    }
}

#[test]
fn groff_preprocessors_read_input_and_emit_transformed_text() {
    for (command, slot) in [
        ("eqn /opt/secret", "input_paths"),
        ("tbl /opt/secret", "input_paths"),
        ("soelim /opt/secret", "input_paths"),
    ] {
        let b = bind(command);
        assert_eq!(values(&b, slot), ["/opt/secret"]);
        assert!(effect_targets(&b, EffectKind::ReadPath, slot));
        assert!(b
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::TransformData));
        let stream = b.stream_contract.unwrap();
        assert_eq!(stream.stdout_mode, StreamOutputMode::Data);
        assert_eq!(stream.stdout_dependency, StreamDataDependency::Inputs);
    }
    let soelim = bind("soelim -I /opt/includes /opt/secret");
    assert_eq!(
        values(&soelim, "include_directories"),
        ["/opt/includes"],
        "{soelim:?}"
    );
    assert!(soelim
        .effects
        .iter()
        .any(|e| e.kind == EffectKind::ReadPath && e.target == EffectTarget::None));
}

#[test]
fn xz_known_suffix_outputs_keep_and_file_stream_boundaries() {
    let b = bind("xz -d /workspace/archive.xz");
    assert_eq!(b.form_id.as_str(), "decompress_file_xz_suffix");
    assert_eq!(values(&b, "input_paths"), ["/workspace/archive.xz"]);
    assert!(b.effects.iter().any(
        |e| e.kind == EffectKind::WritePath && matches!(e.target, EffectTarget::DerivedPath(_))
    ));

    let unknown_name = bind("xz -d /workspace/archive.raw");
    assert_eq!(
        unknown_name.form_id.as_str(),
        "decompress_file_other_suffix_unresolved"
    );
    assert!(unknown_name
        .effects
        .iter()
        .any(|e| e.kind == EffectKind::WritePath && e.target == EffectTarget::None));

    let keep = bind("xz -k /workspace/input");
    assert_eq!(keep.form_id.as_str(), "compress_file_keep");
    assert!(!keep
        .effects
        .iter()
        .any(|e| e.kind == EffectKind::DeletePath));

    let decoded_stdout = bind("xz -dc /workspace/archive.xz");
    assert_eq!(decoded_stdout.form_id.as_str(), "decompress_stdout_files");
    assert_eq!(
        values(&decoded_stdout, "input_paths"),
        ["/workspace/archive.xz"]
    );
    assert_eq!(
        decoded_stdout.stream_contract.unwrap().stdout_mode,
        StreamOutputMode::Data
    );

    let leading_dash_name = bind("xz -c -- -looks-like-an-option");
    assert_eq!(leading_dash_name.form_id.as_str(), "compress_stdout_files");
    assert_eq!(
        values(&leading_dash_name, "input_paths"),
        ["-looks-like-an-option"]
    );
    assert!(effect_targets(
        &leading_dash_name,
        EffectKind::ReadPath,
        "input_paths"
    ));
    assert!(!leading_dash_name.operation_semantics_unresolved);
    assert!(leading_dash_name.residuals.is_empty());
}

#[test]
fn preprocessors_separate_file_stdin_and_mixed_sources() {
    for (tool, file_form, stdin_form, mixed_form) in [
        (
            "eqn",
            "preprocess_equations",
            "preprocess_equations_from_stdin",
            "preprocess_equations_with_stdin_and_files",
        ),
        (
            "tbl",
            "preprocess_tables",
            "preprocess_tables_from_stdin",
            "preprocess_tables_with_stdin_and_files",
        ),
        (
            "soelim",
            "expand_so_requests",
            "expand_so_requests_from_stdin",
            "expand_so_requests_with_stdin_and_files",
        ),
    ] {
        let file = bind(&format!("{tool} /workspace/source"));
        assert_eq!(file.form_id.as_str(), file_form);
        assert_eq!(
            file.stream_contract.unwrap().stdin_mode,
            caushell_profile::StreamInputMode::Ignored
        );

        let stdin = bind(tool);
        assert_eq!(stdin.form_id.as_str(), stdin_form);
        assert_eq!(
            stdin.stream_contract.unwrap().stdin_mode,
            caushell_profile::StreamInputMode::DataRequired
        );

        let mixed = bind(&format!("{tool} - /workspace/source"));
        assert_eq!(mixed.form_id.as_str(), mixed_form);
        assert_eq!(values(&mixed, "stdin_markers"), ["-"]);
        assert_eq!(values(&mixed, "input_paths"), ["/workspace/source"]);
        assert_eq!(
            mixed.stream_contract.unwrap().stdin_mode,
            caushell_profile::StreamInputMode::DataRequired
        );
    }
}

#[test]
fn option_values_are_not_reclassified_as_file_paths() {
    let wall = bind("wall --group /opt/group --timeout 5 /opt/message");
    assert_eq!(values(&wall, "group_name"), ["/opt/group"]);
    assert_eq!(values(&wall, "timeout_seconds"), ["5"]);
    assert_eq!(values(&wall, "message_file"), ["/opt/message"]);

    let setfacl = bind("setfacl -m /opt/acl-spec /opt/target /workspace/second");
    assert_eq!(
        values(&setfacl, "acl_spec"),
        ["/opt/acl-spec"],
        "{setfacl:?}"
    );
    assert_eq!(
        values(&setfacl, "targets"),
        ["/opt/target", "/workspace/second"],
        "{setfacl:?}"
    );

    let no_read_for_transform_dimensions = bind("dialog --textbox /workspace/public 0 0");
    assert_eq!(
        values(&no_read_for_transform_dimensions, "text_file"),
        ["/workspace/public"]
    );
    assert_eq!(values(&no_read_for_transform_dimensions, "height"), ["0"]);
}

#[test]
fn stdin_markers_unknown_options_and_missing_operands_keep_boundaries() {
    for command in ["xz -c", "xz -c -", "xz -d"] {
        let b = bind(command);
        assert!(b.stream_contract.is_some(), "{command}: {b:?}");
        assert_eq!(values(&b, "input_paths").len(), 0, "{command}: {b:?}");
    }
    let explicit_stdin = bind("xz -c -- -");
    assert_eq!(explicit_stdin.form_id.as_str(), "compress_stdout_dash");
    assert_eq!(values(&explicit_stdin, "stdin_marker"), ["-"]);
    for command in [
        "setcap cap_setuid+ep",
        "setcap cap_setuid+ep /opt/first cap_net_bind_service+ep /opt/second",
        "setfacl -m u:alice:rwx",
        "chattr +i",
        "dialog --textbox /opt/secret 24",
        "whiptail --textbox /opt/secret",
        "soelim --mystery /opt/secret",
    ] {
        let b = bind(command);
        assert!(
            b.operation_semantics_unresolved || !b.residuals.is_empty(),
            "{command}: {b:?}"
        );
    }
}
