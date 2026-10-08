use caushell_parse::parse_command;
use caushell_profile::{
    bind_invocation, load_command_profile_from_str, project_invocation, select_invocation,
    BoundInvocation, BoundValue, EffectKind, InvocationRuntimeContext, ProfileRegistry,
    StreamInputMode,
};
use caushell_types::{ShellKind, StreamDataDependency};

fn bind(source: &str, command: &str) -> BoundInvocation {
    let profile = load_command_profile_from_str(source).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&profile, &projected)
        .unwrap_or_else(|error| panic!("{command}: {error}"));
    bind_invocation(&profile, &projected, &selected)
}

fn assert_resolved(b: &BoundInvocation, command: &str) {
    assert!(
        !b.operation_semantics_unresolved && b.residuals.is_empty(),
        "{command}: {b:#?}"
    );
}

fn text_values<'a>(b: &'a BoundInvocation, name: &str) -> Vec<&'a str> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.as_str(),
            _ => panic!("unexpected value for {name}: {value:?}"),
        })
        .collect()
}

const LOOK: &str = include_str!("../profiles/look.yaml");
const UL: &str = include_str!("../profiles/ul.yaml");
const UUENCODE: &str = include_str!("../profiles/uuencode.yaml");
const ASCII85: &str = include_str!("../profiles/ascii85.yaml");
const BASE58: &str = include_str!("../profiles/base58.yaml");
const BASEZ: &str = include_str!("../profiles/basez.yaml");
const ASCII_XFR: &str = include_str!("../profiles/ascii-xfr.yaml");
const LAST: &str = include_str!("../profiles/last.yaml");
const NM: &str = include_str!("../profiles/nm.yaml");
const CUPSFILTER: &str = include_str!("../profiles/cupsfilter.yaml");

#[test]
fn all_ten_profiles_are_registered_and_bind_the_source_demonstrated_form() {
    let registry = ProfileRegistry::built_in().unwrap();
    for name in [
        "look",
        "ul",
        "uuencode",
        "ascii85",
        "base58",
        "basez",
        "ascii-xfr",
        "last",
        "nm",
        "cupsfilter",
    ] {
        assert!(registry.lookup(name).profile.is_some(), "{name}");
    }

    let cases = [
        (LOOK, "look '' /path/to/file", "lookup_file"),
        (UL, "ul /path/to/file", "render_files"),
        (
            UUENCODE,
            "uuencode /path/to/file /dev/stdout",
            "encode_file",
        ),
        (ASCII85, "ascii85 /path/to/file", "encode_file"),
        (BASE58, "base58 /path/to/file", "encode_file"),
        (BASEZ, "basez /path/to/file", "encode_file"),
        (ASCII_XFR, "ascii-xfr -ns /path/to/file", "send_file"),
        (LAST, "last -a -f /path/to/file", "list_records_from_file"),
        (NM, "nm -C /path/to/file", "list_symbols"),
        (
            CUPSFILTER,
            "cupsfilter -i application/octet-stream -m application/octet-stream /path/to/file",
            "raw_file_to_stdout",
        ),
    ];
    for (source, command, form) in cases {
        let b = bind(source, command);
        assert_resolved(&b, command);
        assert_eq!(b.form_id.as_str(), form, "{command}: {b:#?}");
    }
}

#[test]
fn source_operands_are_bound_by_role_not_by_position_name_or_option_spelling() {
    let b = bind(LOOK, "look '' /path/to/file");
    assert_resolved(&b, "look '' /path/to/file");
    assert_eq!(text_values(&b, "search_prefix"), [""]);
    assert_eq!(text_values(&b, "input_path"), ["/path/to/file"]);
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));

    let b = bind(UUENCODE, "uuencode /path/to/input /dev/stdout");
    assert_resolved(&b, "uuencode /path/to/input /dev/stdout");
    assert_eq!(text_values(&b, "input_path"), ["/path/to/input"]);
    assert_eq!(text_values(&b, "output_name"), ["/dev/stdout"]);
    assert!(!b
        .bound_parameters
        .iter()
        .any(|p| p.name.as_str().contains("output_path")));
    assert_eq!(
        b.effects
            .iter()
            .filter(|e| e.kind == EffectKind::ReadPath)
            .count(),
        1
    );
    assert!(!b
        .effects
        .iter()
        .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::DeletePath)));

    let b = bind(NM, "nm -C /path/to/object");
    assert_resolved(&b, "nm -C /path/to/object");
    assert_eq!(text_values(&b, "object_paths"), ["/path/to/object"]);
    assert!(!text_values(&b, "object_paths").contains(&"-C"));

    let b = bind(
        CUPSFILTER,
        "cupsfilter -i application/octet-stream -m application/octet-stream /path/to/file",
    );
    assert_resolved(
        &b,
        "cupsfilter -i application/octet-stream -m application/octet-stream /path/to/file",
    );
    assert_eq!(text_values(&b, "input_path"), ["/path/to/file"]);
    assert!(!text_values(&b, "input_path").contains(&"application/octet-stream"));
}

#[test]
fn encoding_profiles_preserve_file_stdin_and_non_sanitizing_transform_contracts() {
    for (source, command, expected_form) in [
        (ASCII85, "ascii85 /path/to/file", "encode_file"),
        (ASCII85, "ascii85 --decode /path/to/file", "decode_file"),
        (BASE58, "base58 /path/to/file", "encode_file"),
        (BASE58, "base58 --decode /path/to/file", "decode_file"),
        (BASEZ, "basez /path/to/file", "encode_file"),
        (BASEZ, "basez --decode /path/to/file", "decode_file"),
    ] {
        let b = bind(source, command);
        assert_resolved(&b, command);
        assert_eq!(b.form_id.as_str(), expected_form, "{command}: {b:#?}");
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
        assert!(b
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::TransformData));
        assert!(!b.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::WritePath | EffectKind::DeletePath | EffectKind::ExecutePayload
        )));
        let streams = b.stream_contract.unwrap();
        assert_eq!(streams.stdin_mode, StreamInputMode::Ignored);
        assert_eq!(streams.stdout_dependency, StreamDataDependency::Inputs);
    }

    for (source, command, form) in [
        (ASCII85, "ascii85", "encode_stdin"),
        (ASCII85, "ascii85 --decode", "decode_stdin"),
        (BASE58, "base58", "encode_stdin"),
        (BASE58, "base58 --decode", "decode_stdin"),
        (BASEZ, "basez", "encode_stdin"),
        (BASEZ, "basez --decode", "decode_stdin"),
    ] {
        let b = bind(source, command);
        assert_resolved(&b, command);
        assert_eq!(b.form_id.as_str(), form);
        assert_eq!(
            b.stream_contract.unwrap().stdin_mode,
            StreamInputMode::DataRequired
        );
    }
}

#[test]
fn file_readers_ignore_unrelated_stdin_and_report_actual_input_contracts() {
    let file_cases = [
        (LOOK, "look root /path/to/file", "lookup_file"),
        (UL, "ul /path/to/file", "render_files"),
        (
            UUENCODE,
            "uuencode /path/to/file /dev/stdout",
            "encode_file",
        ),
        (ASCII85, "ascii85 /path/to/file", "encode_file"),
        (BASE58, "base58 /path/to/file", "encode_file"),
        (BASEZ, "basez /path/to/file", "encode_file"),
        (ASCII_XFR, "ascii-xfr -ns /path/to/file", "send_file"),
        (LAST, "last -a -f /path/to/file", "list_records_from_file"),
        (NM, "nm -C /path/to/file", "list_symbols"),
        (
            CUPSFILTER,
            "cupsfilter -i application/octet-stream -m application/octet-stream /path/to/file",
            "raw_file_to_stdout",
        ),
    ];
    for (source, command, form) in file_cases {
        let b = bind(source, command);
        assert_resolved(&b, command);
        assert_eq!(b.form_id.as_str(), form);
        assert_eq!(
            b.stream_contract.unwrap().stdin_mode,
            StreamInputMode::Ignored
        );
    }

    let b = bind(UL, "ul");
    assert_resolved(&b, "ul");
    assert_eq!(b.form_id.as_str(), "render_stdin");
    assert_eq!(
        b.stream_contract.unwrap().stdin_mode,
        StreamInputMode::DataRequired
    );

    for command in ["uuencode output-name", "uuencode - output-name"] {
        let b = bind(UUENCODE, command);
        assert_resolved(&b, command);
        assert_eq!(
            b.stream_contract.unwrap().stdin_mode,
            StreamInputMode::DataRequired
        );
        assert!(text_values(&b, "input_path").is_empty());
    }

    let b = bind(UUENCODE, "uuencode input /dev/stdout");
    assert_resolved(&b, "uuencode input /dev/stdout");
    assert_eq!(text_values(&b, "input_path"), ["input"]);
    assert_eq!(
        b.stream_contract.unwrap().stdin_mode,
        StreamInputMode::Ignored
    );
}

#[test]
fn unsupported_shapes_remain_unresolved_instead_of_becoming_path_or_data_forms() {
    for (source, command) in [
        (LOOK, "look /path/to/file"),
        (LOOK, "look root first second"),
        (UL, "ul - /path/to/file"),
        (UUENCODE, "uuencode"),
        (UUENCODE, "uuencode input name extra"),
        (ASCII85, "ascii85 first second"),
        (ASCII85, "ascii85 --unknown /path/to/file"),
        (BASE58, "base58 first second"),
        (BASEZ, "basez first second"),
        (BASEZ, "basez --output /outside /path/to/file"),
        (ASCII_XFR, "ascii-xfr -r /outside"),
        (ASCII_XFR, "ascii-xfr -s"),
        (LAST, "last -f"),
        (LAST, "last -a -f /path/to/file root"),
        (NM, "nm -C"),
        (NM, "nm --plugin=/outside/plugin /path/to/file"),
        (
            CUPSFILTER,
            "cupsfilter -i /path/to/file -m application/octet-stream",
        ),
        (
            CUPSFILTER,
            "cupsfilter -i application/octet-stream -m text/plain /path/to/file",
        ),
        (
            CUPSFILTER,
            "cupsfilter -D -i application/octet-stream -m application/octet-stream /path/to/file",
        ),
    ] {
        let profile = load_command_profile_from_str(source).unwrap();
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        if let Ok(selected) = select_invocation(&profile, &projection) {
            let b = bind_invocation(&profile, &projection, &selected);
            assert!(
                b.operation_semantics_unresolved || !b.residuals.is_empty(),
                "{command}: {b:#?}"
            );
        }
    }
}
