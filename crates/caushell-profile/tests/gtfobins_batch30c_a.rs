//! Static argv/effect checks for the A group of the fixed GTFOBins snapshot.
//! Child commands are parsed and projected; no shell example is executed.
use caushell_parse::parse_command;
use caushell_profile::StreamInputMode;
use caushell_profile::*;
use caushell_types::{ShellKind, StreamDataDependency};

const HEXDUMP: &str = include_str!("../profiles/hexdump.yaml");
const LAST: &str = include_str!("../profiles/last.yaml");
const ZSOELIM: &str = include_str!("../profiles/zsoelim.yaml");
const MTR: &str = include_str!("../profiles/mtr.yaml");
const NASM: &str = include_str!("../profiles/nasm.yaml");
const TIC: &str = include_str!("../profiles/tic.yaml");
const PAX: &str = include_str!("../profiles/pax.yaml");
const GENISOIMAGE: &str = include_str!("../profiles/genisoimage.yaml");
const ASPELL: &str = include_str!("../profiles/aspell.yaml");
const QPDF: &str = include_str!("../profiles/qpdf.yaml");

fn bind(source: &str, command: &str) -> BoundInvocation {
    let profile = load_command_profile_from_str(source).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&profile, &projected)
        .unwrap_or_else(|error| panic!("{command}: {error}"));
    bind_invocation(&profile, &projected, &selected)
}

fn assert_form(source: &str, command: &str, expected: &str) -> BoundInvocation {
    let bound = bind(source, command);
    assert_eq!(bound.form_id.as_str(), expected, "{command}: {bound:#?}");
    assert!(bound.residuals.is_empty(), "{command}: {bound:#?}");
    assert!(
        !bound.operation_semantics_unresolved,
        "{command}: {bound:#?}"
    );
    bound
}

fn args(bound: &BoundInvocation, name: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|value| value.name.as_str() == name)
        .flat_map(|value| &value.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.clone(),
            other => panic!("unexpected {name} binding: {other:?}"),
        })
        .collect()
}

fn has_effect(bound: &BoundInvocation, effect: EffectKind) -> bool {
    bound
        .effects
        .iter()
        .any(|candidate| candidate.kind == effect)
}

#[test]
fn all_ten_entries_load_with_snapshot_research_and_scope() {
    for (name, source) in [
        ("hexdump", HEXDUMP),
        ("last", LAST),
        ("zsoelim", ZSOELIM),
        ("mtr", MTR),
        ("nasm", NASM),
        ("tic", TIC),
        ("pax", PAX),
        ("genisoimage", GENISOIMAGE),
        ("aspell", ASPELL),
        ("qpdf", QPDF),
    ] {
        let profile =
            load_command_profile_from_str(source).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(profile.identity.canonical_name.as_str(), name);
        assert!(
            profile
                .extensions
                .contains_key("caushell.profile/source_research"),
            "{name}"
        );
        assert!(
            profile
                .extensions
                .contains_key("caushell.profile/known_limitations"),
            "{name}"
        );
    }
    assert!(
        load_command_profile_from_str(HEXDUMP)
            .unwrap()
            .identity
            .aliases
            .iter()
            .any(|alias| alias.as_str() == "hd")
    );
    assert!(
        load_command_profile_from_str(LAST)
            .unwrap()
            .identity
            .aliases
            .iter()
            .any(|alias| alias.as_str() == "lastb")
    );
}

#[test]
fn read_and_probe_recipes_bind_real_sources_and_stream_dependencies() {
    let hd = assert_form(HEXDUMP, "hd -C /opt/shared/secret", "dump_files");
    assert_eq!(args(&hd, "input_paths"), ["/opt/shared/secret"]);
    assert!(has_effect(&hd, EffectKind::ReadPath));
    assert_eq!(
        hd.stream_contract.unwrap().stdout_dependency,
        StreamDataDependency::Inputs
    );
    let format_file = assert_form(HEXDUMP, "hd -f /opt/shared/hexdump.format", "dump_stream");
    assert_eq!(
        args(&format_file, "format_paths"),
        ["/opt/shared/hexdump.format"]
    );
    assert!(has_effect(&format_file, EffectKind::ReadPath));

    let last = assert_form(LAST, "lastb -f /opt/shared/btmp", "list_records_from_file");
    assert_eq!(args(&last, "input_path"), ["/opt/shared/btmp"]);
    assert!(has_effect(&last, EffectKind::ReadPath));

    let zsoelim = assert_form(
        ZSOELIM,
        "zsoelim /opt/shared/man.roff",
        "satisfy_so_requests_from_files",
    );
    assert_eq!(args(&zsoelim, "input_paths"), ["/opt/shared/man.roff"]);
    assert!(
        zsoelim
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ReadPath
                && matches!(effect.target, EffectTarget::None))
    );
    let stdin_roff = assert_form(ZSOELIM, "zsoelim", "satisfy_so_requests_from_stdin");
    assert!(has_effect(&stdin_roff, EffectKind::ConsumeStdin));

    let mtr = assert_form(
        MTR,
        "mtr --raw -F /opt/shared/hosts",
        "probe_targets_from_file",
    );
    assert_eq!(args(&mtr, "host_file"), ["/opt/shared/hosts"]);
    assert!(has_effect(&mtr, EffectKind::ReadPath));
    assert!(has_effect(&mtr, EffectKind::NetworkEndpoint));
    let mtr_stdin = assert_form(MTR, "mtr --raw -F -", "probe_targets_from_stdin");
    assert!(has_effect(&mtr_stdin, EffectKind::ConsumeStdin));
    assert!(has_effect(&mtr_stdin, EffectKind::NetworkEndpoint));
    let mtr_help = assert_form(MTR, "mtr --help", "show_help_or_version");
    assert_eq!(
        mtr_help.stream_contract.unwrap().stdin_mode,
        StreamInputMode::Ignored
    );
    let zsoelim_help = assert_form(ZSOELIM, "zsoelim -h", "show_help_or_version");
    assert_eq!(
        zsoelim_help.stream_contract.unwrap().stdout_dependency,
        StreamDataDependency::Independent
    );
}

#[test]
fn response_translation_and_archive_modes_keep_path_roles_distinct() {
    let nasm = assert_form(NASM, "nasm -@ /opt/shared/nasm.args", "parse_argument_file");
    assert_eq!(
        args(&nasm, "response_file_paths"),
        ["/opt/shared/nasm.args"]
    );
    assert!(has_effect(&nasm, EffectKind::ReadPath));
    let nasm_profile = load_command_profile_from_str(NASM).unwrap();
    assert_eq!(
        nasm_profile.argument_files[0].possible_effects,
        [EffectKind::ReadPath, EffectKind::WritePath]
    );
    let normal_nasm = assert_form(
        NASM,
        "nasm -f elf64 /tmp/safe.asm -o /tmp/safe.o",
        "assemble_to_explicit_output",
    );
    assert_eq!(args(&normal_nasm, "source_paths"), ["/tmp/safe.asm"]);
    assert_eq!(args(&normal_nasm, "output_file"), ["/tmp/safe.o"]);
    let default_output_nasm = assert_form(
        NASM,
        "nasm -f elf64 /tmp/safe.asm",
        "assemble_to_default_output",
    );
    assert!(
        default_output_nasm
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::WritePath
                && matches!(effect.target, EffectTarget::None))
    );

    let translated = assert_form(
        TIC,
        "tic -C /opt/shared/terminfo.src",
        "translate_to_termcap",
    );
    assert_eq!(
        args(&translated, "source_paths"),
        ["/opt/shared/terminfo.src"]
    );
    assert!(!has_effect(&translated, EffectKind::WritePath));
    assert!(has_effect(&translated, EffectKind::TransformData));
    let checked = assert_form(TIC, "tic -c /opt/shared/terminfo.src", "validate_only");
    assert!(!has_effect(&checked, EffectKind::WritePath));
    let translated_with_output_dir = assert_form(
        TIC,
        "tic -C -o /opt/shared/ignored-dir /opt/shared/terminfo.src",
        "translate_to_termcap",
    );
    assert!(!has_effect(
        &translated_with_output_dir,
        EffectKind::WritePath
    ));
    let check_dominates_translation =
        assert_form(TIC, "tic -C -c /opt/shared/terminfo.src", "validate_only");
    assert!(!has_effect(
        &check_dominates_translation,
        EffectKind::WritePath
    ));
    assert_eq!(
        check_dominates_translation
            .stream_contract
            .unwrap()
            .stdout_dependency,
        StreamDataDependency::Independent
    );
    let compiled = assert_form(
        TIC,
        "tic -o /opt/shared/terminfo.db /opt/shared/terminfo.src",
        "compile_database_entries",
    );
    assert!(has_effect(&compiled, EffectKind::WritePath));

    let archive_stdout = assert_form(PAX, "pax -w /opt/shared/secret", "write_archive_to_stdout");
    assert_eq!(
        args(&archive_stdout, "source_paths"),
        ["/opt/shared/secret"]
    );
    assert_eq!(
        archive_stdout.stream_contract.unwrap().stdout_mode,
        StreamOutputMode::Data
    );
    let archive_file = assert_form(
        PAX,
        "pax -w -f /opt/shared/a.pax /opt/shared/secret",
        "write_archive_file",
    );
    assert_eq!(args(&archive_file, "source_paths"), ["/opt/shared/secret"]);
    assert_eq!(
        args(&archive_file, "archive_output_path"),
        ["/opt/shared/a.pax"]
    );
    assert!(has_effect(&archive_file, EffectKind::WritePath));
    let extract = assert_form(
        PAX,
        "pax -r -f /opt/shared/a.pax secret/member",
        "extract_archive_members",
    );
    assert_eq!(args(&extract, "member_patterns"), ["secret/member"]);
    assert_eq!(args(&extract, "archive_input_path"), ["/opt/shared/a.pax"]);
    assert!(has_effect(&extract, EffectKind::WritePath));
    let archive_from_stdin = assert_form(PAX, "pax -r secret/member", "extract_archive_from_stdin");
    assert!(has_effect(&archive_from_stdin, EffectKind::ConsumeStdin));
    let list_to_stdin = assert_form(PAX, "pax -w", "write_archive_from_stdin_path_list");
    assert!(has_effect(&list_to_stdin, EffectKind::ConsumeStdin));
}

#[test]
fn output_files_tuis_and_attachment_members_have_explicit_effects() {
    let iso = assert_form(
        GENISOIMAGE,
        "genisoimage -q -o - /opt/shared/secret",
        "create_iso_to_stdout",
    );
    assert_eq!(args(&iso, "source_paths"), ["/opt/shared/secret"]);
    assert_eq!(
        iso.stream_contract.unwrap().stdout_mode,
        StreamOutputMode::Data
    );
    let sort_only = assert_form(
        GENISOIMAGE,
        "genisoimage -sort /opt/shared/order",
        "diagnose_sort_file",
    );
    assert_eq!(args(&sort_only, "sort_path"), ["/opt/shared/order"]);
    assert!(has_effect(&sort_only, EffectKind::ReadPath));
    assert_eq!(
        sort_only.stream_contract.unwrap().stdout_dependency,
        StreamDataDependency::Independent
    );
    let sort = assert_form(
        GENISOIMAGE,
        "genisoimage -sort /opt/shared/order -o /opt/shared/disk.iso /opt/shared/tree",
        "create_iso_to_file",
    );
    assert_eq!(args(&sort, "source_paths"), ["/opt/shared/tree"]);
    assert!(has_effect(&sort, EffectKind::ReadPath));
    assert!(has_effect(&sort, EffectKind::WritePath));
    assert_eq!(
        sort.stream_contract.unwrap().stdout_dependency,
        StreamDataDependency::Independent
    );
    let iso_stdout = assert_form(
        GENISOIMAGE,
        "genisoimage -o - /opt/shared/tree",
        "create_iso_to_stdout",
    );
    assert_eq!(
        iso_stdout.stream_contract.unwrap().stdout_dependency,
        StreamDataDependency::Inputs
    );
    let path_list = assert_form(
        GENISOIMAGE,
        "genisoimage -path-list /opt/shared/paths.list -o - /opt/shared/tree",
        "create_iso_with_path_list_to_stdout",
    );
    assert!(
        path_list
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ReadPath
                && matches!(effect.target, EffectTarget::None))
    );
    let path_list_only = assert_form(
        GENISOIMAGE,
        "genisoimage -path-list /opt/shared/paths.list -o -",
        "create_iso_with_path_list_to_stdout",
    );
    assert_eq!(
        args(&path_list_only, "path_list_file"),
        ["/opt/shared/paths.list"]
    );

    let check = assert_form(
        ASPELL,
        "aspell -c /opt/shared/secret.txt",
        "interactive_check_file",
    );
    assert_eq!(args(&check, "input_path"), ["/opt/shared/secret.txt"]);
    assert!(has_effect(&check, EffectKind::ReadPath));
    assert!(has_effect(&check, EffectKind::WritePath));
    assert!(has_effect(&check, EffectKind::OpenInteractiveEscapeSurface));
    let config = assert_form(
        ASPELL,
        "aspell --conf /opt/shared/aspell.conf",
        "parse_configuration_file",
    );
    assert_eq!(args(&config, "config_path"), ["/opt/shared/aspell.conf"]);
    let check_with_config = assert_form(
        ASPELL,
        "aspell --conf /opt/shared/aspell.conf -c /opt/shared/secret.txt",
        "interactive_check_file",
    );
    assert_eq!(
        args(&check_with_config, "input_path"),
        ["/opt/shared/secret.txt"]
    );
    assert!(has_effect(&check_with_config, EffectKind::ReadPath));
    let aspell_help = assert_form(ASPELL, "aspell --help", "show_help_or_version");
    assert_eq!(
        aspell_help.stream_contract.unwrap().stdin_mode,
        StreamInputMode::Ignored
    );

    let add = assert_form(
        QPDF,
        "qpdf --empty --add-attachment /opt/shared/secret --key=x -- /opt/shared/out.pdf",
        "add_attachment_to_new_pdf",
    );
    assert_eq!(args(&add, "attachment_path"), ["/opt/shared/secret"]);
    assert_eq!(args(&add, "output_path"), ["/opt/shared/out.pdf"]);
    assert!(has_effect(&add, EffectKind::ReadPath));
    assert!(has_effect(&add, EffectKind::WritePath));
    let show = assert_form(
        QPDF,
        "qpdf --show-attachment=x /opt/shared/out.pdf",
        "show_pdf_attachment",
    );
    assert_eq!(args(&show, "pdf_paths"), ["/opt/shared/out.pdf"]);
    assert_eq!(
        show.stream_contract.unwrap().stdout_mode,
        StreamOutputMode::Data
    );
    let stdout = assert_form(
        QPDF,
        "qpdf --empty --add-attachment /opt/shared/secret --key=x -- -",
        "add_attachment_to_stdout",
    );
    assert_eq!(
        stdout.stream_contract.unwrap().stdout_mode,
        StreamOutputMode::Data
    );
}

#[test]
fn normal_and_ambiguous_boundaries_are_not_misclassified_as_recipes() {
    for (source, command) in [
        (TIC, "tic -c /tmp/safe.terminfo"),
        (NASM, "nasm -f elf64 /tmp/safe.asm -o /tmp/safe.o"),
        (PAX, "pax -w /tmp/safe-file"),
        (GENISOIMAGE, "genisoimage -o /tmp/safe.iso /tmp/safe-tree"),
    ] {
        let _ = bind(source, command);
    }
    let bad_alias = load_command_profile_from_str(ZSOELIM).unwrap();
    let parsed = parse_command("zsoelim -I /opt/shared", ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    assert!(select_invocation(&bad_alias, &projection).is_err());
    let qpdf = load_command_profile_from_str(QPDF).unwrap();
    let parsed = parse_command(
        "qpdf --add-attachment /tmp/safe --key=x -- /tmp/out.pdf",
        ShellKind::Bash,
    )
    .unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    assert!(
        select_invocation(&qpdf, &projection).is_err(),
        "--empty is required for the file-read recipe form"
    );
}
