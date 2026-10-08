use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, EffectTarget, InvocationRuntimeContext,
    ProfileRegistry, ResolveInvocationResult, load_command_profile_from_str, project_invocation,
    resolve_invocation, select_invocation,
};
use caushell_types::{ShellKind, StreamDataDependency};

const PROFILES: [&str; 10] = [
    include_str!("../profiles/msgattrib.yaml"),
    include_str!("../profiles/msgcat.yaml"),
    include_str!("../profiles/msgconv.yaml"),
    include_str!("../profiles/msgmerge.yaml"),
    include_str!("../profiles/msguniq.yaml"),
    include_str!("../profiles/readelf.yaml"),
    include_str!("../profiles/highlight.yaml"),
    include_str!("../profiles/espeak.yaml"),
    include_str!("../profiles/atobm.yaml"),
    include_str!("../profiles/redcarpet.yaml"),
];

fn registry() -> ProfileRegistry {
    let names = [
        "msgattrib",
        "msgcat",
        "msgconv",
        "msgmerge",
        "msguniq",
        "readelf",
        "highlight",
        "espeak",
        "atobm",
        "redcarpet",
    ];
    ProfileRegistry::from_profiles(
        PROFILES
            .into_iter()
            .enumerate()
            .map(|(index, source)| {
                load_command_profile_from_str(source)
                    .unwrap_or_else(|error| panic!("{}: {error:?}", names[index]))
            })
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
            other => panic!("unexpected {name} value: {other:?}"),
        })
        .collect()
}

fn has_target(bound: &BoundInvocation, kind: EffectKind, slot: &str) -> bool {
    bound.effects.iter().any(|effect| {
        effect.kind == kind
            && matches!(&effect.target, EffectTarget::Slot(name) if name.as_str() == slot)
    })
}

fn assert_bound_source(command: &str, name: &str, path: &str, form: &str) -> BoundInvocation {
    let bound = bind(command);
    assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
    assert!(
        !bound.operation_semantics_unresolved,
        "{command}: {bound:#?}"
    );
    assert!(bound.residuals.is_empty(), "{command}: {bound:#?}");
    assert_eq!(values(&bound, name), [path], "{command}: {bound:#?}");
    assert!(
        has_target(&bound, EffectKind::ReadPath, name),
        "{command}: {bound:#?}"
    );
    bound
}

#[test]
fn all_ten_source_forms_load_and_bind_their_real_input_positions() {
    let cases = [
        (
            "msgattrib -P /tmp/project/catalog.po",
            "input_path",
            "/tmp/project/catalog.po",
            "read_properties",
        ),
        (
            "msgcat -P /tmp/project/a.po",
            "input_paths",
            "/tmp/project/a.po",
            "concatenate_properties",
        ),
        (
            "msgconv -P /tmp/project/catalog.po",
            "input_path",
            "/tmp/project/catalog.po",
            "convert_properties",
        ),
        (
            "msgmerge -P /tmp/project/old.po /dev/null",
            "input_po",
            "/tmp/project/old.po",
            "merge_properties",
        ),
        (
            "msguniq -P /tmp/project/catalog.po",
            "input_path",
            "/tmp/project/catalog.po",
            "deduplicate_properties",
        ),
        (
            "readelf -a /tmp/project/program",
            "elf_paths",
            "/tmp/project/program",
            "inspect_elf_files",
        ),
        (
            "highlight --no-doc --failsafe /tmp/project/source.c",
            "input_path",
            "/tmp/project/source.c",
            "highlight_failsafe_file",
        ),
        (
            "espeak -qXf /tmp/project/words.txt",
            "input_path",
            "/tmp/project/words.txt",
            "phoneme_trace_file",
        ),
        (
            "atobm /tmp/project/image.bm",
            "input_path",
            "/tmp/project/image.bm",
            "convert_bitmap_file",
        ),
        (
            "redcarpet /tmp/project/README.md",
            "input_path",
            "/tmp/project/README.md",
            "render_markdown_file",
        ),
    ];
    for (command, parameter, path, form) in cases {
        let bound = assert_bound_source(command, parameter, path, form);
        assert_eq!(
            bound.stream_contract.unwrap().stdout_dependency,
            StreamDataDependency::Inputs,
            "{command}"
        );
    }
}

#[test]
fn gettext_output_files_are_distinct_content_open_writes() {
    for (name, command, input_parameter, input) in [
        (
            "msgattrib",
            "msgattrib -P -o /opt/shared/out.po /tmp/project/in.po",
            "input_path",
            "/tmp/project/in.po",
        ),
        (
            "msgcat",
            "msgcat -P -o /opt/shared/out.po /tmp/project/a.po /tmp/project/b.po",
            "input_paths",
            "/tmp/project/a.po",
        ),
        (
            "msgconv",
            "msgconv -P -o /opt/shared/out.po /tmp/project/in.po",
            "input_path",
            "/tmp/project/in.po",
        ),
        (
            "msgmerge",
            "msgmerge -P -o /opt/shared/out.po /tmp/project/old.po /tmp/project/new.pot",
            "input_po",
            "/tmp/project/old.po",
        ),
        (
            "msguniq",
            "msguniq -P -o /opt/shared/out.po /tmp/project/in.po",
            "input_path",
            "/tmp/project/in.po",
        ),
    ] {
        let bound = bind(command);
        assert_eq!(
            bound.form_id.as_str(),
            match name {
                "msgattrib" => "read_properties_to_file",
                "msgcat" => "concatenate_properties_to_file",
                "msgconv" => "convert_properties_to_file",
                "msgmerge" => "merge_properties_to_file",
                _ => "deduplicate_properties_to_file",
            },
            "{command}: {bound:#?}"
        );
        assert_eq!(
            values(&bound, input_parameter).first().copied(),
            Some(input),
            "{command}: {bound:#?}"
        );
        assert_eq!(
            values(&bound, "output_path"),
            ["/opt/shared/out.po"],
            "{command}: {bound:#?}"
        );
        assert!(
            has_target(&bound, EffectKind::WritePath, "output_path"),
            "{command}: {bound:#?}"
        );
    }

    let merge = bind("msgmerge -P /tmp/project/old.po /dev/null");
    assert_eq!(values(&merge, "input_po"), ["/tmp/project/old.po"]);
    assert_eq!(values(&merge, "template_pot"), ["/dev/null"]);
    assert!(has_target(&merge, EffectKind::ReadPath, "input_po"));
    assert!(has_target(&merge, EffectKind::ReadPath, "template_pot"));
}

#[test]
fn source_parsers_keep_stdout_and_diagnostics_input_dependent() {
    for command in [
        "msgattrib -P /tmp/project/catalog.po",
        "msgcat -P /tmp/project/a.po /tmp/project/b.po",
        "msgconv -P /tmp/project/catalog.po",
        "msgmerge -P /tmp/project/old.po /tmp/project/new.pot",
        "msguniq -P /tmp/project/catalog.po",
        "readelf -a /tmp/project/program",
        "highlight --no-doc --failsafe /tmp/project/source.c",
        "espeak -qXf /tmp/project/words.txt",
        "redcarpet /tmp/project/README.md",
    ] {
        let bound = bind(command);
        let streams = bound.stream_contract.unwrap();
        assert_eq!(
            streams.stdout_dependency,
            StreamDataDependency::Inputs,
            "{command}"
        );
        assert_eq!(
            streams.stderr_dependency,
            StreamDataDependency::Inputs,
            "{command}"
        );
    }

    let atobm = bind("atobm -chars ' .' /tmp/project/image.bm");
    let streams = atobm.stream_contract.unwrap();
    assert_eq!(streams.stderr_dependency, StreamDataDependency::Inputs);
    assert_eq!(values(&atobm, "output_chars"), [" ."]);
    assert!(!values(&atobm, "output_chars").contains(&"/tmp/project/image.bm"));
}

#[test]
fn readelf_response_argument_is_opaque_and_keeps_possible_file_read_effect() {
    let profile = load_command_profile_from_str(include_str!("../profiles/readelf.yaml")).unwrap();
    let parsed = parse_command("readelf -a @/tmp/project/argv.txt", ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&profile, &projected);
    let selected = selected.expect("@FILE has a dedicated response-file form");
    let projected_bound = caushell_profile::bind_invocation(&profile, &projected, &selected);
    assert_eq!(projected_bound.form_id.as_str(), "inspect_response_file");
    let response_paths = projected_bound
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name.as_str() == "response_paths")
        .unwrap();
    assert!(
        matches!(&response_paths.values[0], BoundValue::Argument { text, .. } if text == "@/tmp/project/argv.txt")
    );
    assert_eq!(
        response_paths.projected_values.as_ref().unwrap()[0].resolution,
        caushell_profile::SemanticValueResolution::Known("/tmp/project/argv.txt".into())
    );

    let bound = match resolve_invocation(
        &ProfileRegistry::from_profiles(vec![profile]).unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(resolved) => resolved.bound,
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => bound,
        other => panic!("{other:?}"),
    };
    assert!(
        bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ReadPath)
    );
    assert_eq!(bound.form_id.as_str(), "inspect_response_file");
}

#[test]
fn gettext_output_modes_do_not_conflate_file_writes_with_stdout() {
    for (command, form) in [
        ("msgattrib -P /tmp/project/.env", "read_properties"),
        (
            "msgattrib -P -o /tmp/project/cache.po /tmp/project/.env",
            "read_properties_to_file",
        ),
        (
            "msgattrib -P -o - /tmp/project/.env",
            "read_properties_output_stdout",
        ),
    ] {
        let bound = bind(command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
        let streams = bound.stream_contract.unwrap();
        assert_eq!(
            streams.stdout_dependency,
            if form == "read_properties_to_file" {
                StreamDataDependency::Independent
            } else {
                StreamDataDependency::Inputs
            },
            "{command}"
        );
        assert_eq!(
            bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::WritePath),
            form == "read_properties_to_file",
            "{command}: {bound:#?}"
        );
    }

    let help = bind("msgattrib --help -o /opt/shared/should-not-write");
    assert_eq!(help.form_id.as_str(), "information");
    assert!(
        !help
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::WritePath)
    );
}

#[test]
fn unsupported_parser_and_configuration_options_remain_unresolved() {
    for command in [
        "msgattrib /tmp/project/catalog.po",
        "msguniq -P /tmp/project/a.po /tmp/project/b.po",
        "msgmerge -P /tmp/project/old.po",
        "highlight --no-doc --failsafe --config-file /tmp/project/custom.lang /tmp/project/source.c",
        "highlight --no-doc --failsafe --plug-in /tmp/project/plugin.lua /tmp/project/source.c",
        "redcarpet --unmodeled /tmp/project/README.md",
    ] {
        let bound = bind(command);
        assert!(
            bound.operation_semantics_unresolved || !bound.residuals.is_empty(),
            "{command}: {bound:#?}"
        );
    }
}
