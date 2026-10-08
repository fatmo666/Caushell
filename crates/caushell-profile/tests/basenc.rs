use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, InvocationRuntimeContext, ProfileRegistry,
    StreamInputMode, bind_invocation, load_command_profile_from_str, project_invocation,
    select_invocation,
};
use caushell_types::{ShellKind, StreamDataDependency};

fn bind(command: &str) -> BoundInvocation {
    let profile = load_command_profile_from_str(include_str!("../profiles/basenc.yaml")).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&profile, &projected)
        .unwrap_or_else(|error| panic!("{command}: {error}"));
    bind_invocation(&profile, &projected, &selected)
}

fn paths(bound: &BoundInvocation) -> Vec<&str> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == "input_path")
        .flat_map(|p| &p.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.as_str(),
            _ => panic!("unexpected input: {value:?}"),
        })
        .collect()
}

#[test]
fn all_declared_encodings_read_one_file_and_preserve_transform_semantics() {
    for encoding in [
        "base64",
        "base64url",
        "base32",
        "base32hex",
        "base16",
        "base2msbf",
        "base2lsbf",
        "z85",
        "base58",
    ] {
        for decode in [false, true] {
            let command = format!(
                "basenc --{encoding} {} input",
                if decode { "-d" } else { "" }
            );
            let b = bind(&command);
            assert!(
                !b.operation_semantics_unresolved && b.residuals.is_empty(),
                "{command}: {b:?}"
            );
            assert_eq!(paths(&b), ["input"]);
            assert_eq!(
                b.form_id.as_str(),
                if decode { "decode_file" } else { "encode_file" }
            );
            assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
            assert!(
                b.effects
                    .iter()
                    .any(|e| e.kind == EffectKind::TransformData)
            );
            assert!(!b.effects.iter().any(|e| matches!(
                e.kind,
                EffectKind::WritePath | EffectKind::DeletePath | EffectKind::ExecutePayload
            )));
            let streams = b.stream_contract.unwrap();
            assert_eq!(streams.stdin_mode, StreamInputMode::Ignored);
            assert_eq!(streams.stdout_dependency, StreamDataDependency::Inputs);
        }
    }
}

#[test]
fn absent_file_and_dash_read_stdin_without_fake_paths() {
    for command in [
        "basenc --base64",
        "basenc -d --base64",
        "basenc --base64 -",
        "basenc --base64 -di -",
    ] {
        let b = bind(command);
        assert!(
            !b.operation_semantics_unresolved && b.residuals.is_empty(),
            "{command}: {b:?}"
        );
        assert!(paths(&b).is_empty());
        assert!(!b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
        assert_eq!(
            b.stream_contract.unwrap().stdin_mode,
            StreamInputMode::DataRequired
        );
    }
}

#[test]
fn permuted_inline_and_clustered_options_preserve_native_argv_ownership() {
    for (command, input) in [
        ("basenc input --base64 --wrap=0", "input"),
        ("basenc --base64 -w0 input", "input"),
        ("basenc --base64 -dw0 input", "input"),
        ("basenc --base64 -- -d", "-d"),
        ("basenc --base64 -- '--help'", "--help"),
    ] {
        let b = bind(command);
        assert!(
            !b.operation_semantics_unresolved && b.residuals.is_empty(),
            "{command}: {b:?}"
        );
        assert_eq!(paths(&b), [input]);
    }
}

#[test]
fn information_mode_does_not_read_ignored_file_or_consume_stdin() {
    for command in [
        "basenc --help /opt/shared/file",
        "basenc --version --base64 input",
    ] {
        let b = bind(command);
        assert!(
            !b.operation_semantics_unresolved && b.residuals.is_empty(),
            "{command}: {b:?}"
        );
        assert!(b.effects.is_empty());
        assert_eq!(
            b.stream_contract.unwrap().stdout_dependency,
            StreamDataDependency::Independent
        );
    }
}

#[test]
fn unsupported_forms_keep_explicit_resolution_uncertainty() {
    assert!(
        ProfileRegistry::built_in()
            .unwrap()
            .lookup("basenc")
            .profile
            .is_some()
    );
    for command in [
        "basenc --base64 --unknown input",
        "basenc --base64 first second",
        "basenc --base64 -w",
    ] {
        let profile =
            load_command_profile_from_str(include_str!("../profiles/basenc.yaml")).unwrap();
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        if let Ok(selected) = select_invocation(&profile, &projection) {
            let b = bind_invocation(&profile, &projection, &selected);
            assert!(
                b.operation_semantics_unresolved || !b.residuals.is_empty(),
                "{command}: {b:?}"
            );
        }
    }
}
