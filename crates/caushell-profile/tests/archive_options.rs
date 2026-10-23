use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str, environment: Option<&str>) -> ResolveInvocationArtifactResult {
    let mut bindings = SessionBindings::new();
    bindings.reset_child_environment(true);
    if let Some(value) = environment {
        bindings.set_environment_value("TAR_OPTIONS", SessionValue::ExactScalar(value.into()));
    }
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation_artifact_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
        &bindings,
    )
}

fn argv(command: &str, environment: &str) -> Vec<String> {
    let result = resolve(command, Some(environment));
    let ResolveInvocationArtifactResult::Resolved(result) = result else {
        panic!("{result:#?}")
    };
    result
        .materialized_projection
        .invocation
        .args
        .iter()
        .map(|arg| argument_structure(arg).exact_value().unwrap().into())
        .collect()
}

#[test]
fn explicit_argv_keeps_scalar_origin_after_environment_composition() {
    let mut bindings = SessionBindings::new().with_exact_scalar("ARCHIVE", "bundle.tar");
    bindings.set_environment_value(
        "TAR_OPTIONS",
        SessionValue::ExactScalar("--directory=cache".into()),
    );
    let parsed = parse_command("tar xf \"$ARCHIVE\"", ShellKind::Bash).unwrap();
    let result = resolve_invocation_artifact_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
        &bindings,
    );
    let ResolveInvocationArtifactResult::Resolved(result) = result else {
        panic!("{result:#?}")
    };
    assert!(result.materialized_projection.arg_resolutions.iter().any(|resolution| matches!(resolution,
        ValueMaterialization::ResolvedExactScalar { variable_name, value, .. } if variable_name == "ARCHIVE" && value == "bundle.tar")));
    assert!(result.bound.bound_parameters.iter().flat_map(|p| &p.values).any(|value| matches!(value,
        BoundValue::Argument { text, materialization: BoundArgumentMaterialization::ResolvedExactScalar { variable_name }, .. }
        if text == "bundle.tar" && variable_name == "ARCHIVE")));
}

#[test]
fn environment_options_precede_modernized_explicit_argv_as_native_data() {
    assert_eq!(
        argv("tar xf bundle.tar -C sub", "--directory='cache with space'"),
        [
            "--directory=cache with space",
            "-x",
            "-f",
            "bundle.tar",
            "-C",
            "sub"
        ]
    );
    assert_eq!(
        argv("tar Cxf cache bundle.tar", "--verbose"),
        ["--verbose", "-C", "cache", "-x", "-f", "bundle.tar"]
    );
    assert_eq!(
        argv("tar -xf bundle.tar", r"--directory=cache\ with\ space"),
        ["--directory=cache with space", "-xf", "bundle.tar"]
    );
}

#[test]
fn native_environment_does_not_expand_twice_or_execute_shell_text() {
    assert_eq!(
        argv("tar -xf bundle.tar", "--directory='$OTHER'"),
        ["--directory=$OTHER", "-xf", "bundle.tar"]
    );
    for value in [
        "--directory=$OTHER",
        "--directory=\"unterminated",
        "--directory=\\",
        "--directory=\0",
    ] {
        assert!(
            matches!(
                resolve("tar -xf bundle.tar", Some(value)),
                ResolveInvocationArtifactResult::SelectionError { .. }
            ),
            "{value}"
        );
    }
}

#[test]
fn environment_parse_cannot_borrow_an_operand_from_explicit_argv() {
    for value in [
        "-f",
        "--directory",
        "--directory=cache extra",
        "--",
        "xf bundle.tar",
        "-- --extract",
        "--unknown-control",
    ] {
        assert!(
            matches!(
                resolve("tar -xf bundle.tar", Some(value)),
                ResolveInvocationArtifactResult::SelectionError { .. }
            ),
            "{value}"
        );
    }
}

#[test]
fn empty_and_unset_environment_preserve_existing_invocation() {
    for value in [None, Some(""), Some(" \t\n")] {
        let result = resolve("tar -xf bundle.tar", value);
        let ResolveInvocationArtifactResult::Resolved(result) = result else {
            panic!("{result:#?}")
        };
        assert!(!result.bound.operation_semantics_unresolved);
        assert_eq!(result.materialized_projection.invocation.args.len(), 2);
    }
}

#[test]
fn missing_environment_observation_is_not_evidence_of_absence() {
    let parsed = parse_command("tar -xf bundle.tar", ShellKind::Bash).unwrap();
    let result = resolve_invocation_artifact_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
        &SessionBindings::new(),
    );
    let ResolveInvocationArtifactResult::Resolved(result) = result else {
        panic!("{result:#?}")
    };
    assert!(result.bound.operation_semantics_unresolved);
    assert!(
        result
            .bound
            .residuals
            .iter()
            .any(|r| r.reason.contains("TAR_OPTIONS"))
    );
}

#[test]
fn extraction_codec_preserves_directory_order_and_option_operands() {
    for args in [
        vec!["-xvf", "bundle.tar", "-C", "cache", "--directory=sub"],
        vec!["xvfC", "bundle.tar", "cache", "-Csub"],
    ] {
        let decoded =
            gnu_tar_extraction(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).unwrap();
        assert_eq!(decoded.archive, "bundle.tar");
        assert_eq!(decoded.directories, ["cache", "sub"]);
    }
    let decoded = gnu_tar_extraction(&["-xf".into(), "--directory=not-an-option".into()]).unwrap();
    assert_eq!(decoded.archive, "--directory=not-an-option");
}

#[test]
fn extraction_codec_rejects_incomplete_or_unsupported_semantics() {
    for args in [
        vec!["-xf"],
        vec!["-xf", "-"],
        vec!["-xf", "host:archive"],
        vec!["-xxf", "archive"],
        vec!["-xf", "a", "-f", "b"],
        vec!["-xf", "a", "member"],
        vec!["-xf", "a", "--strip-components=1"],
        vec!["-xf", "a", "--transform=s,x,y,"],
        vec!["-zxf", "a"],
        vec!["-Pxf", "a"],
        vec!["-xf", "a", "--directory="],
    ] {
        assert!(
            gnu_tar_extraction(&args.iter().map(|s| (*s).into()).collect::<Vec<_>>()).is_err(),
            "{args:?}"
        );
    }
}
