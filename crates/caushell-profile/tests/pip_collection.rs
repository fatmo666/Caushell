//! Contract tests only: no pip process, network or package code is executed.
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r.bound,
        ResolveInvocationArtifactResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => bound,
        other => panic!("{command}: {other:?}"),
    }
}

#[test]
fn collection_and_build_keep_backend_execution_and_native_unknowns() {
    for (command, form, destination) in [
        (
            "pip download package-a -d /workspace/dist --no-deps -q",
            "collect_distributions",
            "/workspace/dist",
        ),
        (
            "pip3 download --dest=/outside package-b",
            "collect_distributions",
            "/outside",
        ),
        (
            "pip wheel /workspace/src -w/workspace/dist --no-deps",
            "build_wheels",
            "/workspace/dist",
        ),
        (
            "pip wheel package-a --wheel-dir /workspace/wheels",
            "build_wheels",
            "/workspace/wheels",
        ),
    ] {
        let r = resolve(command);
        assert!(r.form_id.as_str().ends_with(form), "{command}: {r:#?}");
        assert!(
            r.operation_semantics_unresolved,
            "native config/cache/backend behavior is still unobserved"
        );
        for kind in [
            EffectKind::ImportPackage,
            EffectKind::ExecuteImportedPackageLogic,
            EffectKind::WritePath,
            EffectKind::LoadConfig,
        ] {
            assert!(
                r.effects.iter().any(|e| e.kind == kind),
                "{command}: {kind:?}"
            );
        }
        let out = r
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "output_directory")
            .unwrap();
        assert!(
            out.values
                .iter()
                .any(|v| matches!(v, BoundValue::Argument {text, ..} if text == destination)),
            "{command}: {out:#?}"
        );
        let specs = r
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "package_specs")
            .unwrap();
        assert!(
            !specs
                .values
                .iter()
                .any(|v| matches!(v, BoundValue::Argument {text, ..} if text == destination))
        );
    }
}

#[test]
fn config_rewrite_is_not_a_query_or_filesystem_deletion() {
    for command in [
        "pip config set global.timeout 10",
        "pip config --user set global.timeout 10",
        "pip config set --global global.timeout 10",
        "pip config unset global.timeout",
        "pip config --site unset global.timeout",
    ] {
        let r = resolve(command);
        assert!(r.operation_semantics_unresolved, "{command}");
        assert!(
            r.effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath && e.target == EffectTarget::None),
            "{command}: {r:#?}"
        );
        assert!(
            !r.effects.iter().any(|e| e.kind == EffectKind::DeletePath),
            "unset rewrites configuration, not deletes a file"
        );
    }
    for command in [
        "pip config get global.timeout",
        "pip config list",
        "pip config debug",
        "pip download --help",
        "pip wheel --help",
    ] {
        let r = resolve(command);
        assert!(
            !r.effects.iter().any(|e| matches!(
                e.kind,
                EffectKind::WritePath
                    | EffectKind::ExecuteImportedPackageLogic
                    | EffectKind::DeletePath
            )),
            "{command}: {r:#?}"
        );
    }
}

#[test]
fn partial_collection_still_exposes_hazards() {
    // Unsupported root/subcommand controls may leave the entire invocation
    // opaque; absence of a partial package slot must never mean safe execution.
    for command in [
        "pip download package-a --unknown",
        "pip wheel package-a -w /outside --unknown",
    ] {
        assert!(resolve(command).operation_semantics_unresolved, "{command}");
    }
    for command in [
        "pip download -r requirements.txt",
        "pip wheel -e /workspace/src",
    ] {
        let r = resolve(command);
        assert!(r.operation_semantics_unresolved, "{command}");
        assert!(
            r.effects
                .iter()
                .any(|e| e.kind == EffectKind::ExecuteImportedPackageLogic),
            "{command}: {r:#?}"
        );
    }
}
