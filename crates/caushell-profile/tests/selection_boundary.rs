//! Static argv/semantic checks. No commands are executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> ResolvedInvocationArtifact {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => r.into_artifact(),
        other => panic!("{command}: {other:#?}"),
    }
}

fn complete(command: &str) -> ResolvedInvocationArtifact {
    let r = resolve(command);
    assert!(
        !r.bound.operation_semantics_unresolved && r.bound.residuals.is_empty(),
        "{command}: {r:#?}"
    );
    r
}

#[test]
fn variable_width_child_operands_keep_partial_effects_and_ownership_gap() {
    for command in [
        r"find . -exec echo report* \;",
        r"find . -execdir tar -cvf filename.tar RS* \;",
        r"find . -exec chmod 755 {}/* \;",
    ] {
        let r = resolve(command);
        assert!(r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
        assert_eq!(r.bound.argument_regions.len(), 1, "{r:#?}");
    }
    // Renaming the parent Profile must leave the proof unchanged.
    let source = include_str!("../profiles/find.yaml")
        .replace("canonical_name: find", "canonical_name: ownership_fixture");
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(&source).unwrap()])
            .unwrap();
    let parsed = parse_command(
        r"ownership_fixture . -exec echo report* \;",
        ShellKind::Bash,
    )
    .unwrap();
    let ResolveInvocationResult::Resolved(r) = resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) else {
        panic!()
    };
    assert!(r.bound.operation_semantics_unresolved);
    // Quoting establishes one shell field, not a synthetic filename lookup.
    for command in [
        r"find . -exec echo 'report*' \;",
        r"find . -execdir tar -cvf filename.tar 'RS*' \;",
        r"find . -exec chmod 755 '{}/*' \;",
    ] {
        assert_eq!(complete(command).bound.argument_regions.len(), 1);
    }
}

#[test]
fn possible_child_delimiters_and_unknown_executables_remain_unresolved() {
    for command in [
        r"find . -exec $command report* \;",
        r"find . -exec echo * \;",
        r"find . -exec echo $args \;",
        r#"find . -exec echo "$arg" \;"#,
        r#"find . -exec echo "$@" \;"#,
        r"find . -exec echo [+] \;",
    ] {
        assert!(
            resolve(command).bound.operation_semantics_unresolved,
            "{command}"
        );
    }
}

#[test]
fn last_filters_are_data_and_explicit_files_keep_their_read_dependency() {
    for command in [
        "last",
        "last -w",
        "last -i root tty0",
        "lastb root",
        "last -a -f /opt/input root",
    ] {
        let r = complete(command);
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ReadPath)
        );
        assert!(
            !r.bound
                .effects
                .iter()
                .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::DeletePath))
        );
    }
    let r = complete("last -a -f /opt/input root");
    let filters = r
        .bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "record_filters")
        .unwrap();
    assert!(matches!(&filters.values[0], BoundValue::Argument { text, .. } if text == "root"));
}

#[test]
fn package_query_modes_are_not_installation() {
    for command in [
        "dpkg --get-selections",
        "dpkg --print-architecture",
        "dpkg --print-foreign-architectures",
        "dpkg -S /bin/ls",
        "dpkg -I package.deb",
        "rpm -qf /bin/ls",
        "rpm -qfi /bin/ls",
        "rpm --query --file /bin/ls",
    ] {
        let r = complete(command);
        assert!(
            !r.bound.effects.iter().any(|e| matches!(
                e.kind,
                EffectKind::WritePath
                    | EffectKind::ExecuteImportedPackageLogic
                    | EffectKind::ImportPackage
            )),
            "{command}: {r:#?}"
        );
    }
    for command in [
        "dpkg -i package.deb",
        "dpkg --install package.deb",
        "rpm -ivh package.rpm",
    ] {
        let r = complete(command);
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ExecuteImportedPackageLogic),
            "{command}"
        );
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath),
            "{command}"
        );
    }
}

#[test]
fn display_and_stdin_defaults_keep_stream_semantics() {
    complete("readelf -a -W input.a");
    let pandoc = complete("pandoc -f markdown_github");
    complete("pandoc --from=markdown+smart --to=html5 input.md");
    complete("pandoc -r gfm -w plain input.md");
    assert_eq!(
        pandoc.proven_stream_contract().unwrap().stdin_mode,
        StreamInputMode::DataRequired
    );
    let r = complete("systemctl list-units --type=service --all");
    assert!(
        r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
    );
    let r = complete("systemctl list-unit-files --type=service --no-pager");
    assert!(
        !r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
    );
}

#[test]
fn archive_options_do_not_swallow_output_or_fabricate_shell_execution() {
    for command in [
        "cpio -p --owner user:group ./cache",
        "cpio -pRuser:group /opt/cache",
    ] {
        let r = complete(command);
        assert!(
            r.bound
                .bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "destination_path" && !p.values.is_empty())
        );
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath)
        );
    }
    let r = complete("zip -9 -j archive.zip -@");
    assert_eq!(
        r.proven_stream_contract().unwrap().stdin_mode,
        StreamInputMode::DataOptional
    );
    assert!(
        r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ConsumeStdin)
    );
    assert!(
        r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    assert!(
        !r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecutePayload)
    );
    // '-' is also a stdin member source; lack of -@ is not proof of ignored stdin.
    for command in ["zip -9 archive.zip input", "zip archive.zip -", "zip - -"] {
        assert_eq!(
            complete(command)
                .proven_stream_contract()
                .unwrap()
                .stdin_mode,
            StreamInputMode::DataOptional,
            "{command}"
        );
    }
}
