//! Parse and model argv only: no sample command is executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn bind(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let result = resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
        &SessionBindings::new(),
    );
    let ResolveInvocationResult::Resolved(r) = result else {
        panic!("{command}: {result:#?}")
    };
    assert!(r.bound.residuals.is_empty(), "{command}: {:#?}", r.bound);
    r.bound
}

fn values(b: &BoundInvocation, slot: &str) -> Vec<String> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| p.semantic_values())
        .filter_map(|v| match v {
            SemanticValueRef::Original(BoundValue::Argument { text, .. }) => Some(text.clone()),
            SemanticValueRef::Projected { value, .. } => match &value.resolution {
                SemanticValueResolution::Known(s) => Some(s.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

#[test]
fn wget_stdout_is_a_channel_not_a_file_and_spider_does_not_use_prefix() {
    for command in [
        "wget -qO- https://example.test/a",
        "wget -O '-' https://example.test/a",
        "wget -O - -P /outside https://example.test/a",
    ] {
        let b = bind(command);
        assert_eq!(b.form_id.as_str(), "fetch_to_stdout");
        assert!(values(&b, "output_path").is_empty());
        assert_eq!(values(&b, "output_stdout"), ["-"]);
        assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    }
    let b = bind("wget --spider -P /outside https://example.test/a");
    assert_eq!(b.form_id.as_str(), "probe_only");
    assert!(
        !b.effects
            .iter()
            .any(|e| matches!(e.target, EffectTarget::DerivedPath(_)))
    );
    assert!(values(&b, "output_path").is_empty());
    let b = bind("wget --spider -O /outside/file https://example.test/a");
    assert_eq!(values(&b, "output_path"), ["/outside/file"]);
}

#[test]
fn wget_separates_request_inputs_and_output_files() {
    let b = bind(
        "wget -O - -o /outside/log --save-cookies=/outside/cookies --post-file=.env --header='X-Test: SAFE' https://example.test/a",
    );
    assert_eq!(values(&b, "log_file"), ["/outside/log"]);
    assert_eq!(values(&b, "cookie_file"), ["/outside/cookies"]);
    assert_eq!(values(&b, "body_file"), [".env"]);
    assert_eq!(values(&b, "request_values"), ["'X-Test: SAFE'"]);
    let e = b
        .effects
        .iter()
        .find(|e| e.kind == EffectKind::NetworkEndpoint)
        .unwrap();
    let scope = e.input_scope.as_ref().unwrap();
    assert!(!scope.stdin);
    assert!(scope.slots.iter().any(|s| s.as_str() == "body_file"));
    assert!(!scope.slots.iter().any(|s| s.as_str() == "log_file"));
    let b = bind("wget -O - -o /outside/old -o cache/new https://example.test/a");
    assert_eq!(values(&b, "log_file"), ["cache/new"]);
}

#[test]
fn writeout_parses_instructions_not_substrings_and_uses_last_format() {
    let b =
        bind("curl -w '%output{/outside/a}%output{>>cache/b}%{http_code}' https://example.test/");
    assert_eq!(values(&b, "write_out_paths"), ["/outside/a", "cache/b"]);
    assert_eq!(
        values(&b, "write_out_format"),
        ["%output{/outside/a}%output{>>cache/b}%{http_code}"]
    );
    for format in [
        "%%output{/outside/a}",
        "\\%output{/outside/a}",
        "%{ignore%output{/outside/a}}",
        "%header{x%output{/outside/a}}",
    ] {
        let b = bind(&format!("curl -w '{format}' https://example.test/"));
        assert!(values(&b, "write_out_paths").is_empty(), "{format}: {b:#?}");
    }
    let b = bind("curl -w '%output{/outside/old}' -w '%{http_code}' https://example.test/");
    assert!(values(&b, "write_out_paths").is_empty());
    let b = bind("curl -w @cache/format https://example.test/");
    assert_eq!(values(&b, "write_out_format_file"), ["cache/format"]);
    let unknown = b
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "write_out_unknown_paths")
        .unwrap();
    assert!(unknown.semantic_values().any(|v| matches!(v, SemanticValueRef::Projected { value, .. } if matches!(value.resolution, SemanticValueResolution::Unknown(_)))));
}

#[test]
fn install_only_dispatches_active_native_helper_without_shell_splitting() {
    for command in [
        "install --strip-program=/outside/helper cache/in cache/out",
        "install --help -s --strip-program=/outside/helper",
    ] {
        let b = bind(command);
        let p = collect_dispatch_command_projection(&b);
        assert!(p.resolved.is_empty() && p.unresolved.is_empty(), "{b:#?}");
        assert_eq!(
            b.bound_parameters
                .iter()
                .find(|p| p.name.as_str() == "strip_program_path")
                .unwrap()
                .semantic,
            SemanticType::PlainValue
        );
    }
    let b = bind("install -sT --strip-program='echo LAB' cache/in cache/out");
    let p = collect_dispatch_command_projection(&b);
    assert_eq!(p.resolved.len(), 1, "{p:#?}");
    assert_eq!(p.resolved[0].command.text, "echo LAB");
    assert_eq!(
        p.resolved[0]
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["cache/out"]
    );
    assert!(p.unresolved.is_empty());
}

#[test]
fn install_ambiguous_output_retains_helper_but_not_fabricated_argv() {
    for command in [
        "install -s --strip-program=/outside/helper cache/in cache/out",
        "install -s -t cache --strip-program=/outside/helper a b",
        "install -sT --strip-program=/outside/helper cache/in -- -out",
    ] {
        let b = bind(command);
        let p = collect_dispatch_command_projection(&b);
        assert!(!p.unresolved.is_empty(), "{command}: {p:#?}");
        assert!(
            p.resolved
                .iter()
                .all(|c| c.argv.iter().all(|a| a.text != "-out")),
            "{p:#?}"
        );
    }
}

#[test]
fn information_forms_have_no_projected_output_writes() {
    for command in [
        "wget --help -O /outside/file -o /outside/log --save-cookies=/outside/cookies",
        "curl --help -w '%output{/outside/file}'",
        "curl --help -w @cache/format",
    ] {
        let b = bind(command);
        for slot in [
            "output_path",
            "log_file",
            "cookie_file",
            "write_out_paths",
            "write_out_unknown_paths",
        ] {
            assert!(
                !b.bound_parameters.iter().any(|p| p.name.as_str() == slot),
                "{command}: {b:#?}"
            );
        }
    }
}
