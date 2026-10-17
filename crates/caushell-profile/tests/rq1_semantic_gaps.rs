//! Native CLI declarations and positive proofs; no sample command is executed.
use caushell_profile::*;
use caushell_types::{ShellKind, StateOperationDomain, StateOperationKind};
use std::sync::OnceLock;

fn resolve(command: &str) -> ResolvedInvocationArtifact {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap());
    let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}
fn values(r: &ResolvedInvocationArtifact, slot: &str) -> Vec<String> {
    r.bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| p.semantic_values())
        .filter_map(
            |value| match project_semantic_value(&ValueProjection::Identity, value) {
                Some(SemanticValueResolution::Known(text)) => Some(text),
                _ => None,
            },
        )
        .collect()
}

#[test]
fn remote_host_grammar_does_not_import_windows_drive_exceptions() {
    for command in [
        "rsync x:x",
        "rsync x:",
        "rsync x::module",
        "rsync user@x:file",
        "rsync '[::1]:file'",
    ] {
        let r = resolve(command);
        assert_eq!(
            r.bound.form_id.as_str(),
            "list_single_source_remote",
            "{command}"
        );
    }
    for command in ["rsync ./x:x", "rsync /tmp/x:x", "rsync dir/x:x"] {
        assert_eq!(
            resolve(command).bound.form_id.as_str(),
            "list_single_source_local",
            "{command}"
        );
    }
}

#[test]
fn git_patch_controls_own_their_values_and_unsafe_writes_are_explicit() {
    let r = resolve("git apply --unsafe-paths --directory / x.patch");
    assert_eq!(values(&r, "patch_paths"), ["x.patch"]);
    assert_eq!(values(&r, "directory_prefix"), ["/"]);
    assert!(r.bound.effects.iter().any(|e| e.kind == EffectKind::WritePath && matches!(&e.target, EffectTarget::ConfiguredPath(t) if t.missing == ConfiguredPathMissing::Unknown)));
    for command in [
        "git apply --check --unsafe-paths x.patch",
        "git apply --index --unsafe-paths x.patch",
    ] {
        let r = resolve(command);
        assert!(!r.bound.effects.iter().any(|e| matches!(&e.target, EffectTarget::ConfiguredPath(t) if t.missing == ConfiguredPathMissing::Unknown)), "{command}");
    }
}

#[test]
fn docker_paths_keep_client_and_container_namespaces_separate() {
    let r = resolve("docker cp x:/input /opt/output");
    assert_eq!(r.bound.form_id.as_str(), "copy_from_container");
    assert_eq!(values(&r, "host_destination"), ["/opt/output"]);
    assert!(
        r.bound
            .bound_parameters
            .iter()
            .filter(|p| p.name.as_str() == "container_source")
            .all(|p| p.semantic == SemanticType::PlainValue)
    );
    let r = resolve("docker cp /opt/input x:/output");
    assert_eq!(values(&r, "host_source"), ["/opt/input"]);
    assert!(r.bound.effects.iter().any(|e| {
        e.state_operation.is_some_and(|s| {
            s.domain == StateOperationDomain::ContainerRuntime
                && s.operation == StateOperationKind::Mutate
        })
    }));
    let r = resolve("docker cp x:/input -");
    assert!(values(&r, "host_destination").is_empty());
    assert!(
        !r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    let r = resolve("docker run -v /:/host alpine sh -c 'rm /host/file'");
    assert_eq!(values(&r, "image"), ["alpine"]);
    assert_eq!(values(&r, "container_argv"), ["sh", "-c", "rm /host/file"]);
    assert!(
        !r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DispatchCommand)
    );
}

#[test]
fn supplied_environment_inputs_use_generic_declarations_and_data_not_shell_spelling() {
    let profile = load_command_profile_from_str(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: native-fixture}
environment_inputs:
  - name: program
    environment: {name: FIXTURE_PROGRAM, empty_is_unset: true}
    semantic: {kind: payload, language: opaque, source: dynamic_reference, recursive: true}
forms: [{id: run}]
"#,
    )
    .unwrap();
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    for (command, bindings, count) in [
        ("native-fixture", SessionBindings::new(), 0),
        (
            "FIXTURE_PROGRAM='' native-fixture",
            SessionBindings::new(),
            0,
        ),
        (
            "FIXTURE_PROGRAM='$(not_a_shell_expansion)' native-fixture",
            SessionBindings::new(),
            1,
        ),
        (
            "FIXTURE_PROGRAM=$UNKNOWN native-fixture",
            SessionBindings::new(),
            1,
        ),
    ] {
        let p = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationArtifactResult::Resolved(r) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &p.commands[0],
                InvocationRuntimeContext::new(),
                &bindings,
            )
        else {
            panic!("{command}");
        };
        assert_eq!(
            collect_recursive_payload_candidates(&r.bound).len(),
            count,
            "{command}"
        );
        assert_eq!(
            r.bound
                .effects
                .iter()
                .filter(|e| e.kind == EffectKind::ExecutePayload)
                .count(),
            count,
            "{command}"
        );
        if command.contains("not_a_shell") {
            assert_eq!(values(&r, "program"), ["$(not_a_shell_expansion)"]);
        }
    }
}

#[test]
fn prefix_assignments_expand_in_order_without_changing_ordinary_argv_or_caller_frame() {
    let bindings = SessionBindings::new().with_exact_scalar("fixture_value", "old");
    let parsed = caushell_parse::parse_command("fixture_value=new FIXTURE_PROGRAM=$fixture_value fixture_value=last native-fixture \"$fixture_value\"", ShellKind::Bash).unwrap();
    let command = &parsed.commands[0];
    let prefix = materialize_prefix_environment(command, &bindings);
    assert_eq!(
        prefix,
        [
            ("fixture_value".into(), SessionValue::exact_scalar("new")),
            ("FIXTURE_PROGRAM".into(), SessionValue::exact_scalar("new")),
            ("fixture_value".into(), SessionValue::exact_scalar("last")),
        ]
    );
    let argv = materialize_projected_invocation(
        &project_invocation(command, InvocationRuntimeContext::new()),
        &bindings,
    );
    assert_eq!(argv.invocation.args[0].text, "old");
    assert_eq!(
        bindings.get("fixture_value").unwrap().value,
        &SessionValue::exact_scalar("old")
    );
    let oracle = "fixture_value=old\nf(){ builtin printf '%s|%s' \"$fixture_value\" \"$FIXTURE_PROGRAM\"; }\nfixture_value=new FIXTURE_PROGRAM=$fixture_value fixture_value=last f";
    let output = std::process::Command::new("/bin/bash")
        .args(["--noprofile", "--norc", "-c", oracle])
        .env_clear()
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"last|new");
}

#[test]
fn native_environment_input_validation_rejects_collisions_and_bad_sources() {
    let yaml = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: fixture}\nforms: [{id: run}]\nenvironment_inputs:\n  - name: code\n    environment: {name: FIXTURE}\n    semantic: {kind: payload, language: opaque, source: dynamic_reference, recursive: true}\n";
    assert!(load_command_profile_from_str(yaml).is_ok());
    for bad in [
        yaml.replace("name: FIXTURE", "name: 'BAD-NAME'"),
        yaml.replace("name: code", "name: ''"),
        yaml.replace("environment: {name: FIXTURE}", "environment: {name: FIXTURE}\n    unless_modifiers: [undeclared]"),
        yaml.replace("forms: [{id: run}]", "forms: [{id: run, parameters: [{name: code, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}]}]"),
    ] { assert!(load_command_profile_from_str(&bad).is_err(), "{bad}"); }
}

#[test]
fn mktemp_native_option_values_are_not_path_templates() {
    let r = resolve("mktemp --suffix .cmd");
    assert_eq!(r.bound.form_id.as_str(), "create_default_temporary_path");
    assert_eq!(values(&r, "suffix"), [".cmd"]);
    assert!(values(&r, "template_paths").is_empty());
    let r = resolve("mktemp --tmpdir /tmp/item.XXXXXX");
    assert_eq!(values(&r, "template_names"), ["/tmp/item.XXXXXX"]);
    assert!(values(&r, "long_target_directory").is_empty());
    let r = resolve("mktemp -p /tmp/item parent/child.XXXXXX");
    assert_eq!(values(&r, "target_directory"), ["/tmp/item"]);
    assert_eq!(values(&r, "template_paths"), ["parent/child.XXXXXX"]);
}

#[test]
fn grep_proves_only_complete_nul_records_without_mixed_data_or_decorations() {
    for command in [
        "grep -az pattern",
        "grep -azZ pattern",
        "grep -az -e pattern",
        "grep -lZ pattern .",
        "grep -LZr pattern .",
    ] {
        let r = resolve(command);
        assert!(
            r.proven_stdout_records().is_some(),
            "{command}: {:?}",
            r.bound.residuals
        );
    }
    for command in [
        "grep -azn pattern",
        "grep -azo pattern",
        "grep -azH pattern",
        "grep -azc pattern",
        "grep -az -1 pattern",
        "grep -az -A 1 pattern",
        "grep -az --color=always pattern",
        "grep -az pattern - local-file",
        "grep -lZ pattern -",
        "grep -lZ pattern - local-file",
    ] {
        assert!(
            resolve(command).proven_stdout_records().is_none(),
            "{command}"
        );
    }
}

#[test]
fn strace_owns_only_outer_options_and_keeps_inner_controls_verbatim() {
    let r = resolve("strace -ff -o /tmp/trace xargs -0 -I '{}' mv '{}' /tmp/other");
    assert_eq!(values(&r, "output_path"), ["/tmp/trace"]);
    assert_eq!(values(&r, "wrapped_command"), ["xargs"]);
    let d = collect_dispatch_command_candidates(&r.bound);
    assert_eq!(d.len(), 1);
    assert_eq!(
        d[0].argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["-0", "-I", "{}", "mv", "{}", "/tmp/other"]
    );
    assert!(!d[0].stdin_from_parent && d[0].stdout_to_parent);
}

#[test]
fn quoted_scalar_proof_respects_outer_not_inner_field_expansion() {
    for (word, scalar) in [
        (r#""$(echo $@) ? [y/N] ""#, true),
        (r#""${1:-Are you sure? [y/N]} ""#, true),
        (r#""${prompt:-Hi! [yes/no]}""#, true),
        (r#""${prompt:-$(echo "$@")}""#, true),
        (r#""\$@ literal""#, true),
        (r#""$@""#, false),
        (r#""${items[@]}""#, false),
        (r#""${!name}""#, false),
        (r#""${prompt:-$@}""#, false),
        (r#""${prompt:-${items[@]}}""#, false),
        (r#""${prompt:-'$@'}""#, false),
    ] {
        let p = caushell_parse::parse_command(&format!("echo {word}"), ShellKind::Bash).unwrap();
        let inv = project_invocation(&p.commands[0], InvocationRuntimeContext::new());
        assert_eq!(
            argument_structure(&inv.args[0]).fields == ArgumentFieldCount::ExactlyOne,
            scalar,
            "{word}"
        );
    }
}

#[test]
fn quoted_field_proofs_match_a_pure_builtin_bash_oracle() {
    // Self-authored words, not a replay of tools from the benchmark. The
    // oracle performs only set/unset, an array assignment and builtin printf.
    let words = [
        r#""$(builtin printf '%s' "$@") ? [y/N]""#,
        r#""${prompt:-Are you sure? [y/N]}""#,
        r#""${prompt:-Hello! [yes/no]}""#,
        r#""${prompt:-$@}""#,
        r#""${prompt:-${items[@]}}""#,
        r#""${prompt:-$(builtin printf '%s' "$@")}""#,
        r#""\$@ literal""#,
        r#""${prompt:-\$@}""#,
        r#""${prompt:-'$@'}""#,
    ];
    for word in words {
        let p = caushell_parse::parse_command(&format!("echo {word}"), ShellKind::Bash).unwrap();
        let inv = project_invocation(&p.commands[0], InvocationRuntimeContext::new());
        let single = argument_structure(&inv.args[0]).fields == ArgumentFieldCount::ExactlyOne;
        for positions in ["", "first second"] {
            let script = format!(
                "set -- {positions}\nunset prompt\nitems=(one two)\nset -- {word}\nbuiltin printf '%s' \"$#\""
            );
            let output = std::process::Command::new("/bin/bash")
                .args(["--noprofile", "--norc", "-c", &script])
                .env_clear()
                .output()
                .unwrap();
            assert!(output.status.success(), "{word}: {:?}", output.stderr);
            let fields: usize = std::str::from_utf8(&output.stdout)
                .unwrap()
                .parse()
                .unwrap();
            if single {
                assert_eq!(fields, 1, "{word} with {positions}");
            }
            if fields != 1 {
                assert!(!single, "{word}: a vector was hidden");
            }
        }
    }
}
