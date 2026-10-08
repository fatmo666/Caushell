//! Static CLI contracts; no tested command strings are executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => {
            assert!(
                !r.bound.operation_semantics_unresolved,
                "{command}: {:?}",
                r.bound.residuals
            );
            assert!(
                r.bound.residuals.is_empty(),
                "{command}: {:?}",
                r.bound.residuals
            );
            r.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}
fn values(bound: &BoundInvocation, slot: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .filter_map(|v| match v {
            BoundValue::Argument { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect()
}
fn module(command: &str) -> BoundInvocation {
    let parent = resolve(command);
    let children = collect_dispatch_command_candidates(&parent);
    assert_eq!(children.len(), 1);
    let child = &children[0];
    assert_eq!(child.module_runtime.as_deref(), Some("python"));
    let registry = ProfileRegistry::built_in().unwrap();
    match resolve_invocation_in_namespace(
        &registry,
        &child.to_command_fact(),
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
        child.module_runtime.as_deref(),
    ) {
        ResolveInvocationResult::Resolved(r) => {
            assert!(
                r.bound.residuals.is_empty(),
                "{command}: {:?}",
                r.bound.residuals
            );
            r.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}
#[test]
fn first_interface_option_owns_all_tail_arguments() {
    for command in [
        "python -m pytest -m slow --help",
        "python -mpytest -m slow --help",
        "python -Om pytest -m slow --help",
    ] {
        let b = resolve(command);
        assert_eq!(b.form_id.as_str(), "module");
        assert_eq!(values(&b, "module_name"), ["pytest"]);
        assert_eq!(values(&b, "module_args"), ["-m", "slow", "--help"]);
        assert_eq!(
            b.applied_modifiers
                .iter()
                .filter(|m| m.as_str() == "module_entry")
                .count(),
            1
        );
    }
}
#[test]
fn inline_and_file_arguments_are_not_interpreter_flags() {
    for command in [
        "python -c 'print(1)' -m http.server -X anything",
        "python -cprint -m http.server",
    ] {
        let b = resolve(command);
        assert_eq!(b.form_id.as_str(), "command_string");
        assert!(collect_dispatch_command_candidates(&b).is_empty());
        assert!(
            !b.applied_modifiers
                .iter()
                .any(|m| m.as_str() == "opaque_runtime")
        );
    }
    let b = resolve("python app.py -m http.server -i");
    assert_eq!(b.form_id.as_str(), "script_file");
    assert_eq!(values(&b, "script_args"), ["-m", "http.server", "-i"]);
}
#[test]
fn interpreter_options_do_not_steal_module_help_or_values() {
    let b = resolve(
        "python -B -OO -W ignore -u --check-hash-based-pycs always -m json.tool --indent 2 in.json out.json",
    );
    assert_eq!(
        values(&b, "module_args"),
        ["--indent", "2", "in.json", "out.json"]
    );
    assert_eq!(
        module("python -m json.tool --help").form_id.as_str(),
        "help"
    );
    let b = resolve("python --help -m http.server --unknown");
    assert!(b.effects.is_empty());
}
#[test]
fn json_inputs_outputs_and_dash_contract_are_distinct() {
    for (command, form) in [
        ("python -m json.tool", "stdin_to_stdout"),
        ("python -m json.tool -", "stdin_to_stdout"),
        ("python -m json.tool in.json", "file_to_stdout"),
        (
            "python -m json.tool --compact in.json out.json",
            "file_to_file",
        ),
        (
            "python -m json.tool - out.json --sort-keys",
            "stdin_to_file",
        ),
        ("python -m json.tool in.json -", "file_to_file"),
    ] {
        assert_eq!(module(command).form_id.as_str(), form);
    }
    assert_eq!(
        values(&module("python -m json.tool in.json -"), "output"),
        ["-"]
    );
}
#[test]
fn http_options_have_native_ownership_and_no_cwd_effect() {
    let b = module(
        "python -m http.server 8123 --bind 127.0.0.1 --directory public -p HTTP/1.1 --tls-cert cert.pem --tls-key key.pem --tls-password-file pass.txt",
    );
    assert_eq!(values(&b, "port"), ["8123"]);
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::ListenNetwork)
    );
    assert!(!b.effects.iter().any(|e| matches!(
        e.kind,
        EffectKind::SetCurrentWorkingDirectory
            | EffectKind::SetExecutionWorkingDirectory
            | EffectKind::ExecutePayload
    )));
    assert!(module("python -m http.server --help").effects.is_empty());
}
#[test]
fn builtin_modules_are_separate_from_executable_names() {
    let r = ProfileRegistry::built_in().unwrap();
    for m in ["json.tool", "http.server", "py_compile", "compileall"] {
        assert!(r.lookup_module("python", m).profile.is_some());
        assert!(r.lookup(m).profile.is_none());
        assert!(
            !r.lookup_module("python", m)
                .profile
                .unwrap()
                .matches_name(m)
        );
        assert!(
            lookup_command_profile(m, r.profiles().iter().cloned())
                .profile
                .is_none()
        );
        assert!(r.lookup_module("other", m).profile.is_none());
        assert!(
            r.lookup_module("python", &format!("/usr/bin/{m}"))
                .profile
                .is_none()
        );
    }
    for m in ["pip", "pytest", "uvicorn"] {
        assert!(r.lookup(m).profile.is_some());
        assert!(r.lookup_module("python", m).profile.is_some());
    }
    assert!(r.lookup_module("python", "rm").profile.is_none());
}

#[test]
fn compiler_forms_separate_stdin_lists_legacy_outputs_and_metadata() {
    for (command, form) in [
        ("python -m py_compile -", "stdin_list"),
        ("python -m py_compile - a.py", "files"),
        ("python -m py_compile --quiet a.py b.py", "files"),
        (
            "python -m compileall src -d /outside/names",
            "explicit_or_sys_path",
        ),
        ("python -m compileall -b src", "legacy_explicit_or_sys_path"),
        ("python -m compileall -i paths.txt", "file_list"),
        ("python -m compileall -i -", "stdin_list"),
        ("python -m compileall -b -i paths.txt", "legacy_file_list"),
        ("python -m compileall -b -i -", "legacy_stdin_list"),
    ] {
        let b = module(command);
        assert_eq!(b.form_id.as_str(), form, "{command}");
        assert!(
            !b.operation_semantics_unresolved,
            "{command}: {:?}",
            b.residuals
        );
        assert!(
            !b.effects
                .iter()
                .any(|e| e.kind == EffectKind::ExecutePayload)
        );
    }
    for c in [
        "python -m py_compile a.py --help --unknown",
        "python -m compileall src --help --unknown",
    ] {
        assert!(module(c).effects.is_empty());
    }
    assert_eq!(
        values(
            &module("python -m compileall -d /outside/names src"),
            "traceback_names"
        ),
        ["/outside/names"]
    );
    let b = module("python -m compileall -b src");
    assert!(
        b.effects
            .iter()
            .filter_map(|e| match &e.target {
                EffectTarget::ConfiguredPath(p) => Some(p),
                _ => None,
            })
            .all(|p| p.environment.is_none())
    );
}
const FIXTURE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
option_scope: leading_options
identity: {canonical_name: entry-fixture}
forms:
  - id: entry
    parameters:
      - {name: target, semantic: {kind: plain_value}, binding: {kind: following_flag, flag: '-e', operand_mode: next_arg}, cardinality: required_one}
      - {name: tail, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}
modifiers:
  - {id: entry, matcher: {kind: any_flag, flags: ['-e']}, ends_option_scope: true}
  - {id: flag, matcher: {kind: any_flag, flags: ['-v']}}
"#;
#[test]
fn generic_entry_boundary_does_not_depend_on_python() {
    let r = ProfileRegistry::from_profiles(vec![load_command_profile_from_str(FIXTURE).unwrap()])
        .unwrap();
    for command in [
        "entry-fixture -e payload --unknown -e other",
        "entry-fixture -vepayload --unknown -e other",
    ] {
        let p = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(b) =
            resolve_invocation(&r, &p.commands[0], InvocationRuntimeContext::new())
        else {
            panic!("{command}")
        };
        assert!(b.bound.residuals.is_empty(), "{:?}", b.bound.residuals);
        assert_eq!(values(&b.bound, "target"), ["payload"]);
        assert_eq!(values(&b.bound, "tail"), ["--unknown", "-e", "other"]);
    }
}
#[test]
fn new_declarations_reject_invalid_and_duplicate_entries() {
    assert!(
        load_command_profile_from_str(&FIXTURE.replace("leading_options", "all_arguments"))
            .is_err()
    );
    let base = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: module-fixture, module_only: true, module_entrypoints: [{runtime: python, name: example}]}\nforms: [{id: run}]\n";
    assert!(load_command_profile_from_str(base).is_ok());
    for changed in [
        base.replace("runtime: python", "runtime: ''"),
        base.replace("name: example", "name: ''"),
        base.replace("module_only: true", "module_only: true, aliases: [exe]"),
        base.replace(
            "module_entrypoints: [{runtime: python, name: example}]",
            "module_entrypoints: []",
        ),
        base.replace(
            "{runtime: python, name: example}]",
            "{runtime: python, name: example}, {runtime: python, name: example}]",
        ),
    ] {
        assert!(
            load_command_profile_from_str(&changed).is_err(),
            "{changed}"
        );
    }
    let a = load_command_profile_from_str(base).unwrap();
    assert!(ProfileRegistry::from_profiles(vec![a.clone(), a]).is_err());
}
#[test]
fn identical_module_and_executable_names_do_not_collide() {
    let a = load_command_profile_from_str("dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: sample}\nforms: [{id: executable}]\n").unwrap();
    let b = load_command_profile_from_str("dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: module-profile, module_only: true, module_entrypoints: [{runtime: python, name: sample}]}\nforms: [{id: module}]\n").unwrap();
    let r = ProfileRegistry::from_profiles(vec![a, b]).unwrap();
    assert_eq!(
        r.lookup("sample").profile.unwrap().forms[0].id.as_str(),
        "executable"
    );
    assert_eq!(
        r.lookup_module("python", "sample").profile.unwrap().forms[0]
            .id
            .as_str(),
        "module"
    );
}

#[test]
fn flag_without_operand_ends_short_cluster_before_tail_is_reinterpreted() {
    let yaml = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
option_scope: leading_options
identity: {canonical_name: halt-fixture}
forms:
  - id: information
    parameters: [{name: tail, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}]
modifiers:
  - {id: halt, matcher: {kind: any_flag, flags: ['-H']}, ends_option_scope: true}
  - {id: verbosity, matcher: {kind: any_flag, flags: ['-v']}}
"#;
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(yaml).unwrap()]).unwrap();
    for command in [
        "halt-fixture -Hunknown -e payload",
        "halt-fixture -vHunknown --unknown",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
        ) else {
            panic!("{command}")
        };
        assert!(
            r.bound.residuals.is_empty(),
            "{command}: {:?}",
            r.bound.residuals
        );
        assert!(
            r.bound
                .applied_modifiers
                .iter()
                .any(|m| m.as_str() == "halt")
        );
        assert_eq!(
            r.bound.applied_modifiers.len(),
            if command.contains("-vH") { 2 } else { 1 }
        );
    }
}
