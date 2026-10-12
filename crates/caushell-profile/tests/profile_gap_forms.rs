//! Audited native form regression coverage. Commands are resolved statically and never executed.
use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationResult, resolve_invocation,
};
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn result(command: &str) -> ResolveInvocationResult<'static> {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    )
}

fn resolve(command: &str) -> BoundInvocation {
    match result(command) {
        ResolveInvocationResult::Resolved(resolved) => {
            assert!(
                resolved.bound.residuals.is_empty(),
                "{command}: {:?}",
                resolved.bound
            );
            resolved.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}

fn values(bound: &BoundInvocation, name: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == name)
        .flat_map(|parameter| &parameter.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.clone(),
            other => panic!("{name}: {other:?}"),
        })
        .collect()
}

fn has_effect(bound: &BoundInvocation, kind: EffectKind) -> bool {
    bound.effects.iter().any(|effect| effect.kind == kind)
}

#[test]
fn chmod_missing_targets_requires_a_proven_error_only_form() {
    for command in ["chmod", "chmod 644", "chmod u+w", "chmod a=", "chmod -w"] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), "missing_targets", "{command}");
        assert!(bound.effects.is_empty(), "{command}: {bound:?}");
    }
    let ordinary = resolve("chmod 644 cache/file");
    assert_eq!(ordinary.form_id.as_str(), "change_mode");
    assert!(has_effect(&ordinary, EffectKind::ChangeMode));
    for command in ["chmod \"$mode\"", "chmod --unsupported 644"] {
        assert!(
            !matches!(result(command), ResolveInvocationResult::Resolved(r)
            if r.bound.form_id.as_str() == "missing_targets"),
            "{command}"
        );
    }
}

#[test]
fn audited_native_forms_resolve_without_losing_argument_ownership() {
    for command in [
        "java -jar program.jar arg",
        "git -c color.status=always status",
        "git help config",
        "git -p help",
        "git init .",
        "git grep '^needle' src/file.rs",
        "git whatchanged --all",
        "git symbolic-ref HEAD",
        "npm -C . i example-package",
        "npm config get prefix",
        "apt-get changelog apt",
        "apt-get update -o APT::Update::Pre-Invoke::=/bin/sh",
        "pip config --editor '/bin/sh -s' edit",
        "cargo help doc",
        "ffmpeg -i input.m4a -aq 6 -vn -ac 2 output.ogg",
        "tshark -c 5 -i eth0",
        "nmap -Pn -sS -sV -p 80 192.0.2.1",
        "octave -q --eval 'disp(1)'",
        "kill -SIGINT 123",
        "killall -u alice dropbox",
        "sudo -l",
        "gcc -print-search-dirs",
        "aspell check text.txt",
        "hg st -R /tmp/repo",
        "vagrant ssh-config --host default",
        "brew doctor",
        "brew update",
        "rpm -Uvh https://example.test/package.rpm",
        "yum -y groupinstall 'Development Tools'",
        "composer validate composer.json",
        "fd",
        "grep --help",
        "ssh -V",
        "latexmk -c",
    ] {
        resolve(command);
    }
}

#[test]
fn opaque_and_mutating_forms_keep_their_effect_classes() {
    let java = resolve("java -jar program.jar");
    assert_eq!(java.form_id.as_str(), "launch_jar");
    assert!(has_effect(&java, EffectKind::ExecutePayload));
    assert!(has_effect(&java, EffectKind::ReadPath));
    assert_eq!(values(&java, "jar_source"), ["program.jar"]);
    let java_arguments = resolve("java -jar program.jar --help --version");
    assert_eq!(java_arguments.form_id.as_str(), "launch_jar");
    assert_eq!(
        values(&java_arguments, "program_args"),
        ["--help", "--version"]
    );

    let hook = resolve("apt-get update -o APT::Update::Pre-Invoke::=/bin/sh");
    assert!(has_effect(&hook, EffectKind::ExecutePayload));
    assert_eq!(
        values(&hook, "option_values"),
        ["APT::Update::Pre-Invoke::=/bin/sh"]
    );

    let pip = resolve("pip config --editor '/bin/sh -s' edit");
    assert!(has_effect(&pip, EffectKind::DispatchCommand));
    assert_eq!(values(&pip, "editor_command"), ["/bin/sh -s"]);

    let ports = resolve("nmap -Pn -sS -sV -p 80 192.0.2.1");
    assert_eq!(values(&ports, "port_specs"), ["80"]);
    assert_eq!(values(&ports, "scan_targets"), ["192.0.2.1"]);

    let capture = resolve("tshark -c 5 -i eth0");
    assert_eq!(values(&capture, "capture_count"), ["5"]);
    assert!(
        values(&capture, "capture_count")
            .iter()
            .all(|v| v != "eth0")
    );

    let sudo = resolve("sudo -l");
    assert_eq!(sudo.form_id.as_str(), "list_privileges");
    assert!(!has_effect(&sudo, EffectKind::DispatchCommand));
}

#[test]
fn query_forms_are_not_promoted_to_execution_or_mutation() {
    for command in [
        "sudo -l",
        "grep --help",
        "ssh -V",
        "gcc -print-search-dirs",
        "npm config get prefix",
        "git help config",
        "cargo help doc",
    ] {
        let bound = resolve(command);
        assert!(!has_effect(&bound, EffectKind::ExecutePayload), "{command}");
        assert!(
            !has_effect(&bound, EffectKind::DispatchCommand),
            "{command}"
        );
        assert!(!has_effect(&bound, EffectKind::WritePath), "{command}");
        assert!(!has_effect(&bound, EffectKind::DeletePath), "{command}");
    }
}

#[test]
fn unknown_git_commands_and_unmodeled_npm_mutations_remain_unresolved() {
    assert!(matches!(
        result("git x"),
        ResolveInvocationResult::SelectionError { .. }
    ));
    assert!(matches!(
        result("npm config set prefix /tmp/out"),
        ResolveInvocationResult::SelectionError { .. }
    ));
}
