use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, EffectTarget, InvocationRuntimeContext,
    ProfileRegistry, ResolveInvocationResult, StreamInputMode, StreamOutputMode,
    load_command_profile_from_str, resolve_invocation,
};
use caushell_types::ShellKind;

const PROFILES: [&str; 8] = [
    include_str!("../profiles/gcc.yaml"),
    include_str!("../profiles/mawk.yaml"),
    include_str!("../profiles/run-parts.yaml"),
    include_str!("../profiles/start-stop-daemon.yaml"),
    include_str!("../profiles/ld.so.yaml"),
    include_str!("../profiles/check_by_ssh.yaml"),
    include_str!("../profiles/perlbug.yaml"),
    include_str!("../profiles/bashbug.yaml"),
];

fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        PROFILES
            .into_iter()
            .map(|source| load_command_profile_from_str(source).unwrap())
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
            other => panic!("unexpected {name}: {other:?}"),
        })
        .collect()
}

fn has_effect(bound: &BoundInvocation, kind: EffectKind, slot: &str) -> bool {
    bound.effects.iter().any(|effect| {
        effect.kind == kind
            && matches!(&effect.target, EffectTarget::Slot(name) if name.as_str() == slot)
    })
}

fn has_dispatch_to(bound: &BoundInvocation, command: &str) -> bool {
    bound.effects.iter().any(|effect| {
        effect.kind == EffectKind::DispatchCommand
            && matches!(&effect.target, EffectTarget::Dispatch(target)
                if matches!(&target.command, caushell_profile::DispatchCommandSource::Slot(slot)
                    if slot.as_str() == command))
    })
}

fn has_dispatch_literal(bound: &BoundInvocation, command: &str, argv: &[&str]) -> bool {
    bound.effects.iter().any(|effect| {
        effect.kind == EffectKind::DispatchCommand
            && matches!(&effect.target, EffectTarget::Dispatch(target)
                if matches!(&target.command, caushell_profile::DispatchCommandSource::Literal(actual) if actual == command)
                    && target.argv_suffix.iter().map(String::as_str).eq(argv.iter().copied()))
    })
}

#[test]
fn gcc_aliases_are_real_resolved_compiler_invocations() {
    for executable in ["c89", "c99", "g++"] {
        let command = format!("{executable} -o /tmp/program /tmp/input.c");
        let bound = bind(&command);
        assert_eq!(
            bound.form_id.as_str(),
            "compile_to_explicit_output",
            "{command}"
        );
        assert!(
            !bound.operation_semantics_unresolved,
            "{command}: {bound:#?}"
        );
        assert_eq!(values(&bound, "input_paths"), ["/tmp/input.c"]);
        assert!(has_effect(&bound, EffectKind::WritePath, "output_path"));
    }
    for executable in ["c89", "c99", "g++"] {
        let command = format!("{executable} -wrapper /bin/sh,-s x");
        let bound = bind(&command);
        assert_eq!(
            bound.form_id.as_str(),
            "shell_wrapper_stdin",
            "{command}: {bound:#?}"
        );
        assert!(
            has_dispatch_literal(&bound, "/bin/sh", &["-s"]),
            "{command}: {bound:#?}"
        );
        assert_eq!(values(&bound, "wrapper_command"), ["/bin/sh,-s"]);
    }

    let preprocess = bind("gcc -x c -E /tmp/input.c");
    assert_eq!(preprocess.form_id.as_str(), "preprocess_to_stdout");
    assert!(
        !preprocess
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::WritePath)
    );
    assert_eq!(values(&preprocess, "input_paths"), ["/tmp/input.c"]);

    let preprocess_stdin = bind("gcc -x c -E -");
    assert_eq!(
        preprocess_stdin.form_id.as_str(),
        "preprocess_stdin_to_stdout"
    );
    let stream = preprocess_stdin.stream_contract.unwrap();
    assert_eq!(stream.stdin_mode, StreamInputMode::DataRequired);
    assert_eq!(stream.stdout_mode, StreamOutputMode::Data);

    let no_input = parse_command("gcc -x c -E", ShellKind::Bash).unwrap();
    assert!(matches!(
        resolve_invocation(
            &registry(),
            &no_input.commands[0],
            InvocationRuntimeContext::new(),
        ),
        ResolveInvocationResult::SelectionError { .. }
    ));

    let preprocess_to_file = bind("gcc -x c -E -o /tmp/output.i /tmp/input.c");
    assert_eq!(preprocess_to_file.form_id.as_str(), "preprocess_to_file");
    let stream = preprocess_to_file.stream_contract.unwrap();
    assert_eq!(stream.stdin_mode, StreamInputMode::Ignored);
    assert_eq!(stream.stdout_mode, StreamOutputMode::Opaque);

    let dash_output = parse_command("gcc -x c -E -o - /tmp/input.c", ShellKind::Bash).unwrap();
    assert!(matches!(
        resolve_invocation(
            &registry(),
            &dash_output.commands[0],
            InvocationRuntimeContext::new(),
        ),
        ResolveInvocationResult::SelectionError { .. }
    ));
}

#[test]
fn gcc_response_file_is_a_concrete_read_input() {
    let response = bind("gcc @/tmp/compiler.args");
    assert_eq!(
        response.form_id.as_str(),
        "response_file_arguments",
        "{response:#?}"
    );
    assert_eq!(
        values(&response, "response_argument"),
        ["@/tmp/compiler.args"]
    );
    assert!(has_effect(
        &response,
        EffectKind::ReadPath,
        "response_file_path"
    ));
    assert!(format!("{:#?}", response.bound_parameters).contains("/tmp/compiler.args"));
}

#[test]
fn mawk_runs_an_opaque_awk_program_and_binds_file_inputs() {
    let read = bind("mawk '//' /tmp/input");
    assert_eq!(read.form_id.as_str(), "execute_inline_program");
    assert_eq!(values(&read, "input_paths"), ["/tmp/input"]);
    assert!(has_effect(&read, EffectKind::ExecutePayload, "program"));
    assert!(has_effect(&read, EffectKind::ReadPath, "input_paths"));

    for command in [
        "mawk 'BEGIN { print \"DATA\" > \"/tmp/output\" }'",
        "mawk 'BEGIN {system(\"/bin/sh\")}'",
        "mawk -f /tmp/program.awk /tmp/input",
    ] {
        let bound = bind(command);
        assert!(
            bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::ExecutePayload),
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn run_parts_keeps_directory_contents_opaque_and_respects_test_mode() {
    let command = "run-parts --new-session --regex '^sh$' /bin";
    let bound = bind(command);
    assert_eq!(bound.form_id.as_str(), "execute_matching_directory_entries");
    assert_eq!(values(&bound, "script_directory"), ["/bin"]);
    assert!(has_effect(&bound, EffectKind::ReadPath, "script_directory"));
    assert!(has_effect(
        &bound,
        EffectKind::ExecutePayload,
        "script_directory"
    ));
    assert!(values(&bound, "script_arguments").is_empty());

    let list = bind("run-parts --test --regex '^sh$' /bin");
    assert_eq!(list.form_id.as_str(), "list_matching_directory_entries");
    assert!(
        !list
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ExecutePayload)
    );

    let source_argument = bind("run-parts /tmp/scripts --arg=-p");
    assert_eq!(
        source_argument.form_id.as_str(),
        "execute_matching_directory_entries"
    );
    assert_eq!(values(&source_argument, "script_arguments"), ["-p"]);
    assert!(has_effect(
        &source_argument,
        EffectKind::ExecutePayload,
        "script_directory"
    ));
}

#[test]
fn daemon_start_and_stop_have_distinct_process_semantics() {
    let start = bind("start-stop-daemon --start --exec /bin/sh -- -p");
    assert_eq!(start.form_id.as_str(), "start_explicit_executable");
    assert_eq!(values(&start, "executable"), ["/bin/sh"]);
    assert_eq!(values(&start, "child_argv"), ["-p"]);
    assert!(has_dispatch_to(&start, "executable"));
    assert!(start.effects.iter().any(|effect| {
        effect.kind == EffectKind::SetExecutionWorkingDirectory
            && matches!(&effect.target, EffectTarget::ConfiguredPath(target)
                if target.default_value.as_deref() == Some("/"))
    }));

    let start_as = bind(
        "start-stop-daemon --start --exec /usr/bin/matcher --startas /bin/sh --chdir /tmp -- -p",
    );
    assert_eq!(values(&start_as, "executable"), ["/usr/bin/matcher"]);
    assert_eq!(values(&start_as, "start_as"), ["/bin/sh"]);
    assert_eq!(values(&start_as, "child_argv"), ["-p"]);
    assert!(has_dispatch_to(&start_as, "start_as"));
    assert!(start_as.effects.iter().any(|effect| {
        effect.kind == EffectKind::SetExecutionWorkingDirectory
            && matches!(&effect.target, EffectTarget::ConfiguredPath(target)
                if target.sources.iter().any(|source| source.slot.as_str() == "working_directory"))
    }));

    let stop = bind("start-stop-daemon --stop --exec /bin/sh");
    assert_eq!(stop.form_id.as_str(), "stop_matching_processes");
    assert!(
        stop.effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ControlProcess)
    );
    assert!(
        !stop
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::DispatchCommand)
    );

    let test_mode = bind("start-stop-daemon --start --exec /bin/sh --test");
    assert_eq!(test_mode.form_id.as_str(), "dry_run");
    assert!(!test_mode.effects.iter().any(|effect| matches!(
        effect.kind,
        EffectKind::DispatchCommand | EffectKind::ControlProcess
    )));
}

#[test]
fn loader_dispatch_and_ssh_option_data_keep_their_boundaries() {
    let loader = bind("ld.so /bin/sh -p");
    assert_eq!(loader.form_id.as_str(), "load_and_run_program");
    assert_eq!(values(&loader, "target_program"), ["/bin/sh"]);
    assert_eq!(values(&loader, "target_argv"), ["-p"]);
    assert!(has_dispatch_to(&loader, "target_program"));

    let list = bind("ld.so --list /bin/ls");
    assert_eq!(list.form_id.as_str(), "list_dependencies");
    assert_eq!(values(&list, "target_program"), ["/bin/ls"]);
    assert!(
        !list
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::DispatchCommand)
    );
    assert!(has_effect(&list, EffectKind::ReadPath, "target_program"));

    let check = bind("check_by_ssh -o 'ProxyCommand /bin/sh -i' -H localhost -C uptime");
    assert_eq!(check.form_id.as_str(), "remote_check");
    assert_eq!(values(&check, "ssh_options"), ["ProxyCommand /bin/sh -i"]);
    assert_eq!(values(&check, "remote_host"), ["localhost"]);
    assert_eq!(values(&check, "remote_command"), ["uptime"]);
    assert!(has_effect(
        &check,
        EffectKind::NetworkEndpoint,
        "remote_host"
    ));
    assert!(has_effect(
        &check,
        EffectKind::ExecuteRemoteCommand,
        "remote_command"
    ));
    assert!(
        check
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::DispatchCommand)
    );
}

#[test]
fn perlbug_editor_option_is_shell_input_not_perl_code() {
    let command = "perlbug -s 'x x x' -r x -c x -e 'exec /bin/sh #'";
    let bound = bind(command);
    assert_eq!(bound.form_id.as_str(), "editor_command");
    assert_eq!(values(&bound, "editor_command"), ["exec /bin/sh #"]);
    assert!(has_effect(
        &bound,
        EffectKind::ExecutePayload,
        "editor_command"
    ));
}

#[test]
fn bashbug_uses_an_interactive_editor_surface() {
    let bound = bind("bashbug");
    assert_eq!(bound.form_id.as_str(), "inherited_interactive_editor");
    assert!(
        bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::OpenInteractiveEscapeSurface)
    );

    let help = bind("bashbug --help");
    assert_eq!(help.form_id.as_str(), "help_or_version");
    assert!(
        !help
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::OpenInteractiveEscapeSurface)
    );
}
