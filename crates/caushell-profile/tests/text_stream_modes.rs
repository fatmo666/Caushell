//! Native argv contracts only; sample commands are never executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ShellKind, StreamDataDependency};

fn resolved(command: &str) -> ResolvedInvocationArtifact {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn file_operands_ignore_unrequested_stdin_and_dash_restores_it() {
    for (files, stdin) in [
        ("cat public", "cat public -"),
        ("head -n1 public", "head -n1 public -"),
        ("tail -n1 public", "tail -n1 public -"),
        ("paste public", "paste public -"),
        ("cut -f1 public", "cut -f1 public -"),
        ("wc -l public", "wc -l public -"),
        ("grep x public", "grep x public -"),
        ("grep -e x public", "grep -e x public -"),
        ("sed 's/x/y/' public", "sed 's/x/y/' public -"),
        ("sed -e 's/x/y/' public", "sed -e 's/x/y/' public -"),
    ] {
        assert_eq!(
            resolved(files).proven_stream_contract().unwrap().stdin_mode,
            StreamInputMode::Ignored,
            "{files}"
        );
        assert_ne!(
            resolved(stdin).proven_stream_contract().unwrap().stdin_mode,
            StreamInputMode::Ignored,
            "{stdin}"
        );
    }
    for command in [
        "cat",
        "head -n1",
        "tail -n1",
        "paste",
        "cut -f1",
        "wc -l",
        "grep x",
        "grep -e x",
        "sed 's/x/y/'",
        "sed -e 's/x/y/'",
    ] {
        assert_ne!(
            resolved(command)
                .proven_stream_contract()
                .unwrap()
                .stdin_mode,
            StreamInputMode::Ignored,
            "{command}"
        );
    }
}

#[test]
fn unknown_operands_do_not_prove_stream_independence() {
    for command in [
        "cat \"$input\"",
        "head *.txt",
        "head *",
        "head \"$input\"",
        "grep x \"$input\"",
        "sed -i 's/x/y/' \"$input\"",
    ] {
        assert!(
            resolved(command).proven_stream_contract().is_none(),
            "{command}"
        );
    }
    for command in [
        "head '*.txt'",
        "head \\*",
        "head \"*.txt\"",
        "head 'a'\\*",
        "grep '^x$' public",
    ] {
        assert!(
            resolved(command).proven_stream_contract().is_some(),
            "{command}"
        );
    }
}

#[test]
fn quiet_grep_keeps_reads_but_has_no_content_stdout() {
    for command in [
        "grep -q x .env",
        "grep --quiet x .env",
        "grep --silent -e x .env",
        "grep -q -f .env public",
    ] {
        let r = resolved(command);
        assert_eq!(
            r.proven_stream_contract().unwrap().stdout_dependency,
            StreamDataDependency::Independent,
            "{command}"
        );
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ReadPath),
            "{command}"
        );
    }
    assert_eq!(
        resolved("grep -r x")
            .proven_stream_contract()
            .unwrap()
            .stdin_mode,
        StreamInputMode::Ignored
    );
    assert_ne!(
        resolved("grep -r -f - public")
            .proven_stream_contract()
            .unwrap()
            .stdin_mode,
        StreamInputMode::Ignored
    );
}

#[test]
fn in_place_sed_keeps_writes_and_treats_dash_as_a_filename() {
    for command in [
        "sed -i 's/x/y/' .env",
        "sed --in-place 's/x/y/' .env",
        "sed -i.bak -e 's/x/y/' .env",
        "sed -i 's/x/y/' -",
    ] {
        let r = resolved(command);
        let streams = r.proven_stream_contract().unwrap();
        assert_eq!(
            streams.stdout_dependency,
            StreamDataDependency::Independent,
            "{command}"
        );
        assert_eq!(streams.stdin_mode, StreamInputMode::Ignored, "{command}");
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ReadPath)
        );
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath)
        );
    }
    let r = resolved("sed -i 's/x/y/' -");
    assert!(
        r.bound
            .bound_parameters
            .iter()
            .any(|p| p.name.as_str() == "in_place_dash_paths" && !p.values.is_empty())
    );
}

#[test]
fn information_forms_have_independent_outputs_and_no_path_effects() {
    for command in [
        "cat", "head", "tail", "paste", "cut", "wc", "grep", "sed", "tr", "tee",
    ] {
        for flag in ["--help", "--version"] {
            let command = format!("{command} {flag} .env");
            let r = resolved(&command);
            let streams = r.proven_stream_contract().unwrap();
            assert_eq!(streams.stdin_mode, StreamInputMode::Ignored, "{command}");
            assert_eq!(
                streams.stdout_dependency,
                StreamDataDependency::Independent,
                "{command}"
            );
            assert!(
                r.bound.effects.is_empty(),
                "{command}: {:#?}",
                r.bound.effects
            );
        }
    }
}
