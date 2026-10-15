//! Native command modeling only: no compressor or sample command is executed.
use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, CommandProfile, EffectKind, EffectTarget,
    InvocationRuntimeContext, StreamInputMode, StreamOutputMode, bind_invocation,
    load_command_profile_from_str, project_invocation, select_invocation,
};
use caushell_types::{RuntimeArgumentDomain, ShellKind};

fn profile() -> CommandProfile {
    load_command_profile_from_str(include_str!("../profiles/bunzip2.yaml")).unwrap()
}
fn bind(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let p = profile();
    let selected = select_invocation(&p, &projection).unwrap_or_else(|e| panic!("{command}: {e}"));
    let b = bind_invocation(&p, &projection, &selected);
    assert!(!b.operation_semantics_unresolved, "{command}: {b:#?}");
    assert!(b.residuals.is_empty(), "{command}: {b:#?}");
    b
}
fn has(b: &BoundInvocation, kind: EffectKind) -> bool {
    b.effects.iter().any(|e| e.kind == kind)
}
fn texts<'a>(b: &'a BoundInvocation, name: &str) -> Vec<&'a str> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.as_str(),
            _ => panic!("Expected original literal: {v:#?}"),
        })
        .collect()
}
#[test]
fn file_modes_preserve_deletion_keep_and_permuted_option_semantics() {
    for command in [
        "bunzip2 x.bz2",
        "bunzip2 -d x.bz2",
        "bunzip2 x.bz2 -fv",
        "bunzip2 --decompress --force x.bz2",
        "bunzip2 -sv9 x.bz2",
    ] {
        let b = bind(command);
        assert_eq!(b.form_id.as_str(), "decompress_files");
        assert!(
            has(&b, EffectKind::ReadPath)
                && has(&b, EffectKind::WritePath)
                && has(&b, EffectKind::DeletePath),
            "{command}: {b:#?}"
        );
    }
    for command in [
        "bunzip2 -k x.bz2",
        "bunzip2 x.bz2 --keep",
        "bunzip2 -dkfv x.bz2",
    ] {
        let b = bind(command);
        assert_eq!(b.form_id.as_str(), "decompress_files_keep");
        assert!(has(&b, EffectKind::WritePath));
        assert!(!has(&b, EffectKind::DeletePath));
    }
}
#[test]
fn stdout_and_integrity_modes_do_not_invent_file_mutations() {
    for command in [
        "bunzip2 -c /opt/input.bz2",
        "bunzip2 /opt/input.bz2 --stdout",
        "bunzip2 -dc /opt/input.bz2",
        "bunzip2 -kc /opt/input.bz2",
        "bunzip2 -vt /opt/input.bz2",
        "bunzip2 --test /opt/input.bz2",
    ] {
        let b = bind(command);
        assert!(has(&b, EffectKind::ReadPath));
        assert!(!has(&b, EffectKind::WritePath) && !has(&b, EffectKind::DeletePath));
        let s = b.stream_contract.unwrap();
        assert_eq!(s.stdin_mode, StreamInputMode::Ignored);
        assert_eq!(
            s.stdout_mode,
            if command.contains("--test") || command.contains("-vt") {
                StreamOutputMode::Opaque
            } else {
                StreamOutputMode::Data
            }
        );
    }
}
#[test]
fn no_file_modes_consume_stdin_without_fabricating_a_path() {
    for command in [
        "bunzip2",
        "bunzip2 -c",
        "bunzip2 -d",
        "bunzip2 -k",
        "bunzip2 -z",
        "bunzip2 -zc",
        "bunzip2 -t",
    ] {
        let b = bind(command);
        assert!(!has(&b, EffectKind::WritePath) && !has(&b, EffectKind::DeletePath));
        assert_eq!(
            b.stream_contract.unwrap().stdin_mode,
            StreamInputMode::DataRequired
        );
    }
}
#[test]
fn explicit_compression_and_information_have_native_meaning() {
    for (command, delete) in [("bunzip2 -z input", true), ("bunzip2 -zk input", false)] {
        let b = bind(command);
        assert_eq!(has(&b, EffectKind::DeletePath), delete);
        assert!(
            b.effects
                .iter()
                .any(|e| matches!(&e.target,EffectTarget::DerivedPath(p)
            if p.rule == caushell_types::DerivedPathRule::AppendSuffix {suffix:".bz2".into()}))
        );
    }
    for flag in ["-V", "-L", "--version", "--license"] {
        let b = bind(&format!("bunzip2 {flag} input.bz2"));
        assert!(has(&b, EffectKind::WritePath) && has(&b, EffectKind::DeletePath));
    }
    for command in ["bunzip2 --help /opt/input.bz2", "bunzip2 /opt/input.bz2 -h"] {
        assert!(bind(command).effects.is_empty(), "{command}");
    }
}
#[test]
fn mixed_suffixes_are_bound_individually_without_losing_original_argv() {
    let b = bind("bunzip2 -k a.bz2 b.bz c.tbz2 d.tbz other 'line\nbreak.bz2'");
    for (name, expected) in [
        ("bz2_inputs", vec!["a.bz2", "line\nbreak.bz2"]),
        ("bz_inputs", vec!["b.bz"]),
        ("tbz2_inputs", vec!["c.tbz2"]),
        ("tbz_inputs", vec!["d.tbz"]),
        ("other_inputs", vec!["other"]),
    ] {
        assert_eq!(texts(&b, name), expected);
    }
    assert!(
        b.effects
            .iter()
            .any(|e| matches!(&e.target,EffectTarget::DerivedPath(p)
        if p.rule == caushell_types::DerivedPathRule::SiblingFiles))
    );
}
#[test]
fn native_batch_domains_survive_the_unknown_name_fallback() {
    let parsed = parse_command("bunzip2 placeholder", ShellKind::Bash).unwrap();
    let mut projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let arg = &mut projection.args[0];
    arg.text.clear();
    arg.quoted = true;
    arg.node_kind = "runtime_argument_list".into();
    arg.implicit_input_source = Some(caushell_types::ImplicitInputSource::DispatchOutput);
    let domain = RuntimeArgumentDomain::PathSet {
        roots: vec!["./input".into()],
        may_escape: false,
    };
    arg.runtime_argument_domain = Some(domain.clone());
    let p = profile();
    let selected = select_invocation(&p, &projection).unwrap();
    let b = bind_invocation(&p, &projection, &selected);
    assert!(!b.operation_semantics_unresolved, "{b:#?}");
    let values = &b
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "other_inputs")
        .unwrap()
        .values;
    assert!(
        matches!(&values[..],[BoundValue::ImplicitInput {domain:Some(actual),origin:Some(o),..}]
        if actual == &domain && !o.single_field)
    );
    assert!(has(&b, EffectKind::DeletePath));
}
#[test]
fn terminator_owns_option_looking_filenames() {
    let b = bind("bunzip2 -- -k.bz2 -t.bz");
    assert!(has(&b, EffectKind::DeletePath));
    assert!(
        !b.applied_modifiers
            .iter()
            .any(|m| ["keep", "test"].contains(&m.as_str()))
    );
    assert_eq!(texts(&b, "bz2_inputs"), ["-k.bz2"]);
    assert_eq!(texts(&b, "bz_inputs"), ["-t.bz"]);
}
#[test]
fn unknown_flags_dynamic_controls_and_conflicting_modes_remain_unresolved() {
    for command in [
        "bunzip2 --unknown x.bz2",
        "bunzip2 --to-stdout x.bz2",
        "bunzip2 -dz x.bz2",
        "bunzip2 -zd x.bz2",
        "bunzip2 -tc x.bz2",
        "bunzip2 -dt x.bz2",
        "bunzip2 -- -",
        "bunzip2 \"$FILE\"",
        "bunzip2 *.bz2",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        let p = profile();
        if let Ok(s) = select_invocation(&p, &projection) {
            let b = bind_invocation(&p, &projection, &s);
            assert!(
                b.operation_semantics_unresolved || !b.residuals.is_empty(),
                "{command}: {b:#?}"
            );
        }
    }
}
