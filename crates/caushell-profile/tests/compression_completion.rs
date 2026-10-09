use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, CommandProfile, EffectKind, EffectTarget, InvocationRuntimeContext,
    StreamInputMode, StreamOutputMode, bind_invocation, load_command_profile_from_str,
    project_invocation, select_invocation,
};
use caushell_types::ShellKind;
fn profile(name: &str) -> CommandProfile {
    load_command_profile_from_str(match name {
        "gunzip" => include_str!("../profiles/gunzip.yaml"),
        "bzip2" => include_str!("../profiles/bzip2.yaml"),
        "compress" => include_str!("../profiles/compress.yaml"),
        _ => panic!("fixture profile"),
    })
    .unwrap()
}
fn bound(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let p = profile(parsed.commands[0].command_name.as_deref().unwrap());
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&p, &projection).unwrap_or_else(|e| panic!("{command}: {e}"));
    let b = bind_invocation(&p, &projection, &selected);
    assert!(b.residuals.is_empty(), "{command}: {b:?}");
    b
}
fn has(b: &BoundInvocation, kind: EffectKind) -> bool {
    b.effects.iter().any(|e| e.kind == kind)
}
#[test]
fn default_file_operations_and_keep_have_distinct_success_possible_effects() {
    for tool in ["gunzip", "bzip2", "compress"] {
        let filename = if tool == "gunzip" { "file.gz" } else { "file" };
        for (flag, delete) in [("", true), ("-k", false)] {
            let b = bound(&format!("{tool} {flag} {filename}"));
            assert!(has(&b, EffectKind::ReadPath) && has(&b, EffectKind::WritePath));
            assert_eq!(has(&b, EffectKind::DeletePath), delete);
        }
    }
}
#[test]
fn stdout_and_test_never_declare_file_mutations() {
    for command in [
        "gunzip -c /opt/input.gz",
        "gunzip -vt /opt/input.gz",
        "gunzip -l /opt/input.gz",
        "bzip2 -c /opt/input",
        "bzip2 -t /opt/input.bz2",
        "compress -c /opt/input",
        "compress -dc /opt/input.Z",
    ] {
        let b = bound(command);
        assert!(has(&b, EffectKind::ReadPath));
        assert!(
            !has(&b, EffectKind::WritePath) && !has(&b, EffectKind::DeletePath),
            "{command}"
        );
    }
}
#[test]
fn native_decode_suffixes_are_not_misclassified_as_compression() {
    use caushell_types::DerivedPathRule;
    for (command, expected) in [
        (
            "bzip2 -d x.bz2",
            DerivedPathRule::StripSuffix {
                suffix: ".bz2".into(),
            },
        ),
        (
            "bzip2 -dk x.bz",
            DerivedPathRule::StripSuffix {
                suffix: ".bz".into(),
            },
        ),
        (
            "bzip2 -d x.tbz2",
            DerivedPathRule::ReplaceSuffix {
                from: ".tbz2".into(),
                to: ".tar".into(),
            },
        ),
        (
            "bzip2 -dk x.tbz",
            DerivedPathRule::ReplaceSuffix {
                from: ".tbz".into(),
                to: ".tar".into(),
            },
        ),
        (
            "gunzip x.gz",
            DerivedPathRule::StripSuffix {
                suffix: ".gz".into(),
            },
        ),
        (
            "compress -d x.Z",
            DerivedPathRule::StripSuffix {
                suffix: ".Z".into(),
            },
        ),
    ] {
        let b = bound(command);
        assert!(
            b.effects
                .iter()
                .any(|e| matches!(&e.target, EffectTarget::DerivedPath(t) if t.rule == expected)),
            "{command}: {b:?}"
        );
    }
}
#[test]
fn bzip_unknown_decode_names_use_native_sibling_family_not_fake_bz2_output() {
    use caushell_types::DerivedPathRule;
    let b = bound("bzip2 -d arbitrary");
    assert!(b.effects.iter().any(|e| matches!(&e.target, EffectTarget::DerivedPath(t) if t.rule == DerivedPathRule::SiblingFiles)));
}
#[test]
fn no_file_inputs_use_stdin_and_stdout_without_a_dash_file() {
    for tool in ["gunzip", "bzip2", "compress"] {
        for command in [
            tool.to_string(),
            format!("{tool} -c"),
            format!("{tool} -dc"),
        ] {
            let b = bound(&command);
            assert!(!has(&b, EffectKind::WritePath) && !has(&b, EffectKind::DeletePath));
            let p = profile(tool);
            let streams = p
                .forms
                .iter()
                .find(|f| f.id == b.form_id)
                .unwrap()
                .stream_contract
                .unwrap();
            assert_eq!(streams.stdin_mode, StreamInputMode::DataRequired);
            assert_eq!(streams.stdout_mode, StreamOutputMode::Data);
        }
    }
}
#[test]
fn explicit_gunzip_stdin_and_file_inputs_keep_both_effects() {
    for command in ["gunzip - file.gz", "gunzip -k file.gz -"] {
        let b = bound(command);
        assert!(has(&b, EffectKind::WritePath));
        let p = profile("gunzip");
        let stream = p
            .forms
            .iter()
            .find(|f| f.id == b.form_id)
            .unwrap()
            .stream_contract
            .unwrap();
        assert_eq!(stream.stdin_mode, StreamInputMode::DataRequired);
    }
    assert!(!has(&bound("gunzip -"), EffectKind::WritePath));
}
#[test]
fn unknown_options_and_conflicting_bzip_modes_keep_analysis_gap() {
    for command in [
        "bzip2 --unknown file",
        "gunzip --unknown file.gz",
        "compress --unknown file",
        "bzip2 -dt file.bz2",
        "bzip2 -td file.bz2",
        "bzip2 -dz file.bz2",
        "bzip2 -tc file.bz2",
        "bzip2 -- -",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let p = profile(parsed.commands[0].command_name.as_deref().unwrap());
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        match select_invocation(&p, &projection) {
            Err(_) => {}
            Ok(s) => {
                let b = bind_invocation(&p, &projection, &s);
                assert!(!b.residuals.is_empty(), "{command}: {b:?}");
            }
        }
    }
}
#[test]
fn information_options_are_independent_and_do_not_read_supplied_files() {
    for command in [
        "gunzip --help /opt/input.gz",
        "bzip2 -V /opt/input",
        "bzip2 -L /opt/input",
        "compress -V /opt/input",
    ] {
        assert!(bound(command).effects.is_empty(), "{command}");
    }
}
#[test]
fn declared_unknown_outputs_and_operand_ownership_remain_explicit() {
    for command in [
        "gunzip -N file.gz",
        "gunzip -r dir",
        "gunzip -S.custom file",
        "compress -r dir",
    ] {
        let b = bound(command);
        assert!(
            b.effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath && e.target == EffectTarget::None),
            "{command}: {b:?}"
        );
    }
    assert_eq!(
        bound("compress -b 12 file")
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "maxbits")
            .unwrap()
            .values
            .len(),
        1
    );
    assert!(has(&bound("bzip2 -- -t"), EffectKind::WritePath));
    assert!(
        !has(&bound("bzip2 -- -t"), EffectKind::TransformData)
            || !bound("bzip2 -- -t")
                .applied_modifiers
                .iter()
                .any(|m| m.as_str() == "test")
    );
}
