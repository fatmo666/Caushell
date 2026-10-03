use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn profile(matching: OptionMatchingPolicy) -> CommandProfile {
    CommandProfile::new("arbitrary-cluster-tool")
        .with_option_matching(matching)
        .with_form(Form::new("default"))
        .with_modifier(Modifier::new("a").with_flag_name("-a"))
        .with_modifier(Modifier::new("b").with_flag_name("-b"))
        .with_modifier(Modifier::new("four").with_flag_name("-4"))
        .with_modifier(Modifier::new("z").with_flag_name("-z"))
        .with_modifier(
            Modifier::new("output")
                .with_flag_name("-o")
                .with_parameter(Parameter::new(
                    "output",
                    SemanticType::PlainValue,
                    BindingSpec::FollowingMatchedFlag {
                        operand_mode: FlagOperandMode::NextArg,
                    },
                )),
        )
}

fn bound_with(profile: &CommandProfile, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(profile, &projection).unwrap();
    bind_invocation(profile, &projection, &selected)
}

fn bound(command: &str) -> BoundInvocation {
    bound_with(&profile(OptionMatchingPolicy::ShortClusters), command)
}

fn modifier_names(b: &BoundInvocation) -> Vec<&str> {
    b.applied_modifiers.iter().map(|m| m.as_str()).collect()
}

fn output(b: &BoundInvocation) -> Option<&str> {
    b.bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "output")
        .and_then(|p| p.values.first())
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("{other:?}"),
        })
}

#[test]
fn flag_only_prefix_survives_attached_operands_including_dash_and_unicode() {
    for (arg, value) in [
        ("-abo-", "-"),
        ("-abo/etc/report", "/etc/report"),
        ("-abo报告.bin", "报告.bin"),
        ("-abo--anything", "--anything"),
    ] {
        let c = format!("arbitrary-cluster-tool {arg}");
        let b = bound(&c);
        assert_eq!(modifier_names(&b), ["a", "b", "output"], "{c}: {b:?}");
        assert_eq!(output(&b), Some(value), "{c}: {b:?}");
        assert!(b.residuals.is_empty(), "{c}: {b:?}");
    }
}

#[test]
fn declared_numeric_flags_are_valid_prefix_members() {
    for (c, value) in [
        ("arbitrary-cluster-tool -a4o-", Some("-")),
        (
            "arbitrary-cluster-tool -a4o /etc/report",
            Some("/etc/report"),
        ),
        ("arbitrary-cluster-tool -a4", None),
    ] {
        let b = bound(c);
        assert!(modifier_names(&b).contains(&"a"), "{c}: {b:?}");
        assert!(modifier_names(&b).contains(&"four"), "{c}: {b:?}");
        assert_eq!(output(&b), value, "{c}: {b:?}");
    }
}

#[test]
fn operand_suffix_is_not_scanned_as_a_later_flag() {
    for (c, value) in [
        ("arbitrary-cluster-tool -aoz.txt", "z.txt"),
        ("arbitrary-cluster-tool -ao4.txt", "4.txt"),
        ("arbitrary-cluster-tool -aob.txt", "b.txt"),
    ] {
        let b = bound(c);
        assert_eq!(modifier_names(&b), ["a", "output"], "{c}: {b:?}");
        assert_eq!(output(&b), Some(value));
    }
}

#[test]
fn unknown_prefix_does_not_certify_later_flag_only_members() {
    let b = bound("arbitrary-cluster-tool -qaobo-");
    assert!(!modifier_names(&b).contains(&"a"), "{b:?}");
    assert!(!modifier_names(&b).contains(&"b"), "{b:?}");
}

#[test]
fn separate_values_and_next_argument_clusters_keep_existing_binding() {
    for c in [
        "arbitrary-cluster-tool -ab -o value",
        "arbitrary-cluster-tool -abo value",
    ] {
        let b = bound(c);
        assert_eq!(modifier_names(&b), ["a", "b", "output"], "{c}: {b:?}");
        assert_eq!(output(&b), Some("value"));
    }
}

#[test]
fn exact_names_and_real_option_terminator_do_not_enable_prefix_scanning() {
    let p = profile(OptionMatchingPolicy::ExactNames);
    let b = bound_with(&p, "arbitrary-cluster-tool -abo-");
    assert!(b.applied_modifiers.is_empty(), "{b:?}");
    let b = bound("arbitrary-cluster-tool -- -abo-");
    assert!(b.applied_modifiers.is_empty(), "{b:?}");
}
