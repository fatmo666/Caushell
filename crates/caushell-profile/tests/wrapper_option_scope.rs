use caushell_parse::parse_command;
use caushell_profile::{
    BindingSpec, BoundInvocation, BoundValue, CommandProfile, FlagName, FlagOperandMode, Form,
    InvocationRuntimeContext, Modifier, OptionScopePolicy, Parameter, SelectorExpr,
    SelectorPredicate, SemanticType, bind_invocation, project_invocation, select_invocation,
};
use caushell_types::ShellKind;

fn wrapper() -> CommandProfile {
    CommandProfile::new("arbitrary-wrapper")
        .with_option_scope(OptionScopePolicy::LeadingOptions)
        .with_modifier(Modifier::new("verbose").with_flag_name("-v"))
        .with_modifier(Modifier::new("help").with_flag_name("--help"))
        .with_modifier(
            Modifier::new("password")
                .with_flag_name("-p")
                .with_parameter(Parameter::new(
                    "password",
                    SemanticType::PlainValue,
                    BindingSpec::FollowingMatchedFlag {
                        operand_mode: FlagOperandMode::NextArg,
                    },
                )),
        )
        .with_modifier(
            Modifier::new("file")
                .with_flag_name("-f")
                .with_parameter(Parameter::new(
                    "file",
                    SemanticType::PlainValue,
                    BindingSpec::FollowingMatchedFlag {
                        operand_mode: FlagOperandMode::NextArg,
                    },
                )),
        )
        .with_modifier(
            Modifier::new("env").with_flag_name("-e").with_parameter(
                Parameter::new(
                    "env_name",
                    SemanticType::PlainValue,
                    BindingSpec::FollowingMatchedFlag {
                        operand_mode: FlagOperandMode::InlineOrShortAttached,
                    },
                )
                .optional(),
            ),
        )
        .with_form(
            Form::new("dispatch")
                .with_selector(SelectorExpr::All(vec![
                    SelectorExpr::Predicate(SelectorPredicate::HasPositionalAt(0)),
                    SelectorExpr::Predicate(SelectorPredicate::LacksFlag(FlagName::new("--help"))),
                ]))
                .with_parameter(Parameter::new(
                    "command",
                    SemanticType::PlainValue,
                    BindingSpec::NextPositional,
                ))
                .with_parameter(
                    Parameter::new("argv", SemanticType::PlainValue, BindingSpec::RemainingArgs)
                        .optional()
                        .variadic(),
                ),
        )
        .with_form(
            Form::new("show_help")
                .with_selector_predicate(SelectorPredicate::HasFlag(FlagName::new("--help"))),
        )
}

fn bound(profile: &CommandProfile, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection =
        select_invocation(profile, &projection).unwrap_or_else(|e| panic!("{command}: {e}"));
    let bound = bind_invocation(profile, &projection, &selection);
    assert!(
        bound.residuals.is_empty(),
        "{command}: {:?}",
        bound.residuals
    );
    bound
}

fn values<'a>(bound: &'a BoundInvocation, name: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("{other:?}"),
        })
        .collect()
}

#[test]
fn child_options_and_help_do_not_belong_to_parent() {
    for command in [
        "arbitrary-wrapper -e ssh -p 2222 host",
        "arbitrary-wrapper -e ssh -f password.txt -p 2222 --help host",
        "arbitrary-wrapper ssh --help -e -p password -f file",
    ] {
        let result = bound(&wrapper(), command);
        assert_eq!(result.form_id.as_str(), "dispatch");
        assert_eq!(values(&result, "command"), ["ssh"]);
        assert!(values(&result, "password").is_empty());
        assert!(values(&result, "file").is_empty());
        let child_text = command
            .split_once("ssh ")
            .unwrap()
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        assert_eq!(values(&result, "argv"), child_text);
    }
    assert_eq!(
        bound(&wrapper(), "arbitrary-wrapper --help ssh -p 2222 host")
            .form_id
            .as_str(),
        "show_help"
    );
}

#[test]
fn option_operands_that_look_like_flags_are_not_reinterpreted() {
    for operand in ["--help", "-f", "--", "-v"] {
        let command = format!("arbitrary-wrapper -p {operand} -f actual.txt ssh -p 2222 host");
        let result = bound(&wrapper(), &command);
        assert_eq!(result.form_id.as_str(), "dispatch");
        assert_eq!(values(&result, "password"), [operand]);
        assert_eq!(values(&result, "file"), ["actual.txt"]);
        assert_eq!(values(&result, "command"), ["ssh"]);
        assert_eq!(values(&result, "argv"), ["-p", "2222", "host"]);
    }
}

#[test]
fn clusters_and_optional_attached_operands_preserve_child_argv() {
    for (command, password, env) in [
        ("arbitrary-wrapper -vpSECRET ssh -p 2222 host", "SECRET", ""),
        ("arbitrary-wrapper -vp -f ssh --help", "-f", ""),
        ("arbitrary-wrapper -veCUSTOM ssh -p 2222 host", "", "CUSTOM"),
        ("arbitrary-wrapper -ve ssh -p 2222 host", "", ""),
    ] {
        let result = bound(&wrapper(), command);
        assert_eq!(values(&result, "command"), ["ssh"]);
        assert_eq!(
            values(&result, "password"),
            if password.is_empty() {
                vec![]
            } else {
                vec![password]
            }
        );
        assert_eq!(
            values(&result, "env_name"),
            if env.is_empty() { vec![] } else { vec![env] }
        );
        assert!(
            result
                .applied_modifiers
                .iter()
                .any(|id| id.as_str() == "verbose")
        );
        assert_eq!(
            values(&result, "argv"),
            command
                .split_once("ssh ")
                .unwrap()
                .1
                .split_whitespace()
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn only_parent_separator_is_consumed() {
    for command in [
        "arbitrary-wrapper -- ssh -- -p file",
        "arbitrary-wrapper -p secret -- ssh -- -p file",
    ] {
        let result = bound(&wrapper(), command);
        assert_eq!(values(&result, "command"), ["ssh"]);
        assert_eq!(values(&result, "argv"), ["--", "-p", "file"]);
    }
}

#[test]
fn unknown_arity_or_missing_option_operand_does_not_guess_a_child() {
    for command in [
        "arbitrary-wrapper -x mystery ssh -p 22 host",
        "arbitrary-wrapper -vx ssh host",
        "arbitrary-wrapper -p",
        "arbitrary-wrapper -vp",
        "arbitrary-wrapper --help=value ssh",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        assert!(
            select_invocation(&wrapper(), &projection).is_err(),
            "{command}"
        );
    }
}

#[test]
fn built_in_wrappers_keep_command_options_out_of_their_own_bindings() {
    let registry = caushell_profile::ProfileRegistry::built_in().unwrap();
    for (name, command, parameter, expected) in [
        (
            "sshpass",
            "sshpass -e ssh -p 2222 --help host",
            "password",
            vec![],
        ),
        (
            "sshpass",
            "sshpass -f pass.txt ssh -f -p 2222 host",
            "password_file",
            vec!["pass.txt"],
        ),
        (
            "sshpass",
            "sshpass -p -- -P prompt ssh -f ignored",
            "password",
            vec!["--"],
        ),
        (
            "env",
            "env -u TMP CUSTOM=value ssh -u user --help -C /etc host",
            "unset_names",
            vec!["TMP"],
        ),
        (
            "nice",
            "nice -n -5 ssh -n --help host",
            "adjustment_value",
            vec!["-5"],
        ),
        (
            "timeout",
            "timeout -s TERM -k 1s 2s ssh -s --help host",
            "signal_name",
            vec!["TERM"],
        ),
    ] {
        let profile = registry.lookup(name).profile.unwrap();
        let result = bound(profile, command);
        assert_eq!(values(&result, parameter), expected, "{command}");
        assert_eq!(values(&result, "wrapped_command"), ["ssh"], "{command}");
        assert_eq!(
            values(&result, "wrapped_args"),
            command
                .split_once("ssh ")
                .unwrap()
                .1
                .split_whitespace()
                .collect::<Vec<_>>(),
            "{command}"
        );
        let child = caushell_profile::collect_dispatch_command_candidates(&result);
        assert_eq!(child.len(), 1);
        assert_eq!(child[0].command.text, "ssh");
        assert_eq!(
            child[0]
                .argv
                .iter()
                .map(|arg| arg.text.as_str())
                .collect::<Vec<_>>(),
            values(&result, "wrapped_args")
        );
    }
}

#[test]
fn sshpass_password_sources_and_information_have_distinct_effects() {
    let registry = caushell_profile::ProfileRegistry::built_in().unwrap();
    let profile = registry.lookup("/usr/bin/sshpass").profile.unwrap();
    for command in [
        "sshpass -p secret ssh host",
        "sshpass -f pass.txt ssh host",
        "sshpass -d 3 ssh host",
        "sshpass -e ssh host",
        "sshpass -veCUSTOM ssh host",
    ] {
        let result = bound(profile, command);
        assert_eq!(
            result.form_id.as_str(),
            "dispatch_with_password_source",
            "{command}"
        );
        assert!(
            !result
                .effects
                .iter()
                .any(|e| e.kind == caushell_profile::EffectKind::ConsumeStdin)
        );
        assert_eq!(
            result
                .effects
                .iter()
                .any(|e| e.kind == caushell_profile::EffectKind::ReadPath),
            command.contains("-f pass.txt")
        );
    }
    let result = bound(profile, "sshpass ssh host");
    assert_eq!(result.form_id.as_str(), "dispatch_with_stdin_password");
    assert!(
        result
            .effects
            .iter()
            .any(|e| e.kind == caushell_profile::EffectKind::ConsumeStdin)
    );
    for command in [
        "sshpass -h",
        "sshpass -V",
        "sshpass -f pass.txt -h ssh host",
    ] {
        let result = bound(profile, command);
        assert!(result.effects.is_empty(), "{command}");
        assert!(caushell_profile::collect_dispatch_command_candidates(&result).is_empty());
    }
    for command in [
        "sshpass -p secret -e ssh host",
        "sshpass -f pass.txt -d 3 ssh host",
        "sshpass -f",
        "sshpass -x thing ssh host",
        "sshpass -e",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        assert!(
            select_invocation(profile, &projection).is_err(),
            "{command}"
        );
    }
}

#[test]
fn known_modifier_effects_survive_an_unknown_later_option() {
    let registry = caushell_profile::ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(
        "sshpass -f /etc/pass.txt -x mystery ssh host",
        ShellKind::Bash,
    )
    .unwrap();
    match caushell_profile::resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        caushell_profile::ResolveInvocationResult::SelectionError {
            partial_bound: Some(partial),
            ..
        } => {
            assert_eq!(values(&partial, "password_file"), ["/etc/pass.txt"]);
            assert!(
                partial
                    .effects
                    .iter()
                    .any(|e| e.kind == caushell_profile::EffectKind::ReadPath)
            );
            assert!(caushell_profile::collect_dispatch_command_candidates(&partial).is_empty());
        }
        result => panic!("{result:?}"),
    }
}

#[test]
#[cfg(target_os = "linux")]
fn native_gnu_wrapper_argv_matches_the_profile_dispatch() {
    // These benign real-command checks run inside the same Docker container.
    // No command received from a benchmark or model is executed here.
    let registry = caushell_profile::ProfileRegistry::built_in().unwrap();
    let child = ["/bin/printf", "%s\\n", "--help", "-p", "2222", "--", "-f"];
    for (name, own_args) in [
        ("env", vec!["-u", "WRAPPER_TEST_MISSING"]),
        ("env", vec!["--block-signal"]),
        ("nice", vec!["-n", "1"]),
        ("timeout", vec!["-k", "1s", "2s"]),
    ] {
        let output = std::process::Command::new(name)
            .args(&own_args)
            .args(child)
            .output()
            .unwrap();
        assert!(output.status.success(), "{name}: {output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "--help\n-p\n2222\n--\n-f\n"
        );
        let command = format!(
            "{name} {} /bin/printf '%s\\n' --help -p 2222 -- -f",
            own_args.join(" ")
        );
        let result = bound(registry.lookup(name).profile.unwrap(), &command);
        let candidates = caushell_profile::collect_dispatch_command_candidates(&result);
        assert_eq!(
            candidates[0]
                .argv
                .iter()
                .map(|arg| arg.text.as_str())
                .collect::<Vec<_>>(),
            child[1..]
        );
    }
}

#[test]
fn nested_subcommand_nodes_have_independent_option_ownership() {
    let node_profile = wrapper();
    let mut profile = wrapper();
    profile.forms.clear();
    profile.subcommands = Some(caushell_profile::SubcommandTree {
        roots: vec![caushell_profile::SubcommandNode {
            name: "run".to_string(),
            aliases: vec![],
            forms: node_profile.forms,
            modifiers: node_profile.modifiers,
            option_scope: OptionScopePolicy::LeadingOptions,
            option_matching: Default::default(),
            children: vec![],
            default_behavior: None,
            extensions: Default::default(),
        }],
    });
    for command in [
        "arbitrary-wrapper -p ROOT run -f NODE ssh -p 2222 --help host",
        "arbitrary-wrapper -p ROOT -- run -f NODE -- ssh -p 2222 --help host",
        "arbitrary-wrapper -p -- -v run -f NODE ssh -p 2222 --help host",
    ] {
        let result = bound(&profile, command);
        assert_eq!(result.subcommand_path, ["run"]);
        assert_eq!(
            values(&result, "password"),
            [if command.contains("ROOT") {
                "ROOT"
            } else {
                "--"
            }]
        );
        assert_eq!(values(&result, "file"), ["NODE"]);
        assert_eq!(values(&result, "command"), ["ssh"]);
        assert_eq!(values(&result, "argv"), ["-p", "2222", "--help", "host"]);
    }
}

#[test]
fn argumentless_subcommands_are_accounted_for_before_the_owned_node_scope() {
    for policy in [
        OptionScopePolicy::LeadingOptions,
        OptionScopePolicy::PermutedOptions,
    ] {
        let forms = vec![
            Form::new("query").with_selector(SelectorExpr::All(vec![
                SelectorExpr::Predicate(SelectorPredicate::NoArguments),
                SelectorExpr::Not(Box::new(SelectorExpr::Predicate(
                    SelectorPredicate::HasModifier(caushell_profile::ModifierId::new("help")),
                ))),
            ])),
            Form::new("show_help").with_selector_predicate(SelectorPredicate::HasModifier(
                caushell_profile::ModifierId::new("help"),
            )),
        ];
        let node = caushell_profile::SubcommandNode {
            name: "run".into(),
            aliases: vec![],
            forms: forms.clone(),
            modifiers: vec![Modifier::new("help").with_flag_name("--help")],
            option_scope: policy,
            option_matching: Default::default(),
            children: vec![],
            default_behavior: None,
            extensions: Default::default(),
        };
        let mut profile = wrapper();
        profile.forms.clear();
        profile.opaque_on_unresolved = true;
        let mut group = node.clone();
        group.name = "group".into();
        group.modifiers.clear();
        group.option_scope = OptionScopePolicy::LeadingOptions;
        group.children = vec![node.clone()];
        profile.subcommands = Some(caushell_profile::SubcommandTree {
            roots: vec![node, group],
        });
        for c in [
            "arbitrary-wrapper run",
            "arbitrary-wrapper -p ROOT run",
            "arbitrary-wrapper -p --help run",
            "arbitrary-wrapper -p -- -v run --help",
            "arbitrary-wrapper group run",
            "arbitrary-wrapper -v group run --help",
        ] {
            let result = bound(&profile, c);
            assert!(!result.operation_semantics_unresolved, "{c}: {result:?}");
            assert_eq!(result.subcommand_path.last().unwrap(), "run");
        }
        for c in [
            "arbitrary-wrapper --unknown run",
            "arbitrary-wrapper run --unknown",
        ] {
            let parsed = parse_command(c, ShellKind::Bash).unwrap();
            let projection =
                project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
            assert!(select_invocation(&profile, &projection).is_err(), "{c}");
        }
    }
}

#[test]
fn explicit_form_flag_bindings_use_the_same_option_boundary() {
    let mut profile = wrapper();
    profile
        .modifiers
        .iter_mut()
        .find(|modifier| modifier.id.as_str() == "password")
        .unwrap()
        .parameters
        .clear();
    profile.forms[0].parameters.insert(
        0,
        Parameter::new(
            "password",
            SemanticType::PlainValue,
            BindingSpec::FollowingFlag {
                flag_name: FlagName::new("-p"),
                operand_mode: FlagOperandMode::NextArg,
            },
        )
        .optional(),
    );
    for (command, password) in [
        ("arbitrary-wrapper -p SECRET ssh -p 2222 host", "SECRET"),
        ("arbitrary-wrapper -vpSECRET ssh -p 2222 host", "SECRET"),
        ("arbitrary-wrapper ssh -p 2222 host", ""),
    ] {
        let result = bound(&profile, command);
        assert_eq!(
            values(&result, "password"),
            if password.is_empty() {
                vec![]
            } else {
                vec![password]
            }
        );
        assert_eq!(values(&result, "command"), ["ssh"]);
        assert_eq!(values(&result, "argv"), ["-p", "2222", "host"]);
    }
}

#[test]
fn long_inline_and_repeated_option_operands_do_not_leak_into_child_argv() {
    let registry = caushell_profile::ProfileRegistry::built_in().unwrap();
    let result = bound(
        registry.lookup("env").profile.unwrap(),
        "env --unset=--help -u -- -u THIRD A=value ssh -u child --help host",
    );
    assert_eq!(values(&result, "unset_names"), ["--help", "--", "THIRD"]);
    assert_eq!(values(&result, "scoped_env"), ["A=value"]);
    assert_eq!(values(&result, "wrapped_command"), ["ssh"]);
    assert_eq!(
        values(&result, "wrapped_args"),
        ["-u", "child", "--help", "host"]
    );
    let result = bound(
        registry.lookup("nice").profile.unwrap(),
        "nice --adjustment=1 ssh --adjustment=2 host",
    );
    assert_eq!(values(&result, "adjustment_value"), ["1"]);
    assert_eq!(values(&result, "wrapped_args"), ["--adjustment=2", "host"]);
}

#[test]
fn option_scope_is_validated_and_opt_in_in_yaml() {
    let prefix = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: sample}\n";
    let default_profile = caushell_profile::load_command_profile_from_str(&format!(
        "{prefix}forms: [{{id: normal}}]\n"
    ))
    .unwrap();
    assert_eq!(
        default_profile.option_scope,
        OptionScopePolicy::AllArguments
    );
    let explicit = caushell_profile::load_command_profile_from_str(&format!(
        "{prefix}option_scope: leading_options\nforms: [{{id: normal}}]\n"
    ))
    .unwrap();
    assert_eq!(explicit.option_scope, OptionScopePolicy::LeadingOptions);
    for invalid in [
        "option_scope: misspelled\nforms: [{id: normal}]\n",
        "option_scope: leading_options\nforms: [{id: normal}]\nmodifiers: [{id: input, matcher: {kind: any_flag, flags: ['-p']}, parameters: [{name: value, semantic: {kind: plain_value}, binding: {kind: next_positional}}]}]\n",
        "option_scope: leading_options\nforms: [{id: normal, parameters: [{name: value, semantic: {kind: plain_value}, binding: {kind: following_flag, flag: '-x', operand_mode: next_arg}}]}]\n",
        "option_scope: leading_options\nforms: [{id: normal}]\nmodifiers: [{id: a, matcher: {kind: any_flag, flags: ['-p']}, parameters: [{name: value, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}}]}, {id: b, matcher: {kind: any_flag, flags: ['-p']}, parameters: [{name: other, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: inline_only}}]}]\n",
    ] {
        assert!(
            caushell_profile::load_command_profile_from_str(&format!("{prefix}{invalid}")).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn legacy_all_argument_profiles_still_accept_options_after_operands() {
    let registry = caushell_profile::ProfileRegistry::built_in().unwrap();
    let profile = registry.lookup("cp").profile.unwrap();
    assert_eq!(profile.option_scope, OptionScopePolicy::AllArguments);
    let result = bound(profile, "cp source.txt -f destination.txt");
    assert!(
        result
            .applied_modifiers
            .iter()
            .any(|id| id.as_str() == "force")
    );
    assert_eq!(values(&result, "source_paths"), ["source.txt"]);
    assert_eq!(values(&result, "destination_path"), ["destination.txt"]);
}

#[test]
fn optional_long_signal_arguments_do_not_consume_the_child_command() {
    let registry = caushell_profile::ProfileRegistry::built_in().unwrap();
    let profile = registry.lookup("env").profile.unwrap();
    for (option, parameter) in [
        ("--block-signal", "blocked_signals"),
        ("--default-signal", "defaulted_signals"),
        ("--ignore-signal", "ignored_signals"),
    ] {
        for suffix in ["", "=PIPE", "="] {
            let command = format!("env {option}{suffix} rm -f /etc/target");
            let result = bound(profile, &command);
            assert_eq!(values(&result, "wrapped_command"), ["rm"]);
            assert_eq!(values(&result, "wrapped_args"), ["-f", "/etc/target"]);
            assert_eq!(
                values(&result, parameter),
                if suffix.is_empty() {
                    vec![]
                } else {
                    vec![&suffix[1..]]
                }
            );
        }
    }
}

#[test]
fn partial_binding_retains_known_cluster_members_before_unknown_arity() {
    let registry = caushell_profile::ProfileRegistry::built_in().unwrap();
    let parsed = parse_command("sshpass -vx mystery ssh -p 22 host", ShellKind::Bash).unwrap();
    match caushell_profile::resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        caushell_profile::ResolveInvocationResult::SelectionError {
            partial_bound: Some(partial),
            ..
        } => {
            assert!(
                partial
                    .applied_modifiers
                    .iter()
                    .any(|id| id.as_str() == "verbose")
            );
            assert!(caushell_profile::collect_dispatch_command_candidates(&partial).is_empty());
        }
        result => panic!("{result:?}"),
    }
}

#[test]
fn terminators_after_the_option_boundary_are_literal_operands() {
    let registry = caushell_profile::ProfileRegistry::built_in().unwrap();
    for (name, command) in [
        ("env", "env A=value -- rm -f /etc/target"),
        ("timeout", "timeout 2s -- rm -f /etc/target"),
    ] {
        let result = bound(registry.lookup(name).profile.unwrap(), command);
        assert_eq!(values(&result, "wrapped_command"), ["--"], "{command}");
        assert_eq!(values(&result, "wrapped_args"), ["rm", "-f", "/etc/target"]);
    }
    // No command-specific knowledge: the first operand is consumed by the
    // form, while the option-looking next operand is data rather than a flag.
    let mut profile = wrapper();
    profile.forms[0].parameters.insert(
        0,
        Parameter::new(
            "first",
            SemanticType::PlainValue,
            BindingSpec::NextPositional,
        ),
    );
    let result = bound(&profile, "arbitrary-wrapper first -p value --help");
    assert_eq!(values(&result, "first"), ["first"]);
    assert_eq!(values(&result, "command"), ["-p"]);
    assert_eq!(values(&result, "argv"), ["value", "--help"]);
    assert!(values(&result, "password").is_empty());
}

#[test]
fn positional_bindings_after_dashdash_use_only_the_owned_terminator() {
    let mut profile = wrapper();
    profile.forms[0].parameters[0].binding = BindingSpec::NextPositionalAfterDashDash;
    let result = bound(&profile, "arbitrary-wrapper -- ssh -- -p 22");
    assert_eq!(values(&result, "command"), ["ssh"]);
    assert_eq!(values(&result, "argv"), ["--", "-p", "22"]);

    profile.forms[0].parameters[1].binding = BindingSpec::RemainingPositionalsAfterDashDash;
    let result = bound(&profile, "arbitrary-wrapper -- ssh -- -p 22");
    assert_eq!(values(&result, "command"), ["ssh"]);
    assert_eq!(values(&result, "argv"), ["--", "-p", "22"]);
}

#[test]
fn subcommand_option_failure_retains_confirmed_parent_and_node_effects() {
    let mut node_profile = wrapper();
    node_profile
        .modifiers
        .iter_mut()
        .find(|modifier| modifier.id.as_str() == "file")
        .unwrap()
        .effects
        .push(
            caushell_profile::Effect::new(caushell_profile::EffectKind::ReadPath).for_slot("file"),
        );
    let mut profile = wrapper();
    profile.forms.clear();
    profile.subcommands = Some(caushell_profile::SubcommandTree {
        roots: vec![caushell_profile::SubcommandNode {
            name: "run".to_string(),
            aliases: vec![],
            forms: node_profile.forms,
            modifiers: node_profile.modifiers,
            option_scope: OptionScopePolicy::LeadingOptions,
            option_matching: Default::default(),
            children: vec![],
            default_behavior: None,
            extensions: Default::default(),
        }],
    });
    let registry = caushell_profile::ProfileRegistry::from_profiles(vec![profile]).unwrap();
    let parsed = parse_command(
        "arbitrary-wrapper -p ROOT run -f NODE -x mystery ssh -p 22 host",
        ShellKind::Bash,
    )
    .unwrap();
    match caushell_profile::resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        caushell_profile::ResolveInvocationResult::SelectionError {
            partial_bound: Some(partial),
            ..
        } => {
            assert_eq!(partial.subcommand_path, ["run"]);
            assert_eq!(values(&partial, "password"), ["ROOT"]);
            assert_eq!(values(&partial, "file"), ["NODE"]);
            assert!(
                partial
                    .effects
                    .iter()
                    .any(|effect| effect.kind == caushell_profile::EffectKind::ReadPath)
            );
            assert!(caushell_profile::collect_dispatch_command_candidates(&partial).is_empty());
        }
        result => panic!("{result:?}"),
    }
}
