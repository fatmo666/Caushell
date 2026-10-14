//! Shape proofs are opt-in; no shell evaluation or concrete filename guessing.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{RuntimeArgumentDomain, ShellKind};

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-filter-tool}
option_scope: leading_options
opaque_on_unresolved: true
forms:
  - id: files
    parameters:
      - name: files
        semantic: {kind: path, role: write}
        binding: {kind: positionals_not_prefixed, prefix: '-', except_literals: ['-']}
        cardinality: optional_many
        value_constraints: [{kind: exclude_literal, value: ''}]
    effects: [{kind: write_path, target: {kind: slot, name: files}}]
modifiers:
  - {id: switch, matcher: {kind: any_flag, flags: [-x]}}
  - id: value
    matcher: {kind: any_flag, flags: [-v]}
    parameters: [{name: value, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_one}]
"#;

fn profile() -> CommandProfile {
    load_command_profile_from_str(PROFILE).unwrap()
}
fn bind_projection(p: &CommandProfile, projected: &ProjectedInvocation) -> BoundInvocation {
    let selected = select_invocation(p, projected).unwrap();
    bind_invocation(p, projected, &selected)
}
fn bind(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    bind_projection(
        &profile(),
        &project_invocation(&parsed.commands[0], InvocationRuntimeContext::new()),
    )
}
fn slot(b: &BoundInvocation) -> &BoundParameter {
    b.bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "files")
        .unwrap()
}
fn values(b: &BoundInvocation) -> Vec<&str> {
    slot(b)
        .values
        .iter()
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.as_str(),
            _ => panic!("{v:?}"),
        })
        .collect()
}
fn files(b: &BoundInvocation) -> &[BoundValue] {
    b.bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "files")
        .map_or(&[], |p| p.values.as_slice())
}
fn native(kind: &str, domain: Option<RuntimeArgumentDomain>) -> ProjectedInvocation {
    let parsed = parse_command("arbitrary-filter-tool placeholder", ShellKind::Bash).unwrap();
    let mut p = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let arg = &mut p.args[0];
    arg.text.clear();
    arg.node_kind = kind.into();
    arg.quoted = true;
    arg.implicit_input_source = Some(caushell_types::ImplicitInputSource::DispatchOutput);
    arg.runtime_argument_domain = domain;
    p
}

#[test]
fn normalized_declaration_and_original_argv_are_preserved() {
    let p = profile();
    assert_eq!(
        p.forms[0].parameters[0].binding,
        BindingSpec::PositionalsNotPrefixed {
            prefix: "-".into(),
            except_literals: vec!["-".into()]
        }
    );
    let b = bind("arbitrary-filter-tool -x -v -- ./first '/absolute/spaced file' -");
    assert!(!b.operation_semantics_unresolved, "{b:#?}");
    assert_eq!(values(&b), ["./first", "/absolute/spaced file", "-"]);
    assert_eq!(slot(&b).values.len(), 3);
    assert!(b.applied_modifiers.iter().any(|m| m.as_str() == "switch"));
    let parsed = parse_command("arbitrary-filter-tool './first two'", ShellKind::Bash).unwrap();
    let proj = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let b = bind_projection(&p, &proj);
    assert!(matches!(&slot(&b).values[0],
        BoundValue::Argument {text, span, quoted, node_kind, binding_source: ArgumentBindingSource::Positional {kind: PositionalBindingSource::MatchingPositionals}, ..}
        if text == &proj.args[0].text && span == &proj.args[0].span && quoted == &proj.args[0].quoted && node_kind == &proj.args[0].node_kind));
}

#[test]
fn bounded_scalar_and_batch_domains_keep_source_scope_and_field_width() {
    for kind in ["runtime_scalar", "runtime_argument_list"] {
        for roots in [
            vec!["."],
            vec!["./one", "/opt/shared"],
            vec!["local", "/absolute"],
        ] {
            let domain = RuntimeArgumentDomain::PathSet {
                roots: roots.into_iter().map(String::from).collect(),
                may_escape: false,
            };
            let p = native(kind, Some(domain.clone()));
            let b = bind_projection(&profile(), &p);
            assert!(!b.operation_semantics_unresolved, "{kind}: {b:#?}");
            assert!(
                matches!(&slot(&b).values[..], [BoundValue::ImplicitInput {domain:Some(actual), origin:Some(origin), ..}]
                if actual == &domain && origin.span == p.args[0].span && origin.single_field == (kind == "runtime_scalar"))
            );
            assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
        }
    }
}

#[test]
fn unbounded_or_control_capable_domains_are_not_matched_as_empty_placeholders() {
    for domain in [
        None,
        Some(RuntimeArgumentDomain::Unbounded),
        Some(RuntimeArgumentDomain::PathSet {
            roots: vec![],
            may_escape: false,
        }),
        Some(RuntimeArgumentDomain::PathSet {
            roots: vec![".".into(), "-n".into()],
            may_escape: false,
        }),
        Some(RuntimeArgumentDomain::PathSet {
            roots: vec![".".into()],
            may_escape: true,
        }),
    ] {
        for kind in [
            "runtime_scalar",
            "runtime_argument_list",
            "xargs_input_item",
        ] {
            let b = bind_projection(&profile(), &native(kind, domain.clone()));
            assert!(files(&b).is_empty(), "{kind} {domain:?}: {b:#?}");
            assert!(b.operation_semantics_unresolved, "{b:#?}");
            assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
        }
    }
}

#[test]
fn every_shell_field_must_exclude_the_control_prefix() {
    for c in [
        "arbitrary-filter-tool \"$UNKNOWN\"",
        "arbitrary-filter-tool ./first $UNKNOWN",
        "arbitrary-filter-tool ./first $(printf '%s' unknown)",
        "arbitrary-filter-tool ./first *.txt",
        "arbitrary-filter-tool ./first --help",
        "arbitrary-filter-tool ./first ''",
    ] {
        let b = bind(c);
        assert!(b.operation_semantics_unresolved, "{c}: {b:#?}");
    }
    for c in [
        "arbitrary-filter-tool \"./$UNKNOWN\"",
        "arbitrary-filter-tool ./*.txt",
        "arbitrary-filter-tool ./first /absolute/*.txt",
    ] {
        let b = bind(c);
        assert!(!b.operation_semantics_unresolved, "{c}: {b:#?}");
        assert!(!slot(&b).values.is_empty());
    }
    // A lexical prefix before an unquoted expansion does not protect later
    // split fields; the existing field query must remain authoritative.
    let b = bind("arbitrary-filter-tool ./prefix$UNKNOWN");
    assert!(b.operation_semantics_unresolved);
}

#[test]
fn exact_exceptions_and_constraints_do_not_widen_unknown_values() {
    let b = bind("arbitrary-filter-tool -");
    assert!(!b.operation_semantics_unresolved);
    let mut p = profile();
    p.forms[0].parameters[0]
        .value_constraints
        .push(ValueConstraint::ExcludeLiteral("./blocked".into()));
    let b = bind_projection(
        &p,
        &native(
            "runtime_argument_list",
            Some(RuntimeArgumentDomain::PathSet {
                roots: vec![".".into()],
                may_escape: false,
            }),
        ),
    );
    assert!(files(&b).is_empty());
    assert!(b.operation_semantics_unresolved);
    let parsed = parse_command("arbitrary-filter-tool ./allowed", ShellKind::Bash).unwrap();
    let b = bind_projection(
        &p,
        &project_invocation(&parsed.commands[0], InvocationRuntimeContext::new()),
    );
    assert!(!b.operation_semantics_unresolved);
}

#[test]
fn malformed_declarations_fail_at_load_time() {
    for changed in [
        PROFILE.replace("prefix: '-'", "prefix: ''"),
        PROFILE.replace("except_literals: ['-']", "except_literals: ['-', '-']"),
        PROFILE.replace("except_literals: ['-']", "except_literals: ['ordinary']"),
        PROFILE.replace("prefix: '-'", "prefix: \"\\0\""),
    ] {
        assert!(load_command_profile_from_str(&changed).is_err());
    }
}

#[test]
fn literal_regex_bindings_retain_their_previous_known_value_contract() {
    let p = load_command_profile_from_str(&PROFILE.replace(
        "kind: positionals_not_prefixed, prefix: '-', except_literals: ['-']",
        "kind: positionals_matching, matcher: {kind: regex_pattern, pattern: '^([^-].*|-)$'}",
    ))
    .unwrap();
    let b = bind_projection(
        &p,
        &native(
            "runtime_scalar",
            Some(RuntimeArgumentDomain::PathSet {
                roots: vec![".".into()],
                may_escape: false,
            }),
        ),
    );
    assert!(files(&b).is_empty());
    assert!(b.operation_semantics_unresolved);
}
