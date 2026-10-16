//! Native content selection is command-independent and never samples unknown bytes.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ImplicitInputSource, RuntimeArgumentDomain, ShellKind};

fn selection(prefix: &str, suffix: &str, pattern: &str) -> Result<String, BindError> {
    let profile = load_command_profile_from_str(&format!(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: semantic-fixture}}
option_scope: permuted_options
forms:
  - id: special
    selector: &special {{kind: has_positional_at_or_after_matching, index: 0, matcher: {{kind: regex_pattern, pattern: '{pattern}'}}}}
    parameters: &args [{{name: values, semantic: {{kind: plain_value}}, binding: {{kind: remaining_positionals}}, cardinality: optional_many}}]
  - id: ordinary
    selector: {{kind: not, item: *special}}
    parameters: *args
"#)).unwrap();
    let parsed = parse_command("semantic-fixture placeholder", ShellKind::Bash).unwrap();
    let mut p = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let arg = &mut p.args[0];
    arg.text.clear();
    arg.node_kind = "runtime_scalar".into();
    arg.implicit_input_source = Some(ImplicitInputSource::StdinData);
    arg.runtime_argument_domain = Some(RuntimeArgumentDomain::TextTemplate {
        prefix: prefix.into(),
        suffix: suffix.into(),
    });
    let scoped = select_invocation(&profile, &p).map(|s| s.form.id.as_str().to_owned());
    let public = select_form(&profile, &p.shape()).map(|form| form.id.as_str().to_owned());
    assert_eq!(
        scoped.as_ref().map_err(|_| ()),
        public.as_ref().map_err(|_| ())
    );
    scoped
}

#[test]
fn native_prefixes_select_only_a_proven_operation() {
    assert_eq!(selection("safe:", "", "^[^s]").unwrap(), "ordinary");
    assert_eq!(selection("mutate:", "", "^[^s]").unwrap(), "special");
    assert_eq!(selection("read:", "", "^read:").unwrap(), "special");
    for (prefix, suffix, pattern) in [
        ("read:", "", "^read:$"),
        ("", "read:", "^read:"),
        ("r", "", "^read:"),
        ("read:", "", "read:"),
    ] {
        assert!(
            selection(prefix, suffix, pattern).is_err(),
            "{prefix} {suffix} {pattern}"
        );
    }
}

#[test]
fn unknown_subcommands_cannot_fall_back_to_a_readonly_root_form() {
    let profile = load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: semantic-fixture}
option_scope: permuted_options
forms:
  - id: inspect_root
    parameters: [{name: values, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}]
subcommands:
  roots:
    - name: modify
      aliases: [change]
      forms: [{id: mutate}]
"#).unwrap();
    for (prefix, suffix, known) in [
        ("mod", "", false),
        ("cha", "", false),
        ("path/", "", true),
        ("", "/file", true),
    ] {
        let parsed = parse_command("semantic-fixture placeholder", ShellKind::Bash).unwrap();
        let mut p = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        p.args[0].text.clear();
        p.args[0].node_kind = "runtime_scalar".into();
        p.args[0].implicit_input_source = Some(ImplicitInputSource::StdinData);
        p.args[0].runtime_argument_domain = Some(RuntimeArgumentDomain::TextTemplate {
            prefix: prefix.into(),
            suffix: suffix.into(),
        });
        assert_eq!(
            select_invocation(&profile, &p).is_ok(),
            known,
            "{prefix} {suffix}"
        );
    }
}
