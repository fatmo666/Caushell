//! Static acceptance for GTFOBins batch 30f group C. Embedded languages are never run.
use caushell_parse::parse_command;
use caushell_profile::{
    InvocationRuntimeContext, ProfileRegistry, ResolveInvocationResult,
    collect_dispatch_command_candidates, load_command_profile_from_str, resolve_invocation,
};
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 10] = [
    ("dc", include_str!("../profiles/dc.yaml")),
    ("gnuplot", include_str!("../profiles/gnuplot.yaml")),
    ("elvish", include_str!("../profiles/elvish.yaml")),
    ("dosbox", include_str!("../profiles/dosbox.yaml")),
    ("csvtool", include_str!("../profiles/csvtool.yaml")),
    ("facter", include_str!("../profiles/facter.yaml")),
    ("expect", include_str!("../profiles/expect.yaml")),
    ("csh", include_str!("../profiles/csh.yaml")),
    ("tcsh", include_str!("../profiles/tcsh.yaml")),
    ("fish", include_str!("../profiles/fish.yaml")),
];

fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        PROFILES
            .iter()
            .map(|(_, source)| load_command_profile_from_str(source).unwrap())
            .collect(),
    )
    .unwrap()
}

fn bind(command: &str) -> caushell_profile::BoundInvocation {
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

#[test]
fn all_profiles_load_and_gtfobins_forms_resolve() {
    for (name, source) in PROFILES {
        let profile =
            load_command_profile_from_str(source).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(profile.identity.canonical_name.as_str(), name);
        assert!(
            profile
                .extensions
                .contains_key("caushell.profile/source_research")
        );
        assert!(
            profile
                .extensions
                .contains_key("caushell.profile/known_limitations")
        );
    }
    for (command, expected_form) in [
        ("dc -e '!/bin/sh'", "evaluate_dc_program"),
        ("gnuplot -e 'system(\"/bin/sh 1>&0\")'", "evaluate_commands"),
        (
            "elvish -c 'print (slurp </tmp/project/input)'",
            "command_string",
        ),
        (
            "dosbox -c 'mount c /' -c 'type c:\\input'",
            "execute_dos_commands",
        ),
        (
            "csvtool trim t /tmp/project/input.csv",
            "trim_csv_to_stdout",
        ),
        (
            "csvtool trim t /tmp/project/input.csv -o /tmp/project/output.csv",
            "trim_csv_to_file",
        ),
        (
            "csvtool call '/bin/sh;false' /tmp/project/input.csv",
            "call_expression",
        ),
        (
            "facter --custom-dir=/tmp/project/facts x",
            "custom_facts_directory",
        ),
        ("expect -c 'spawn /bin/sh;interact'", "command_string"),
        ("expect /tmp/project/script.exp", "script_file"),
        ("csh -c 'echo DATA >/tmp/project/out' -b", "command_string"),
        ("tcsh -bc 'echo DATA >/tmp/project/out'", "command_string"),
        ("fish", "interactive_shell"),
    ] {
        let bound = bind(command);
        assert_eq!(
            bound.form_id.as_str(),
            expected_form,
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn non_bash_program_text_is_opaque_and_never_becomes_a_child_command() {
    for command in [
        "dc -e '!/bin/sh'",
        "gnuplot -e 'system(\"/bin/sh 1>&0\")'",
        "elvish -c 'print (slurp </tmp/project/input)'",
        "dosbox -c 'mount c /' -c 'type c:\\input'",
        "csvtool call '/bin/sh;false' /tmp/project/input.csv",
        "expect -c 'spawn /bin/sh;interact'",
        "csh -c 'echo DATA >/tmp/project/out'",
        "tcsh -c 'echo DATA >/tmp/project/out'",
        "fish",
    ] {
        let bound = bind(command);
        assert!(
            collect_dispatch_command_candidates(&bound).is_empty(),
            "{command}: {bound:#?}"
        );
    }
}

#[test]
fn real_host_file_references_remain_distinct_from_opaque_program_text() {
    let csv = bind("csvtool trim t /tmp/project/input.csv -o /tmp/project/output.csv");
    assert_eq!(csv.form_id.as_str(), "trim_csv_to_file");
    assert!(
        csv.effects
            .iter()
            .any(|effect| effect.kind == caushell_profile::EffectKind::ReadPath)
    );
    assert!(
        csv.effects
            .iter()
            .any(|effect| effect.kind == caushell_profile::EffectKind::WritePath)
    );

    let expect = bind("expect /tmp/project/script.exp");
    assert_eq!(expect.form_id.as_str(), "script_file");
    assert!(
        expect
            .effects
            .iter()
            .any(|effect| effect.kind == caushell_profile::EffectKind::ReadPath)
    );
    assert!(
        expect
            .effects
            .iter()
            .any(|effect| effect.kind == caushell_profile::EffectKind::ExecutePayload)
    );

    let dosbox = bind("dosbox -c 'mount c /' -c 'type c:\\input'");
    assert!(
        !dosbox
            .effects
            .iter()
            .any(|effect| effect.kind == caushell_profile::EffectKind::ReadPath)
    );
}

#[test]
fn tcsh_stays_distinct_from_csh_and_facter_targets_a_directory_not_a_fabricated_rb_file() {
    assert_eq!(
        bind("csh -c 'echo DATA >/tmp/project/out' -b")
            .form_id
            .as_str(),
        "command_string"
    );
    assert_eq!(
        bind("tcsh -bc 'echo DATA >/tmp/project/out'")
            .form_id
            .as_str(),
        "command_string"
    );
    let facter = bind("facter --custom-dir=/tmp/project/facts x");
    assert_eq!(facter.form_id.as_str(), "custom_facts_directory");
    assert!(
        facter
            .effects
            .iter()
            .any(|effect| effect.kind == caushell_profile::EffectKind::ReadPath)
    );
    assert!(
        facter
            .effects
            .iter()
            .any(|effect| effect.kind == caushell_profile::EffectKind::ExecutePayload)
    );
}
