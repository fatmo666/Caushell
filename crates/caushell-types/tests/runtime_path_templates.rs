use caushell_types::RuntimeArgumentDomain;

fn paths() -> RuntimeArgumentDomain {
    RuntimeArgumentDomain::PathSet {
        roots: vec![".".into(), "src".into()],
        may_escape: true,
    }
}

#[test]
fn single_replacement_keeps_origin_and_affixes_without_shell_evaluation() {
    assert_eq!(paths().substitute_into("{}", "{}"), paths());
    let template = paths().substitute_into("dest/{}.bak", "{}");
    assert_eq!(
        template,
        RuntimeArgumentDomain::PathTemplate {
            roots: vec![".".into(), "src".into()],
            may_escape: true,
            prefix: "dest/".into(),
            suffix: ".bak".into(),
        }
    );
    assert_eq!(
        template.substitute_into("copy/%/index", "%"),
        RuntimeArgumentDomain::PathTemplate {
            roots: vec![".".into(), "src".into()],
            may_escape: true,
            prefix: "copy/dest/".into(),
            suffix: ".bak/index".into(),
        }
    );
}

#[test]
fn unsupported_templates_and_unknown_inputs_never_gain_a_path_domain() {
    for (text, token) in [("{}{}", "{}"), ("prefix", "{}"), ("{}", "")] {
        assert_eq!(
            paths().substitute_into(text, token),
            RuntimeArgumentDomain::Unbounded
        );
    }
    assert_eq!(
        paths().substitute_into(&format!("{}{{}}", "x".repeat(4097)), "{}"),
        RuntimeArgumentDomain::Unbounded
    );
    assert_eq!(
        RuntimeArgumentDomain::Unbounded.substitute_into("/tmp/copy/{}", "{}"),
        RuntimeArgumentDomain::Unbounded
    );
    let inner = paths().substitute_into(&format!("{}{{}}", "x".repeat(3000)), "{}");
    assert_eq!(
        inner.substitute_into(&format!("{}{{}}", "y".repeat(1500)), "{}"),
        RuntimeArgumentDomain::Unbounded
    );
}

#[test]
fn new_and_existing_domains_round_trip_through_snapshot_json() {
    for domain in [
        paths(),
        paths().substitute_into("{}.$HOME*", "{}"),
        RuntimeArgumentDomain::Unbounded,
    ] {
        let json = serde_json::to_string(&domain).unwrap();
        assert_eq!(
            serde_json::from_str::<RuntimeArgumentDomain>(&json).unwrap(),
            domain
        );
    }
    let old_json = r#"{"kind":"path_set","roots":["."],"may_escape":false}"#;
    assert!(matches!(
        serde_json::from_str::<RuntimeArgumentDomain>(old_json).unwrap(),
        RuntimeArgumentDomain::PathSet { .. }
    ));
}
