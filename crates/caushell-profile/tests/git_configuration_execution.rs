use caushell_profile::*;
#[test]
fn config_values_keep_native_quotes_comments_continuations_and_order() {
    let events=parse_git_configuration("[Core]\n FsMonitor = \"printf #SAFE\" # comment\n fsmonitor = false\n[include]\n path = next.inc\n[core]\n hooksPath = \"custom\\tpath\"\n").unwrap();
    assert_eq!(
        events[0],
        GitConfigEvent::Value {
            key: "core.fsmonitor".into(),
            value: Some("printf #SAFE".into())
        }
    );
    assert_eq!(
        events[1],
        GitConfigEvent::Value {
            key: "core.fsmonitor".into(),
            value: Some("false".into())
        }
    );
    assert_eq!(
        events[2],
        GitConfigEvent::Include {
            path: "next.inc".into(),
            conditional: false
        }
    );
    assert_eq!(
        events[3],
        GitConfigEvent::Value {
            key: "core.hookspath".into(),
            value: Some("custom\tpath".into())
        }
    );
    let e = parse_git_configuration("[core]\nfsmonitor = print\\\nf safe").unwrap();
    assert_eq!(
        e[0],
        GitConfigEvent::Value {
            key: "core.fsmonitor".into(),
            value: Some("printf safe".into())
        }
    );
}
#[test]
fn uncertain_lower_sources_can_only_be_replaced_by_a_later_same_key() {
    let mut state = GitConfiguration::default();
    assert!(state.is_complete());
    state.set("core.fsmonitor", Some("bad".into()), "low");
    state.unresolved("unknown include");
    state.set("core.hooksPath", Some("hooks".into()), "later");
    assert!(matches!(
        state.get("core.fsmonitor"),
        GitConfigValue::Unknown { .. }
    ));
    state.set("Core.Fsmonitor", Some("false".into()), "-c");
    assert!(
        !state.is_complete(),
        "one key override is not proof of complete configuration"
    );
    assert_eq!(
        state.get("core.fsmonitor"),
        GitConfigValue::Known {
            value: Some("false".into()),
            source: "-c".into()
        }
    );
}
#[test]
fn git_environment_parameters_are_data_not_shell_source() {
    assert_eq!(
        parse_git_config_parameters(
            "'core.fsmonitor=printf SAFE' 'core.hooksPath'='a b' 'core.fsmonitor'='false'"
        )
        .unwrap(),
        vec![
            ("core.fsmonitor".into(), Some("printf SAFE".into())),
            ("core.hooksPath".into(), Some("a b".into())),
            ("core.fsmonitor".into(), Some("false".into()))
        ]
    );
    for value in [
        "core.fsmonitor=foo",
        "$(printf unsafe)",
        "'unterminated",
        "'core.fsmonitor'=foo",
    ] {
        assert!(parse_git_config_parameters(value).is_err());
    }
}
#[test]
fn malformed_or_budget_exhausted_configuration_does_not_become_absent() {
    for value in [
        "[core\nfsmonitor=bad",
        "[core]\nfsmonitor=\"unfinished",
        "[core]\nfsmonitor=bad\\q",
        "fsmonitor=bad",
        "[core]\nfsmonitor=bad\0",
    ] {
        assert!(parse_git_configuration(value).is_err(), "{value:?}");
    }
    assert!(parse_git_configuration(&"a".repeat(65537)).is_err());
    assert!(matches!(
        parse_git_configuration("[includeIf \"onbranch:main\"]\npath=private").unwrap()[0],
        GitConfigEvent::Include {
            conditional: true,
            ..
        }
    ));
}
#[test]
fn native_boolean_modes_remain_distinct_from_executable_strings() {
    for value in [Some("false"), Some("0"), Some(""), Some("OFF")] {
        assert_eq!(git_boolean(value), Some(false));
    }
    for value in [None, Some("true"), Some("1"), Some("YeS")] {
        assert_eq!(git_boolean(value), Some(true));
    }
    assert_eq!(git_boolean(Some("./false")), None);
    assert_eq!(git_boolean(Some("printf SAFE")), None);
}
