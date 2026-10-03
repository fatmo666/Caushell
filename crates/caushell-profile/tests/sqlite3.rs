use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => {
            assert!(
                r.bound.residuals.is_empty(),
                "{command}: {:?}",
                r.bound.residuals
            );
            r.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}

fn opaque(bound: &BoundInvocation) -> bool {
    bound
        .effects
        .iter()
        .any(|e| e.kind == EffectKind::WritePath && e.target == EffectTarget::None)
}

#[test]
fn safe_flags_never_remove_unknown_sql_writes() {
    for command in [
        "sqlite3 --safe --noinit db.sqlite 'SELECT 1;'",
        "sqlite3 -safe -noinit :memory: 'SELECT 1;'",
        "sqlite3 db.sqlite 'CREATE TABLE t(x);' --safe --noinit --csv",
        "sqlite3 --safe --noinit --batch db.sqlite",
        "sqlite3 --safe --noinit --batch",
    ] {
        let bound = resolve(command);
        assert!(opaque(&bound), "{command}");
    }
    for command in [
        "sqlite3 db.sqlite 'SELECT 1;'",
        "sqlite3 --readonly db.sqlite 'SELECT 1;'",
        "sqlite3 --safe db.sqlite 'SELECT 1;'",
        "sqlite3 --noinit db.sqlite 'SELECT 1;'",
        "sqlite3 --safe --noinit db.sqlite",
        "sqlite3 --safe --noinit",
    ] {
        assert!(opaque(&resolve(command)), "{command}");
    }
}

#[test]
fn database_is_not_sql_and_potential_writes_remain() {
    let bound = resolve("sqlite3 --safe --noinit --readonly db.sqlite 'SELECT 1;' 'SELECT 2;'");
    assert!(bound.effects.iter().any(|e| e.kind == EffectKind::WritePath
        && matches!(&e.target, EffectTarget::Slot(s) if s.as_str()=="database_file")));
    assert!(bound.bound_parameters.iter().any(
        |p| p.name.as_str() == "database_file" && matches!(&p.semantic, SemanticType::Path(_))
    ));
    let sql = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "sql_inputs")
        .unwrap();
    assert_eq!(sql.values.len(), 2);
    assert!(matches!(
        sql.semantic,
        SemanticType::Payload(PayloadSemantic {
            language: PayloadLanguage::SqliteCli,
            ..
        })
    ));
}

#[test]
fn memory_does_not_become_a_disk_path() {
    for command in [
        "sqlite3 --safe --noinit :memory: 'SELECT 1;'",
        "sqlite3 --safe --noinit --batch",
    ] {
        let b = resolve(command);
        assert!(
            !b.bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "database_file" && !p.values.is_empty())
        );
    }
}

#[test]
fn startup_nonce_and_special_modes_do_not_gain_exemption() {
    for option in [
        "--cmd 'SELECT 1;'",
        "--init init.sql",
        "--nonce abc",
        "--vfs unix",
        "--append",
        "--zip",
        "--deserialize",
        "--unsafe-testing",
        "--interactive",
        "--memtrace",
        "--threadsafe 0",
        "--pagecache 4096 2",
        "--separator ,",
    ] {
        let c = format!("sqlite3 --safe --noinit {option} db.sqlite 'SELECT 1;'");
        assert!(opaque(&resolve(&c)), "{c}");
    }
}

#[test]
fn actual_cli_script_dispatch_and_uri_are_ambiguous() {
    for db in [
        "first.sql",
        "first.SQL",
        "first.txt",
        "first.TXT",
        "file:db.sqlite?mode=ro",
        "''",
    ] {
        let c = format!("sqlite3 --safe --noinit {db} /opt/actual.sqlite 'SELECT 1;'");
        assert!(opaque(&resolve(&c)), "{c}");
    }
    assert_eq!(
        resolve("sqlite3 --safe --noinit data.weird 'SELECT 1;'")
            .form_id
            .as_str(),
        "inline_without_startup"
    );
}

#[test]
fn unknown_archive_options_are_recorded_in_every_position() {
    for command in [
        "sqlite3 -Acr --safe --noinit archive.sqlite 'SELECT 1;'",
        "sqlite3 --safe -Acr --noinit archive.sqlite 'SELECT 1;'",
        "sqlite3 --safe --noinit archive.sqlite -Acr 'SELECT 1;'",
        "sqlite3 --safe --noinit archive.sqlite 'SELECT 1;' -Acr",
        "sqlite3 -Acr --noinit --version",
    ] {
        let bound = resolve(command);
        assert!(
            bound
                .bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "unrecognized_cli" && !p.values.is_empty()),
            "{command}: {bound:?}"
        );
    }
}

#[test]
fn flag_values_and_real_dashdash_do_not_enable_safe() {
    for command in [
        "sqlite3 --noinit --separator --safe db.sqlite 'SELECT 1;'",
        "sqlite3 --noinit -- db.sqlite --safe",
        "sqlite3 --safe=true --noinit db.sqlite 'SELECT 1;'",
        "sqlite3 -safex --noinit db.sqlite 'SELECT 1;'",
    ] {
        assert!(opaque(&resolve(command)), "{command}");
    }
}

#[test]
fn informational_calls_do_not_ignore_startup() {
    assert!(!opaque(&resolve("sqlite3 --noinit --version")));
    assert!(!opaque(&resolve("sqlite3 -noinit -help")));
    for command in [
        "sqlite3 --version",
        "sqlite3 --cmd 'SELECT 1;' --noinit --version",
        "sqlite3 --init init.sql --noinit --version",
    ] {
        assert!(opaque(&resolve(command)), "{command}");
    }
}

#[test]
fn sql_and_dot_commands_are_not_bash_subcalls() {
    let bound = resolve("sqlite3 --safe --noinit :memory: '.shell rm -f /opt/example'");
    let candidates = collect_recursive_payload_candidates(&bound);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].language, PayloadLanguage::SqliteCli);
    assert!(matches!(
        parse_recursive_payload_candidate(&candidates[0]),
        RecursivePayloadParseResult::UnsupportedLanguage { .. }
    ));
}

#[test]
fn two_operand_options_and_repetition_do_not_steal_database() {
    for command in [
        "sqlite3 --noinit --pagecache 4096 2 db.sqlite 'SELECT 1;'",
        "sqlite3 --noinit --lookaside 128 10 --pagecache 4096 2 db.sqlite 'SELECT 1;'",
        "sqlite3 --noinit --lookaside 128 10 --lookaside 256 20 db.sqlite 'SELECT 1;'",
        "sqlite3 --noinit --separator , --separator : db.sqlite 'SELECT 1;'",
    ] {
        let b = resolve(command);
        let db = b
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "database_file")
            .unwrap();
        assert!(
            matches!(&db.values[0], BoundValue::Argument {text,..} if text=="db.sqlite"),
            "{command}: {b:?}"
        );
    }
}

#[test]
fn stdin_is_ignored_when_sql_operands_are_present() {
    let inline = resolve("sqlite3 --noinit db.sqlite 'SELECT 1;'");
    assert!(inline.bound_implicit_inputs.is_empty());
    let stdin = resolve("sqlite3 --noinit db.sqlite");
    assert!(matches!(
        stdin.bound_implicit_inputs[0].semantic,
        SemanticType::Payload(PayloadSemantic {
            language: PayloadLanguage::SqliteCli,
            source: PayloadSource::Stdin,
            ..
        })
    ));
}
