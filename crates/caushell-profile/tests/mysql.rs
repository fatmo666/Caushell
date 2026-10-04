//! Static MySQL argv contracts; submitted SQL/client commands are never run.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{DatabaseOperationKind, ShellKind};
use std::sync::OnceLock;

fn registry() -> &'static ProfileRegistry {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap())
}
fn result(command: &str) -> ResolveInvocationResult<'static> {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation(
        registry(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    )
}
fn clean(command: &str) -> BoundInvocation {
    let ResolveInvocationResult::Resolved(r) = result(command) else {
        panic!("{command}: {:?}", result(command));
    };
    assert!(r.bound.residuals.is_empty(), "{command}: {:?}", r.bound);
    assert!(
        !r.bound.operation_semantics_unresolved,
        "{command}: {:?}",
        r.bound
    );
    r.bound
}
fn values(b: &BoundInvocation, name: &str) -> Vec<String> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|v| match project_value(&ValueProjection::Identity, v) {
            Some(SemanticValueResolution::Known(s)) => s,
            other => panic!("{v:?}: {other:?}"),
        })
        .collect()
}
fn opaque(b: &BoundInvocation) {
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::DatabaseOperation
                && e.database_operation == Some(DatabaseOperationKind::Opaque)),
        "{b:?}"
    );
    assert!(
        !b.effects
            .iter()
            .any(|e| e.database_operation == Some(DatabaseOperationKind::Read))
    );
}
fn input_mode(command: &str) -> StreamInputMode {
    let ResolveInvocationResult::Resolved(r) = result(command) else {
        panic!("{command}");
    };
    r.selection.form.stream_contract.unwrap().stdin_mode
}

#[test]
fn registers_official_client_without_mariadb_alias() {
    for name in ["mysql", "/usr/bin/mysql"] {
        let p = registry().lookup(name).profile.unwrap();
        assert_eq!(p.primary_name(), "mysql");
        assert!(p.identity.aliases.is_empty());
        assert!(p.opaque_on_unresolved);
        assert_eq!(p.option_scope, OptionScopePolicy::PermutedOptions);
    }
    assert!(registry().lookup("mariadb").profile.is_none());
}
#[test]
fn sql_queries_and_mutations_have_one_deliberate_opaque_boundary() {
    for c in [
        "mysql -e 'SELECT 1;'",
        "mysql --execute='DROP TABLE lab;'",
        "mysql --safe-updates -e 'DELETE FROM lab WHERE id=1;'",
        "mysql --binary-mode --commands=OFF --system-command=OFF -e 'SELECT 1;'",
        "mysql -B --skip-system-command --skip-commands db",
    ] {
        opaque(&clean(c));
    }
}
#[test]
fn inline_protocol_is_mysql_not_a_bash_or_sqlite_payload() {
    let b = clean(
        "mysql db -e 'system rm -f /etc/example' --init-command='SELECT 1;' --init-command-add='SET @x=1;' -e 'source /etc/example.sql'",
    );
    assert_eq!(
        values(&b, "execute_protocol"),
        ["system rm -f /etc/example", "source /etc/example.sql"]
    );
    assert_eq!(values(&b, "initialization_sql"), ["SELECT 1;", "SET @x=1;"]);
    let candidates = collect_recursive_payload_candidates(&b);
    assert_eq!(candidates.len(), 2);
    for candidate in &candidates {
        assert_eq!(candidate.language, PayloadLanguage::MysqlCli);
        assert!(matches!(
            parse_recursive_payload_candidate(candidate),
            RecursivePayloadParseResult::UnsupportedLanguage { .. }
        ));
    }
}
#[test]
fn stdin_is_executable_mixed_protocol_but_inline_execution_ignores_it() {
    for c in [
        "mysql",
        "mysql -B db",
        "mysql --quick db",
        "mysql --binary-mode db",
    ] {
        let b = clean(c);
        assert_eq!(input_mode(c), StreamInputMode::PayloadOptional);
        assert!(
            b.effects
                .iter()
                .any(|e| e.kind == EffectKind::ExecutePayload
                    && matches!(e.target, EffectTarget::ImplicitInput(_)))
        );
        assert!(b.bound_implicit_inputs.iter().any(|i| matches!(
            i.semantic,
            SemanticType::Payload(PayloadSemantic {
                language: PayloadLanguage::MysqlCli,
                ..
            })
        )));
    }
    let b = clean("mysql -e 'SELECT 1;' db");
    assert_eq!(
        input_mode("mysql -e 'SELECT 1;' db"),
        StreamInputMode::Ignored
    );
    assert!(b.bound_implicit_inputs.is_empty());
}
#[test]
fn required_operands_own_flag_shaped_values_and_native_permuted_options() {
    let b =
        clean("mysql db -h --help -u --version -e 'SELECT 1;' -P3306 -BN -S/tmp/project/db.sock");
    assert_eq!(values(&b, "hosts"), ["--help"]);
    assert_eq!(values(&b, "connection_values"), ["--version", "3306"]);
    assert_eq!(values(&b, "database_names"), ["db"]);
    assert_eq!(values(&b, "sockets"), ["/tmp/project/db.sock"]);
    assert!(
        !b.applied_modifiers
            .contains(&ModifierId::new("information"))
    );
    opaque(&b);
    let b = clean("mysql -e -- --tee=/etc/log db");
    assert_eq!(values(&b, "execute_protocol"), ["--"]);
    assert_eq!(values(&b, "tee_outputs"), ["/etc/log"]);
}
#[test]
fn terminator_turns_option_looking_words_into_database_data() {
    let b = clean("mysql -- --help --tee=/etc/log");
    assert_eq!(values(&b, "database_names"), ["--help", "--tee=/etc/log"]);
    assert!(
        !b.applied_modifiers
            .contains(&ModifierId::new("information"))
    );
    assert!(values(&b, "tee_outputs").is_empty());
    opaque(&b);
}
#[test]
fn database_ids_and_localhost_socket_are_not_filesystem_write_targets() {
    let b =
        clean("mysql /etc/not-a-file -h 127.0.0.1 -D /etc/another-db -S db.sock -e 'SELECT 1;'");
    assert_eq!(values(&b, "database_names"), ["/etc/not-a-file"]);
    assert!(
        b.bound_parameters
            .iter()
            .filter(|p| ["database_names", "connection_values"].contains(&p.name.as_str()))
            .all(|p| p.semantic == SemanticType::PlainValue)
    );
    assert!(
        !b.effects
            .iter()
            .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::DeletePath))
    );
    opaque(&b);
}
#[test]
fn explicit_configuration_tls_and_plugin_inputs_remain_typed() {
    let b = clean(
        "mysql --defaults-file=/etc/my.cnf --defaults-extra-file=extra.cnf --ssl-ca=/etc/ca.pem --ssl-key=client.key --plugin-dir=plugins --default-auth=custom --ssl-session-data=session.txt -e 'SELECT 1;'",
    );
    assert_eq!(values(&b, "defaults_files"), ["/etc/my.cnf", "extra.cnf"]);
    assert_eq!(
        values(&b, "local_inputs"),
        ["/etc/ca.pem", "client.key", "session.txt"]
    );
    assert_eq!(values(&b, "plugin_directories"), ["plugins"]);
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::LoadInProcessCode)
    );
    assert!(!b.effects.iter().any(|e| e.kind == EffectKind::LoadConfig));
}
#[test]
fn tee_outputs_survive_batch_information_and_disable_flags() {
    for c in [
        "mysql --tee=/etc/log -B -e 'SELECT 1;'",
        "mysql --tee=/etc/log --help",
        "mysql --tee=/etc/log --skip-tee --version",
        "mysql --tee=/etc/log --tee=local --disable-tee --help",
    ] {
        let b = clean(c);
        assert!(values(&b, "tee_outputs").contains(&"/etc/log".into()));
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath
            && matches!(&e.target, EffectTarget::Slot(s) if s.as_str() == "tee_outputs")));
    }
}
#[test]
fn optional_long_values_and_bare_password_do_not_steal_database_or_options() {
    let b = clean("mysql --password --pager --commands db -p -e 'SELECT 1;'");
    assert!(values(&b, "passwords").is_empty());
    assert!(values(&b, "pager_commands").is_empty());
    assert!(values(&b, "boolean_controls").is_empty());
    assert_eq!(values(&b, "database_names"), ["db"]);
    assert_eq!(values(&b, "execute_protocol"), ["SELECT 1;"]);
    let b =
        clean("mysql --password=fixture --pager='cat > /etc/log' --commands=OFF db -e 'SELECT 1;'");
    assert_eq!(values(&b, "passwords"), ["fixture"]);
    assert_eq!(values(&b, "pager_commands"), ["cat > /etc/log"]);
    assert_eq!(values(&b, "boolean_controls"), ["OFF"]);
}
#[test]
fn history_is_only_a_possible_interactive_output_not_inline_or_batch_output() {
    let b = clean("mysql db");
    assert!(b.effects.iter().any(|e| matches!(&e.target, EffectTarget::ConfiguredPath(p) if p.environment.as_ref().is_some_and(|v| v.name == "MYSQL_HISTFILE"))));
    for c in ["mysql -B db", "mysql -q db", "mysql -e 'SELECT 1;' db"] {
        assert!(!clean(c).effects.iter().any(|e| matches!(&e.target, EffectTarget::ConfiguredPath(p) if p.environment.as_ref().is_some_and(|v| v.name == "MYSQL_HISTFILE"))));
    }
}
#[test]
fn unknown_options_abbreviations_and_malformed_operands_retain_database_fallback() {
    for c in [
        "mysql --future --help",
        "mysql --exec 'SELECT 1;'",
        "mysql --loose-tee=/etc/log --version",
        "mysql -e",
        "mysql --defaults-file config.cnf --help",
    ] {
        match result(c) {
            ResolveInvocationResult::SelectionError {
                partial_bound: Some(b),
                ..
            } => opaque(&b),
            ResolveInvocationResult::Resolved(r) if r.bound.operation_semantics_unresolved => {
                opaque(&r.bound)
            }
            other => panic!("{c}: expected unresolved semantics, got {other:?}"),
        }
    }
}

#[test]
fn position_proven_config_free_information_has_no_database_or_startup_effects() {
    for c in [
        "mysql --no-defaults --no-login-paths --help",
        "mysql --no-defaults --no-login-paths --version",
        "mysql --no-defaults --no-login-paths -?",
        "mysql --no-defaults --no-login-paths -I",
        "mysql --no-defaults --no-login-paths -V",
    ] {
        let b = clean(c);
        assert_eq!(b.form_id.as_str(), "information_config_free", "{c}");
        assert!(b.effects.is_empty(), "{c}: {b:?}");
        assert!(b.bound_implicit_inputs.is_empty());
        assert!(collect_recursive_payload_candidates(&b).is_empty());
        assert_eq!(input_mode(c), StreamInputMode::Ignored);
    }
}

#[test]
fn position_sensitive_prefix_and_mixed_information_are_not_certified_pure() {
    for c in [
        "mysql --no-login-paths --no-defaults --help",
        "mysql --help --no-defaults --no-login-paths",
        "mysql --no-defaults --help --no-login-paths",
        "mysql --no-defaults --no-login-paths --help --tee=/etc/log",
        "mysql --no-defaults --no-login-paths --help --debug",
        "mysql --no-defaults --no-login-paths --help --plugin-dir=plugins",
        "mysql --no-defaults --no-login-paths -e 'SELECT 1;' --help",
        "mysql --no-defaults --no-login-paths --help db",
    ] {
        opaque(&clean(c));
    }
}

#[test]
fn password_bare_and_cluster_attached_arity_matches_native_mysql() {
    let b = clean("mysql db -pfixture -qpsecond -p --password --password=third -e 'SELECT 1;'");
    assert_eq!(values(&b, "passwords"), ["fixture", "second", "third"]);
    assert_eq!(values(&b, "database_names"), ["db"]);
    let b = clean("mysql -pV -e 'SELECT 1;'");
    assert_eq!(values(&b, "passwords"), ["V"]);
    assert!(
        !b.applied_modifiers
            .contains(&ModifierId::new("information"))
    );
    opaque(&b);
    let b = clean("mysql -#d,fixture -e 'SELECT 1;'");
    assert_eq!(values(&b, "debug_controls"), ["d,fixture"]);
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
}

#[test]
fn pure_information_whitelist_covers_every_other_profile_modifier() {
    let p = registry().lookup("mysql").profile.unwrap();
    let SelectorExpr::All(items) = &p.forms[0].selector else {
        panic!("pure selector");
    };
    let SelectorExpr::Not(blocked) = items.last().unwrap() else {
        panic!("whitelist gate");
    };
    let SelectorExpr::Any(blocked) = blocked.as_ref() else {
        panic!("blocked modifiers");
    };
    let blocked: std::collections::BTreeSet<_> = blocked
        .iter()
        .map(|item| match item {
            SelectorExpr::Predicate(SelectorPredicate::HasModifier(id)) => id.as_str(),
            other => panic!("{other:?}"),
        })
        .collect();
    let expected = p
        .modifiers
        .iter()
        .map(|m| m.id.as_str())
        .filter(|id| !["information", "no_defaults", "no_login_paths"].contains(id))
        .collect();
    assert_eq!(
        blocked, expected,
        "Every new modifier needs explicit information-admission review"
    );
}
