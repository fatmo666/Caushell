use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;
fn resolve(source: &str) -> BoundInvocation {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r.bound,
        ResolveInvocationArtifactResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => bound,
        other => panic!("{source}: {other:#?}"),
    }
}
#[test]
fn default_and_explicit_show_preserve_query_option_ownership() {
    for source in [
        "git reflog",
        "git reflog --date=iso",
        "git reflog HEAD",
        "git reflog show --date relative HEAD",
        "git reflog --oneline -1234 HEAD",
        "git --no-pager reflog show --max-count=12 --date=iso refs/heads/topic",
        "git reflog show --since yesterday --until today HEAD",
    ] {
        let r = resolve(source);
        assert!(!r.operation_semantics_unresolved, "{source}: {r:#?}");
        assert!(r.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
        assert!(!r.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::WritePath | EffectKind::DeletePath | EffectKind::ExecuteHook
        )));
        assert!(r.stream_contract.is_some());
    }
}
#[test]
fn history_pager_is_separate_and_global_option_order_is_preserved() {
    for source in ["git reflog", "git reflog show HEAD"] {
        assert!(
            resolve(source)
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
        );
    }
    for source in ["git --no-pager reflog", "git -P reflog show HEAD"] {
        assert!(
            !resolve(source)
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
        );
    }
    assert!(
        resolve("git --no-pager --paginate reflog")
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
    );
    assert!(
        !resolve("git --paginate --no-pager reflog")
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
    );
}
#[test]
fn list_and_exists_are_distinct_read_only_queries() {
    for source in ["git reflog list", "git reflog exists refs/heads/topic"] {
        let r = resolve(source);
        assert!(!r.operation_semantics_unresolved, "{source}: {r:#?}");
        assert!(r.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
        assert!(!r.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::WritePath
                | EffectKind::DeletePath
                | EffectKind::OpenInteractiveEscapeSurface
        )));
    }
}
#[test]
fn mutations_cannot_fall_through_to_the_default_query() {
    for source in [
        "git reflog delete HEAD@{0}",
        "git reflog drop refs/heads/topic",
        "git reflog expire --expire=now --all",
        "git reflog delete --dry-run HEAD@{0}",
        "git reflog delete --unknown HEAD@{0}",
    ] {
        let r = resolve(source);
        assert!(r.operation_semantics_unresolved, "{source}: {r:#?}");
        assert!(
            r.effects.iter().any(|e| e.kind == EffectKind::DeletePath),
            "{source}: {r:#?}"
        );
    }
    let r = resolve("git reflog write refs/heads/topic deadbeef cafebabe message");
    assert!(r.operation_semantics_unresolved);
    assert!(r.effects.iter().any(|e| e.kind == EffectKind::WritePath));
}
#[test]
fn unknown_options_and_executable_helpers_remain_unresolved() {
    for source in [
        "git reflog --unknown",
        "git reflog show --output=/outside/log",
        "git reflog --ext-diff",
        "git reflog --date",
        "git reflog show --date=\"$UNKNOWN\"",
        "git reflog --no-pager",
        "git reflog -n",
        "git reflog show --max-count=bad",
        "git reflog HEAD --output=/outside/log",
    ] {
        assert!(resolve(source).operation_semantics_unresolved, "{source}");
    }
}
