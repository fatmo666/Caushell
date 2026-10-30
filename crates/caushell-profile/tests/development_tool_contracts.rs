use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;
fn bound(s: &str) -> Option<BoundInvocation> {
    static REG: OnceLock<ProfileRegistry> = OnceLock::new();
    let p = parse_command(s, ShellKind::Bash).unwrap();
    match resolve_invocation(
        REG.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &p.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => Some(r.bound),
        _ => None,
    }
}
fn resolve(s: &str) -> Option<BoundInvocation> {
    bound(s).filter(|b| !b.operation_semantics_unresolved)
}
#[test]
fn read_queries_do_not_borrow_mutator_authority() {
    for c in [
        "pip --disable-pip-version-check list",
        "pip --disable-pip-version-check list --format=json --path /opt/packages",
        "pip config list",
        "pip config get global.index-url",
        "pip --disable-pip-version-check show --files package",
    ] {
        let b = resolve(c).unwrap_or_else(|| panic!("{c}"));
        assert!(
            !b.effects.iter().any(|e| matches!(
                e.kind,
                EffectKind::WritePath | EffectKind::ExecutePayload | EffectKind::DispatchCommand
            )),
            "{c}: {b:?}"
        );
    }
    let default = resolve("pip list").unwrap();
    assert!(
        default
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    for c in [
        "pip config set global.index-url x",
        "pip list --outdated",
        "pip list --unknown",
        "R CMD arbitrary-script",
    ] {
        assert!(resolve(c).is_none(), "{c}");
    }
    let b = resolve("pip --log /outside/a.log list").unwrap();
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
}
#[test]
fn clone_options_retain_endpoint_and_destination_effects() {
    for c in [
        "git clone --depth 2 --branch release https://example.org/a.git /work/repo",
        "git clone -bdev --single-branch https://example.org/a.git /work/repo",
    ] {
        let b = bound(c).unwrap_or_else(|| panic!("{c}"));
        assert!(
            b.operation_semantics_unresolved,
            "native clone configuration remains unbounded"
        );
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
        assert!(
            b.effects
                .iter()
                .any(|e| e.kind == EffectKind::NetworkEndpoint)
        );
    }
    let implicit = bound("git clone --depth 2 https://example.org/a.git").unwrap();
    assert!(
        implicit
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath && matches!(e.target, EffectTarget::None))
    );
    assert!(resolve("git clone --depth 2 'ext::sh -c bad' /work/repo").is_none());
    assert!(resolve("git clone --depth https://example.org/a.git").is_none());
    assert!(resolve("git clone --upload-pack='sh -c bad' host:a /work/repo").is_none());
}

#[test]
fn configuration_query_does_not_claim_makefile_execution_is_fully_analyzed() {
    let b = bound("R CMD config BLAS_LIBS").unwrap();
    assert!(b.operation_semantics_unresolved);
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::LoadConfig));
    assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
}
#[test]
fn tex_models_cli_without_claiming_source_controlled_io_is_bounded() {
    let b =
        resolve("pdflatex -interaction=nonstopmode -output-directory=/work/pdf main.tex").unwrap();
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecutePayload)
    );
    assert!(
        b.effects.iter().any(|e| e.kind == EffectKind::WritePath
            && matches!(e.target, EffectTarget::ConfiguredPath(_)))
    );
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath && matches!(e.target, EffectTarget::None))
    );
}
#[test]
fn video_filters_are_whole_graph_effect_contracts() {
    for c in [
        "ffmpeg -i source.mp4 -vf \"select='not(mod(n,17))'\" -vsync vfr frame_%04d.png",
        "ffmpeg -i source.mp4 -filter:v scale=320:240,fps=2 output.mp4",
    ] {
        let b = resolve(c).unwrap_or_else(|| panic!("{c}"));
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    }
    for c in [
        "ffmpeg -i x -vf scale=2:2 -vf movie=secret out.mp4",
        "ffmpeg -i x -vf scale=2:2 -filter:v movie=secret out.mp4",
    ] {
        assert!(resolve(c).is_none(), "{c}");
    }
    for graph in [
        "movie=/etc/passwd",
        "scale=2:2,movie=secret",
        "drawtext=textfile=secret",
        "select=/expr=secret",
        "scale=2:2;hflip",
    ] {
        assert!(
            resolve(&format!("ffmpeg -i x -vf '{graph}' out.mp4")).is_none(),
            "{graph}"
        );
    }
}
