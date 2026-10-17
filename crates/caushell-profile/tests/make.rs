//! Make argv modeling only; no make program or recipe is executed.
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn resolved(command: &str) -> ResolvedInvocationArtifact {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap());
    let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn eval_is_opaque_make_code_with_all_native_operand_spellings() {
    for command in [
        "make --eval='$(shell id)' .",
        "make --eval '$(shell id)'",
        "make -E'$(shell id)'",
        "gmake -sE '$(shell id)'",
        "make all --eval='$(shell id)'",
    ] {
        let r = resolved(command);
        assert!(
            !r.bound.operation_semantics_unresolved,
            "{command}: {:?}",
            r.bound.residuals
        );
        let candidates = collect_recursive_payload_candidates(&r.bound);
        assert_eq!(candidates.len(), 1, "{command}: {candidates:?}");
        assert_eq!(candidates[0].language, PayloadLanguage::Opaque);
        assert!(
            matches!(candidates[0].origin, RecursivePayloadOrigin::Parameter { ref slot } if slot.as_str() == "eval_code")
        );
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ExecutePayload)
        );
    }
    let r = resolved("make --eval='$(shell id)' -E '$(file >outside,data)'");
    let candidates = collect_recursive_payload_candidates(&r.bound);
    assert_eq!(candidates.len(), 1);
    assert!(
        matches!(&candidates[0].input, RecursivePayloadInput::ArgumentFragments {fragments} if fragments.len() == 2)
    );
}

#[test]
fn option_values_and_post_separator_text_are_not_eval_options() {
    for command in [
        "make -f --eval=x",
        "make --file=--eval=x",
        "make -- --eval=x",
        "make -o --eval=x",
        "make -W --eval=x",
    ] {
        let r = resolved(command);
        assert!(
            collect_recursive_payload_candidates(&r.bound).is_empty(),
            "{command}: {r:?}"
        );
        assert!(
            !r.bound
                .applied_modifiers
                .iter()
                .any(|id| id.as_str() == "eval")
        );
    }
}

#[test]
fn file_aliases_and_repetitions_retain_each_code_path() {
    let r = resolved("make -f first.mk --file second.mk --makefile=third.mk");
    let files = r
        .bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "config_paths")
        .unwrap();
    let values: Vec<_> = files
        .semantic_values()
        .filter_map(|v| match v {
            SemanticValueRef::Projected { value, .. } => match &value.resolution {
                SemanticValueResolution::Known(s) => Some(s.as_str()),
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(values, ["first.mk", "second.mk", "third.mk"]);
    assert!(
        r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::LoadInProcessCode)
    );
}

#[test]
fn stdin_files_and_changed_directories_do_not_invent_caller_paths() {
    let stdin = resolved("make -f - -f extra.mk");
    assert_eq!(stdin.bound.form_id.as_str(), "stdin_makefile");
    assert!(
        collect_recursive_payload_candidates(&stdin.bound)
            .iter()
            .any(|c| matches!(c.input, RecursivePayloadInput::ImplicitInput { .. }))
    );
    for c in ["make -C sub", "make -C / -C etc -f rules.mk"] {
        let r = resolved(c);
        assert!(r.bound.operation_semantics_unresolved);
        assert!(!r.bound.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::LoadConfig | EffectKind::LoadInProcessCode
        )));
    }
}

#[test]
fn immediate_shell_assignments_and_make_function_assignments_are_code() {
    for c in [
        "make 'X!='/bin/sh",
        "make 'X:=$(shell id)'",
        "make 'X=$(file >out,data)'",
        "make '$(shell id)=value'",
    ] {
        let r = resolved(c);
        assert!(
            collect_recursive_payload_candidates(&r.bound)
                .iter()
                .any(|c| c.language == PayloadLanguage::Opaque),
            "{c}: {r:?}"
        );
    }
    assert!(
        collect_recursive_payload_candidates(&resolved("make CFLAGS=-O2 X:=value").bound)
            .is_empty()
    );
}
