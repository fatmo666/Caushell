use caushell_parse::parse_command;
use caushell_profile::{
    DispatchCommandSource, DispatchStringSyntax, EffectKind, EffectTarget,
    InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult, SessionBindings,
    load_command_profile_from_str, resolve_invocation_artifact_with_bindings,
};
use caushell_types::ShellKind;

#[test]
fn empty_native_template_retains_its_declared_dispatch_without_a_name_special_case() {
    let source = include_str!("../profiles/parallel.yaml")
        .replace("canonical_name: parallel", "canonical_name: arbitrary_jobs");
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(&source).unwrap()])
            .unwrap();
    let parsed = parse_command("arbitrary_jobs", ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(resolved) =
        resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
            &SessionBindings::new(),
        )
    else {
        panic!("the declared native form must resolve");
    };
    assert!(resolved.bound.effects.iter().any(|effect| {
        effect.kind == EffectKind::DispatchCommand && matches!(&effect.target,
            EffectTarget::Dispatch(target) if matches!(&target.command,
                DispatchCommandSource::CommandString { syntax: DispatchStringSyntax::GnuParallel, .. }))
    }));
}
