use caushell_profile::*;

#[test]
fn entry_transfer_annotations_are_explicit_path_mutations_not_read_grants() {
    let source = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: mover}\nforms:\n - id: move\n   parameters: [{name: input, semantic: {kind: path, role: read}, binding: {kind: next_positional}, cardinality: required_one}, {name: output, semantic: {kind: path, role: write}, binding: {kind: next_positional}, cardinality: required_one}]\n   effects: [{kind: move_path, namespace_effect: entry_relocation, target: {kind: slot, name: input}}, {kind: write_path, namespace_effect: entry_relocation, target: {kind: slot, name: output}}]\n";
    let profile = load_command_profile_from_str(source).unwrap();
    for effect in &profile.forms[0].effects {
        assert_eq!(effect.filesystem_namespace_impact(), FilesystemNamespaceImpact::PathMutation);
        assert_eq!(serde_json::to_value(effect.namespace_effect).unwrap(), "entry_relocation");
    }
    for invalid in [source.replace("kind: move_path", "kind: read_path"),
        source.replace("kind: move_path", "kind: delete_path"),
        source.replace("namespace_effect: entry_relocation,", "namespace_effect: entry_relocation, path_scope: {kind: subtree},"),
        source.replace("target: {kind: slot, name: input}", "target: {kind: none}")] {
        assert!(load_command_profile_from_str(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn native_move_contracts_keep_backup_and_opaque_program_uncertainty() {
    for command in ["mv -b x y", "mv --exchange x y", "rename 'system(\"id\")' x"] {
        let parsed = caushell_parse::parse_command(command, caushell_types::ShellKind::Bash).unwrap();
        if let ResolveInvocationArtifactResult::Resolved(r) = resolve_invocation_artifact_with_bindings(
            &ProfileRegistry::built_in().unwrap(), &parsed.commands[0], InvocationRuntimeContext::new(), &SessionBindings::new()) {
            assert!(r.bound.operation_semantics_unresolved || !r.bound.residuals.is_empty()
                || r.bound.effects.iter().any(|e| e.kind == EffectKind::ExecutePayload), "{command}");
        }
    }
}
