use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;
fn registry() -> &'static ProfileRegistry {
    static R: OnceLock<ProfileRegistry> = OnceLock::new(); R.get_or_init(|| ProfileRegistry::built_in().unwrap())
}
fn resolve(command: &str, r: &ProfileRegistry) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(r, &parsed.commands[0], InvocationRuntimeContext::new(), &SessionBindings::new()) {
        ResolveInvocationArtifactResult::Resolved(r) => r.bound, r => panic!("{command}: {r:#?}"),
    }
}
fn guarded(command: &str) -> bool {
    let parsed=parse_command(command,ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(registry(),&parsed.commands[0],InvocationRuntimeContext::new(),&SessionBindings::new()) {
        ResolveInvocationArtifactResult::Resolved(r)=>r.bound.operation_semantics_unresolved || !r.bound.residuals.is_empty(),
        ResolveInvocationArtifactResult::SelectionError {..}=>true,
        other=>panic!("{other:#?}"),
    }
}
#[test]
fn network_capability_is_distinct_from_data_reads_and_round_trips_as_a_set() {
    let network: NativeArgvEffectEnvelope = serde_json::from_value(serde_json::json!(["network_query"])).unwrap();
    let effect = Effect::new(EffectKind::NetworkEndpoint).for_slot("query");
    assert!(native_effect_contract_allows_effect(network, &effect));
    for other in [NativeArgvEffectEnvelope::DataOnly, NativeArgvEffectEnvelope::ContentRead, NativeArgvEffectEnvelope::MetadataQuery] {
        assert!(!native_effect_contract_allows_effect(other, &effect));
    }
    for kind in [EffectKind::ReadPath, EffectKind::WritePath, EffectKind::ExecutePayload, EffectKind::DispatchCommand] {
        assert!(!native_effect_contract_allows_effect(network, &Effect::new(kind)));
    }
    assert_eq!(serde_json::to_value(network).unwrap(), serde_json::json!(["network_query"]));
    assert!(serde_json::from_value::<NativeArgvEffectEnvelope>(serde_json::json!(["network_query","network_query"])).is_err());
    let proof=caushell_types::NativeInputEffectEvidence {node_id:"n".into(),producer_node_id:"p".into(),child_node_ids:vec![],observation_gap:"unknown records".into(),effect_envelope:Some(network),bound_effects:None,control_envelope:true};
    let wire=serde_json::to_value(&proof).unwrap();assert!(wire.get("effect_envelope").is_none());assert_eq!(wire["effect_capabilities"],serde_json::json!(["network_query"]));
    assert_eq!(serde_json::from_value::<caushell_types::NativeInputEffectEvidence>(wire).unwrap(),proof);
}
#[test]
fn symbolic_queries_keep_network_inputs_and_never_certify_output_or_local_routing() {
    for text in ["host example.test", "host $(hostname)", "host \"$(hostname)\"", "host -t A $(hostname)"] {
        let r = resolve(text, registry());
        assert!(!r.operation_semantics_unresolved && r.residuals.is_empty(), "{text}: {r:#?}");
        assert!(r.effects.iter().any(|e| e.kind == EffectKind::NetworkEndpoint));
        assert!(r.stdout_records.is_none() && r.stdout_scalar.is_none() && r.stdout_growth.is_none());
        for p in r.bound_parameters.iter().filter(|p| matches!(p.semantic, SemanticType::Endpoint(_))) {
            assert!(p.semantic_values().all(|v| matches!(v, SemanticValueRef::Projected { value: ProjectedSemanticValue { resolution: SemanticValueResolution::Unknown(_), .. }, .. })), "{p:#?}");
        }
    }
}
#[test]
fn closure_is_generic_and_rejects_every_hidden_effect_or_configuration() {
    let p = registry().lookup("host").profile.unwrap().clone(); let contract = p.native_argv_effect_envelope.unwrap();
    let mut renamed = p.clone(); renamed.identity.canonical_name = CommandName::new("fixture_dns"); renamed.identity.aliases.clear();
    let r = resolve("fixture_dns $(hostname)", &ProfileRegistry::from_profiles(vec![renamed]).unwrap());
    assert!(!r.operation_semantics_unresolved && r.residuals.is_empty());
    for kind in [EffectKind::ReadPath, EffectKind::WritePath, EffectKind::ExecutePayload, EffectKind::DispatchCommand] {
        let mut bad = p.clone(); bad.forms[0].effects.push(Effect::new(kind)); assert!(!native_effect_contract_is_closed(&bad, contract));
    }
    let mut bad=p.clone();bad.forms[0].operation_semantics_unresolved=true;assert!(!native_effect_contract_is_closed(&bad,contract));
    let mut bad=p.clone();bad.native_configuration=Some(NativeConfigurationSyntax::Pip25_3Linux);assert!(!native_effect_contract_is_closed(&bad,contract));
}
#[test]
fn unknown_literal_controls_and_controls_after_uncertain_fields_stay_unresolved() {
    for text in ["host --unreviewed x", "host $(hostname) -t A", "host $(hostname) +unreviewed"] {
        assert!(guarded(text),"{text}");
    }
    let r=resolve("nslookup $(hostname)",registry());assert!(r.operation_semantics_unresolved || !r.residuals.is_empty());
}
#[test]
fn agrep_finite_modes_keep_input_files_and_pattern_files_as_real_reads() {
    for text in ["agrep -2 -il Subject mail.txt", "agrep -dEOE grep", "agrep -f patterns.txt mail.txt"] {
        let r=resolve(text,registry());assert!(!r.operation_semantics_unresolved && r.residuals.is_empty(),"{text}: {r:#?}");
        assert!(r.native_argv_effect_envelope.is_none()); assert!(r.stdout_records.is_none() && r.stdout_scalar.is_none());
    }
    let r=resolve("agrep -f .env mail.txt",registry());
    assert!(r.effects.iter().any(|e|e.kind==EffectKind::ReadPath && matches!(&e.target,EffectTarget::Slot(s) if s.as_str()=="pattern_files")));
    assert!(r.bound_parameters.iter().find(|p|p.name.as_str()=="pattern_files").unwrap().values.iter().any(|v|matches!(v,BoundValue::Argument{text,..} if text==".env")));
    assert!(guarded("agrep -H /unobserved pattern file"));
}
