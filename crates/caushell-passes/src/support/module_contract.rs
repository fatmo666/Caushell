//! Join registered CLI children with current, host-admitted loader evidence.
//! Language lookup/startup semantics belong to the supplying loader component.
use super::{bound_invocation, environment_default, graph_backed_execution_resolve_records};
use caushell_profile::{
    EffectKind, EnvironmentValueSource, ResolveInvocationArtifactResult, SemanticValueResolution,
};
use caushell_runner::RunnerContext;
use caushell_types::*;

pub(crate) fn module_contract_evidence(
    ctx: &RunnerContext,
    parent_id: &str,
) -> Vec<ModuleContractEvidence> {
    let records = graph_backed_execution_resolve_records(ctx);
    let Some(parent) = records
        .iter()
        .find(|r| r.source_node_id().0 == parent_id)
        .copied()
    else {
        return Vec::new();
    };
    let Some(bound) = bound_invocation(parent.result()) else {
        return Vec::new();
    };
    let projection = caushell_profile::collect_dispatch_command_projection(bound);
    let parent_record = ctx
        .execution_unit_resolve_records()
        .iter()
        .find(|r| r.source_node_id.0 == parent_id)
        .unwrap();
    let cwd = parent.cwd_options(ctx.request().shell_state_before.cwd());
    let binding = ctx
        .request()
        .shell_state_before
        .execution_frame
        .as_ref()
        .map(|f| f.binding.clone())
        .unwrap_or_else(|| {
            ExecutionFrameBinding::for_request(ctx.request(), "unobserved-executor")
        });
    projection.resolved.iter().filter_map(|candidate| {
        let runtime=candidate.module_runtime.as_ref()?;
        let invocation=ModuleInvocation{binding:binding.clone(),node_id:parent_id.into(),runtime:runtime.clone(),module:candidate.command.text.clone(),command:parent_record.rendered_command_text.clone(),cwd:match cwd.as_slice(){[Some(c)]=>c.to_string(),_=>String::new()}};
        let mut evidence=ModuleContractEvidence{invocation:invocation.clone(),identity_sha256:None,identity_verified:false,grant_id:None,gap:Some("module loader identity and CLI permission were not supplied by the owning host".into())};
        let child=ctx.execution_unit_resolve_records().iter().find(|r|r.parent_execution_node_id.0==parent_id && r.origin_kind==caushell_runner::ExecutionUnitOriginKind::Dispatch && r.origin_index==candidate.dispatch_index);
        if bound.operation_semantics_unresolved || !projection.unresolved.is_empty() || !matches!(child.map(|r|&r.result),Some(ResolveInvocationArtifactResult::Resolved(r)) if !r.bound.operation_semantics_unresolved && r.bound.residuals.is_empty()) || invocation.cwd.is_empty(){
            evidence.gap=Some("module invocation or registered CLI child is incomplete".into());return Some(evidence);
        }
        let Some(scope)=ctx.module_contract_scope() else{return Some(evidence)};
        evidence=scope.verify(&invocation,ctx.filesystem_view().as_ref());
        let Some(identity)=scope.identity(&invocation) else{return Some(evidence)};
        for (name,expected) in &identity.environment {
            let observed=match environment_default(&EnvironmentValueSource{name:name.clone(),empty_is_unset:false},Some(parent)) {
                None=>ShellEnvironmentValue::Absent,
                Some(SemanticValueResolution::Known(value))=>ShellEnvironmentValue::Present{value},
                _=>ShellEnvironmentValue::Unknown,
            };
            if observed!=*expected{evidence.identity_verified=false;evidence.grant_id=None;evidence.gap=Some(format!("module loader environment is changed or unknown: {name}"));return Some(evidence);}
        }
        // Another opaque execution or code loader may change import resolution
        // without a declared file effect. A CLI identity cannot cover it.
        let child_id=child.unwrap().source_node_id.0.as_str();
        let opaque=ctx.execution_unit_resolve_records().iter().any(|r| {
            if r.source_node_id.0==parent_id || r.source_node_id.0==child_id{return false;}
            let Some(b)=bound_invocation(&r.result) else{return true};
            b.operation_semantics_unresolved || b.effects.iter().any(|e|matches!(e.kind,EffectKind::ExecutePayload|EffectKind::SourceScriptIntoCurrentShell|EffectKind::LoadInProcessCode|EffectKind::ExecuteConfigDefinedTask))
        });
        let mutations=ctx.pending_mutations().iter().filter_map(|m|match m{caushell_runner::PendingMutation::AddPathTargetFact{fact,..} if fact.operation.is_mutation() && fact.source_node_id!=child_id=>Some(fact),_=>None});
        let mut changed=opaque;
        for fact in mutations {
            let roots=match &fact.resolution {
                SemanticResolution::Resolved{value:PathResolution::Concrete{path}}=>vec![path.as_str()],
                SemanticResolution::Resolved{value:PathResolution::BoundedPathSet{roots,may_escape:false}}=>roots.iter().map(String::as_str).collect(),
                SemanticResolution::NotApplicable{..}=>continue,
                _=>{changed=true;break;}
            };
            changed|=roots.iter().any(|root|identity.files.keys().chain(identity.namespace.iter().map(|o|&o.path)).chain(identity.directories.iter().map(|o|&o.path)).any(|path|caushell_query::path_is_within_root(path,root)||caushell_query::path_is_within_root(root,path)));
        }
        if changed{evidence.identity_verified=false;evidence.grant_id=None;evidence.gap=Some("another operation may invalidate the module loading closure".into());}
        Some(evidence)
    }).collect()
}
