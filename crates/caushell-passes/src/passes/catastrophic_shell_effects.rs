use std::collections::{BTreeMap, BTreeSet};

use caushell_parse::{
    ParseStatus, ParsedCommandArtifact, PipelinePosition, SourceSpan, StatementTerminator,
    parse_command,
};
use caushell_runner::{
    ExecutionUnitOriginKind, NestedPayloadResolution, RunnerContext, SessionAnalysisPass,
    SessionView,
};
use caushell_types::{
    CatastrophicShellExpansionModeEvidence, Evidence, FindingEnforcementClass, RuleId,
    SessionFunctionBinding, ShellKind,
};

use crate::support::visible_function_bindings_before_span;

pub struct CatastrophicShellEffectsPass;

impl SessionAnalysisPass for CatastrophicShellEffectsPass {
    fn name(&self) -> &'static str {
        "catastrophic_shell_effects"
    }

    fn run(
        &self,
        session: SessionView<'_>,
        _staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    ) {
        let Some(parsed) = ctx.parsed_command().cloned() else {
            return;
        };

        let request = ctx.request().clone();
        let mut seen_effects = BTreeSet::new();
        analyze_shell_unit(
            session.summary(),
            &request,
            &parsed,
            request.shell_kind,
            &mut seen_effects,
            ctx,
        );

        let nested_units: Vec<(ShellKind, ParsedCommandArtifact)> = ctx
            .nested_payload_records()
            .iter()
            .filter_map(|record| {
                let NestedPayloadResolution::Parsed { shell_kind, parsed } = &record.resolution
                else {
                    return None;
                };
                matches!(shell_kind, ShellKind::Bash | ShellKind::Sh)
                    .then(|| (*shell_kind, parsed.clone()))
            })
            .collect();

        for (shell_kind, parsed) in nested_units {
            analyze_shell_unit(
                session.summary(),
                &request,
                &parsed,
                shell_kind,
                &mut seen_effects,
                ctx,
            );
        }

        let derived_shell_units: Vec<(ShellKind, ParsedCommandArtifact)> = ctx
            .execution_unit_resolve_records()
            .iter()
            .filter(|record| record.origin_kind != ExecutionUnitOriginKind::TopLevel)
            .filter(|record| matches!(record.shell_kind, ShellKind::Bash | ShellKind::Sh))
            .map(|record| (record.shell_kind, record.parsed_scope.clone()))
            .collect();

        for (shell_kind, parsed) in derived_shell_units {
            analyze_shell_unit(
                session.summary(),
                &request,
                &parsed,
                shell_kind,
                &mut seen_effects,
                ctx,
            );
        }
    }
}

fn analyze_shell_unit(
    summary: &caushell_types::SessionSummary,
    request: &caushell_types::CheckRequest,
    parsed: &ParsedCommandArtifact,
    shell_kind: ShellKind,
    seen_effects: &mut BTreeSet<(String, Vec<String>, CatastrophicShellExpansionModeEvidence)>,
    ctx: &mut RunnerContext,
) {
    for command in &parsed.commands {
        let Some(trigger_name) = command.command_name.as_deref() else {
            continue;
        };

        let overlay = visible_function_bindings_before_span(
            summary,
            request,
            parsed,
            &command.span,
            request.sequence_no,
        );

        let Some(_binding) = overlay.get(trigger_name) else {
            continue;
        };

        let analysis = analyze_process_explosion(trigger_name, &overlay, shell_kind);
        let Some(effect) = analysis else {
            continue;
        };

        let effect_key = (
            effect.trigger_function.clone(),
            effect.recursive_scc_members.clone(),
            effect.expansion_mode,
        );
        if !seen_effects.insert(effect_key) {
            continue;
        }

        let evidence = Evidence::catastrophic_shell_process_explosion(
            effect.trigger_function.clone(),
            effect.recursive_scc_members.clone(),
            effect.expansion_mode,
            command.text.clone(),
        );
        let reason = evidence.summary.clone();

        ctx.add_evidence(evidence);
        ctx.add_finding_with_class(
            RuleId::CatastrophicShellProcessExplosion,
            reason,
            FindingEnforcementClass::HardDenyFloor,
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ProcessExplosionEffect {
    trigger_function: String,
    recursive_scc_members: Vec<String>,
    expansion_mode: CatastrophicShellExpansionModeEvidence,
}

#[derive(Debug, Clone)]
struct FunctionSemantics {
    direct_calls: Vec<DirectCall>,
}

#[derive(Debug, Clone)]
struct DirectCall {
    callee_name: String,
    guarded: bool,
    pipeline_span: Option<SourceSpan>,
    pipeline_position: Option<PipelinePosition>,
    terminator: Option<StatementTerminator>,
}

fn analyze_process_explosion(
    trigger_name: &str,
    bindings: &BTreeMap<String, SessionFunctionBinding>,
    shell_kind: caushell_types::ShellKind,
) -> Option<ProcessExplosionEffect> {
    let semantics = collect_function_semantics(bindings, shell_kind);
    if !semantics.contains_key(trigger_name) {
        return None;
    }

    let graph = direct_call_graph(&semantics);
    let reachable = reachable_functions(trigger_name, &graph);
    if reachable.is_empty() {
        return None;
    }

    let sccs = strongly_connected_components(&graph, &reachable);
    for scc in sccs {
        if !is_recursive_component(&scc, &graph) {
            continue;
        }

        let (has_pipeline, has_background) = component_expansion_modes(&scc, &semantics);
        if !has_pipeline && !has_background {
            continue;
        }

        let expansion_mode = match (has_pipeline, has_background) {
            (true, true) => CatastrophicShellExpansionModeEvidence::Mixed,
            (true, false) => CatastrophicShellExpansionModeEvidence::Pipeline,
            (false, true) => CatastrophicShellExpansionModeEvidence::Background,
            (false, false) => continue,
        };

        let mut members = scc.into_iter().collect::<Vec<_>>();
        members.sort();

        return Some(ProcessExplosionEffect {
            trigger_function: trigger_name.to_string(),
            recursive_scc_members: members,
            expansion_mode,
        });
    }

    None
}

fn collect_function_semantics(
    bindings: &BTreeMap<String, SessionFunctionBinding>,
    shell_kind: caushell_types::ShellKind,
) -> BTreeMap<String, FunctionSemantics> {
    bindings
        .iter()
        .filter_map(|(name, binding)| {
            parse_command(&binding.body, shell_kind)
                .ok()
                .filter(|parsed| parsed.status != ParseStatus::Partial)
                .map(|parsed| (name.clone(), analyze_function_body(parsed, bindings)))
        })
        .collect()
}

fn analyze_function_body(
    parsed: ParsedCommandArtifact,
    bindings: &BTreeMap<String, SessionFunctionBinding>,
) -> FunctionSemantics {
    let mut direct_calls = Vec::new();

    for command in parsed.commands {
        let Some(callee_name) = command.command_name.clone() else {
            continue;
        };

        let is_known_function = bindings.contains_key(&callee_name);
        if is_known_function {
            direct_calls.push(DirectCall {
                callee_name: callee_name.clone(),
                guarded: command.guarded,
                pipeline_span: command.pipeline_span.clone(),
                pipeline_position: command.pipeline_position,
                terminator: command.terminator,
            });
        }
    }

    FunctionSemantics { direct_calls }
}

fn direct_call_graph(
    semantics: &BTreeMap<String, FunctionSemantics>,
) -> BTreeMap<String, BTreeSet<String>> {
    semantics
        .iter()
        .map(|(name, semantics)| {
            let edges = semantics
                .direct_calls
                .iter()
                .filter(|call| !call.guarded)
                .map(|call| call.callee_name.clone())
                .collect();
            (name.clone(), edges)
        })
        .collect()
}

fn reachable_functions(
    trigger_name: &str,
    graph: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut visited = BTreeSet::new();
    let mut stack = vec![trigger_name.to_string()];

    while let Some(name) = stack.pop() {
        if !visited.insert(name.clone()) {
            continue;
        }
        if let Some(neighbors) = graph.get(&name) {
            stack.extend(neighbors.iter().cloned());
        }
    }

    visited
}

fn strongly_connected_components(
    graph: &BTreeMap<String, BTreeSet<String>>,
    reachable: &BTreeSet<String>,
) -> Vec<BTreeSet<String>> {
    let mut reverse = BTreeMap::<String, BTreeSet<String>>::new();
    for name in reachable {
        reverse.entry(name.clone()).or_default();
    }
    for (node, neighbors) in graph {
        if !reachable.contains(node) {
            continue;
        }
        for neighbor in neighbors {
            if reachable.contains(neighbor) {
                reverse
                    .entry(neighbor.clone())
                    .or_default()
                    .insert(node.clone());
            }
        }
    }

    let mut visited = BTreeSet::new();
    let mut order = Vec::new();
    for node in reachable {
        dfs_postorder(node, graph, reachable, &mut visited, &mut order);
    }

    let mut assigned = BTreeSet::new();
    let mut components = Vec::new();
    while let Some(node) = order.pop() {
        if assigned.contains(&node) {
            continue;
        }

        let mut component = BTreeSet::new();
        let mut stack = vec![node.clone()];
        while let Some(current) = stack.pop() {
            if !assigned.insert(current.clone()) {
                continue;
            }
            component.insert(current.clone());
            if let Some(neighbors) = reverse.get(&current) {
                stack.extend(neighbors.iter().cloned());
            }
        }
        components.push(component);
    }

    components
}

fn dfs_postorder(
    node: &str,
    graph: &BTreeMap<String, BTreeSet<String>>,
    reachable: &BTreeSet<String>,
    visited: &mut BTreeSet<String>,
    order: &mut Vec<String>,
) {
    if !visited.insert(node.to_string()) {
        return;
    }

    if let Some(neighbors) = graph.get(node) {
        for neighbor in neighbors {
            if reachable.contains(neighbor) {
                dfs_postorder(neighbor, graph, reachable, visited, order);
            }
        }
    }

    order.push(node.to_string());
}

fn is_recursive_component(
    component: &BTreeSet<String>,
    graph: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    if component.len() > 1 {
        return true;
    }

    let Some(name) = component.iter().next() else {
        return false;
    };

    graph
        .get(name)
        .is_some_and(|neighbors| neighbors.contains(name))
}

fn component_expansion_modes(
    component: &BTreeSet<String>,
    semantics: &BTreeMap<String, FunctionSemantics>,
) -> (bool, bool) {
    let mut has_background = false;
    let mut pipeline_groups = BTreeMap::<(String, usize, usize), usize>::new();

    for name in component {
        let Some(semantics) = semantics.get(name) else {
            continue;
        };

        for call in &semantics.direct_calls {
            if call.guarded || !component.contains(&call.callee_name) {
                continue;
            }

            if call.terminator == Some(StatementTerminator::Background) {
                has_background = true;
            }

            if matches!(
                call.pipeline_position,
                Some(
                    PipelinePosition::First
                        | PipelinePosition::Middle
                        | PipelinePosition::Last
                        | PipelinePosition::Only
                )
            ) && let Some(span) = &call.pipeline_span
            {
                let key = (name.clone(), span.start_byte, span.end_byte);
                *pipeline_groups.entry(key).or_default() += 1;
            }
        }
    }

    (
        pipeline_groups.values().any(|count| *count >= 2),
        has_background,
    )
}

#[cfg(test)]
mod tests {
    use super::CatastrophicShellEffectsPass;
    use crate::{
        DecisionAssemblyPass, ExtractFunctionBindingsPass, ParseCommandPass,
        ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_graph::SessionGraph;
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, EvidenceKind, FindingEnforcementClass,
        RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "codex".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    fn built_in_registry() -> ProfileRegistry {
        ProfileRegistry::built_in().expect("expected built-in registry to load")
    }

    fn run_pass_with_summary(command: &str, summary: SessionSummary) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ExtractFunctionBindingsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_analysis_pass(CatastrophicShellEffectsPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);

        let graph = SessionGraph::new();
        let mut ctx = RunnerContext::new(sample_request(command));

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    fn run_pass(command: &str) -> RunnerContext {
        run_pass_with_summary(command, SessionSummary::default())
    }

    #[test]
    fn catastrophic_shell_effects_deny_colon_fork_bomb() {
        let ctx = run_pass(":(){ :|:& };:");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicShellProcessExplosion
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
        }));
        assert!(ctx.evidence.iter().any(|evidence| matches!(
            evidence.kind,
            EvidenceKind::CatastrophicShellProcessExplosion(_)
        )));
    }

    #[test]
    fn catastrophic_shell_effects_deny_pipeline_recursive_expansion() {
        let ctx = run_pass("f(){ f|f; }; f");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicShellProcessExplosion
        }));
    }

    #[test]
    fn catastrophic_shell_effects_deny_background_recursive_expansion() {
        let ctx = run_pass("f(){ f & }; f");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicShellProcessExplosion
        }));
    }

    #[test]
    fn catastrophic_shell_effects_deny_mutual_recursive_pipeline_expansion() {
        let ctx = run_pass("a(){ b|b; } b(){ a; }; a");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicShellProcessExplosion
        }));
    }

    #[test]
    fn catastrophic_shell_effects_deny_static_eval_wrapped_fork_bomb() {
        let ctx = run_pass(r#"eval ':(){ :|:& };:'"#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicShellProcessExplosion
                && finding.enforcement_class == FindingEnforcementClass::HardDenyFloor
        }));
        assert!(ctx.evidence.iter().any(|evidence| matches!(
            &evidence.kind,
            EvidenceKind::CatastrophicShellProcessExplosion(process)
                if process.trigger_command == ":"
        )));
    }

    #[test]
    fn catastrophic_shell_effects_deny_same_request_eval_payload_from_variable() {
        let ctx = run_pass(r#"payload='f(){ f|f; }; f'; eval "$payload""#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicShellProcessExplosion
        }));
        assert!(ctx.evidence.iter().any(|evidence| matches!(
            &evidence.kind,
            EvidenceKind::CatastrophicShellProcessExplosion(process)
                if process.trigger_function == "f"
                    && process.trigger_command == "f"
        )));
    }

    #[test]
    fn catastrophic_shell_effects_deny_nested_static_eval_payload() {
        let ctx = run_pass(r#"payload='inner="f(){ f|f; }; f"; eval "$inner"'; eval "$payload""#);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicShellProcessExplosion
        }));
        assert!(ctx.evidence.iter().any(|evidence| matches!(
            &evidence.kind,
            EvidenceKind::CatastrophicShellProcessExplosion(process)
                if process.trigger_function == "f"
        )));
    }

    #[test]
    fn catastrophic_shell_effects_ignore_static_eval_of_benign_payload() {
        let ctx = run_pass(r#"eval "echo ok""#);

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_shell_effects_ignore_non_recursive_function() {
        let ctx = run_pass("deploy(){ npm test; }; deploy");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_shell_effects_ignore_plain_recursive_execution_without_fanout() {
        let ctx = run_pass("f(){ f; }; f");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_shell_effects_ignore_guarded_recursive_pipeline() {
        let ctx = run_pass("f(){ if cond; then f|f; fi; }; f");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_shell_effects_deny_session_visible_function_trigger() {
        let mut summary = SessionSummary::default();
        summary.upsert_function_binding(caushell_types::SessionFunctionBinding::new(
            "f",
            "f|f;",
            CommandSequenceNo::new(1),
        ));

        let ctx = run_pass_with_summary("f", summary);

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicShellProcessExplosion
        }));
    }

    #[test]
    fn catastrophic_shell_effects_ignore_future_same_input_definition() {
        let ctx = run_pass("f\nf(){ f|f; }");

        assert_eq!(ctx.final_decision, Some(Decision::Allow));
        assert!(ctx.findings.is_empty());
    }

    #[test]
    fn catastrophic_shell_effects_deny_when_trigger_reaches_recursive_scc() {
        let ctx = run_pass("start(){ f; } f(){ f|f; }; start");

        assert_eq!(ctx.final_decision, Some(Decision::Deny));
        assert!(ctx.findings.iter().any(|finding| {
            finding.rule_id == caushell_types::RuleId::CatastrophicShellProcessExplosion
        }));
    }
}
