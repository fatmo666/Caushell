use std::collections::{BTreeMap, BTreeSet};

use caushell_parse::{CommandFact, StatementTerminator};
use caushell_profile::{BoundInvocation, EffectKind};
use caushell_query::{PathTargetQuery, QuerySession};
use caushell_runner::{ExecutionUnitOriginKind, RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{PathMetadataMutationKind, PathTargetOperation, RuleId, SemanticResolution};

use crate::support::{
    bound_invocation, decision_for_rule_action, graph_backed_execution_resolve_records,
};

/// Enforces the declared execution-identity/privilege boundary independently
/// of the child's filesystem targets or otherwise read-only behavior.
pub struct PrivilegeBoundaryGuardPass;

fn has_candidate(bound: &BoundInvocation) -> bool {
    bound
        .effects
        .iter()
        .any(|effect| effect.kind == EffectKind::PrivilegeModifier)
}

fn requests_set_id(mode: &str) -> bool {
    let numeric = mode.strip_prefix(['+', '-', '=']).unwrap_or(mode);
    if !numeric.is_empty() && numeric.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return !mode.starts_with('-')
            && u32::from_str_radix(numeric, 8)
                .is_ok_and(|bits| bits <= 0o7777 && bits & 0o6000 != 0);
    }

    // Track explicit requests in clause order. A chmod applies the final
    // mode to a regular file, even if earlier clauses set a bit it clears.
    let mut set = 0;
    for clause in mode.split(',') {
        let Some(actions_start) = clause.find(['+', '-', '=']) else {
            return false;
        };
        let (who, mut actions) = clause.split_at(actions_start);
        let mut mask = if who.is_empty() { 0o6000 } else { 0 };
        for byte in who.bytes() {
            mask |= match byte {
                b'u' => 0o4000,
                b'g' => 0o2000,
                b'a' => 0o6000,
                b'o' => 0,
                _ => return false,
            };
        }
        while !actions.is_empty() {
            let (operator, tail) = actions.split_at(1);
            let end = tail.find(['+', '-', '=']).unwrap_or(tail.len());
            let (permissions, rest) = tail.split_at(end);
            if !matches!(permissions, "u" | "g" | "o")
                && !permissions.bytes().all(|byte| b"rwxXst".contains(&byte))
            {
                return false;
            }
            let has_id = permissions.contains('s');
            match (operator, has_id) {
                ("+" | "=", true) => set |= mask,
                ("-", true) | ("=", false) => set &= !mask,
                _ => {}
            }
            actions = rest;
        }
    }
    set != 0
}

fn is_ordered_top_level_command(command: &CommandFact) -> bool {
    !command.in_pipeline
        && !command.guarded
        && !command.conditional_execution
        && command.control_flow_span.is_none()
        && command.shell_scope_span.is_none()
        && command.terminator != Some(StatementTerminator::Background)
}

fn set_id_execution_reasons(ctx: &RunnerContext, staged: SessionView<'_>) -> Vec<String> {
    let records = ctx.execution_unit_resolve_records();
    if !records.iter().any(|record| {
        record.origin_kind == ExecutionUnitOriginKind::TopLevel
            && bound_invocation(&record.result).is_some_and(|bound| {
                bound
                    .effects
                    .iter()
                    .any(|effect| effect.kind == EffectKind::ChangeMode)
            })
    }) {
        return Vec::new();
    }
    let Some(parsed) = ctx.parsed_command() else {
        return Vec::new();
    };
    let facts = PathTargetQuery::new(ctx.request().sequence_no)
        .execute(QuerySession::from_session(&staged));
    let mut mode_targets = BTreeSet::new();
    let mut executable_paths = BTreeSet::new();
    for fact in &facts {
        let SemanticResolution::Resolved { value } = &fact.resolution else {
            continue;
        };
        let Some(path) = value.concrete_path() else {
            continue;
        };
        let target = (fact.source_node_id.as_str(), path);
        if fact.operation == PathTargetOperation::Metadata
            && fact.metadata_mutation.as_ref().is_some_and(|mutation| {
                !mutation.recursive
                    && mutation
                        .mutation_kinds
                        .contains(&PathMetadataMutationKind::ChangeMode)
                    && mutation.raw_operand.as_deref().is_some_and(requests_set_id)
            })
        {
            mode_targets.insert(target);
        } else if fact.operation == PathTargetOperation::ExecuteFile
            && fact.slot_name == crate::path::EXECUTABLE_FILE_SLOT
        {
            executable_paths.insert(target);
        }
    }
    if mode_targets.is_empty() || executable_paths.is_empty() {
        return Vec::new();
    }

    let commands: BTreeMap<_, _> = records
        .iter()
        .filter_map(|record| {
            let index = record.command_ref.command_index;
            let command = parsed.commands.get(index)?;
            (record.origin_kind == ExecutionUnitOriginKind::TopLevel
                && record.command_ref.span == command.span
                && is_ordered_top_level_command(command))
            .then_some((index, (record.source_node_id.0.as_str(), command)))
        })
        .collect();
    let mut reasons = BTreeSet::new();
    for (&index, &(source, command)) in &commands {
        let Some(&(next_source, next)) = commands.get(&(index + 1)) else {
            continue;
        };
        // Some shell actions, such as assignments, have no command index.
        // Only a simple separator proves there is no intervening action.
        if !ctx
            .request()
            .command
            .get(command.span.end_byte..next.span.start_byte)
            .is_some_and(|between| {
                between
                    .bytes()
                    .all(|byte| byte.is_ascii_whitespace() || byte == b';')
            })
        {
            continue;
        }
        for &(_, path) in mode_targets
            .range((source, "")..)
            .take_while(|&&(id, _)| id == source)
        {
            if executable_paths.contains(&(next_source, path)) {
                reasons.insert(format!(
                    "direct execution of {path:?} follows a mode change requesting set-user-ID or set-group-ID; crossing the execution-identity boundary requires approval"
                ));
            }
        }
    }
    reasons.into_iter().collect()
}

impl SessionAnalysisPass for PrivilegeBoundaryGuardPass {
    fn name(&self) -> &'static str {
        "privilege_boundary_guard"
    }

    fn run(
        &self,
        _session: SessionView<'_>,
        staged_session: SessionView<'_>,
        ctx: &mut RunnerContext,
    ) {
        let has_declared_effect = ctx
            .execution_unit_resolve_records()
            .iter()
            .any(|record| bound_invocation(&record.result).is_some_and(has_candidate));
        let mut reasons = set_id_execution_reasons(ctx, staged_session);
        if has_declared_effect {
            reasons.extend(graph_backed_execution_resolve_records(ctx).into_iter().filter_map(|record| {
                let bound = bound_invocation(record.result()).filter(|bound| has_candidate(bound))?;
                Some(format!("{} ({}) declares an execution-identity or privilege change; crossing this boundary requires approval", bound.command_name.as_str(), bound.form_id.as_str()))
            }));
        }
        let action = ctx
            .policy()
            .rule_policy
            .action_for(RuleId::PrivilegeBoundary);
        for reason in reasons {
            ctx.add_finding(RuleId::PrivilegeBoundary, reason.clone());
            if let Some(decision) = decision_for_rule_action(action) {
                ctx.propose_decision(self.name(), RuleId::PrivilegeBoundary, decision, reason);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DecisionAssemblyPass, ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_graph::SessionGraph;
    use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
    use caushell_runner::PassRunner;
    use caushell_types::{
        CheckRequest, CommandSequenceNo, Decision, PolicyConfig, RuleAction, RulePolicyEntry,
        RuntimeMetadata, SessionId, SessionSummary, ShellKind, ShellRuntimeCapabilities,
        ShellStateSnapshot,
    };

    fn run(command: &str, action: RuleAction) -> RunnerContext {
        let profile = load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-identity-tool}
option_scope: leading_options
opaque_on_unresolved: true
forms:
  - id: query
    selector: {kind: has_modifier, modifier: inspect}
  - id: change_identity
    selector: {kind: not, item: {kind: has_modifier, modifier: inspect}}
    effects: [{kind: privilege_modifier, target: {kind: none}}]
    parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}]
modifiers: [{id: inspect, matcher: {kind: any_flag, flags: [--inspect]}}]
"#).unwrap();
        let request = CheckRequest {
            session_id: SessionId::new("privilege-test"),
            sequence_no: CommandSequenceNo::new(1),
            command: command.into(),
            shell_state_before: ShellStateSnapshot::new("/workspace"),
            shell_kind: ShellKind::Bash,
            home: None,
            workspace_root: Some("/workspace".into()),
            runtime: RuntimeMetadata {
                runtime_name: "static-test".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
        };
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .rules
            .insert(RuleId::PrivilegeBoundary, RulePolicyEntry::new(action));
        let mut ctx = RunnerContext::with_policy(request, policy);
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::from_profiles(vec![profile]).unwrap(),
        ));
        runner.register_session_analysis_pass(PrivilegeBoundaryGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        runner.run(
            SessionView::new(&SessionGraph::new(), &SessionSummary::default()),
            &mut ctx,
        );
        ctx
    }

    #[test]
    fn consumes_declarations_without_command_names_or_extra_action_metadata() {
        for (action, expected) in [
            (RuleAction::Observe, Decision::Allow),
            (RuleAction::NeedApproval, Decision::NeedApproval),
            (RuleAction::Deny, Decision::Deny),
        ] {
            let ctx = run("arbitrary-identity-tool", action);
            assert_eq!(ctx.final_decision, Some(expected));
            assert_eq!(
                ctx.findings
                    .iter()
                    .filter(|f| f.rule_id == RuleId::PrivilegeBoundary)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn skips_queries_and_unknown_tool_without_privilege_effects() {
        for command in ["arbitrary-identity-tool --inspect", "unknown-tool"] {
            let ctx = run(command, RuleAction::NeedApproval);
            assert_eq!(ctx.final_decision, Some(Decision::Allow));
            assert!(ctx.findings.is_empty(), "{command}");
        }
    }

    #[test]
    fn retains_declared_effects_on_partial_bound_invocations() {
        let ctx = run(
            "arbitrary-identity-tool \"$UNKNOWN\"",
            RuleAction::NeedApproval,
        );
        assert_eq!(ctx.final_decision, Some(Decision::NeedApproval));
        assert!(
            ctx.findings
                .iter()
                .any(|f| f.rule_id == RuleId::PrivilegeBoundary)
        );
    }

    #[test]
    fn unprojected_records_cannot_trigger_enforcement() {
        let resolved = run("arbitrary-identity-tool", RuleAction::NeedApproval);
        let mut ctx = RunnerContext::new(resolved.request().clone());
        ctx.set_execution_unit_resolve_records(resolved.execution_unit_resolve_records().to_vec());
        let graph = SessionGraph::new();
        let summary = SessionSummary::default();
        PrivilegeBoundaryGuardPass.run(
            SessionView::new(&graph, &summary),
            SessionView::new(&graph, &summary),
            &mut ctx,
        );
        assert!(ctx.findings.is_empty());
        assert!(ctx.decision_proposals.is_empty());
    }
}
