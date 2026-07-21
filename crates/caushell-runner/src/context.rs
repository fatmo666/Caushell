use std::collections::{BTreeMap, HashSet};

use crate::PendingMutation;
use crate::nested::NestedPayloadRecord;
use caushell_graph::NodeId;
use caushell_parse::{ParsedCommandArtifact, SourceSpan};
use caushell_profile::{ResolveInvocationArtifactResult, SessionBindings};
use caushell_types::{
    CheckRequest, Decision, Evidence, Finding, FindingEnforcementClass, PolicyConfig,
    ProvenanceConsumeKind, ProvenanceDomainLabel, ProvenanceProduceKind, RuleId, ShellKind,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionProposal {
    pub source_pass: String,
    pub rule_id: RuleId,
    pub decision: Decision,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommandRef {
    pub command_index: usize,
    pub span: SourceSpan,
}

impl ParsedCommandRef {
    pub fn new(command_index: usize, span: SourceSpan) -> Self {
        Self {
            command_index,
            span,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedDispatchRecord {
    pub source_node_id: NodeId,
    pub command_ref: ParsedCommandRef,
    pub dispatch_index: usize,
    pub command_slot: String,
}

impl UnresolvedDispatchRecord {
    pub fn new(
        source_node_id: NodeId,
        command_ref: ParsedCommandRef,
        dispatch_index: usize,
        command_slot: impl Into<String>,
    ) -> Self {
        Self {
            source_node_id,
            command_ref,
            dispatch_index,
            command_slot: command_slot.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommandScope {
    pub scope_node_id: NodeId,
    pub parsed: ParsedCommandArtifact,
    pub command_node_ids: Vec<NodeId>,
}

impl ParsedCommandScope {
    pub fn new(
        scope_node_id: NodeId,
        parsed: ParsedCommandArtifact,
        command_node_ids: Vec<NodeId>,
    ) -> Self {
        Self {
            scope_node_id,
            parsed,
            command_node_ids,
        }
    }

    pub fn command_node_id(&self, command_index: usize) -> Option<&NodeId> {
        self.command_node_ids.get(command_index)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessSubstitutionOuterRelation {
    Consume {
        consume_kind: ProvenanceConsumeKind,
        slot_name: Option<String>,
        domain_label: Option<ProvenanceDomainLabel>,
    },
    Produce {
        produce_kind: ProvenanceProduceKind,
        slot_name: Option<String>,
        domain_label: Option<ProvenanceDomainLabel>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProcessSubstitutionLocationKind {
    Argument,
    Redirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExecutionUnitOriginKind {
    TopLevel,
    FunctionExpansion,
    Dispatch,
    NestedPayload,
    ShellCommandStringPayload,
    CommandSubstitutionBody,
    CommandSubstitutionMaterialization,
    ProcessSubstitutionBody,
    StaticXargs,
    RecursivePayload,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CatastrophicSearchRootScope {
    pub root: String,
    pub via_command_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockDeviceSearchScope {
    pub target: String,
    pub via_command_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionUnitInheritedScope {
    pub catastrophic_search_roots: Vec<CatastrophicSearchRootScope>,
    pub block_device_search_scopes: Vec<BlockDeviceSearchScope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectiveCwd {
    Unreachable,
    Known(String),
    KnownOneOf(Vec<String>),
    KnownOrUnknown(Vec<String>),
    Unknown,
}

impl EffectiveCwd {
    pub fn known(cwd: impl Into<String>) -> Self {
        Self::Known(cwd.into())
    }

    pub fn known_one_of(cwds: impl IntoIterator<Item = String>) -> Self {
        let mut cwds = cwds.into_iter().collect::<Vec<_>>();
        cwds.sort();
        cwds.dedup();

        match cwds.len() {
            0 => Self::Unknown,
            1 => Self::Known(cwds.remove(0)),
            _ => Self::KnownOneOf(cwds),
        }
    }

    pub fn known_or_unknown(cwds: impl IntoIterator<Item = String>) -> Self {
        let mut cwds = cwds.into_iter().collect::<Vec<_>>();
        cwds.sort();
        cwds.dedup();

        if cwds.is_empty() {
            Self::Unknown
        } else {
            Self::KnownOrUnknown(cwds)
        }
    }

    pub fn as_known(&self) -> Option<&str> {
        match self {
            Self::Known(cwd) => Some(cwd.as_str()),
            Self::Unreachable | Self::KnownOneOf(_) | Self::KnownOrUnknown(_) => None,
            Self::Unknown => None,
        }
    }

    pub fn known_cwds(&self) -> Vec<&str> {
        match self {
            Self::Unreachable => Vec::new(),
            Self::Known(cwd) => vec![cwd.as_str()],
            Self::KnownOneOf(cwds) | Self::KnownOrUnknown(cwds) => {
                cwds.iter().map(String::as_str).collect()
            }
            Self::Unknown => Vec::new(),
        }
    }

    pub fn has_unknown(&self) -> bool {
        matches!(self, Self::KnownOrUnknown(_) | Self::Unknown)
    }

    pub fn is_unreachable(&self) -> bool {
        matches!(self, Self::Unreachable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionUnitResolveRecord {
    pub source_node_id: NodeId,
    pub command_ref: ParsedCommandRef,
    pub parsed_scope: ParsedCommandArtifact,
    pub rendered_command_text: String,
    pub result: ResolveInvocationArtifactResult,
    pub shell_kind: ShellKind,
    pub root_command_index: usize,
    pub depth: u8,
    pub parent_execution_node_id: NodeId,
    pub bindings: SessionBindings,
    pub origin_kind: ExecutionUnitOriginKind,
    pub origin_index: usize,
    pub origin_locator: ExecutionUnitOriginLocator,
    pub inherited_scope: ExecutionUnitInheritedScope,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ExecutionUnitOriginLocator {
    #[default]
    None,
    CommandSubstitutionBody {
        token_index: usize,
        substitution_index: usize,
    },
    CommandSubstitutionAssignmentValue {
        assignment_command_index: usize,
        assignment_index: usize,
        substitution_index: usize,
        assignment_name: String,
        assignment_value_text: String,
        substitution_text: String,
        substitution_body_text: String,
    },
    CommandSubstitutionMaterialization,
    ProcessSubstitutionBody {
        location_kind: ProcessSubstitutionLocationKind,
        outer_index: usize,
        location_subindex: usize,
        substitution_index: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Proposals preserve per-pass judgments; final_decision is set only by the
// final decision phase after earlier passes have contributed evidence.
pub struct RunnerContext {
    request: CheckRequest,
    policy: PolicyConfig,
    pending_mutations: Vec<PendingMutation>,
    pending_mutation_index: HashSet<PendingMutation>,
    parsed_command: Option<ParsedCommandArtifact>,
    parsed_command_scopes: Vec<ParsedCommandScope>,
    unresolved_dispatch_records: Vec<UnresolvedDispatchRecord>,
    nested_payload_records: Vec<NestedPayloadRecord>,
    execution_unit_resolve_records: Vec<ExecutionUnitResolveRecord>,
    effective_cwds: BTreeMap<NodeId, EffectiveCwd>,
    request_exit_cwd: Option<EffectiveCwd>,
    pub executed_passes: Vec<String>,
    pub findings: Vec<Finding>,
    pub evidence: Vec<Evidence>,
    pub decision_proposals: Vec<DecisionProposal>,
    pub final_decision: Option<Decision>,
}

impl RunnerContext {
    pub fn new(request: CheckRequest) -> Self {
        Self::with_policy(request, PolicyConfig::default())
    }

    pub fn with_policy(request: CheckRequest, policy: PolicyConfig) -> Self {
        Self {
            request,
            policy,
            pending_mutations: Vec::new(),
            pending_mutation_index: HashSet::new(),
            parsed_command: None,
            parsed_command_scopes: Vec::new(),
            unresolved_dispatch_records: Vec::new(),
            nested_payload_records: Vec::new(),
            execution_unit_resolve_records: Vec::new(),
            effective_cwds: BTreeMap::new(),
            request_exit_cwd: None,
            executed_passes: Vec::new(),
            findings: Vec::new(),
            evidence: Vec::new(),
            decision_proposals: Vec::new(),
            final_decision: None,
        }
    }

    pub fn request(&self) -> &CheckRequest {
        &self.request
    }

    pub fn policy(&self) -> &PolicyConfig {
        &self.policy
    }

    pub fn pending_mutations(&self) -> &[PendingMutation] {
        &self.pending_mutations
    }

    pub fn parsed_command(&self) -> Option<&ParsedCommandArtifact> {
        self.parsed_command.as_ref()
    }

    pub fn set_parsed_command(&mut self, parsed_command: ParsedCommandArtifact) {
        self.parsed_command = Some(parsed_command);
        self.parsed_command_scopes.clear();
        self.unresolved_dispatch_records.clear();
        self.nested_payload_records.clear();
        self.execution_unit_resolve_records.clear();
        self.effective_cwds.clear();
        self.request_exit_cwd = None;
    }

    pub fn parsed_command_scopes(&self) -> &[ParsedCommandScope] {
        &self.parsed_command_scopes
    }

    pub fn set_parsed_command_scopes(&mut self, scopes: Vec<ParsedCommandScope>) {
        self.parsed_command_scopes = scopes;
    }

    pub fn unresolved_dispatch_records(&self) -> &[UnresolvedDispatchRecord] {
        &self.unresolved_dispatch_records
    }

    pub fn set_unresolved_dispatch_records(
        &mut self,
        unresolved_dispatch_records: Vec<UnresolvedDispatchRecord>,
    ) {
        self.unresolved_dispatch_records = unresolved_dispatch_records;
    }

    pub fn nested_payload_records(&self) -> &[NestedPayloadRecord] {
        &self.nested_payload_records
    }

    pub fn set_nested_payload_records(&mut self, nested_payload_records: Vec<NestedPayloadRecord>) {
        self.nested_payload_records = nested_payload_records;
    }

    pub fn execution_unit_resolve_records(&self) -> &[ExecutionUnitResolveRecord] {
        &self.execution_unit_resolve_records
    }

    pub fn set_execution_unit_resolve_records(
        &mut self,
        execution_unit_resolve_records: Vec<ExecutionUnitResolveRecord>,
    ) {
        self.execution_unit_resolve_records = execution_unit_resolve_records;
        self.effective_cwds.clear();
        self.request_exit_cwd = None;
    }

    pub fn effective_cwds(&self) -> &BTreeMap<NodeId, EffectiveCwd> {
        &self.effective_cwds
    }

    pub fn effective_cwd_for_node(&self, node_id: &NodeId) -> Option<&EffectiveCwd> {
        self.effective_cwds.get(node_id)
    }

    pub fn known_effective_cwd_for_node(&self, node_id: &NodeId) -> Option<&str> {
        self.effective_cwd_for_node(node_id)
            .and_then(EffectiveCwd::as_known)
    }

    pub fn set_effective_cwds(&mut self, effective_cwds: BTreeMap<NodeId, EffectiveCwd>) {
        self.effective_cwds = effective_cwds;
    }

    pub fn clear_effective_cwds(&mut self) {
        self.effective_cwds.clear();
        self.request_exit_cwd = None;
    }

    pub fn request_exit_cwd(&self) -> Option<&EffectiveCwd> {
        self.request_exit_cwd.as_ref()
    }

    pub fn known_request_exit_cwd(&self) -> Option<&str> {
        self.request_exit_cwd
            .as_ref()
            .and_then(EffectiveCwd::as_known)
    }

    pub fn set_request_exit_cwd(&mut self, request_exit_cwd: EffectiveCwd) {
        self.request_exit_cwd = Some(request_exit_cwd);
    }

    pub fn record_pass(&mut self, pass_name: impl Into<String>) {
        self.executed_passes.push(pass_name.into());
    }

    pub fn stage_mutation(&mut self, mutation: PendingMutation) {
        if self.pending_mutation_index.insert(mutation.clone()) {
            self.pending_mutations.push(mutation);
        }
    }

    pub fn add_finding(&mut self, rule_id: RuleId, finding: impl Into<String>) {
        self.findings.push(Finding::new(rule_id, finding));
    }

    pub fn add_finding_with_class(
        &mut self,
        rule_id: RuleId,
        finding: impl Into<String>,
        enforcement_class: FindingEnforcementClass,
    ) {
        self.findings
            .push(Finding::new(rule_id, finding).with_enforcement_class(enforcement_class));
    }

    pub fn add_evidence(&mut self, evidence: Evidence) {
        if !self.evidence.contains(&evidence) {
            self.evidence.push(evidence);
        }
    }

    pub fn propose_decision(
        &mut self,
        source_pass: impl Into<String>,
        rule_id: RuleId,
        decision: Decision,
        reason: impl Into<String>,
    ) {
        self.decision_proposals.push(DecisionProposal {
            source_pass: source_pass.into(),
            rule_id,
            decision,
            reason: reason.into(),
        });
    }

    pub fn set_final_decision(&mut self, decision: Decision) {
        self.final_decision = Some(decision);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        EffectiveCwd, ExecutionUnitInheritedScope, ExecutionUnitOriginKind,
        ExecutionUnitOriginLocator, ExecutionUnitResolveRecord, ParsedCommandRef, RunnerContext,
    };
    use crate::PendingMutation;
    use caushell_graph::{EdgeKind, NodeId};
    use caushell_parse::parse_command;
    use caushell_profile::{
        InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult,
        resolve_invocation_artifact,
    };
    use caushell_types::{
        CheckRequest, CommandSequenceNo, PathResolution, PolicyConfig, ResolvedPathPurpose,
        ResolvedPathRole, RuleAction, RuleId, RulePolicy, RulePolicyEntry, RuntimeMetadata,
        SessionId, ShellKind, ShellStateSnapshot,
    };

    fn sample_request() -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: "pwd".to_string(),
            shell_state_before: ShellStateSnapshot::new("/tmp/project"),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "cli".to_string(),
                tool_name: None,
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    fn built_in_registry() -> ProfileRegistry {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profiles_dir = manifest_dir.join("../caushell-profile/profiles");

        ProfileRegistry::load_dir(&profiles_dir)
            .expect("expected built-in profiles directory to load")
    }

    #[test]
    fn runner_context_exposes_its_request() {
        let ctx = RunnerContext::new(sample_request());

        assert_eq!(ctx.request().session_id.0, "sess-1");
        assert_eq!(ctx.request().sequence_no, CommandSequenceNo::new(1));
        assert_eq!(ctx.request().command, "pwd");
    }

    #[test]
    fn runner_context_exposes_its_policy() {
        let ctx = RunnerContext::with_policy(
            sample_request(),
            PolicyConfig {
                rule_policy: RulePolicy {
                    rules: std::collections::BTreeMap::from([(
                        RuleId::MissingCommandName,
                        RulePolicyEntry::new(RuleAction::Deny),
                    )]),
                    ..RulePolicy::default()
                },
                semantic_expansion: caushell_types::SemanticExpansionPolicy::default(),
                runtime_taint: caushell_types::RuntimeTaintPolicy::default(),
                path_trust_sets: std::collections::BTreeMap::new(),
            },
        );

        assert_eq!(
            ctx.policy()
                .rule_policy
                .action_for(RuleId::MissingCommandName),
            RuleAction::Deny
        );
    }

    #[test]
    fn runner_context_tracks_pending_mutations() {
        let mut ctx = RunnerContext::new(sample_request());

        ctx.stage_mutation(PendingMutation::AddPathFact {
            source_node_id: NodeId::new("command:sess-1:1"),
            node_id: NodeId::new("path-1"),
            resolution: PathResolution::Concrete {
                path: "/tmp/project".to_string(),
            },
            role: ResolvedPathRole::Read,
            purpose: Some(ResolvedPathPurpose::GenericOperand),
            slot_name: "path".to_string(),
            normalized_command_name: None,
            relation: EdgeKind::Reads,
        });

        assert_eq!(
            ctx.pending_mutations(),
            &[PendingMutation::AddPathFact {
                source_node_id: NodeId::new("command:sess-1:1"),
                node_id: NodeId::new("path-1"),
                resolution: PathResolution::Concrete {
                    path: "/tmp/project".to_string(),
                },
                role: ResolvedPathRole::Read,
                purpose: Some(ResolvedPathPurpose::GenericOperand),
                slot_name: "path".to_string(),
                normalized_command_name: None,
                relation: EdgeKind::Reads,
            }]
        );
    }

    #[test]
    fn runner_context_deduplicates_identical_pending_mutations() {
        let mut ctx = RunnerContext::new(sample_request());
        let mutation = PendingMutation::AddPathFact {
            source_node_id: NodeId::new("command:sess-1:1"),
            node_id: NodeId::new("path-1"),
            resolution: PathResolution::Concrete {
                path: "/tmp/project".to_string(),
            },
            role: ResolvedPathRole::Read,
            purpose: Some(ResolvedPathPurpose::GenericOperand),
            slot_name: "path".to_string(),
            normalized_command_name: None,
            relation: EdgeKind::Reads,
        };

        ctx.stage_mutation(mutation.clone());
        ctx.stage_mutation(mutation.clone());

        assert_eq!(ctx.pending_mutations(), &[mutation]);
    }

    #[test]
    fn runner_context_stores_parsed_command_artifact() {
        let mut ctx = RunnerContext::new(sample_request());
        let artifact = parse_command("pwd", ShellKind::Bash)
            .expect("expected parse artifact for bash command");

        ctx.set_parsed_command(artifact.clone());

        assert_eq!(ctx.parsed_command(), Some(&artifact));
    }

    #[test]
    fn runner_context_stores_execution_unit_resolve_records() {
        let mut request = sample_request();
        request.command = "bash -c 'echo ok'".to_string();

        let mut ctx = RunnerContext::new(request);
        let registry = built_in_registry();
        let parsed = parse_command(&ctx.request().command, ctx.request().shell_kind)
            .expect("expected parse artifact for bash command");
        let command = parsed
            .commands
            .first()
            .expect("expected parsed command to contain one command");

        let resolved =
            resolve_invocation_artifact(&registry, command, InvocationRuntimeContext::new());

        let expected = vec![
            ExecutionUnitResolveRecord {
                source_node_id: NodeId::new("command:sess-1:1"),
                command_ref: ParsedCommandRef::new(0, command.span.clone()),
                parsed_scope: parsed.clone(),
                rendered_command_text: command.text.clone(),
                result: resolved.clone(),
                shell_kind: ShellKind::Bash,
                root_command_index: 0,
                depth: 0,
                parent_execution_node_id: NodeId::new("command:sess-1:1"),
                bindings: caushell_profile::SessionBindings::default(),
                origin_kind: ExecutionUnitOriginKind::TopLevel,
                origin_index: 0,
                origin_locator: ExecutionUnitOriginLocator::None,
                inherited_scope: ExecutionUnitInheritedScope::default(),
            },
            ExecutionUnitResolveRecord {
                source_node_id: NodeId::new("derived:sess-1:1:0:0"),
                command_ref: ParsedCommandRef::new(1, command.span.clone()),
                parsed_scope: parsed.clone(),
                rendered_command_text: command.text.clone(),
                result: resolved,
                shell_kind: ShellKind::Bash,
                root_command_index: 0,
                depth: 1,
                parent_execution_node_id: NodeId::new("command:sess-1:1"),
                bindings: caushell_profile::SessionBindings::default(),
                origin_kind: ExecutionUnitOriginKind::NestedPayload,
                origin_index: 1,
                origin_locator: ExecutionUnitOriginLocator::None,
                inherited_scope: ExecutionUnitInheritedScope::default(),
            },
        ];
        ctx.set_execution_unit_resolve_records(expected.clone());

        assert_eq!(ctx.execution_unit_resolve_records(), expected.as_slice());

        match &ctx.execution_unit_resolve_records()[0].result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.bound.form_id.as_str(), "command_string");
            }
            other => panic!("expected resolved invocation result, got {other:?}"),
        }
        assert_eq!(
            ctx.execution_unit_resolve_records()[0]
                .command_ref
                .command_index,
            0
        );
        assert_eq!(
            ctx.execution_unit_resolve_records()[0].source_node_id.0,
            "command:sess-1:1"
        );
        assert_eq!(
            ctx.execution_unit_resolve_records()[1]
                .command_ref
                .command_index,
            1
        );
        assert_eq!(
            ctx.execution_unit_resolve_records()[1].source_node_id.0,
            "derived:sess-1:1:0:0"
        );
    }

    #[test]
    fn runner_context_stores_effective_cwds() {
        let mut ctx = RunnerContext::new(sample_request());
        let node_id = NodeId::new("command:sess-1:1");

        ctx.set_effective_cwds(std::collections::BTreeMap::from([(
            node_id.clone(),
            EffectiveCwd::known("/tmp/project"),
        )]));

        assert_eq!(
            ctx.effective_cwd_for_node(&node_id),
            Some(&EffectiveCwd::Known("/tmp/project".to_string()))
        );
        assert_eq!(
            ctx.known_effective_cwd_for_node(&node_id),
            Some("/tmp/project")
        );
    }

    #[test]
    fn runner_context_stores_request_exit_cwd() {
        let mut ctx = RunnerContext::new(sample_request());

        ctx.set_request_exit_cwd(EffectiveCwd::known("/"));

        assert_eq!(
            ctx.request_exit_cwd(),
            Some(&EffectiveCwd::Known("/".to_string()))
        );
        assert_eq!(ctx.known_request_exit_cwd(), Some("/"));
    }

    #[test]
    fn runner_context_preserves_unsuccessful_command_resolution_results() {
        let mut request = sample_request();
        request.command = "unknown-tool --help".to_string();

        let mut ctx = RunnerContext::new(request);
        let registry = built_in_registry();
        let parsed = parse_command(&ctx.request().command, ctx.request().shell_kind)
            .expect("expected parse artifact for bash command");
        let command = parsed
            .commands
            .first()
            .expect("expected parsed command to contain one command");

        let resolved =
            resolve_invocation_artifact(&registry, command, InvocationRuntimeContext::new());

        let records = vec![ExecutionUnitResolveRecord {
            source_node_id: NodeId::new("command:sess-1:1"),
            command_ref: ParsedCommandRef::new(0, command.span.clone()),
            parsed_scope: parsed.clone(),
            rendered_command_text: command.text.clone(),
            result: resolved,
            shell_kind: ShellKind::Bash,
            root_command_index: 0,
            depth: 0,
            parent_execution_node_id: NodeId::new("command:sess-1:1"),
            bindings: caushell_profile::SessionBindings::default(),
            origin_kind: ExecutionUnitOriginKind::TopLevel,
            origin_index: 0,
            origin_locator: ExecutionUnitOriginLocator::None,
            inherited_scope: ExecutionUnitInheritedScope::default(),
        }];
        ctx.set_execution_unit_resolve_records(records);

        match &ctx.execution_unit_resolve_records()[0].result {
            ResolveInvocationArtifactResult::NoProfile {
                normalized_command_name,
                ..
            } => {
                assert_eq!(normalized_command_name, "unknown-tool");
            }
            other => panic!("expected no-profile resolve result, got {other:?}"),
        }
    }

    #[test]
    fn setting_parsed_command_invalidates_prior_execution_unit_resolve_records() {
        let mut request = sample_request();
        request.command = "bash -c 'echo ok'".to_string();

        let mut ctx = RunnerContext::new(request);
        let registry = built_in_registry();
        let parsed = parse_command(&ctx.request().command, ctx.request().shell_kind)
            .expect("expected parse artifact for bash command");
        let command = parsed
            .commands
            .first()
            .expect("expected parsed command to contain one command");

        let resolved =
            resolve_invocation_artifact(&registry, command, InvocationRuntimeContext::new());

        ctx.set_execution_unit_resolve_records(vec![ExecutionUnitResolveRecord {
            source_node_id: NodeId::new("command:sess-1:1"),
            command_ref: ParsedCommandRef::new(0, command.span.clone()),
            parsed_scope: parsed.clone(),
            rendered_command_text: command.text.clone(),
            result: resolved,
            shell_kind: ShellKind::Bash,
            root_command_index: 0,
            depth: 0,
            parent_execution_node_id: NodeId::new("command:sess-1:1"),
            bindings: caushell_profile::SessionBindings::default(),
            origin_kind: ExecutionUnitOriginKind::TopLevel,
            origin_index: 0,
            origin_locator: ExecutionUnitOriginLocator::None,
            inherited_scope: ExecutionUnitInheritedScope::default(),
        }]);
        assert_eq!(ctx.execution_unit_resolve_records().len(), 1);

        ctx.set_parsed_command(parsed);

        assert!(ctx.execution_unit_resolve_records().is_empty());
    }
}
