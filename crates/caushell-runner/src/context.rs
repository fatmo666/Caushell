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
    pub dispatch_working_directory: Option<caushell_profile::DispatchWorkingDirectory>,
    /// A pre-cwd-computation static-input lookup cannot assume the request cwd
    /// after a tool-selected directory. This uncertainty survives wrappers.
    pub static_input_cwd_unproven: bool,
    /// Applies only to this direct Dispatch origin, not arbitrary descendant
    /// shell events. Each new dispatch replaces it from its own declaration.
    pub dispatch_stdout_to_parent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectiveCwd {
    Unreachable,
    Known(String),
    KnownOneOf(Vec<String>),
    KnownOrUnknown(Vec<String>),
    /// Directory-tree bounds are sets, never concrete cwd alternatives.
    Bounded {
        known: Vec<String>,
        roots: Vec<String>,
        unknown: bool,
    },
    Unknown,
}

impl EffectiveCwd {
    pub fn with_bounds(
        known: impl IntoIterator<Item = String>,
        roots: impl IntoIterator<Item = String>,
        unknown: bool,
    ) -> Self {
        let mut known: Vec<_> = known.into_iter().collect();
        let mut roots: Vec<_> = roots.into_iter().collect();
        known.sort();
        known.dedup();
        roots.sort();
        roots.dedup();
        if roots.is_empty() {
            if unknown {
                Self::known_or_unknown(known)
            } else if known.is_empty() {
                Self::Unreachable
            } else {
                Self::known_one_of(known)
            }
        } else {
            Self::Bounded {
                known,
                roots,
                unknown,
            }
        }
    }

    pub fn bounded_roots(&self) -> &[String] {
        match self {
            Self::Bounded { roots, .. } => roots,
            _ => &[],
        }
    }

    pub fn cases(&self) -> Vec<CwdPathContext<'_>> {
        match self {
            Self::Known(path) => return vec![CwdPathContext::Exact(path)],
            Self::Unknown => return vec![CwdPathContext::Unknown],
            Self::Unreachable => return Vec::new(),
            _ => {}
        }
        self.known_cwds()
            .into_iter()
            .map(CwdPathContext::Exact)
            .chain(
                self.bounded_roots()
                    .iter()
                    .map(|root| CwdPathContext::Subtree(root)),
            )
            .chain(self.has_unknown().then_some(CwdPathContext::Unknown))
            .collect()
    }

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
            Self::Unreachable
            | Self::KnownOneOf(_)
            | Self::KnownOrUnknown(_)
            | Self::Bounded { .. } => None,
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
            Self::Bounded { known, .. } => known.iter().map(String::as_str).collect(),
            Self::Unknown => Vec::new(),
        }
    }

    pub fn has_unknown(&self) -> bool {
        matches!(
            self,
            Self::KnownOrUnknown(_) | Self::Unknown | Self::Bounded { unknown: true, .. }
        )
    }

    pub fn is_unreachable(&self) -> bool {
        matches!(self, Self::Unreachable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CwdPathContext<'a> {
    Exact(&'a str),
    Subtree(&'a str),
    Unknown,
}

impl<'a> CwdPathContext<'a> {
    pub fn resolution_base(self, fallback: &'a str) -> &'a str {
        match self {
            Self::Exact(path) | Self::Subtree(path) => path,
            Self::Unknown => fallback,
        }
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
    FunctionExpansion {
        function_name: String,
    },
    DispatchStdinFromParent,
    DispatchInheritedStdin,
    CommandSubstitutionBody {
        token_index: usize,
        substitution_index: usize,
    },
    CommandSubstitutionAssignmentValue {
        /// Namespace of an assignment-bearing nested source scope. This is
        /// provenance identity, not a request/runtime observation.
        assignment_scope_key: Option<String>,
        source_cwd_anchor: ShellSourceCwdAnchor,
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

/// Internal source-location fact, never a request or runtime observation.
/// Executable-free nested substitutions keep their enclosing position anchor.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShellSourceCwdAnchor {
    RequestPosition {
        start_byte: usize,
    },
    RecordScopePosition {
        source_node_id: NodeId,
        start_byte: usize,
    },
    InvocationEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Proposals preserve per-pass judgments; final_decision is set only by the
// final decision phase after earlier passes have contributed evidence.
pub struct RunnerContext {
    request: CheckRequest,
    policy: PolicyConfig,
    pending_mutations: Vec<PendingMutation>,
    // Coextensive with pending_mutations. None identifies an unpositioned
    // observation/final-state fact; Some identifies a shell-state occurrence.
    pending_mutation_sources: Vec<Option<usize>>,
    pending_mutation_index: HashSet<(PendingMutation, Option<usize>)>,
    parsed_command: Option<ParsedCommandArtifact>,
    parsed_command_scopes: Vec<ParsedCommandScope>,
    unresolved_dispatch_records: Vec<UnresolvedDispatchRecord>,
    nested_payload_records: Vec<NestedPayloadRecord>,
    execution_unit_resolve_records: Vec<ExecutionUnitResolveRecord>,
    effective_cwds: BTreeMap<NodeId, EffectiveCwd>,
    execution_cwd_overrides: BTreeMap<NodeId, EffectiveCwd>,
    request_exit_cwd: Option<EffectiveCwd>,
    // Resolver-owned, intra-request state artifact; never a Harness input.
    runtime_variable_final_mutations: Vec<PendingMutation>,
    runtime_function_mutations: Option<Vec<(PendingMutation, usize)>>,
    shell_state_fences: Vec<(usize, usize)>,
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
            pending_mutation_sources: Vec::new(),
            pending_mutation_index: HashSet::new(),
            parsed_command: None,
            parsed_command_scopes: Vec::new(),
            unresolved_dispatch_records: Vec::new(),
            nested_payload_records: Vec::new(),
            execution_unit_resolve_records: Vec::new(),
            effective_cwds: BTreeMap::new(),
            execution_cwd_overrides: BTreeMap::new(),
            request_exit_cwd: None,
            runtime_variable_final_mutations: Vec::new(),
            runtime_function_mutations: None,
            shell_state_fences: Vec::new(),
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
        self.execution_cwd_overrides.clear();
        self.request_exit_cwd = None;
        self.runtime_variable_final_mutations.clear();
        self.runtime_function_mutations = None;
        self.shell_state_fences.clear();
        // Staged entries remain, as before, but old artifact coordinates must
        // not be applied to a replacement artifact's state fences.
        self.pending_mutation_sources.fill(None);
        self.rebuild_pending_mutation_index();
    }

    pub fn set_runtime_variable_final_mutations(&mut self, mutations: Vec<PendingMutation>) {
        self.runtime_variable_final_mutations = mutations;
    }

    pub fn runtime_variable_final_mutations(&self) -> &[PendingMutation] {
        &self.runtime_variable_final_mutations
    }

    pub fn set_runtime_function_mutations(&mut self, mutations: Vec<(PendingMutation, usize)>) {
        self.runtime_function_mutations = Some(mutations);
    }

    pub fn runtime_function_mutations(&self) -> Option<&[(PendingMutation, usize)]> {
        self.runtime_function_mutations.as_deref()
    }

    /// State propagation only; this never removes graph/audit command nodes.
    pub fn shell_state_at_is_reachable(&self, start: usize) -> bool {
        !self
            .shell_state_fences
            .iter()
            .any(|(from, to)| start >= *from && start < *to)
    }

    pub fn has_shell_state_fences(&self) -> bool {
        !self.shell_state_fences.is_empty()
    }

    pub fn root_shell_terminates(&self) -> bool {
        self.shell_state_fences
            .iter()
            .any(|(_, end)| *end == usize::MAX)
    }

    pub fn set_shell_state_fences(&mut self, fences: Vec<(usize, usize)>) {
        self.shell_state_fences = fences;
        if self.shell_state_fences.is_empty() {
            return;
        }
        let fences = &self.shell_state_fences;
        let keep_source = |source: &Option<usize>| {
            source.is_none_or(|p| !fences.iter().any(|(from, to)| p >= *from && p < *to))
        };
        debug_assert_eq!(
            self.pending_mutations.len(),
            self.pending_mutation_sources.len()
        );
        let mut sources = self.pending_mutation_sources.iter();
        self.pending_mutations.retain(|_| {
            keep_source(
                sources
                    .next()
                    .expect("each staged mutation has a source entry"),
            )
        });
        self.pending_mutation_sources.retain(keep_source);
        self.rebuild_pending_mutation_index();
    }

    /// Preserve staging order across distinct source occurrences. Repeated
    /// extraction of the same mutation at the same source remains idempotent.
    pub fn stage_shell_state_mutation(&mut self, mutation: PendingMutation, start: usize) {
        if !self.shell_state_at_is_reachable(start) {
            return;
        }
        self.stage_mutation_with_source(mutation, Some(start));
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
        self.execution_cwd_overrides.clear();
        self.request_exit_cwd = None;
    }

    pub fn effective_cwds(&self) -> &BTreeMap<NodeId, EffectiveCwd> {
        &self.effective_cwds
    }

    pub fn effective_cwd_for_node(&self, node_id: &NodeId) -> Option<&EffectiveCwd> {
        self.effective_cwds.get(node_id)
    }

    /// Process-local cwd, distinct from the shell cwd used to open redirections.
    pub fn execution_cwd_for_node(&self, node_id: &NodeId) -> Option<&EffectiveCwd> {
        self.execution_cwd_overrides
            .get(node_id)
            .or_else(|| self.effective_cwd_for_node(node_id))
    }

    pub fn set_execution_cwd_overrides(&mut self, overrides: BTreeMap<NodeId, EffectiveCwd>) {
        self.execution_cwd_overrides = overrides;
    }

    pub fn known_effective_cwd_for_node(&self, node_id: &NodeId) -> Option<&str> {
        self.effective_cwd_for_node(node_id)
            .and_then(EffectiveCwd::as_known)
    }

    pub fn set_effective_cwds(&mut self, effective_cwds: BTreeMap<NodeId, EffectiveCwd>) {
        self.effective_cwds = effective_cwds;
        self.execution_cwd_overrides.clear();
    }

    pub fn clear_effective_cwds(&mut self) {
        self.effective_cwds.clear();
        self.execution_cwd_overrides.clear();
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
        self.stage_mutation_with_source(mutation, None);
    }

    fn stage_mutation_with_source(&mut self, mutation: PendingMutation, source: Option<usize>) {
        if self
            .pending_mutation_index
            .insert((mutation.clone(), source))
        {
            self.pending_mutations.push(mutation);
            self.pending_mutation_sources.push(source);
        }
    }

    fn rebuild_pending_mutation_index(&mut self) {
        debug_assert_eq!(
            self.pending_mutations.len(),
            self.pending_mutation_sources.len()
        );
        self.pending_mutation_index.clear();
        self.pending_mutation_index.extend(
            self.pending_mutations
                .iter()
                .cloned()
                .zip(self.pending_mutation_sources.iter().copied()),
        );
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
    fn state_fences_keep_pre_exit_duplicates_and_do_not_filter_audit_nodes() {
        let mut ctx = RunnerContext::new(sample_request());
        let mutation = PendingMutation::UpsertAliasBinding {
            binding: caushell_types::SessionAliasBinding::new(
                "a",
                "printf LAB",
                ctx.request().sequence_no,
            ),
        };
        ctx.stage_shell_state_mutation(mutation.clone(), 5);
        ctx.stage_shell_state_mutation(mutation.clone(), 50);
        let late = PendingMutation::UnsetAlias {
            name: "a".into(),
            observed_at: ctx.request().sequence_no,
        };
        ctx.stage_shell_state_mutation(late.clone(), 60);
        ctx.set_shell_state_fences(vec![(20, usize::MAX)]);
        assert!(ctx.pending_mutations().contains(&mutation));
        assert!(!ctx.pending_mutations().contains(&late));
        assert!(ctx.root_shell_terminates());
        assert!(!ctx.shell_state_at_is_reachable(60));
    }

    fn staged_function(body: &str) -> PendingMutation {
        PendingMutation::UpsertFunctionBinding {
            binding: caushell_types::SessionFunctionBinding::new(
                "f",
                body,
                CommandSequenceNo::new(1),
            ),
        }
    }

    fn staged_audit_fact() -> PendingMutation {
        PendingMutation::AddPathFact {
            source_node_id: NodeId::new("command:sess-1:1"),
            node_id: NodeId::new("path-audit"),
            resolution: PathResolution::Concrete {
                path: "/tmp/project".into(),
            },
            role: ResolvedPathRole::Read,
            purpose: Some(ResolvedPathPurpose::GenericOperand),
            slot_name: "path".into(),
            normalized_command_name: None,
            relation: EdgeKind::Reads,
        }
    }

    #[test]
    fn shell_state_occurrences_preserve_order_but_deduplicate_the_same_source() {
        let seq = CommandSequenceNo::new(1);
        for (upsert, unset) in [
            (
                staged_function("printf SAME;"),
                PendingMutation::UnsetFunction {
                    name: "f".into(),
                    observed_at: seq,
                },
            ),
            (
                PendingMutation::UpsertAliasBinding {
                    binding: caushell_types::SessionAliasBinding::new("a", "printf SAME", seq),
                },
                PendingMutation::UnsetAlias {
                    name: "a".into(),
                    observed_at: seq,
                },
            ),
        ] {
            let mut ctx = RunnerContext::new(sample_request());
            ctx.stage_shell_state_mutation(upsert.clone(), 5);
            ctx.stage_shell_state_mutation(unset.clone(), 10);
            ctx.stage_shell_state_mutation(upsert.clone(), 15);
            ctx.stage_shell_state_mutation(upsert.clone(), 15);
            assert_eq!(ctx.pending_mutations(), &[upsert.clone(), unset, upsert]);
        }
    }

    #[test]
    fn shell_state_occurrences_keep_distinct_mutations_at_one_source() {
        let mut ctx = RunnerContext::new(sample_request());
        let first = staged_function("printf FIRST;");
        let second = staged_function("printf SECOND;");
        ctx.stage_shell_state_mutation(first.clone(), 5);
        ctx.stage_shell_state_mutation(second.clone(), 5);
        assert_eq!(ctx.pending_mutations(), &[first, second]);
    }

    #[test]
    fn shell_state_occurrences_are_fenced_individually_without_losing_audit_facts() {
        let mut ctx = RunnerContext::new(sample_request());
        let upsert = staged_function("printf SAME;");
        let unset = PendingMutation::UnsetFunction {
            name: "f".into(),
            observed_at: CommandSequenceNo::new(1),
        };
        let audit = staged_audit_fact();
        ctx.stage_shell_state_mutation(upsert.clone(), 5);
        ctx.stage_mutation(audit.clone());
        ctx.stage_shell_state_mutation(unset.clone(), 10);
        ctx.stage_shell_state_mutation(upsert.clone(), 50);
        ctx.set_shell_state_fences(vec![(20, usize::MAX)]);
        assert_eq!(ctx.pending_mutations(), &[upsert, audit, unset]);
        let mut summary = caushell_types::SessionSummary::new();
        for mutation in ctx.pending_mutations() {
            mutation.apply_summary(&mut summary);
        }
        assert!(summary.function_binding("f").is_none());
    }

    #[test]
    fn shell_state_occurrences_obey_finite_fence_boundaries() {
        let mut ctx = RunnerContext::new(sample_request());
        let mutation = staged_function("printf SAME;");
        for start in [19, 20, 39, 40] {
            ctx.stage_shell_state_mutation(mutation.clone(), start);
        }
        ctx.set_shell_state_fences(vec![(20, 40)]);
        assert_eq!(
            ctx.pending_mutations(),
            &[mutation.clone(), mutation.clone()]
        );
        ctx.stage_shell_state_mutation(mutation.clone(), 20);
        ctx.stage_shell_state_mutation(mutation.clone(), 40);
        ctx.stage_shell_state_mutation(mutation.clone(), 50);
        assert_eq!(
            ctx.pending_mutations(),
            &[mutation.clone(), mutation.clone(), mutation]
        );
    }

    #[test]
    fn shell_state_occurrences_rebuild_deduplication_after_fence_changes() {
        let mut ctx = RunnerContext::new(sample_request());
        let audit = staged_audit_fact();
        let mutation = staged_function("printf SAME;");
        ctx.stage_mutation(audit.clone());
        ctx.stage_shell_state_mutation(mutation.clone(), 5);
        ctx.stage_shell_state_mutation(mutation.clone(), 50);
        ctx.set_shell_state_fences(vec![(20, usize::MAX)]);
        ctx.set_shell_state_fences(Vec::new());
        ctx.stage_shell_state_mutation(mutation.clone(), 50);
        ctx.stage_shell_state_mutation(mutation.clone(), 5);
        ctx.stage_mutation(audit.clone());
        assert_eq!(
            ctx.pending_mutations(),
            &[audit, mutation.clone(), mutation]
        );
    }

    #[test]
    fn shell_state_occurrences_drop_stale_positions_when_parsed_artifact_changes() {
        let mut ctx = RunnerContext::new(sample_request());
        let mutation = staged_function("printf SAME;");
        ctx.stage_shell_state_mutation(mutation.clone(), 5);
        ctx.set_parsed_command(parse_command("pwd", ShellKind::Bash).unwrap());
        // Existing staged entries stay, but their old coordinates cannot fence
        // a new artifact. Its fresh occurrence must have independent identity.
        ctx.stage_shell_state_mutation(mutation.clone(), 50);
        ctx.set_shell_state_fences(vec![(20, usize::MAX)]);
        assert_eq!(ctx.pending_mutations(), &[mutation.clone()]);
        ctx.stage_mutation(mutation.clone());
        assert_eq!(ctx.pending_mutations(), &[mutation]);
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
                sensitive_paths: caushell_types::SensitivePathPolicy::default(),
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
    fn process_cwd_overrides_are_distinct_and_invalidated_with_analysis_inputs() {
        let node = NodeId::new("command:sess-1:1");
        for invalidation in 0..4 {
            let mut ctx = RunnerContext::new(sample_request());
            ctx.set_effective_cwds(std::collections::BTreeMap::from([(
                node.clone(),
                EffectiveCwd::known("/tmp/project"),
            )]));
            ctx.set_execution_cwd_overrides(std::collections::BTreeMap::from([(
                node.clone(),
                EffectiveCwd::known("/opt"),
            )]));
            assert_eq!(
                ctx.known_effective_cwd_for_node(&node),
                Some("/tmp/project")
            );
            assert_eq!(
                ctx.execution_cwd_for_node(&node)
                    .and_then(EffectiveCwd::as_known),
                Some("/opt")
            );
            match invalidation {
                0 => ctx.clear_effective_cwds(),
                1 => ctx.set_execution_unit_resolve_records(Vec::new()),
                2 => ctx.set_effective_cwds(std::collections::BTreeMap::new()),
                _ => ctx.set_parsed_command(
                    caushell_parse::parse_command("echo ok", caushell_types::ShellKind::Bash)
                        .unwrap(),
                ),
            }
            assert!(ctx.execution_cwd_for_node(&node).is_none());
        }
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
