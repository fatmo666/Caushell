use std::collections::BTreeMap;

use crate::{
    ExecutionSemanticsQuery, ExecutionSemanticsRef, ExecutionUnitHistoryQuery, ExecutionUnitRef,
    QuerySession, SequenceWindow, execution_unit_precedes,
};
use caushell_graph::{EdgeKind, NodeId, NodeKind};
use caushell_types::{
    CommandSequenceNo, PathContentConsumeFact, PathContentProduceFact, PayloadArtifactConsume,
    PayloadArtifactProducer, PayloadProvenanceTrace, PayloadSinkStatus, ProvenanceArtifact,
    ProvenanceConsumeKind, ProvenanceEdgeSemantics, ProvenanceProduceKind, RuntimeInputCapture,
    RuntimeInputConsumeFact, RuntimeInputSource, StartupConfigArtifactConsume,
    StartupConfigArtifactProducer, StartupConfigProvenanceTrace, StartupConfigSinkStatus,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathContentConsumeQuery {
    path: Option<String>,
    consume_kind: Option<ProvenanceConsumeKind>,
    used_by_root_sequence: Option<CommandSequenceNo>,
    used_by_execution_unit_node_id: Option<NodeId>,
    window: SequenceWindow,
}

impl PathContentConsumeQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn consume_kind(mut self, consume_kind: ProvenanceConsumeKind) -> Self {
        self.consume_kind = Some(consume_kind);
        self
    }

    pub fn used_by_root_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.used_by_root_sequence = Some(sequence_no);
        self
    }

    pub fn used_by_execution_unit_node_id(mut self, node_id: NodeId) -> Self {
        self.used_by_execution_unit_node_id = Some(node_id);
        self
    }

    pub fn after_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.after_sequence(sequence_no);
        self
    }

    pub fn before_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.before_sequence(sequence_no);
        self
    }

    pub fn window(mut self, window: SequenceWindow) -> Self {
        self.window = window;
        self
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> PathContentConsumeResult<'a> {
        let mut consumes = Vec::new();

        if self.used_by_execution_unit_node_id.is_none() && self.path.is_some() {
            let path = self.path.as_deref().expect("path checked above");
            for artifact_node in session.graph().path_content_artifact_nodes_by_path(path) {
                let Some((artifact_path, version)) = path_content_artifact(artifact_node) else {
                    continue;
                };

                for edge in session.graph().incoming_edges(&artifact_node.id) {
                    if edge.kind != EdgeKind::Consumes {
                        continue;
                    }

                    let Some(ProvenanceEdgeSemantics::Consume {
                        consume_kind,
                        slot_name,
                        normalized_command_name,
                        ..
                    }) = edge.semantics.as_ref()
                    else {
                        continue;
                    };

                    let Some(source_node) = session.graph().get_node(&edge.from) else {
                        continue;
                    };
                    let Some(execution_unit) = ExecutionUnitRef::from_node(source_node) else {
                        continue;
                    };

                    if !self
                        .window
                        .contains(execution_unit.root_command_sequence_no())
                    {
                        continue;
                    }
                    if self.used_by_root_sequence.is_some_and(|sequence_no| {
                        execution_unit.root_command_sequence_no() != sequence_no
                    }) {
                        continue;
                    }
                    if self
                        .consume_kind
                        .is_some_and(|expected| expected != *consume_kind)
                    {
                        continue;
                    }

                    consumes.push(PathContentConsumeRef {
                        artifact_node_id: &artifact_node.id,
                        execution_unit,
                        path: artifact_path,
                        version,
                        consume_kind: *consume_kind,
                        slot_name: slot_name.clone(),
                        normalized_command_name: normalized_command_name.clone(),
                    });
                }
            }
        } else {
            for execution_unit in query_source_units(
                session,
                self.window,
                self.used_by_root_sequence,
                self.used_by_execution_unit_node_id.as_ref(),
            ) {
                for edge in session.graph().outgoing_edges(execution_unit.node_id()) {
                    if edge.kind != EdgeKind::Consumes {
                        continue;
                    }

                    let Some(ProvenanceEdgeSemantics::Consume {
                        consume_kind,
                        slot_name,
                        normalized_command_name,
                        ..
                    }) = edge.semantics.as_ref()
                    else {
                        continue;
                    };

                    let Some(artifact_node) = session.graph().get_node(&edge.to) else {
                        continue;
                    };
                    let Some((path, version)) = path_content_artifact(artifact_node) else {
                        continue;
                    };

                    if self
                        .path
                        .as_deref()
                        .is_some_and(|expected| expected != path)
                    {
                        continue;
                    }

                    if self
                        .consume_kind
                        .is_some_and(|expected| expected != *consume_kind)
                    {
                        continue;
                    }

                    consumes.push(PathContentConsumeRef {
                        artifact_node_id: &artifact_node.id,
                        execution_unit,
                        path,
                        version,
                        consume_kind: *consume_kind,
                        slot_name: slot_name.clone(),
                        normalized_command_name: normalized_command_name.clone(),
                    });
                }
            }
        }

        consumes.sort_by(|left, right| {
            left.execution_unit()
                .root_command_sequence_no()
                .cmp(&right.execution_unit().root_command_sequence_no())
                .then_with(|| {
                    left.execution_unit()
                        .depth()
                        .cmp(&right.execution_unit().depth())
                })
                .then_with(|| {
                    left.execution_unit()
                        .node_id()
                        .0
                        .cmp(&right.execution_unit().node_id().0)
                })
                .then_with(|| left.path().cmp(right.path()))
                .then_with(|| left.artifact_node_id().0.cmp(&right.artifact_node_id().0))
        });

        PathContentConsumeResult { consumes }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathContentConsumeResult<'a> {
    consumes: Vec<PathContentConsumeRef<'a>>,
}

impl<'a> PathContentConsumeResult<'a> {
    pub fn consumes(&self) -> &[PathContentConsumeRef<'a>] {
        self.consumes.as_slice()
    }

    pub fn len(&self) -> usize {
        self.consumes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.consumes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathContentConsumeRef<'a> {
    artifact_node_id: &'a NodeId,
    execution_unit: ExecutionUnitRef<'a>,
    path: &'a str,
    version: Option<u64>,
    consume_kind: ProvenanceConsumeKind,
    slot_name: Option<String>,
    normalized_command_name: Option<String>,
}

impl<'a> PathContentConsumeRef<'a> {
    pub fn artifact_node_id(&self) -> &'a NodeId {
        self.artifact_node_id
    }

    pub fn execution_unit(&self) -> ExecutionUnitRef<'a> {
        self.execution_unit
    }

    pub fn path(&self) -> &'a str {
        self.path
    }

    pub fn version(&self) -> Option<u64> {
        self.version
    }

    pub fn consume_kind(&self) -> ProvenanceConsumeKind {
        self.consume_kind
    }

    pub fn slot_name(&self) -> Option<&str> {
        self.slot_name.as_deref()
    }

    pub fn normalized_command_name(&self) -> Option<&str> {
        self.normalized_command_name.as_deref()
    }

    pub fn to_path_content_consume_fact(&self) -> PathContentConsumeFact {
        PathContentConsumeFact {
            artifact_node_id: self.artifact_node_id.0.clone(),
            source: self.execution_unit.to_execution_unit(),
            path: self.path.to_string(),
            version: self.version,
            consume_kind: self.consume_kind,
            slot_name: self.slot_name.clone(),
            normalized_command_name: self.normalized_command_name.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathContentProduceQuery {
    path: Option<String>,
    produce_kind: Option<ProvenanceProduceKind>,
    produced_by_root_sequence: Option<CommandSequenceNo>,
    produced_by_execution_unit_node_id: Option<NodeId>,
    before_execution_unit_node_id: Option<NodeId>,
    window: SequenceWindow,
}

impl PathContentProduceQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn produce_kind(mut self, produce_kind: ProvenanceProduceKind) -> Self {
        self.produce_kind = Some(produce_kind);
        self
    }

    pub fn produced_by_root_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.produced_by_root_sequence = Some(sequence_no);
        self
    }

    pub fn produced_by_execution_unit_node_id(mut self, node_id: NodeId) -> Self {
        self.produced_by_execution_unit_node_id = Some(node_id);
        self
    }

    pub fn after_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.after_sequence(sequence_no);
        self
    }

    pub fn before_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.before_sequence(sequence_no);
        self
    }

    pub fn before_execution_unit_node_id(mut self, node_id: NodeId) -> Self {
        self.before_execution_unit_node_id = Some(node_id);
        self
    }

    pub fn window(mut self, window: SequenceWindow) -> Self {
        self.window = window;
        self
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> PathContentProduceResult<'a> {
        let mut produces = Vec::new();
        let before_execution_unit = self
            .before_execution_unit_node_id
            .as_ref()
            .and_then(|node_id| session.graph().get_node(node_id))
            .and_then(ExecutionUnitRef::from_node);

        if self.produced_by_execution_unit_node_id.is_none() && self.path.is_some() {
            let path = self.path.as_deref().expect("path checked above");
            for artifact_node in session.graph().path_content_artifact_nodes_by_path(path) {
                let Some((artifact_path, version)) = path_content_artifact(artifact_node) else {
                    continue;
                };

                for edge in session.graph().incoming_edges(&artifact_node.id) {
                    if edge.kind != EdgeKind::Produces {
                        continue;
                    }

                    let Some(ProvenanceEdgeSemantics::Produce {
                        produce_kind,
                        slot_name,
                        normalized_command_name,
                        ..
                    }) = edge.semantics.as_ref()
                    else {
                        continue;
                    };

                    let Some(source_node) = session.graph().get_node(&edge.from) else {
                        continue;
                    };
                    let Some(execution_unit) = ExecutionUnitRef::from_node(source_node) else {
                        continue;
                    };

                    if !self
                        .window
                        .contains(execution_unit.root_command_sequence_no())
                    {
                        continue;
                    }
                    if before_execution_unit
                        .is_some_and(|before| !execution_unit_precedes(execution_unit, before))
                    {
                        continue;
                    }
                    if self.produced_by_root_sequence.is_some_and(|sequence_no| {
                        execution_unit.root_command_sequence_no() != sequence_no
                    }) {
                        continue;
                    }
                    if self
                        .produce_kind
                        .is_some_and(|expected| expected != *produce_kind)
                    {
                        continue;
                    }

                    produces.push(PathContentProduceRef {
                        artifact_node_id: &artifact_node.id,
                        execution_unit,
                        path: artifact_path,
                        version,
                        produce_kind: *produce_kind,
                        slot_name: slot_name.clone(),
                        normalized_command_name: normalized_command_name.clone(),
                    });
                }
            }
        } else {
            for execution_unit in query_source_units(
                session,
                self.window,
                self.produced_by_root_sequence,
                self.produced_by_execution_unit_node_id.as_ref(),
            ) {
                if before_execution_unit
                    .is_some_and(|before| !execution_unit_precedes(execution_unit, before))
                {
                    continue;
                }
                for edge in session.graph().outgoing_edges(execution_unit.node_id()) {
                    if edge.kind != EdgeKind::Produces {
                        continue;
                    }

                    let Some(ProvenanceEdgeSemantics::Produce {
                        produce_kind,
                        slot_name,
                        normalized_command_name,
                        ..
                    }) = edge.semantics.as_ref()
                    else {
                        continue;
                    };

                    let Some(artifact_node) = session.graph().get_node(&edge.to) else {
                        continue;
                    };
                    let Some((path, version)) = path_content_artifact(artifact_node) else {
                        continue;
                    };

                    if self
                        .path
                        .as_deref()
                        .is_some_and(|expected| expected != path)
                    {
                        continue;
                    }

                    if self
                        .produce_kind
                        .is_some_and(|expected| expected != *produce_kind)
                    {
                        continue;
                    }

                    produces.push(PathContentProduceRef {
                        artifact_node_id: &artifact_node.id,
                        execution_unit,
                        path,
                        version,
                        produce_kind: *produce_kind,
                        slot_name: slot_name.clone(),
                        normalized_command_name: normalized_command_name.clone(),
                    });
                }
            }
        }

        produces.sort_by(|left, right| {
            left.execution_unit()
                .root_command_sequence_no()
                .cmp(&right.execution_unit().root_command_sequence_no())
                .then_with(|| {
                    left.execution_unit()
                        .depth()
                        .cmp(&right.execution_unit().depth())
                })
                .then_with(|| {
                    left.execution_unit()
                        .node_id()
                        .0
                        .cmp(&right.execution_unit().node_id().0)
                })
                .then_with(|| left.path().cmp(right.path()))
                .then_with(|| left.artifact_node_id().0.cmp(&right.artifact_node_id().0))
        });

        PathContentProduceResult { produces }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathContentProduceResult<'a> {
    produces: Vec<PathContentProduceRef<'a>>,
}

impl<'a> PathContentProduceResult<'a> {
    pub fn produces(&self) -> &[PathContentProduceRef<'a>] {
        self.produces.as_slice()
    }

    pub fn len(&self) -> usize {
        self.produces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.produces.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathContentProduceRef<'a> {
    artifact_node_id: &'a NodeId,
    execution_unit: ExecutionUnitRef<'a>,
    path: &'a str,
    version: Option<u64>,
    produce_kind: ProvenanceProduceKind,
    slot_name: Option<String>,
    normalized_command_name: Option<String>,
}

impl<'a> PathContentProduceRef<'a> {
    pub fn artifact_node_id(&self) -> &'a NodeId {
        self.artifact_node_id
    }

    pub fn execution_unit(&self) -> ExecutionUnitRef<'a> {
        self.execution_unit
    }

    pub fn path(&self) -> &'a str {
        self.path
    }

    pub fn version(&self) -> Option<u64> {
        self.version
    }

    pub fn produce_kind(&self) -> ProvenanceProduceKind {
        self.produce_kind
    }

    pub fn slot_name(&self) -> Option<&str> {
        self.slot_name.as_deref()
    }

    pub fn normalized_command_name(&self) -> Option<&str> {
        self.normalized_command_name.as_deref()
    }

    pub fn to_path_content_produce_fact(&self) -> PathContentProduceFact {
        PathContentProduceFact {
            artifact_node_id: self.artifact_node_id.0.clone(),
            source: self.execution_unit.to_execution_unit(),
            path: self.path.to_string(),
            version: self.version,
            produce_kind: self.produce_kind,
            slot_name: self.slot_name.clone(),
            normalized_command_name: self.normalized_command_name.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathContentOriginStatus {
    PriorSessionWriteObserved,
    NoPriorSessionWriteObserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathContentOriginQuery {
    path: Option<String>,
    consume_kind: Option<ProvenanceConsumeKind>,
    used_by_root_sequence: Option<CommandSequenceNo>,
    used_by_execution_unit_node_id: Option<NodeId>,
    window: SequenceWindow,
}

impl PathContentOriginQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn consume_kind(mut self, consume_kind: ProvenanceConsumeKind) -> Self {
        self.consume_kind = Some(consume_kind);
        self
    }

    pub fn used_by_root_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.used_by_root_sequence = Some(sequence_no);
        self
    }

    pub fn used_by_execution_unit_node_id(mut self, node_id: NodeId) -> Self {
        self.used_by_execution_unit_node_id = Some(node_id);
        self
    }

    pub fn after_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.after_sequence(sequence_no);
        self
    }

    pub fn before_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.before_sequence(sequence_no);
        self
    }

    pub fn window(mut self, window: SequenceWindow) -> Self {
        self.window = window;
        self
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> PathContentOriginResult<'a> {
        let consumes = PathContentConsumeQuery::new()
            .window(self.window)
            .path_if_some(self.path.clone())
            .consume_kind_if_some(self.consume_kind)
            .used_by_root_sequence_if_some(self.used_by_root_sequence)
            .used_by_execution_unit_node_id_if_some(self.used_by_execution_unit_node_id.clone())
            .execute(session);
        if consumes.is_empty() {
            return PathContentOriginResult {
                origins: Vec::new(),
            };
        }

        let max_sequence = consumes
            .consumes()
            .iter()
            .map(|consume| consume.execution_unit().root_command_sequence_no())
            .max();
        let mut produces_query =
            PathContentProduceQuery::new().produce_kind(ProvenanceProduceKind::PathWrite);

        if let Some(path) = &self.path {
            produces_query = produces_query.path(path.clone());
        }
        if let Some(sequence_no) = max_sequence {
            produces_query = produces_query.before_sequence(sequence_no.next());
        }

        let produces = produces_query.execute(session);
        let mut produces_by_path: BTreeMap<&str, Vec<PathContentProduceRef<'a>>> = BTreeMap::new();
        for produce in produces.produces() {
            produces_by_path
                .entry(produce.path())
                .or_default()
                .push(produce.clone());
        }

        let mut origins = Vec::with_capacity(consumes.len());
        for consume in consumes.consumes() {
            let prior_writes = produces_by_path
                .get(consume.path())
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let mut prior_write_count = 0;
            let mut latest_prior_write = None;

            for write in prior_writes {
                if write.execution_unit().root_command_sequence_no()
                    >= consume.execution_unit().root_command_sequence_no()
                {
                    break;
                }

                prior_write_count += 1;
                latest_prior_write = Some(write.clone());
            }

            origins.push(PathContentOriginRef {
                consume: consume.clone(),
                origin_status: if prior_write_count > 0 {
                    PathContentOriginStatus::PriorSessionWriteObserved
                } else {
                    PathContentOriginStatus::NoPriorSessionWriteObserved
                },
                latest_prior_write,
                prior_write_count,
            });
        }

        PathContentOriginResult { origins }
    }
}

trait PathContentQueryOptionExt: Sized {
    fn path_if_some(self, path: Option<String>) -> Self;
    fn consume_kind_if_some(self, consume_kind: Option<ProvenanceConsumeKind>) -> Self;
    fn used_by_root_sequence_if_some(self, sequence_no: Option<CommandSequenceNo>) -> Self;
    fn used_by_execution_unit_node_id_if_some(self, node_id: Option<NodeId>) -> Self;
}

impl PathContentQueryOptionExt for PathContentConsumeQuery {
    fn path_if_some(self, path: Option<String>) -> Self {
        if let Some(path) = path {
            return self.path(path);
        }

        self
    }

    fn consume_kind_if_some(self, consume_kind: Option<ProvenanceConsumeKind>) -> Self {
        if let Some(consume_kind) = consume_kind {
            return self.consume_kind(consume_kind);
        }

        self
    }

    fn used_by_root_sequence_if_some(self, sequence_no: Option<CommandSequenceNo>) -> Self {
        if let Some(sequence_no) = sequence_no {
            return self.used_by_root_sequence(sequence_no);
        }

        self
    }

    fn used_by_execution_unit_node_id_if_some(self, node_id: Option<NodeId>) -> Self {
        if let Some(node_id) = node_id {
            return self.used_by_execution_unit_node_id(node_id);
        }

        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathContentOriginResult<'a> {
    origins: Vec<PathContentOriginRef<'a>>,
}

impl<'a> PathContentOriginResult<'a> {
    pub fn origins(&self) -> &[PathContentOriginRef<'a>] {
        self.origins.as_slice()
    }

    pub fn len(&self) -> usize {
        self.origins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathContentOriginRef<'a> {
    consume: PathContentConsumeRef<'a>,
    origin_status: PathContentOriginStatus,
    latest_prior_write: Option<PathContentProduceRef<'a>>,
    prior_write_count: usize,
}

impl<'a> PathContentOriginRef<'a> {
    pub fn consume(&self) -> &PathContentConsumeRef<'a> {
        &self.consume
    }

    pub fn origin_status(&self) -> PathContentOriginStatus {
        self.origin_status
    }

    pub fn latest_prior_write(&self) -> Option<&PathContentProduceRef<'a>> {
        self.latest_prior_write.as_ref()
    }

    pub fn prior_write_count(&self) -> usize {
        self.prior_write_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeInputConsumeQuery {
    source: Option<RuntimeInputSource>,
    used_by_root_sequence: Option<CommandSequenceNo>,
    used_by_execution_unit_node_id: Option<NodeId>,
    window: SequenceWindow,
}

impl RuntimeInputConsumeQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn source(mut self, source: RuntimeInputSource) -> Self {
        self.source = Some(source);
        self
    }

    pub fn used_by_root_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.used_by_root_sequence = Some(sequence_no);
        self
    }

    pub fn used_by_execution_unit_node_id(mut self, node_id: NodeId) -> Self {
        self.used_by_execution_unit_node_id = Some(node_id);
        self
    }

    pub fn after_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.after_sequence(sequence_no);
        self
    }

    pub fn before_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.window = self.window.before_sequence(sequence_no);
        self
    }

    pub fn window(mut self, window: SequenceWindow) -> Self {
        self.window = window;
        self
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> RuntimeInputConsumeResult<'a> {
        let mut consumes = Vec::new();

        for execution_unit in query_source_units(
            session,
            self.window,
            self.used_by_root_sequence,
            self.used_by_execution_unit_node_id.as_ref(),
        ) {
            for edge in session.graph().outgoing_edges(execution_unit.node_id()) {
                if edge.kind != EdgeKind::Consumes {
                    continue;
                }

                let Some(ProvenanceEdgeSemantics::Consume {
                    consume_kind,
                    slot_name,
                    normalized_command_name,
                    ..
                }) = edge.semantics.as_ref()
                else {
                    continue;
                };

                if *consume_kind != ProvenanceConsumeKind::RuntimeInput {
                    continue;
                }

                let Some(artifact_node) = session.graph().get_node(&edge.to) else {
                    continue;
                };
                let Some((runtime_input_source, capture, version)) =
                    runtime_input_artifact(artifact_node)
                else {
                    continue;
                };

                if self
                    .source
                    .is_some_and(|expected| expected != runtime_input_source)
                {
                    continue;
                }

                consumes.push(RuntimeInputConsumeRef {
                    artifact_node_id: &artifact_node.id,
                    execution_unit,
                    runtime_input_source,
                    capture,
                    version,
                    consume_kind: *consume_kind,
                    slot_name: slot_name.clone(),
                    normalized_command_name: normalized_command_name.clone(),
                });
            }
        }

        consumes.sort_by(|left, right| {
            left.execution_unit()
                .root_command_sequence_no()
                .cmp(&right.execution_unit().root_command_sequence_no())
                .then_with(|| {
                    left.execution_unit()
                        .depth()
                        .cmp(&right.execution_unit().depth())
                })
                .then_with(|| {
                    left.execution_unit()
                        .node_id()
                        .0
                        .cmp(&right.execution_unit().node_id().0)
                })
                .then_with(|| {
                    runtime_input_source_sort_key(left.runtime_input_source())
                        .cmp(&runtime_input_source_sort_key(right.runtime_input_source()))
                })
                .then_with(|| left.artifact_node_id().0.cmp(&right.artifact_node_id().0))
        });

        RuntimeInputConsumeResult { consumes }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInputConsumeResult<'a> {
    consumes: Vec<RuntimeInputConsumeRef<'a>>,
}

impl<'a> RuntimeInputConsumeResult<'a> {
    pub fn consumes(&self) -> &[RuntimeInputConsumeRef<'a>] {
        self.consumes.as_slice()
    }

    pub fn len(&self) -> usize {
        self.consumes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.consumes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInputConsumeRef<'a> {
    artifact_node_id: &'a NodeId,
    execution_unit: ExecutionUnitRef<'a>,
    runtime_input_source: RuntimeInputSource,
    capture: &'a RuntimeInputCapture,
    version: u64,
    consume_kind: ProvenanceConsumeKind,
    slot_name: Option<String>,
    normalized_command_name: Option<String>,
}

impl<'a> RuntimeInputConsumeRef<'a> {
    pub fn artifact_node_id(&self) -> &'a NodeId {
        self.artifact_node_id
    }

    pub fn execution_unit(&self) -> ExecutionUnitRef<'a> {
        self.execution_unit
    }

    pub fn runtime_input_source(&self) -> RuntimeInputSource {
        self.runtime_input_source
    }

    pub fn capture(&self) -> &'a RuntimeInputCapture {
        self.capture
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn consume_kind(&self) -> ProvenanceConsumeKind {
        self.consume_kind
    }

    pub fn slot_name(&self) -> Option<&str> {
        self.slot_name.as_deref()
    }

    pub fn normalized_command_name(&self) -> Option<&str> {
        self.normalized_command_name.as_deref()
    }

    pub fn to_runtime_input_consume_fact(&self) -> RuntimeInputConsumeFact {
        RuntimeInputConsumeFact {
            artifact_node_id: self.artifact_node_id.0.clone(),
            source: self.execution_unit.to_execution_unit(),
            runtime_input_source: self.runtime_input_source,
            capture: self.capture.clone(),
            version: self.version,
            consume_kind: self.consume_kind,
            slot_name: self.slot_name.clone(),
            normalized_command_name: self.normalized_command_name.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PayloadProvenanceTraceQuery {
    execution_unit_node_id: Option<NodeId>,
}

impl PayloadProvenanceTraceQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn execution_unit_node_id(mut self, node_id: NodeId) -> Self {
        self.execution_unit_node_id = Some(node_id);
        self
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> PayloadProvenanceTraceResult<'a> {
        let trace = self
            .execution_unit_node_id
            .as_ref()
            .and_then(|node_id| payload_provenance_trace_for_execution_unit(session, node_id));

        PayloadProvenanceTraceResult { trace }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadProvenanceTraceResult<'a> {
    trace: Option<PayloadProvenanceTraceRef<'a>>,
}

impl<'a> PayloadProvenanceTraceResult<'a> {
    pub fn trace(&self) -> Option<&PayloadProvenanceTraceRef<'a>> {
        self.trace.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StartupConfigProvenanceTraceQuery {
    execution_unit_node_id: Option<NodeId>,
}

impl StartupConfigProvenanceTraceQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn execution_unit_node_id(mut self, node_id: NodeId) -> Self {
        self.execution_unit_node_id = Some(node_id);
        self
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> StartupConfigProvenanceTraceResult<'a> {
        let trace = self.execution_unit_node_id.as_ref().and_then(|node_id| {
            startup_config_provenance_trace_for_execution_unit(session, node_id)
        });

        StartupConfigProvenanceTraceResult { trace }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupConfigProvenanceTraceResult<'a> {
    trace: Option<StartupConfigProvenanceTraceRef<'a>>,
}

impl<'a> StartupConfigProvenanceTraceResult<'a> {
    pub fn trace(&self) -> Option<&StartupConfigProvenanceTraceRef<'a>> {
        self.trace.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadSinkStatusRef {
    MissingSemantics,
    NotPayloadSink,
    PayloadSink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupConfigSinkStatusRef {
    MissingSemantics,
    NotStartupConfigSink,
    StartupConfigSink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadArtifactProducerRef<'a> {
    execution_unit: ExecutionUnitRef<'a>,
    produce_kind: ProvenanceProduceKind,
    slot_name: Option<String>,
    normalized_command_name: Option<String>,
}

impl<'a> PayloadArtifactProducerRef<'a> {
    pub fn execution_unit(&self) -> ExecutionUnitRef<'a> {
        self.execution_unit
    }

    pub fn produce_kind(&self) -> ProvenanceProduceKind {
        self.produce_kind
    }

    pub fn slot_name(&self) -> Option<&str> {
        self.slot_name.as_deref()
    }

    pub fn normalized_command_name(&self) -> Option<&str> {
        self.normalized_command_name.as_deref()
    }

    pub fn to_payload_artifact_producer(&self) -> PayloadArtifactProducer {
        PayloadArtifactProducer {
            source: self.execution_unit.to_execution_unit(),
            produce_kind: self.produce_kind,
            slot_name: self.slot_name.clone(),
            normalized_command_name: self.normalized_command_name.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupConfigArtifactProducerRef<'a> {
    execution_unit: ExecutionUnitRef<'a>,
    produce_kind: ProvenanceProduceKind,
    slot_name: Option<String>,
    normalized_command_name: Option<String>,
}

impl<'a> StartupConfigArtifactProducerRef<'a> {
    pub fn execution_unit(&self) -> ExecutionUnitRef<'a> {
        self.execution_unit
    }

    pub fn produce_kind(&self) -> ProvenanceProduceKind {
        self.produce_kind
    }

    pub fn slot_name(&self) -> Option<&str> {
        self.slot_name.as_deref()
    }

    pub fn normalized_command_name(&self) -> Option<&str> {
        self.normalized_command_name.as_deref()
    }

    pub fn to_startup_config_artifact_producer(&self) -> StartupConfigArtifactProducer {
        StartupConfigArtifactProducer {
            source: self.execution_unit.to_execution_unit(),
            produce_kind: self.produce_kind,
            slot_name: self.slot_name.clone(),
            normalized_command_name: self.normalized_command_name.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadArtifactConsumeRef<'a> {
    artifact_node_id: &'a NodeId,
    artifact: &'a ProvenanceArtifact,
    consume_kind: ProvenanceConsumeKind,
    slot_name: Option<String>,
    normalized_command_name: Option<String>,
    producers: Vec<PayloadArtifactProducerRef<'a>>,
}

impl<'a> PayloadArtifactConsumeRef<'a> {
    pub fn artifact_node_id(&self) -> &'a NodeId {
        self.artifact_node_id
    }

    pub fn artifact(&self) -> &'a ProvenanceArtifact {
        self.artifact
    }

    pub fn consume_kind(&self) -> ProvenanceConsumeKind {
        self.consume_kind
    }

    pub fn slot_name(&self) -> Option<&str> {
        self.slot_name.as_deref()
    }

    pub fn normalized_command_name(&self) -> Option<&str> {
        self.normalized_command_name.as_deref()
    }

    pub fn producers(&self) -> &[PayloadArtifactProducerRef<'a>] {
        self.producers.as_slice()
    }

    pub fn to_payload_artifact_consume(&self) -> PayloadArtifactConsume {
        PayloadArtifactConsume {
            artifact_node_id: self.artifact_node_id.0.clone(),
            artifact: self.artifact.clone(),
            consume_kind: self.consume_kind,
            slot_name: self.slot_name.clone(),
            normalized_command_name: self.normalized_command_name.clone(),
            producers: self
                .producers
                .iter()
                .map(PayloadArtifactProducerRef::to_payload_artifact_producer)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupConfigArtifactConsumeRef<'a> {
    artifact_node_id: &'a NodeId,
    artifact: &'a ProvenanceArtifact,
    consume_kind: ProvenanceConsumeKind,
    slot_name: Option<String>,
    normalized_command_name: Option<String>,
    producers: Vec<StartupConfigArtifactProducerRef<'a>>,
}

impl<'a> StartupConfigArtifactConsumeRef<'a> {
    pub fn artifact_node_id(&self) -> &'a NodeId {
        self.artifact_node_id
    }

    pub fn artifact(&self) -> &'a ProvenanceArtifact {
        self.artifact
    }

    pub fn consume_kind(&self) -> ProvenanceConsumeKind {
        self.consume_kind
    }

    pub fn slot_name(&self) -> Option<&str> {
        self.slot_name.as_deref()
    }

    pub fn normalized_command_name(&self) -> Option<&str> {
        self.normalized_command_name.as_deref()
    }

    pub fn producers(&self) -> &[StartupConfigArtifactProducerRef<'a>] {
        self.producers.as_slice()
    }

    pub fn to_startup_config_artifact_consume(&self) -> StartupConfigArtifactConsume {
        StartupConfigArtifactConsume {
            artifact_node_id: self.artifact_node_id.0.clone(),
            artifact: self.artifact.clone(),
            consume_kind: self.consume_kind,
            slot_name: self.slot_name.clone(),
            normalized_command_name: self.normalized_command_name.clone(),
            producers: self
                .producers
                .iter()
                .map(StartupConfigArtifactProducerRef::to_startup_config_artifact_producer)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadProvenanceTraceRef<'a> {
    source: ExecutionUnitRef<'a>,
    semantics: Option<ExecutionSemanticsRef<'a>>,
    sink_status: PayloadSinkStatusRef,
    payload_inputs: Vec<PayloadArtifactConsumeRef<'a>>,
}

impl<'a> PayloadProvenanceTraceRef<'a> {
    pub fn source(&self) -> ExecutionUnitRef<'a> {
        self.source
    }

    pub fn semantics(&self) -> Option<ExecutionSemanticsRef<'a>> {
        self.semantics
    }

    pub fn sink_status(&self) -> PayloadSinkStatusRef {
        self.sink_status
    }

    pub fn payload_inputs(&self) -> &[PayloadArtifactConsumeRef<'a>] {
        self.payload_inputs.as_slice()
    }

    pub fn to_payload_provenance_trace(&self) -> PayloadProvenanceTrace {
        PayloadProvenanceTrace {
            source: self.source.to_execution_unit(),
            semantics: self
                .semantics
                .map(|semantics| semantics.to_execution_semantics_fact()),
            sink_status: self.sink_status.to_payload_sink_status(),
            payload_inputs: self
                .payload_inputs
                .iter()
                .map(PayloadArtifactConsumeRef::to_payload_artifact_consume)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupConfigProvenanceTraceRef<'a> {
    source: ExecutionUnitRef<'a>,
    semantics: Option<ExecutionSemanticsRef<'a>>,
    sink_status: StartupConfigSinkStatusRef,
    startup_config_inputs: Vec<StartupConfigArtifactConsumeRef<'a>>,
}

impl<'a> StartupConfigProvenanceTraceRef<'a> {
    pub fn source(&self) -> ExecutionUnitRef<'a> {
        self.source
    }

    pub fn semantics(&self) -> Option<ExecutionSemanticsRef<'a>> {
        self.semantics
    }

    pub fn sink_status(&self) -> StartupConfigSinkStatusRef {
        self.sink_status
    }

    pub fn startup_config_inputs(&self) -> &[StartupConfigArtifactConsumeRef<'a>] {
        self.startup_config_inputs.as_slice()
    }

    pub fn to_startup_config_provenance_trace(&self) -> StartupConfigProvenanceTrace {
        StartupConfigProvenanceTrace {
            source: self.source.to_execution_unit(),
            semantics: self
                .semantics
                .map(|semantics| semantics.to_execution_semantics_fact()),
            sink_status: self.sink_status.to_startup_config_sink_status(),
            startup_config_inputs: self
                .startup_config_inputs
                .iter()
                .map(StartupConfigArtifactConsumeRef::to_startup_config_artifact_consume)
                .collect(),
        }
    }
}

impl PayloadSinkStatusRef {
    pub fn to_payload_sink_status(self) -> PayloadSinkStatus {
        match self {
            Self::MissingSemantics => PayloadSinkStatus::MissingSemantics,
            Self::NotPayloadSink => PayloadSinkStatus::NotPayloadSink,
            Self::PayloadSink => PayloadSinkStatus::PayloadSink,
        }
    }
}

impl StartupConfigSinkStatusRef {
    pub fn to_startup_config_sink_status(self) -> StartupConfigSinkStatus {
        match self {
            Self::MissingSemantics => StartupConfigSinkStatus::MissingSemantics,
            Self::NotStartupConfigSink => StartupConfigSinkStatus::NotStartupConfigSink,
            Self::StartupConfigSink => StartupConfigSinkStatus::StartupConfigSink,
        }
    }
}

fn payload_provenance_trace_for_execution_unit<'a>(
    session: QuerySession<'a>,
    node_id: &NodeId,
) -> Option<PayloadProvenanceTraceRef<'a>> {
    let source_node = session.graph().get_node(node_id)?;
    let source = ExecutionUnitRef::from_node(source_node)?;
    let semantics = execution_semantics_for_source(session, node_id);

    let (sink_status, payload_inputs) = match semantics {
        None => (PayloadSinkStatusRef::MissingSemantics, Vec::new()),
        Some(semantics) if !semantics.executes_payload() => {
            (PayloadSinkStatusRef::NotPayloadSink, Vec::new())
        }
        Some(semantics) => (
            PayloadSinkStatusRef::PayloadSink,
            collect_payload_inputs_for_sink(session, semantics),
        ),
    };

    Some(PayloadProvenanceTraceRef {
        source,
        semantics,
        sink_status,
        payload_inputs,
    })
}

fn startup_config_provenance_trace_for_execution_unit<'a>(
    session: QuerySession<'a>,
    node_id: &NodeId,
) -> Option<StartupConfigProvenanceTraceRef<'a>> {
    let source_node = session.graph().get_node(node_id)?;
    let source = ExecutionUnitRef::from_node(source_node)?;
    let semantics = execution_semantics_for_source(session, node_id);

    let (sink_status, startup_config_inputs) = match semantics {
        None => (StartupConfigSinkStatusRef::MissingSemantics, Vec::new()),
        Some(semantics) if !semantics.loads_startup_config() => {
            (StartupConfigSinkStatusRef::NotStartupConfigSink, Vec::new())
        }
        Some(semantics) => (
            StartupConfigSinkStatusRef::StartupConfigSink,
            collect_startup_config_inputs_for_sink(session, semantics),
        ),
    };

    Some(StartupConfigProvenanceTraceRef {
        source,
        semantics,
        sink_status,
        startup_config_inputs,
    })
}

fn execution_semantics_for_source<'a>(
    session: QuerySession<'a>,
    node_id: &NodeId,
) -> Option<ExecutionSemanticsRef<'a>> {
    ExecutionSemanticsQuery::new()
        .execution_unit_node_id(node_id.clone())
        .execute(session)
        .semantics()
        .first()
        .copied()
}

fn collect_payload_inputs_for_sink<'a>(
    session: QuerySession<'a>,
    semantics: ExecutionSemanticsRef<'a>,
) -> Vec<PayloadArtifactConsumeRef<'a>> {
    let mut consumes = Vec::new();

    for edge in session.graph().outgoing_edges(semantics.source().node_id()) {
        if edge.kind != EdgeKind::Consumes {
            continue;
        }

        let Some(ProvenanceEdgeSemantics::Consume {
            consume_kind,
            slot_name,
            normalized_command_name,
            ..
        }) = edge.semantics.as_ref()
        else {
            continue;
        };

        if !matches_payload_consume_kind(*consume_kind, semantics) {
            continue;
        }

        let Some(artifact_node) = session.graph().get_node(&edge.to) else {
            continue;
        };
        let NodeKind::ProvenanceArtifact { artifact } = &artifact_node.kind else {
            continue;
        };

        consumes.push(PayloadArtifactConsumeRef {
            artifact_node_id: &artifact_node.id,
            artifact,
            consume_kind: *consume_kind,
            slot_name: slot_name.clone(),
            normalized_command_name: normalized_command_name.clone(),
            producers: collect_payload_producers_for_artifact(session, &artifact_node.id),
        });
    }

    consumes.sort_by(|left, right| {
        left.artifact_node_id()
            .0
            .cmp(&right.artifact_node_id().0)
            .then_with(|| left.slot_name().cmp(&right.slot_name()))
    });

    consumes
}

fn collect_startup_config_inputs_for_sink<'a>(
    session: QuerySession<'a>,
    semantics: ExecutionSemanticsRef<'a>,
) -> Vec<StartupConfigArtifactConsumeRef<'a>> {
    let mut consumes = Vec::new();

    for edge in session.graph().outgoing_edges(semantics.source().node_id()) {
        if edge.kind != EdgeKind::Consumes {
            continue;
        }

        let Some(ProvenanceEdgeSemantics::Consume {
            consume_kind,
            slot_name,
            normalized_command_name,
            ..
        }) = edge.semantics.as_ref()
        else {
            continue;
        };

        if !matches_startup_config_consume_kind(*consume_kind, semantics) {
            continue;
        }

        let Some(artifact_node) = session.graph().get_node(&edge.to) else {
            continue;
        };
        let NodeKind::ProvenanceArtifact { artifact } = &artifact_node.kind else {
            continue;
        };

        consumes.push(StartupConfigArtifactConsumeRef {
            artifact_node_id: &artifact_node.id,
            artifact,
            consume_kind: *consume_kind,
            slot_name: slot_name.clone(),
            normalized_command_name: normalized_command_name.clone(),
            producers: collect_startup_config_producers_for_artifact(session, &artifact_node.id),
        });
    }

    consumes.sort_by(|left, right| {
        left.artifact_node_id()
            .0
            .cmp(&right.artifact_node_id().0)
            .then_with(|| left.slot_name().cmp(&right.slot_name()))
    });

    consumes
}

fn matches_payload_consume_kind(
    consume_kind: ProvenanceConsumeKind,
    semantics: ExecutionSemanticsRef<'_>,
) -> bool {
    match consume_kind {
        ProvenanceConsumeKind::ScriptSource
        | ProvenanceConsumeKind::CommandString
        | ProvenanceConsumeKind::PipelineInput
        | ProvenanceConsumeKind::RuntimeInput
        | ProvenanceConsumeKind::StdinExplicit
        | ProvenanceConsumeKind::StdinImplicit => semantics.executes_payload(),
        _ => false,
    }
}

fn matches_startup_config_consume_kind(
    consume_kind: ProvenanceConsumeKind,
    semantics: ExecutionSemanticsRef<'_>,
) -> bool {
    consume_kind == ProvenanceConsumeKind::StartupConfigSource && semantics.loads_startup_config()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactProducerRow<'a> {
    execution_unit: ExecutionUnitRef<'a>,
    produce_kind: ProvenanceProduceKind,
    slot_name: Option<String>,
    normalized_command_name: Option<String>,
}

fn collect_producer_rows_for_artifact<'a>(
    session: QuerySession<'a>,
    artifact_node_id: &NodeId,
) -> Vec<ArtifactProducerRow<'a>> {
    let mut producers = Vec::new();

    for edge in session.graph().incoming_edges(artifact_node_id) {
        if edge.kind != EdgeKind::Produces {
            continue;
        }

        let Some(ProvenanceEdgeSemantics::Produce {
            produce_kind,
            slot_name,
            normalized_command_name,
            ..
        }) = edge.semantics.as_ref()
        else {
            continue;
        };

        let Some(source_node) = session.graph().get_node(&edge.from) else {
            continue;
        };
        let Some(execution_unit) = ExecutionUnitRef::from_node(source_node) else {
            continue;
        };

        producers.push(ArtifactProducerRow {
            execution_unit,
            produce_kind: *produce_kind,
            slot_name: slot_name.clone(),
            normalized_command_name: normalized_command_name.clone(),
        });
    }

    producers.sort_by(|left, right| {
        left.execution_unit
            .root_command_sequence_no()
            .cmp(&right.execution_unit.root_command_sequence_no())
            .then_with(|| {
                left.execution_unit
                    .depth()
                    .cmp(&right.execution_unit.depth())
            })
            .then_with(|| {
                left.execution_unit
                    .node_id()
                    .0
                    .cmp(&right.execution_unit.node_id().0)
            })
    });

    producers
}

fn query_source_units<'a>(
    session: QuerySession<'a>,
    window: SequenceWindow,
    root_sequence: Option<CommandSequenceNo>,
    execution_unit_node_id: Option<&NodeId>,
) -> Vec<ExecutionUnitRef<'a>> {
    match execution_unit_node_id {
        Some(node_id) => session
            .graph()
            .get_node(node_id)
            .and_then(ExecutionUnitRef::from_node)
            .filter(|unit| {
                window.contains(unit.root_command_sequence_no())
                    && root_sequence
                        .is_none_or(|sequence_no| unit.root_command_sequence_no() == sequence_no)
            })
            .into_iter()
            .collect(),
        None => ExecutionUnitHistoryQuery::new()
            .window(window)
            .execute(session)
            .execution_units()
            .iter()
            .copied()
            .filter(|unit| {
                root_sequence
                    .is_none_or(|sequence_no| unit.root_command_sequence_no() == sequence_no)
            })
            .collect(),
    }
}

fn collect_payload_producers_for_artifact<'a>(
    session: QuerySession<'a>,
    artifact_node_id: &NodeId,
) -> Vec<PayloadArtifactProducerRef<'a>> {
    collect_producer_rows_for_artifact(session, artifact_node_id)
        .into_iter()
        .map(|row| PayloadArtifactProducerRef {
            execution_unit: row.execution_unit,
            produce_kind: row.produce_kind,
            slot_name: row.slot_name,
            normalized_command_name: row.normalized_command_name,
        })
        .collect()
}

fn collect_startup_config_producers_for_artifact<'a>(
    session: QuerySession<'a>,
    artifact_node_id: &NodeId,
) -> Vec<StartupConfigArtifactProducerRef<'a>> {
    collect_producer_rows_for_artifact(session, artifact_node_id)
        .into_iter()
        .map(|row| StartupConfigArtifactProducerRef {
            execution_unit: row.execution_unit,
            produce_kind: row.produce_kind,
            slot_name: row.slot_name,
            normalized_command_name: row.normalized_command_name,
        })
        .collect()
}

fn path_content_artifact(node: &caushell_graph::GraphNode) -> Option<(&str, Option<u64>)> {
    let NodeKind::ProvenanceArtifact { artifact } = &node.kind else {
        return None;
    };

    match artifact {
        ProvenanceArtifact::PathContent { path, version } => Some((path.as_str(), *version)),
        ProvenanceArtifact::VariableValue { .. }
        | ProvenanceArtifact::InheritedEnvValue { .. }
        | ProvenanceArtifact::PipelineStream { .. }
        | ProvenanceArtifact::TransformOutput { .. }
        | ProvenanceArtifact::MaterializedValue { .. }
        | ProvenanceArtifact::RuntimeInput { .. }
        | ProvenanceArtifact::InlineShellContent { .. }
        | ProvenanceArtifact::CommandSubstitutionOutput { .. }
        | ProvenanceArtifact::ProcessSubstitutionChannel { .. }
        | ProvenanceArtifact::NetworkEndpoint { .. }
        | ProvenanceArtifact::ImportedPackage { .. } => None,
    }
}

fn runtime_input_artifact(
    node: &caushell_graph::GraphNode,
) -> Option<(RuntimeInputSource, &RuntimeInputCapture, u64)> {
    let NodeKind::ProvenanceArtifact { artifact } = &node.kind else {
        return None;
    };

    match artifact {
        ProvenanceArtifact::RuntimeInput {
            source,
            capture,
            version,
        } => Some((*source, capture, *version)),
        ProvenanceArtifact::PathContent { .. }
        | ProvenanceArtifact::VariableValue { .. }
        | ProvenanceArtifact::InheritedEnvValue { .. }
        | ProvenanceArtifact::PipelineStream { .. }
        | ProvenanceArtifact::TransformOutput { .. }
        | ProvenanceArtifact::MaterializedValue { .. }
        | ProvenanceArtifact::InlineShellContent { .. }
        | ProvenanceArtifact::CommandSubstitutionOutput { .. }
        | ProvenanceArtifact::ProcessSubstitutionChannel { .. }
        | ProvenanceArtifact::NetworkEndpoint { .. }
        | ProvenanceArtifact::ImportedPackage { .. } => None,
    }
}

fn runtime_input_source_sort_key(source: RuntimeInputSource) -> u8 {
    match source {
        RuntimeInputSource::StdinPayload => 0,
        RuntimeInputSource::StdinData => 1,
        RuntimeInputSource::InteractiveSession => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PathContentConsumeQuery, PathContentOriginQuery, PathContentOriginStatus,
        PathContentProduceQuery, PayloadProvenanceTraceQuery, PayloadSinkStatusRef,
        RuntimeInputConsumeQuery, StartupConfigProvenanceTraceQuery, StartupConfigSinkStatusRef,
    };
    use crate::{QuerySession, SequenceWindow};
    use caushell_graph::{Edge, EdgeKind, GraphNode, GraphRead, NodeId, NodeKind, SessionGraph};
    use caushell_types::{
        CommandSequenceNo, DerivedInvocationOrigin, ExecutionPayloadMode, ExecutionSemantics,
        PayloadSinkStatus, ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceDomainLabel,
        ProvenanceEdgeSemantics, ProvenanceProduceKind, ResolvedPathPurpose, ResolvedPathRole,
        RuntimeInputCapture, RuntimeInputSource, SessionId, SessionSummary, ShellKind,
        StartupConfigSinkStatus,
    };

    fn graph_with_path_provenance() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:3"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(3),
            "echo hi > ./build.sh",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("derived:sess-1:10:0:0"),
            caushell_graph::NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(10),
                origin: DerivedInvocationOrigin::NestedPayload {
                    nested_record_id: 0,
                },
                derived_command_index: 0,
                raw_text: "bash ../shared/build.sh".to_string(),
                command_name: Some("bash".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 1,
            },
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:path-content:/tmp/project/build.sh"),
            ProvenanceArtifact::PathContent {
                path: "/tmp/project/build.sh".to_string(),
                version: None,
            },
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:path-content:/tmp/shared/build.sh"),
            ProvenanceArtifact::PathContent {
                path: "/tmp/shared/build.sh".to_string(),
                version: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:3"),
            NodeId::new("artifact:path-content:/tmp/project/build.sh"),
            EdgeKind::Produces,
            ProvenanceEdgeSemantics::Produce {
                produce_kind: ProvenanceProduceKind::PathWrite,
                slot_name: Some("redirect_target_0".to_string()),
                normalized_command_name: None,
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Write,
                    purpose: None,
                }),
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("derived:sess-1:10:0:0"),
            NodeId::new("artifact:path-content:/tmp/shared/build.sh"),
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::ScriptSource,
                slot_name: Some("script_path".to_string()),
                normalized_command_name: Some("bash".to_string()),
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::ScriptSource),
                }),
            },
        ));

        graph
    }

    #[test]
    fn path_content_consume_query_filters_by_kind_and_root_sequence() {
        let graph = graph_with_path_provenance();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathContentConsumeQuery::new()
            .consume_kind(ProvenanceConsumeKind::ScriptSource)
            .used_by_root_sequence(CommandSequenceNo::new(10))
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.consumes()[0].path(), "/tmp/shared/build.sh");
        assert_eq!(
            result.consumes()[0].execution_unit().node_id(),
            &NodeId::new("derived:sess-1:10:0:0")
        );
        assert_eq!(result.consumes()[0].normalized_command_name(), Some("bash"));
        assert_eq!(result.consumes()[0].slot_name(), Some("script_path"));
    }

    #[test]
    fn path_content_consume_query_respects_execution_unit_filter() {
        let graph = graph_with_path_provenance();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathContentConsumeQuery::new()
            .used_by_execution_unit_node_id(NodeId::new("command:sess-1:3"))
            .execute(session);

        assert!(result.is_empty());
    }

    #[test]
    fn path_content_consume_ref_converts_to_contract_value() {
        let graph = graph_with_path_provenance();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let consume = PathContentConsumeQuery::new()
            .consume_kind(ProvenanceConsumeKind::ScriptSource)
            .execute(session)
            .consumes()[0]
            .clone();

        let fact = consume.to_path_content_consume_fact();

        assert_eq!(
            fact.artifact_node_id,
            "artifact:path-content:/tmp/shared/build.sh"
        );
        assert_eq!(fact.source.node_id, "derived:sess-1:10:0:0");
        assert_eq!(
            fact.source.execution_kind,
            caushell_types::ExecutionUnitKind::Derived
        );
        assert_eq!(fact.path, "/tmp/shared/build.sh");
        assert_eq!(fact.consume_kind, ProvenanceConsumeKind::ScriptSource);
        assert_eq!(fact.slot_name, Some("script_path".to_string()));
        assert_eq!(fact.normalized_command_name, Some("bash".to_string()));
    }

    #[test]
    fn path_content_produce_query_filters_by_path_and_window() {
        let graph = graph_with_path_provenance();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathContentProduceQuery::new()
            .path("/tmp/project/build.sh")
            .produce_kind(ProvenanceProduceKind::PathWrite)
            .window(SequenceWindow::new().before_sequence(CommandSequenceNo::new(10)))
            .execute(session);

        assert_eq!(result.len(), 1);
        assert_eq!(result.produces()[0].path(), "/tmp/project/build.sh");
        assert_eq!(
            result.produces()[0].execution_unit().node_id(),
            &NodeId::new("command:sess-1:3")
        );
        assert_eq!(result.produces()[0].slot_name(), Some("redirect_target_0"));
    }

    #[test]
    fn path_content_produce_query_ignores_non_matching_kind() {
        let graph = graph_with_path_provenance();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathContentProduceQuery::new()
            .produce_kind(ProvenanceProduceKind::MaterializedValue)
            .execute(session);

        assert!(result.is_empty());
    }

    #[test]
    fn path_content_produce_ref_converts_to_contract_value() {
        let graph = graph_with_path_provenance();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let produce = PathContentProduceQuery::new()
            .produce_kind(ProvenanceProduceKind::PathWrite)
            .execute(session)
            .produces()[0]
            .clone();

        let fact = produce.to_path_content_produce_fact();

        assert_eq!(
            fact.artifact_node_id,
            "artifact:path-content:/tmp/project/build.sh"
        );
        assert_eq!(fact.source.node_id, "command:sess-1:3");
        assert_eq!(
            fact.source.execution_kind,
            caushell_types::ExecutionUnitKind::TopLevel
        );
        assert_eq!(fact.path, "/tmp/project/build.sh");
        assert_eq!(fact.produce_kind, ProvenanceProduceKind::PathWrite);
        assert_eq!(fact.slot_name, Some("redirect_target_0".to_string()));
    }

    fn graph_with_runtime_input_sink() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:5"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(5),
            "bash -s",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:command:sess-1:5"),
            NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("bash", "stdin_script_explicit")
                    .with_payload_mode(ExecutionPayloadMode::StdinExplicit)
                    .executing_payload(),
            },
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:5"),
            NodeId::new("execution-semantics:command:sess-1:5"),
            EdgeKind::Defines,
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:runtime-input:command:sess-1:5:stdin_payload"),
            ProvenanceArtifact::RuntimeInput {
                source: RuntimeInputSource::StdinPayload,
                capture: RuntimeInputCapture::NotCaptured,
                version: 5,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:5"),
            NodeId::new("artifact:runtime-input:command:sess-1:5:stdin_payload"),
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::RuntimeInput,
                slot_name: None,
                normalized_command_name: Some("bash".to_string()),
                domain_label: None,
            },
        ));

        graph
    }

    fn graph_with_path_origin_history() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:3"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(3),
            "echo hi > ./build.sh",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:10"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(10),
            "bash ./build.sh",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:11"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(11),
            "bash ../shared/build.sh",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:path-content:/tmp/project/build.sh"),
            ProvenanceArtifact::PathContent {
                path: "/tmp/project/build.sh".to_string(),
                version: None,
            },
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:path-content:/tmp/shared/build.sh"),
            ProvenanceArtifact::PathContent {
                path: "/tmp/shared/build.sh".to_string(),
                version: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:3"),
            NodeId::new("artifact:path-content:/tmp/project/build.sh"),
            EdgeKind::Produces,
            ProvenanceEdgeSemantics::Produce {
                produce_kind: ProvenanceProduceKind::PathWrite,
                slot_name: Some("redirect_target_0".to_string()),
                normalized_command_name: None,
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Write,
                    purpose: None,
                }),
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:10"),
            NodeId::new("artifact:path-content:/tmp/project/build.sh"),
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::ScriptSource,
                slot_name: Some("script_path".to_string()),
                normalized_command_name: Some("bash".to_string()),
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::ScriptSource),
                }),
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:11"),
            NodeId::new("artifact:path-content:/tmp/shared/build.sh"),
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::ScriptSource,
                slot_name: Some("script_path".to_string()),
                normalized_command_name: Some("bash".to_string()),
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::ScriptSource),
                }),
            },
        ));

        graph
    }

    #[test]
    fn runtime_input_consume_query_filters_by_source_and_root_sequence() {
        let graph = graph_with_runtime_input_sink();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = RuntimeInputConsumeQuery::new()
            .source(RuntimeInputSource::StdinPayload)
            .used_by_root_sequence(CommandSequenceNo::new(5))
            .execute(session);

        assert_eq!(result.len(), 1);

        let consume = &result.consumes()[0];
        assert_eq!(
            consume.artifact_node_id(),
            &NodeId::new("artifact:runtime-input:command:sess-1:5:stdin_payload")
        );
        assert_eq!(
            consume.execution_unit().node_id(),
            &NodeId::new("command:sess-1:5")
        );
        assert_eq!(
            consume.runtime_input_source(),
            RuntimeInputSource::StdinPayload
        );
        assert_eq!(consume.capture(), &RuntimeInputCapture::NotCaptured);
        assert_eq!(consume.version(), 5);
        assert_eq!(consume.consume_kind(), ProvenanceConsumeKind::RuntimeInput);
        assert_eq!(consume.slot_name(), None);
        assert_eq!(consume.normalized_command_name(), Some("bash"));
    }

    #[test]
    fn runtime_input_consume_ref_converts_to_contract_value() {
        let graph = graph_with_runtime_input_sink();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let consume = RuntimeInputConsumeQuery::new()
            .source(RuntimeInputSource::StdinPayload)
            .execute(session)
            .consumes()[0]
            .clone();

        let fact = consume.to_runtime_input_consume_fact();

        assert_eq!(
            fact.artifact_node_id,
            "artifact:runtime-input:command:sess-1:5:stdin_payload"
        );
        assert_eq!(fact.source.node_id, "command:sess-1:5");
        assert_eq!(
            fact.source.execution_kind,
            caushell_types::ExecutionUnitKind::TopLevel
        );
        assert_eq!(fact.runtime_input_source, RuntimeInputSource::StdinPayload);
        assert_eq!(fact.capture, RuntimeInputCapture::NotCaptured);
        assert_eq!(fact.version, 5);
        assert_eq!(fact.consume_kind, ProvenanceConsumeKind::RuntimeInput);
        assert_eq!(fact.normalized_command_name, Some("bash".to_string()));
    }

    #[test]
    fn path_content_origin_query_reports_prior_session_write_observed() {
        let graph = graph_with_path_origin_history();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathContentOriginQuery::new()
            .path("/tmp/project/build.sh")
            .consume_kind(ProvenanceConsumeKind::ScriptSource)
            .execute(session);

        assert_eq!(result.len(), 1);
        let origin = &result.origins()[0];
        assert_eq!(
            origin.origin_status(),
            PathContentOriginStatus::PriorSessionWriteObserved
        );
        assert_eq!(origin.prior_write_count(), 1);
        assert_eq!(origin.consume().path(), "/tmp/project/build.sh");

        let latest_prior_write = origin
            .latest_prior_write()
            .expect("expected prior session write");
        assert_eq!(latest_prior_write.path(), "/tmp/project/build.sh");
        assert_eq!(
            latest_prior_write.execution_unit().node_id(),
            &NodeId::new("command:sess-1:3")
        );
        assert_eq!(
            latest_prior_write
                .execution_unit()
                .root_command_sequence_no(),
            CommandSequenceNo::new(3)
        );
    }

    #[test]
    fn path_content_origin_query_reports_no_prior_session_write_observed() {
        let graph = graph_with_path_origin_history();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PathContentOriginQuery::new()
            .path("/tmp/shared/build.sh")
            .consume_kind(ProvenanceConsumeKind::ScriptSource)
            .execute(session);

        assert_eq!(result.len(), 1);
        let origin = &result.origins()[0];
        assert_eq!(
            origin.origin_status(),
            PathContentOriginStatus::NoPriorSessionWriteObserved
        );
        assert_eq!(origin.prior_write_count(), 0);
        assert_eq!(origin.consume().path(), "/tmp/shared/build.sh");
        assert!(origin.latest_prior_write().is_none());
    }

    fn graph_with_payload_sink_trace() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:1"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(1),
            "echo hi > ./scripts/build.sh",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:2"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(2),
            "bash ./scripts/build.sh",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:command:sess-1:2"),
            NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("bash", "script_file")
                    .with_payload_mode(ExecutionPayloadMode::ScriptFile)
                    .executing_payload(),
            },
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:2"),
            NodeId::new("execution-semantics:command:sess-1:2"),
            EdgeKind::Defines,
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:path-content:/tmp/project/scripts/build.sh"),
            ProvenanceArtifact::PathContent {
                path: "/tmp/project/scripts/build.sh".to_string(),
                version: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:1"),
            NodeId::new("artifact:path-content:/tmp/project/scripts/build.sh"),
            EdgeKind::Produces,
            ProvenanceEdgeSemantics::Produce {
                produce_kind: ProvenanceProduceKind::PathWrite,
                slot_name: Some("redirect_target_0".to_string()),
                normalized_command_name: None,
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Write,
                    purpose: None,
                }),
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:2"),
            NodeId::new("artifact:path-content:/tmp/project/scripts/build.sh"),
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::ScriptSource,
                slot_name: Some("script_path".to_string()),
                normalized_command_name: Some("bash".to_string()),
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::ScriptSource),
                }),
            },
        ));

        graph
    }

    fn graph_with_pipeline_payload_sink_trace() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_node(GraphNode::new(
            NodeId::new("pipeline-segment:sess-1:7:0"),
            NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(7),
                origin: DerivedInvocationOrigin::PipelineSegment { command_index: 0 },
                derived_command_index: 0,
                raw_text: "cat ./payload.sh".to_string(),
                command_name: Some("cat".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 0,
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("pipeline-segment:sess-1:7:1"),
            NodeKind::DerivedInvocation {
                root_command_sequence_no: CommandSequenceNo::new(7),
                origin: DerivedInvocationOrigin::PipelineSegment { command_index: 1 },
                derived_command_index: 1,
                raw_text: "bash".to_string(),
                command_name: Some("bash".to_string()),
                shell_kind: ShellKind::Bash,
                depth: 0,
            },
        ));
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:pipeline-segment:sess-1:7:1"),
            NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("bash", "stdin_script_implicit")
                    .with_payload_mode(ExecutionPayloadMode::StdinImplicit)
                    .executing_payload(),
            },
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("pipeline-segment:sess-1:7:1"),
            NodeId::new("execution-semantics:pipeline-segment:sess-1:7:1"),
            EdgeKind::Defines,
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:pipeline-stream:command:sess-1:7:0:0"),
            ProvenanceArtifact::PipelineStream {
                root_command_sequence_no: CommandSequenceNo::new(7),
                pipeline_group_index: 0,
                stream_index: 0,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("pipeline-segment:sess-1:7:0"),
            NodeId::new("artifact:pipeline-stream:command:sess-1:7:0:0"),
            EdgeKind::Produces,
            ProvenanceEdgeSemantics::Produce {
                produce_kind: ProvenanceProduceKind::PipelineOutput,
                slot_name: None,
                normalized_command_name: Some("cat".to_string()),
                domain_label: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("pipeline-segment:sess-1:7:1"),
            NodeId::new("artifact:pipeline-stream:command:sess-1:7:0:0"),
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::PipelineInput,
                slot_name: None,
                normalized_command_name: Some("bash".to_string()),
                domain_label: None,
            },
        ));

        graph
    }

    fn graph_with_startup_config_sink_trace() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:1"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(1),
            "echo 'alias ls=evil' > ./team.rc",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:2"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(2),
            "bash --rcfile ./team.rc -c 'echo ok'",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:command:sess-1:2"),
            NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("bash", "command_string")
                    .with_payload_mode(ExecutionPayloadMode::CommandString)
                    .executing_payload()
                    .loading_startup_config(),
            },
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:2"),
            NodeId::new("execution-semantics:command:sess-1:2"),
            EdgeKind::Defines,
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:path-content:/tmp/project/team.rc"),
            ProvenanceArtifact::PathContent {
                path: "/tmp/project/team.rc".to_string(),
                version: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:1"),
            NodeId::new("artifact:path-content:/tmp/project/team.rc"),
            EdgeKind::Produces,
            ProvenanceEdgeSemantics::Produce {
                produce_kind: ProvenanceProduceKind::PathWrite,
                slot_name: Some("redirect_target_0".to_string()),
                normalized_command_name: None,
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Write,
                    purpose: None,
                }),
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:2"),
            NodeId::new("artifact:path-content:/tmp/project/team.rc"),
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::StartupConfigSource,
                slot_name: Some("startup_config".to_string()),
                normalized_command_name: Some("bash".to_string()),
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Config,
                    purpose: Some(ResolvedPathPurpose::StartupConfig),
                }),
            },
        ));

        graph
    }

    fn graph_with_non_payload_semantics() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:4"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(4),
            "echo ok",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:command:sess-1:4"),
            NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("echo", "ordinary_command"),
            },
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:4"),
            NodeId::new("execution-semantics:command:sess-1:4"),
            EdgeKind::Defines,
        ));

        graph
    }

    fn graph_with_payload_sink_without_producer() -> SessionGraph {
        let mut graph = SessionGraph::new();

        let _ = graph.add_command_invocation(
            NodeId::new("command:sess-1:6"),
            SessionId::new("sess-1"),
            CommandSequenceNo::new(6),
            "bash ./missing.sh",
            "/tmp/project",
            ShellKind::Bash,
        );
        let _ = graph.add_node(GraphNode::new(
            NodeId::new("execution-semantics:command:sess-1:6"),
            NodeKind::ExecutionSemantics {
                semantics: ExecutionSemantics::new("bash", "script_file")
                    .with_payload_mode(ExecutionPayloadMode::ScriptFile)
                    .executing_payload(),
            },
        ));
        let _ = graph.add_edge(Edge::new(
            NodeId::new("command:sess-1:6"),
            NodeId::new("execution-semantics:command:sess-1:6"),
            EdgeKind::Defines,
        ));
        let _ = graph.add_node(GraphNode::new_provenance_artifact(
            NodeId::new("artifact:path-content:/tmp/project/missing.sh"),
            ProvenanceArtifact::PathContent {
                path: "/tmp/project/missing.sh".to_string(),
                version: None,
            },
        ));
        let _ = graph.add_edge(Edge::with_semantics(
            NodeId::new("command:sess-1:6"),
            NodeId::new("artifact:path-content:/tmp/project/missing.sh"),
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::ScriptSource,
                slot_name: Some("script_path".to_string()),
                normalized_command_name: Some("bash".to_string()),
                domain_label: Some(ProvenanceDomainLabel::Path {
                    role: ResolvedPathRole::Read,
                    purpose: Some(ResolvedPathPurpose::ScriptSource),
                }),
            },
        ));

        graph
    }

    struct PanicOnFullScanGraph<'a> {
        inner: &'a SessionGraph,
    }

    impl GraphRead for PanicOnFullScanGraph<'_> {
        fn get_node(&self, id: &NodeId) -> Option<&GraphNode> {
            self.inner.get_node(id)
        }

        fn node_count(&self) -> usize {
            self.inner.node_count()
        }

        fn edge_count(&self) -> usize {
            self.inner.edge_count()
        }

        fn nodes<'a>(&'a self) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            panic!("provenance query should not require graph.nodes()");
        }

        fn edges<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
            panic!("provenance query should not require graph.edges()");
        }

        fn outgoing_edges<'a>(&'a self, id: &NodeId) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
            self.inner.outgoing_edges(id)
        }

        fn incoming_edges<'a>(&'a self, id: &NodeId) -> Box<dyn Iterator<Item = &'a Edge> + 'a> {
            self.inner.incoming_edges(id)
        }

        fn command_nodes_in_window<'a>(
            &'a self,
            after_sequence: Option<CommandSequenceNo>,
            before_sequence: Option<CommandSequenceNo>,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner
                .command_nodes_in_window(after_sequence, before_sequence)
        }

        fn derived_invocation_nodes_in_window<'a>(
            &'a self,
            after_sequence: Option<CommandSequenceNo>,
            before_sequence: Option<CommandSequenceNo>,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner
                .derived_invocation_nodes_in_window(after_sequence, before_sequence)
        }

        fn nested_payload_nodes_in_window<'a>(
            &'a self,
            after_sequence: Option<CommandSequenceNo>,
            before_sequence: Option<CommandSequenceNo>,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner
                .nested_payload_nodes_in_window(after_sequence, before_sequence)
        }

        fn execution_semantics_nodes_in_window<'a>(
            &'a self,
            after_sequence: Option<CommandSequenceNo>,
            before_sequence: Option<CommandSequenceNo>,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner
                .execution_semantics_nodes_in_window(after_sequence, before_sequence)
        }

        fn path_fact_nodes<'a>(&'a self) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner.path_fact_nodes()
        }

        fn path_fact_nodes_by_concrete_path<'a>(
            &'a self,
            path: &str,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner.path_fact_nodes_by_concrete_path(path)
        }

        fn path_content_artifact_nodes<'a>(
            &'a self,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner.path_content_artifact_nodes()
        }

        fn path_content_artifact_nodes_by_path<'a>(
            &'a self,
            path: &str,
        ) -> Box<dyn Iterator<Item = &'a GraphNode> + 'a> {
            self.inner.path_content_artifact_nodes_by_path(path)
        }
    }

    #[test]
    fn payload_provenance_trace_query_returns_sink_inputs_and_producers() {
        let graph = graph_with_payload_sink_trace();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PayloadProvenanceTraceQuery::new()
            .execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .execute(session);
        let trace = result.trace().expect("expected trace to exist");

        assert_eq!(trace.source().node_id(), &NodeId::new("command:sess-1:2"));
        assert_eq!(trace.sink_status(), PayloadSinkStatusRef::PayloadSink);
        let semantics = trace.semantics().expect("expected sink semantics");
        assert!(semantics.executes_payload());
        assert_eq!(
            semantics.payload_mode(),
            Some(ExecutionPayloadMode::ScriptFile)
        );

        assert_eq!(trace.payload_inputs().len(), 1);
        let input = &trace.payload_inputs()[0];
        assert_eq!(
            input.artifact_node_id(),
            &NodeId::new("artifact:path-content:/tmp/project/scripts/build.sh")
        );
        assert_eq!(input.consume_kind(), ProvenanceConsumeKind::ScriptSource);
        assert_eq!(input.slot_name(), Some("script_path"));
        assert_eq!(input.normalized_command_name(), Some("bash"));
        assert_eq!(input.producers().len(), 1);
        assert_eq!(
            input.producers()[0].execution_unit().node_id(),
            &NodeId::new("command:sess-1:1")
        );
        assert_eq!(
            input.producers()[0].produce_kind(),
            ProvenanceProduceKind::PathWrite
        );
    }

    #[test]
    fn payload_provenance_trace_query_includes_pipeline_stream_artifact() {
        let graph = graph_with_pipeline_payload_sink_trace();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PayloadProvenanceTraceQuery::new()
            .execution_unit_node_id(NodeId::new("pipeline-segment:sess-1:7:1"))
            .execute(session);
        let trace = result.trace().expect("expected trace to exist");

        assert_eq!(trace.sink_status(), PayloadSinkStatusRef::PayloadSink);
        assert_eq!(trace.payload_inputs().len(), 1);

        let input = &trace.payload_inputs()[0];
        assert_eq!(
            input.artifact_node_id(),
            &NodeId::new("artifact:pipeline-stream:command:sess-1:7:0:0")
        );
        assert_eq!(input.consume_kind(), ProvenanceConsumeKind::PipelineInput);
        assert_eq!(input.normalized_command_name(), Some("bash"));
        assert_eq!(input.producers().len(), 1);
        assert_eq!(
            input.producers()[0].execution_unit().node_id(),
            &NodeId::new("pipeline-segment:sess-1:7:0")
        );
        assert_eq!(
            input.producers()[0].produce_kind(),
            ProvenanceProduceKind::PipelineOutput
        );
    }

    #[test]
    fn startup_config_provenance_trace_query_returns_sink_inputs_and_producers() {
        let graph = graph_with_startup_config_sink_trace();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = StartupConfigProvenanceTraceQuery::new()
            .execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .execute(session);
        let trace = result.trace().expect("expected trace to exist");

        assert_eq!(trace.source().node_id(), &NodeId::new("command:sess-1:2"));
        assert_eq!(
            trace.sink_status(),
            StartupConfigSinkStatusRef::StartupConfigSink
        );
        let semantics = trace.semantics().expect("expected sink semantics");
        assert!(semantics.loads_startup_config());

        assert_eq!(trace.startup_config_inputs().len(), 1);
        let input = &trace.startup_config_inputs()[0];
        assert_eq!(
            input.artifact_node_id(),
            &NodeId::new("artifact:path-content:/tmp/project/team.rc")
        );
        assert_eq!(
            input.consume_kind(),
            ProvenanceConsumeKind::StartupConfigSource
        );
        assert_eq!(input.slot_name(), Some("startup_config"));
        assert_eq!(input.normalized_command_name(), Some("bash"));
        assert_eq!(input.producers().len(), 1);
        assert_eq!(
            input.producers()[0].execution_unit().node_id(),
            &NodeId::new("command:sess-1:1")
        );
        assert_eq!(
            input.producers()[0].produce_kind(),
            ProvenanceProduceKind::PathWrite
        );
    }

    #[test]
    fn payload_artifact_producer_ref_converts_to_contract_value() {
        let graph = graph_with_payload_sink_trace();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let trace = PayloadProvenanceTraceQuery::new()
            .execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .execute(session);
        let producer =
            trace.trace().expect("expected trace").payload_inputs()[0].producers()[0].clone();

        let contract = producer.to_payload_artifact_producer();

        assert_eq!(contract.source.node_id, "command:sess-1:1");
        assert_eq!(
            contract.source.execution_kind,
            caushell_types::ExecutionUnitKind::TopLevel
        );
        assert_eq!(contract.produce_kind, ProvenanceProduceKind::PathWrite);
        assert_eq!(contract.slot_name, Some("redirect_target_0".to_string()));
    }

    #[test]
    fn payload_artifact_consume_ref_converts_to_contract_value() {
        let graph = graph_with_payload_sink_trace();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let trace = PayloadProvenanceTraceQuery::new()
            .execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .execute(session);
        let consume = trace.trace().expect("expected trace").payload_inputs()[0].clone();

        let contract = consume.to_payload_artifact_consume();

        assert_eq!(
            contract.artifact_node_id,
            "artifact:path-content:/tmp/project/scripts/build.sh"
        );
        assert_eq!(contract.consume_kind, ProvenanceConsumeKind::ScriptSource);
        assert_eq!(contract.slot_name, Some("script_path".to_string()));
        assert_eq!(contract.normalized_command_name, Some("bash".to_string()));
        assert_eq!(contract.producers.len(), 1);
        assert_eq!(contract.producers[0].source.node_id, "command:sess-1:1");
    }

    #[test]
    fn payload_provenance_trace_ref_converts_to_contract_value() {
        let graph = graph_with_payload_sink_trace();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let trace = PayloadProvenanceTraceQuery::new()
            .execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .execute(session);
        let contract = trace
            .trace()
            .expect("expected trace")
            .to_payload_provenance_trace();

        assert_eq!(contract.source.node_id, "command:sess-1:2");
        assert_eq!(contract.sink_status, PayloadSinkStatus::PayloadSink);
        assert_eq!(
            contract
                .semantics
                .as_ref()
                .expect("expected semantics")
                .normalized_command_name,
            "bash"
        );
        assert_eq!(contract.payload_inputs.len(), 1);
        assert_eq!(
            contract.payload_inputs[0].artifact_node_id,
            "artifact:path-content:/tmp/project/scripts/build.sh"
        );
    }

    #[test]
    fn startup_config_provenance_trace_ref_converts_to_contract_value() {
        let graph = graph_with_startup_config_sink_trace();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);
        let trace = StartupConfigProvenanceTraceQuery::new()
            .execution_unit_node_id(NodeId::new("command:sess-1:2"))
            .execute(session);
        let contract = trace
            .trace()
            .expect("expected trace")
            .to_startup_config_provenance_trace();

        assert_eq!(contract.source.node_id, "command:sess-1:2");
        assert_eq!(
            contract.sink_status,
            StartupConfigSinkStatus::StartupConfigSink
        );
        assert_eq!(contract.startup_config_inputs.len(), 1);
        assert_eq!(
            contract.startup_config_inputs[0].artifact_node_id,
            "artifact:path-content:/tmp/project/team.rc"
        );
    }

    #[test]
    fn payload_provenance_trace_query_reports_missing_semantics() {
        let graph = graph_with_path_provenance();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PayloadProvenanceTraceQuery::new()
            .execution_unit_node_id(NodeId::new("command:sess-1:3"))
            .execute(session);
        let trace = result.trace().expect("expected trace to exist");

        assert_eq!(trace.sink_status(), PayloadSinkStatusRef::MissingSemantics);
        assert!(trace.semantics().is_none());
        assert!(trace.payload_inputs().is_empty());
        assert_eq!(
            trace.to_payload_provenance_trace().sink_status,
            PayloadSinkStatus::MissingSemantics
        );
    }

    #[test]
    fn payload_provenance_trace_query_reports_not_payload_sink() {
        let graph = graph_with_non_payload_semantics();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PayloadProvenanceTraceQuery::new()
            .execution_unit_node_id(NodeId::new("command:sess-1:4"))
            .execute(session);
        let trace = result.trace().expect("expected trace to exist");

        assert_eq!(trace.sink_status(), PayloadSinkStatusRef::NotPayloadSink);
        assert!(trace.semantics().is_some());
        assert!(trace.payload_inputs().is_empty());
        assert_eq!(
            trace.to_payload_provenance_trace().sink_status,
            PayloadSinkStatus::NotPayloadSink
        );
    }

    #[test]
    fn startup_config_provenance_trace_query_reports_not_startup_config_sink() {
        let graph = graph_with_non_payload_semantics();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = StartupConfigProvenanceTraceQuery::new()
            .execution_unit_node_id(NodeId::new("command:sess-1:4"))
            .execute(session);
        let trace = result.trace().expect("expected trace to exist");

        assert_eq!(
            trace.sink_status(),
            StartupConfigSinkStatusRef::NotStartupConfigSink
        );
        assert!(trace.semantics().is_some());
        assert!(trace.startup_config_inputs().is_empty());
        assert_eq!(
            trace.to_startup_config_provenance_trace().sink_status,
            StartupConfigSinkStatus::NotStartupConfigSink
        );
    }

    #[test]
    fn payload_provenance_trace_query_reports_payload_input_without_producer() {
        let graph = graph_with_payload_sink_without_producer();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PayloadProvenanceTraceQuery::new()
            .execution_unit_node_id(NodeId::new("command:sess-1:6"))
            .execute(session);
        let trace = result.trace().expect("expected trace to exist");

        assert_eq!(trace.sink_status(), PayloadSinkStatusRef::PayloadSink);
        assert_eq!(trace.payload_inputs().len(), 1);
        assert!(trace.payload_inputs()[0].producers().is_empty());
    }

    #[test]
    fn payload_provenance_trace_query_includes_runtime_input_artifact() {
        let graph = graph_with_runtime_input_sink();
        let summary = SessionSummary::new();
        let session = QuerySession::new(&graph, &summary);

        let result = PayloadProvenanceTraceQuery::new()
            .execution_unit_node_id(NodeId::new("command:sess-1:5"))
            .execute(session);
        let trace = result.trace().expect("expected trace to exist");

        assert_eq!(trace.sink_status(), PayloadSinkStatusRef::PayloadSink);
        assert_eq!(trace.payload_inputs().len(), 1);

        let input = &trace.payload_inputs()[0];
        assert_eq!(
            input.artifact_node_id(),
            &NodeId::new("artifact:runtime-input:command:sess-1:5:stdin_payload")
        );
        assert_eq!(
            input.artifact(),
            &ProvenanceArtifact::RuntimeInput {
                source: RuntimeInputSource::StdinPayload,
                capture: RuntimeInputCapture::NotCaptured,
                version: 5,
            }
        );
        assert_eq!(input.consume_kind(), ProvenanceConsumeKind::RuntimeInput);
        assert_eq!(input.slot_name(), None);
        assert_eq!(input.normalized_command_name(), Some("bash"));
        assert!(input.producers().is_empty());
    }

    #[test]
    fn provenance_queries_do_not_require_full_graph_scan() {
        let graph = graph_with_path_origin_history();
        let wrapped = PanicOnFullScanGraph { inner: &graph };
        let summary = SessionSummary::new();
        let session = QuerySession::new(&wrapped, &summary);

        let consumes = PathContentConsumeQuery::new()
            .path("/tmp/project/build.sh")
            .execute(session);
        assert!(!consumes.is_empty());

        let produces = PathContentProduceQuery::new()
            .path("/tmp/project/build.sh")
            .execute(session);
        assert!(!produces.is_empty());

        let origins = PathContentOriginQuery::new()
            .used_by_execution_unit_node_id(NodeId::new("command:sess-1:10"))
            .execute(session);
        assert!(!origins.is_empty());
    }
}
