//! Profile-driven stream summary. No command names and no runtime FD probes.
use std::collections::BTreeMap;

use caushell_graph::NodeId;
use caushell_profile::{ResolveInvocationArtifactResult, StreamInputMode};
use caushell_query::IoTarget;
use caushell_runner::RunnerContext;
use caushell_types::{
    PathResolution, ProvenanceDomainLabel, ProvenanceEdgeSemantics, StreamDataDependency,
};

pub(crate) struct StreamSemanticsIndex(BTreeMap<NodeId, InvocationStreams>);

struct InvocationStreams {
    ignores_stdin: bool,
    stdin: IoTarget,
    pipeline_has_upstream: bool,
    projected_shell_scope: bool,
    outputs: [(IoTarget, StreamDataDependency); 2],
    pipeline_nonterminal: bool,
}

impl StreamSemanticsIndex {
    pub(crate) fn new(ctx: &RunnerContext) -> Self {
        let mut entries = BTreeMap::new();
        let shell_scopes = super::projected_shell_scope_parents(ctx);
        for record in ctx.execution_unit_resolve_records() {
            // Partial bindings may change the command's mode; do not use their
            // negative dependency claims to erase provenance.
            let contract = match &record.result {
                ResolveInvocationArtifactResult::Resolved(resolved) => {
                    resolved.proven_stream_contract()
                }
                _ => None,
            };
            entries.insert(
                record.source_node_id.clone(),
                invocation_streams(
                    ctx,
                    &record.source_node_id,
                    &record.parsed_scope,
                    record.command_ref.command_index,
                    contract,
                    shell_scopes.contains(&record.source_node_id),
                ),
            );
        }
        // Function callers are graph-backed shell events, but their body
        // expansion can replace the caller's ordinary resolution record.
        // Recover ONLY such known scope owners from existing AST coordinates.
        for parent in &shell_scopes {
            if entries.contains_key(parent) {
                continue;
            }
            if let Some((parsed, index)) = super::shell_io_scope::execution_location(ctx, parent) {
                entries.insert(
                    parent.clone(),
                    invocation_streams(ctx, parent, parsed, index, None, true),
                );
            }
        }
        Self(entries)
    }

    pub(crate) fn ignores_stdin(&self, node: &NodeId) -> bool {
        self.0
            .get(node)
            .is_some_and(|streams| streams.ignores_stdin)
    }
}

fn invocation_streams(
    ctx: &RunnerContext,
    node: &NodeId,
    parsed: &caushell_parse::ParsedCommandArtifact,
    index: usize,
    contract: Option<caushell_profile::StreamContract>,
    projected_shell_scope: bool,
) -> InvocationStreams {
    let entry = ctx.effective_cwd_for_node(node);
    let known_cwds = entry.map(|cwd| cwd.known_cwds()).unwrap_or_default();
    let uncertain_cwd = entry.is_some_and(|cwd| {
        cwd.has_unknown() || !cwd.bounded_roots().is_empty() || known_cwds.len() != 1
    });
    let cwd = known_cwds
        .first()
        .copied()
        .unwrap_or(ctx.request().shell_state_before.cwd());
    let target = |fd: &str| {
        let mut target = super::execution_content_io_target(
            ctx,
            node,
            parsed,
            index,
            None,
            &PathResolution::Concrete {
                path: format!("/dev/fd/{fd}"),
            },
            false,
            cwd,
            ctx.request().home.as_deref(),
        );
        if uncertain_cwd
            && matches!(
                &target,
                IoTarget::Path {
                    cwd_dependent: true,
                    ..
                }
            )
        {
            target = IoTarget::UnknownDescriptor {
                descriptor: fd.into(),
            };
        }
        target
    };
    InvocationStreams {
        stdin: target("0"),
        pipeline_has_upstream: super::pipeline_has_upstream(parsed, index),
        projected_shell_scope,
        ignores_stdin: contract
            .is_some_and(|contract| contract.stdin_mode == StreamInputMode::Ignored),
        outputs: [
            (
                target("1"),
                contract.map_or(StreamDataDependency::Unknown, |contract| {
                    contract.stdout_dependency
                }),
            ),
            (
                target("2"),
                contract.map_or(StreamDataDependency::Unknown, |contract| {
                    contract.stderr_dependency
                }),
            ),
        ],
        pipeline_nonterminal: super::collect_pipeline_groups(parsed).iter().any(|group| {
            group
                .commands
                .iter()
                .take(group.commands.len().saturating_sub(1))
                .any(|command| command.command_index == index)
        }),
    }
}

impl StreamSemanticsIndex {
    /// Include every output FD reaching the target, including stderr aliases.
    /// Unknown routing remains unknown; opaque output is never a sanitizer.
    pub(crate) fn dependency(&self, node: &NodeId, target: &IoTarget) -> StreamDataDependency {
        let Some(streams) = self.0.get(node) else {
            return StreamDataDependency::Unknown;
        };
        // Child producers carry the scope's output directly. Do not also
        // spread the interpreter's broad inputs over every output port.
        if streams.projected_shell_scope {
            return StreamDataDependency::Independent;
        }
        let mut result = StreamDataDependency::Independent;
        for (destination, dependency) in &streams.outputs {
            if matches!(destination, IoTarget::UnknownDescriptor { .. })
                || matches!(destination, IoTarget::Path { resolution, .. } if resolution.concrete_path().is_none())
            {
                return StreamDataDependency::Unknown;
            }
            if same_target(destination, target) {
                result = match (result, dependency) {
                    (_, StreamDataDependency::Unknown) => StreamDataDependency::Unknown,
                    (StreamDataDependency::Unknown, _) => StreamDataDependency::Unknown,
                    (_, StreamDataDependency::Inputs) => StreamDataDependency::Inputs,
                    (current, _) => current,
                };
            }
        }
        result
    }

    pub(crate) fn inherited_stdout(&self, node: &NodeId) -> StreamDataDependency {
        self.dependency(
            node,
            &IoTarget::InheritedDescriptor {
                descriptor: "1".into(),
            },
        )
    }

    pub(crate) fn output_target(&self, node: &NodeId, port: &str) -> Option<&IoTarget> {
        let index = match port {
            "1" => 0,
            "2" => 1,
            _ => return None,
        };
        self.0.get(node).map(|s| &s.outputs[index].0)
    }

    pub(crate) fn pipeline_nonterminal(&self, node: &NodeId) -> bool {
        self.0.get(node).is_some_and(|s| s.pipeline_nonterminal)
    }

    pub(crate) fn inherits_stdin(&self, node: &NodeId) -> bool {
        self.0.get(node).is_some_and(|s| !s.pipeline_has_upstream
            && matches!(&s.stdin, IoTarget::InheritedDescriptor {descriptor} if descriptor == "0"))
    }

    /// Earlier pipeline stages write to the internal pipe, not the enclosing
    /// command/process substitution's stdout capture.
    pub(crate) fn scope_stdout(&self, node: &NodeId) -> StreamDataDependency {
        if self
            .0
            .get(node)
            .is_some_and(|streams| streams.pipeline_nonterminal)
        {
            StreamDataDependency::Independent
        } else {
            self.inherited_stdout(node)
        }
    }
}

pub(super) fn same_target(a: &IoTarget, b: &IoTarget) -> bool {
    match (a, b) {
        (IoTarget::Path { resolution: a, .. }, IoTarget::Path { resolution: b, .. }) => a == b,
        _ => a == b,
    }
}

/// Preserve any existing path-domain label beneath the output-specific fact.
pub(crate) fn annotate_stream_output(
    semantics: &mut ProvenanceEdgeSemantics,
    dependency: StreamDataDependency,
) {
    if dependency == StreamDataDependency::Unknown {
        return;
    }
    if let ProvenanceEdgeSemantics::Produce { domain_label, .. } = semantics {
        *domain_label = Some(ProvenanceDomainLabel::StreamOutput {
            dependency,
            domain: domain_label.take().map(Box::new),
        });
    }
}
