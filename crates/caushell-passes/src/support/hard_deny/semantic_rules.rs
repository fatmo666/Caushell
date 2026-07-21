use super::host_target_catalog::{
    HostTargetKind, HostTargetOperand, classify_host_target_with_optional_cwd,
};
use super::metadata_mutation_classifier::{MetadataMutationKind, classify_metadata_mutation};
use super::resolved_sink::{
    ResolvedHostRiskSemanticClass, ResolvedHostRiskSink, each_resolved_host_risk_sink,
};
use caushell_profile::{
    BoundInvocation, BoundValue, CatastrophicSemanticClass, Effect, EffectKind, EffectTarget,
    HostRiskSemanticClass, ResolvedInvocationArtifact, SessionBindings, ShellParameterReference,
    exact_scalar_shell_parameter_value, exact_shell_parameter_reference,
    materialize_exact_shell_parameter_reference_fields,
    parse_shell_parameter_reference_after_dollar,
};
use caushell_runner::ExecutionUnitResolveRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DestructivePathSemantic {
    pub(crate) semantic_class: DestructivePathSemanticClass,
    pub(crate) command_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DestructiveBlockDeviceSemantic {
    pub(crate) semantic_class: DestructiveBlockDeviceSemanticClass,
    pub(crate) command_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DestructivePathSemanticClass {
    DeletePath,
    MoveSourcePath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DestructiveBlockDeviceSemanticClass {
    RawWriteTarget,
    FormatTarget,
    FilesystemSignatureWipeTarget,
    PartitionTableMutationTarget,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CommandSinkReasonBuckets {
    pub(crate) floor_reasons: Vec<String>,
    pub(crate) path_metadata_mutation_reasons: Vec<String>,
    pub(crate) path_relocation_reasons: Vec<String>,
    pub(crate) partition_layout_mutation_reasons: Vec<String>,
    pub(crate) partition_table_session_reasons: Vec<String>,
    pub(crate) partition_table_mutation_reasons: Vec<String>,
    pub(crate) partition_table_state_mutation_reasons: Vec<String>,
}

pub(crate) fn collect_command_sink_reason_buckets_with_optional_cwd(
    resolved: &ResolvedInvocationArtifact,
    cwd: Option<&str>,
    home: Option<&str>,
    bindings: &SessionBindings,
) -> CommandSinkReasonBuckets {
    let mut buckets = CommandSinkReasonBuckets::default();
    extend_unique(
        &mut buckets.path_metadata_mutation_reasons,
        collect_path_metadata_mutation_reasons(resolved, cwd, home, bindings),
    );
    each_resolved_host_risk_sink(resolved, |sink| {
        let sink_buckets = collect_sink_reasons(sink, cwd, home, bindings);
        extend_unique(&mut buckets.floor_reasons, sink_buckets.floor_reasons);
        extend_unique(
            &mut buckets.path_relocation_reasons,
            sink_buckets.path_relocation_reasons,
        );
        extend_unique(
            &mut buckets.partition_layout_mutation_reasons,
            sink_buckets.partition_layout_mutation_reasons,
        );
        extend_unique(
            &mut buckets.partition_table_session_reasons,
            sink_buckets.partition_table_session_reasons,
        );
        extend_unique(
            &mut buckets.partition_table_mutation_reasons,
            sink_buckets.partition_table_mutation_reasons,
        );
        extend_unique(
            &mut buckets.partition_table_state_mutation_reasons,
            sink_buckets.partition_table_state_mutation_reasons,
        );
    });
    buckets
}

pub(crate) fn collect_execution_unit_scoped_reason_buckets(
    execution_unit_records: &[ExecutionUnitResolveRecord],
) -> CommandSinkReasonBuckets {
    let mut buckets = CommandSinkReasonBuckets::default();

    for record in execution_unit_records {
        let Some(resolved) = resolved_from_execution_record(record) else {
            continue;
        };
        let semantics = collect_dispatch_scoped_path_semantics(resolved);

        for scope in &record.inherited_scope.catastrophic_search_roots {
            for semantic in &semantics {
                match semantic.semantic_class {
                    DestructivePathSemanticClass::DeletePath => buckets.floor_reasons.push(format!(
                        "dispatch-scoped destructive child command {} under catastrophic search root {} via {}",
                        semantic.command_name,
                        scope.root,
                        scope.via_command_name
                    )),
                    DestructivePathSemanticClass::MoveSourcePath => {
                        buckets.path_relocation_reasons.push(format!(
                            "dispatch-scoped relocation child command {} under catastrophic search root {} via {}",
                            semantic.command_name,
                            scope.root,
                            scope.via_command_name
                        ))
                    }
                }
            }
        }

        let block_device_semantics = collect_dispatch_scoped_block_device_semantics(resolved);
        for scope in &record.inherited_scope.block_device_search_scopes {
            for semantic in &block_device_semantics {
                buckets.floor_reasons.push(format!(
                    "dispatch-scoped destructive block-device child command {} under block-device search target {} via {}",
                    semantic.command_name,
                    scope.target,
                    scope.via_command_name
                ));
            }
        }
    }

    buckets
}

pub(crate) fn collect_destructive_path_semantics(
    resolved: &ResolvedInvocationArtifact,
) -> Vec<DestructivePathSemantic> {
    let mut semantics = Vec::new();
    each_resolved_host_risk_sink(resolved, |sink| {
        let Some(semantic_class) = destructive_path_semantic_class(sink.semantic_class) else {
            return;
        };

        let semantic = DestructivePathSemantic {
            semantic_class,
            command_name: sink.normalized_command_name.to_string(),
        };
        if !semantics.contains(&semantic) {
            semantics.push(semantic);
        }
    });
    semantics
}

fn destructive_path_semantic_class(
    semantic_class: ResolvedHostRiskSemanticClass,
) -> Option<DestructivePathSemanticClass> {
    match semantic_class {
        ResolvedHostRiskSemanticClass::Catastrophic(CatastrophicSemanticClass::DeletePath) => {
            Some(DestructivePathSemanticClass::DeletePath)
        }
        ResolvedHostRiskSemanticClass::HostRisk(HostRiskSemanticClass::MoveSourcePath) => {
            Some(DestructivePathSemanticClass::MoveSourcePath)
        }
        _ => None,
    }
}

fn collect_sink_reasons(
    sink: ResolvedHostRiskSink<'_>,
    cwd: Option<&str>,
    home: Option<&str>,
    bindings: &SessionBindings,
) -> CommandSinkReasonBuckets {
    let target_operands = materialized_host_target_operands(&sink.target_operands, bindings);
    match sink.semantic_class {
        ResolvedHostRiskSemanticClass::HostRisk(HostRiskSemanticClass::MoveSourcePath) => {
            CommandSinkReasonBuckets {
                path_relocation_reasons: target_operands
                    .iter()
                    .filter(|target| {
                        sink_matches_host_target(
                            sink.semantic_class,
                            target.as_operand(),
                            cwd,
                            home,
                        )
                    })
                    .map(|target| sink_reason(&sink, target.text.as_str()))
                    .collect(),
                ..CommandSinkReasonBuckets::default()
            }
        }
        ResolvedHostRiskSemanticClass::HostRisk(
            HostRiskSemanticClass::PartitionTableSessionTarget,
        ) => CommandSinkReasonBuckets {
            partition_table_session_reasons: target_operands
                .iter()
                .filter(|target| {
                    sink_matches_host_target(sink.semantic_class, target.as_operand(), cwd, home)
                })
                .map(|target| sink_reason(&sink, target.text.as_str()))
                .collect(),
            ..CommandSinkReasonBuckets::default()
        },
        ResolvedHostRiskSemanticClass::HostRisk(
            HostRiskSemanticClass::PartitionLayoutMutationTarget,
        ) => CommandSinkReasonBuckets {
            partition_layout_mutation_reasons: target_operands
                .iter()
                .filter(|target| {
                    sink_matches_host_target(sink.semantic_class, target.as_operand(), cwd, home)
                })
                .map(|target| sink_reason(&sink, target.text.as_str()))
                .collect(),
            ..CommandSinkReasonBuckets::default()
        },
        ResolvedHostRiskSemanticClass::HostRisk(
            HostRiskSemanticClass::PartitionTableStateMutationTarget,
        ) => CommandSinkReasonBuckets {
            partition_table_state_mutation_reasons: collect_partition_table_state_mutation_reasons(
                sink,
                cwd,
                home,
                &target_operands,
            ),
            ..CommandSinkReasonBuckets::default()
        },
        _ => CommandSinkReasonBuckets {
            floor_reasons: target_operands
                .iter()
                .filter(|target| {
                    sink_matches_host_target(sink.semantic_class, target.as_operand(), cwd, home)
                })
                .map(|target| sink_reason(&sink, target.text.as_str()))
                .collect(),
            ..CommandSinkReasonBuckets::default()
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedHostTargetOperand {
    text: String,
    quoted: bool,
    node_kind: String,
}

impl OwnedHostTargetOperand {
    fn from_borrowed(operand: HostTargetOperand<'_>) -> Self {
        Self {
            text: operand.text.to_string(),
            quoted: operand.quoted,
            node_kind: operand.node_kind.to_string(),
        }
    }

    fn as_operand(&self) -> HostTargetOperand<'_> {
        HostTargetOperand {
            text: self.text.as_str(),
            quoted: self.quoted,
            node_kind: self.node_kind.as_str(),
        }
    }
}

fn materialized_host_target_operands(
    operands: &[HostTargetOperand<'_>],
    bindings: &SessionBindings,
) -> Vec<OwnedHostTargetOperand> {
    let mut materialized = Vec::new();
    for operand in operands.iter().copied() {
        push_unique_operand(
            &mut materialized,
            OwnedHostTargetOperand::from_borrowed(operand),
        );

        if let Some(text) = materialize_simple_shell_path_word(operand.text, bindings) {
            push_unique_operand(
                &mut materialized,
                OwnedHostTargetOperand {
                    text,
                    quoted: false,
                    node_kind: "word".to_string(),
                },
            );
        }

        if matches!(
            exact_shell_parameter_reference(operand.text),
            Some(ShellParameterReference::AllPositionals(_))
        ) {
            if let Some(fields) = materialize_exact_shell_parameter_reference_fields(
                operand.text,
                operand.quoted,
                bindings,
            ) {
                for field in fields {
                    push_unique_operand(
                        &mut materialized,
                        OwnedHostTargetOperand {
                            text: field.text,
                            quoted: false,
                            node_kind: "word".to_string(),
                        },
                    );
                }
            }
        }
    }
    materialized
}

fn push_unique_operand(target: &mut Vec<OwnedHostTargetOperand>, operand: OwnedHostTargetOperand) {
    if !target.contains(&operand) {
        target.push(operand);
    }
}

fn materialize_simple_shell_path_word(text: &str, bindings: &SessionBindings) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut quote = ShellQuote::None;
    let mut changed = false;

    while let Some(ch) = chars.next() {
        match quote {
            ShellQuote::None => match ch {
                '\'' => quote = ShellQuote::Single,
                '"' => quote = ShellQuote::Double,
                '\\' => {
                    out.push(ch);
                    out.push(chars.next()?);
                }
                '$' => {
                    let parameter = parse_shell_parameter_reference_after_dollar(&mut chars)?;
                    let value = exact_scalar_shell_parameter_value(bindings, &parameter)?;
                    push_unquoted_materialized_value(&mut out, &value);
                    changed = true;
                }
                _ => out.push(ch),
            },
            ShellQuote::Single => {
                if ch == '\'' {
                    quote = ShellQuote::None;
                } else {
                    push_quoted_materialized_char(&mut out, ch);
                }
            }
            ShellQuote::Double => match ch {
                '"' => quote = ShellQuote::None,
                '\\' => {
                    let escaped = chars.next()?;
                    push_quoted_materialized_char(&mut out, '\\');
                    push_quoted_materialized_char(&mut out, escaped);
                }
                '$' => {
                    let parameter = parse_shell_parameter_reference_after_dollar(&mut chars)?;
                    let value = exact_scalar_shell_parameter_value(bindings, &parameter)?;
                    push_quoted_materialized_value(&mut out, &value);
                    changed = true;
                }
                _ => push_quoted_materialized_char(&mut out, ch),
            },
        }
    }

    (quote == ShellQuote::None && changed).then_some(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellQuote {
    None,
    Single,
    Double,
}

fn push_unquoted_materialized_value(out: &mut String, value: &str) {
    out.push_str(value);
}

fn push_quoted_materialized_value(out: &mut String, value: &str) {
    for ch in value.chars() {
        push_quoted_materialized_char(out, ch);
    }
}

fn push_quoted_materialized_char(out: &mut String, ch: char) {
    if matches!(ch, '*' | '?' | '[' | ']' | '{' | '}' | ',' | '\\') {
        out.push('\\');
    }
    out.push(ch);
}

fn sink_matches_host_target(
    semantic_class: ResolvedHostRiskSemanticClass,
    target: HostTargetOperand<'_>,
    cwd: Option<&str>,
    home: Option<&str>,
) -> bool {
    match semantic_class {
        ResolvedHostRiskSemanticClass::Catastrophic(CatastrophicSemanticClass::DeletePath)
        | ResolvedHostRiskSemanticClass::HostRisk(HostRiskSemanticClass::MoveSourcePath) => {
            matches!(
                classify_host_target_with_optional_cwd(target, cwd, home),
                Some(HostTargetKind::CatastrophicDeleteRoot)
            )
        }
        ResolvedHostRiskSemanticClass::Catastrophic(CatastrophicSemanticClass::RawWriteTarget)
        | ResolvedHostRiskSemanticClass::Catastrophic(CatastrophicSemanticClass::FormatTarget)
        | ResolvedHostRiskSemanticClass::Catastrophic(
            CatastrophicSemanticClass::FilesystemSignatureWipeTarget,
        )
        | ResolvedHostRiskSemanticClass::Catastrophic(
            CatastrophicSemanticClass::PartitionTableMutationTarget,
        )
        | ResolvedHostRiskSemanticClass::HostRisk(
            HostRiskSemanticClass::PartitionLayoutMutationTarget,
        )
        | ResolvedHostRiskSemanticClass::HostRisk(
            HostRiskSemanticClass::PartitionTableSessionTarget,
        ) => {
            matches!(
                classify_host_target_with_optional_cwd(target, cwd, home),
                Some(HostTargetKind::BlockDevice)
            )
        }
        ResolvedHostRiskSemanticClass::HostRisk(
            HostRiskSemanticClass::PartitionTableStateMutationTarget,
        ) => false,
    }
}

fn sink_reason(sink: &ResolvedHostRiskSink<'_>, target: &str) -> String {
    match sink.semantic_class {
        ResolvedHostRiskSemanticClass::Catastrophic(CatastrophicSemanticClass::DeletePath) => {
            format!(
                "delete target {target} in command {} is a catastrophic filesystem root delete",
                sink.normalized_command_name
            )
        }
        ResolvedHostRiskSemanticClass::HostRisk(HostRiskSemanticClass::MoveSourcePath) => format!(
            "move source {target} in command {} is a catastrophic filesystem root relocation",
            sink.normalized_command_name
        ),
        ResolvedHostRiskSemanticClass::Catastrophic(CatastrophicSemanticClass::RawWriteTarget) => {
            format!(
                "raw block-device overwrite target {target} via {}",
                sink.normalized_command_name
            )
        }
        ResolvedHostRiskSemanticClass::Catastrophic(CatastrophicSemanticClass::FormatTarget) => {
            format!(
                "destructive block-device target {target} via {}",
                sink.normalized_command_name
            )
        }
        ResolvedHostRiskSemanticClass::Catastrophic(
            CatastrophicSemanticClass::FilesystemSignatureWipeTarget,
        ) => {
            format!(
                "filesystem signature wipe target {target} via {}",
                sink.normalized_command_name
            )
        }
        ResolvedHostRiskSemanticClass::Catastrophic(
            CatastrophicSemanticClass::PartitionTableMutationTarget,
        ) => {
            format!(
                "partition table destruction target {target} via {}",
                sink.normalized_command_name
            )
        }
        ResolvedHostRiskSemanticClass::HostRisk(
            HostRiskSemanticClass::PartitionLayoutMutationTarget,
        ) => {
            format!(
                "partition layout mutation target {target} via {}",
                sink.normalized_command_name
            )
        }
        ResolvedHostRiskSemanticClass::HostRisk(
            HostRiskSemanticClass::PartitionTableSessionTarget,
        ) => {
            format!(
                "partition table session target {target} via {}",
                sink.normalized_command_name
            )
        }
        ResolvedHostRiskSemanticClass::HostRisk(
            HostRiskSemanticClass::PartitionTableStateMutationTarget,
        ) => {
            format!(
                "partition table state mutation target {target} via {}",
                sink.normalized_command_name
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedMetadataMutationSink<'a> {
    target_operands: Vec<HostTargetOperand<'a>>,
    raw_operand: Option<&'a str>,
    recursive: bool,
    normalized_command_name: &'a str,
}

fn collect_path_metadata_mutation_reasons(
    resolved: &ResolvedInvocationArtifact,
    cwd: Option<&str>,
    home: Option<&str>,
    bindings: &SessionBindings,
) -> Vec<String> {
    let mut reasons = Vec::new();
    let mut visited_slots: Vec<&str> = Vec::new();

    for effect in &resolved.bound.effects {
        let Some(slot_name) = slot_name_from_effect_target(&effect.target) else {
            continue;
        };
        if visited_slots.contains(&slot_name) {
            continue;
        }
        visited_slots.push(slot_name);

        let Some(sink) = metadata_mutation_sink_for_slot(resolved, slot_name) else {
            continue;
        };
        extend_unique(
            &mut reasons,
            collect_metadata_mutation_reasons(sink, cwd, home, bindings),
        );
    }

    reasons
}

fn metadata_mutation_sink_for_slot<'a>(
    resolved: &'a ResolvedInvocationArtifact,
    slot_name: &'a str,
) -> Option<ResolvedMetadataMutationSink<'a>> {
    let target_operands = bound_argument_operands_for_slot(&resolved.bound, slot_name);
    if target_operands.is_empty() {
        return None;
    }

    let mut saw_metadata_mutation_effect = false;
    let mut raw_operand = None;
    let mut recursive = false;

    for effect in resolved
        .bound
        .effects
        .iter()
        .filter(|effect| effect_targets_slot(effect, slot_name))
    {
        if !is_metadata_mutation_effect(effect) {
            continue;
        }
        saw_metadata_mutation_effect = true;

        if raw_operand.is_none() {
            raw_operand = metadata_mutation_raw_operand(&resolved.bound, effect);
        }
        recursive |= effect
            .extensions
            .get("metadata_mutation.recursive")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
    }

    saw_metadata_mutation_effect.then_some(ResolvedMetadataMutationSink {
        target_operands,
        raw_operand,
        recursive,
        normalized_command_name: resolved.normalized_command_name.as_str(),
    })
}

fn is_metadata_mutation_effect(effect: &Effect) -> bool {
    matches!(
        effect.kind,
        EffectKind::ChangeMode
            | EffectKind::ChangeOwner
            | EffectKind::ChangeGroup
            | EffectKind::MetadataMutation
    )
}

fn effect_targets_slot(effect: &Effect, slot_name: &str) -> bool {
    matches!(&effect.target, EffectTarget::Slot(target) if target.as_str() == slot_name)
}

fn slot_name_from_effect_target(target: &EffectTarget) -> Option<&str> {
    match target {
        EffectTarget::Slot(slot_name) => Some(slot_name.as_str()),
        _ => None,
    }
}

fn metadata_mutation_raw_operand<'a>(
    bound: &'a BoundInvocation,
    effect: &Effect,
) -> Option<&'a str> {
    let slot_name = effect
        .extensions
        .get("metadata_mutation.raw_operand_slot")
        .and_then(|value| value.as_str())?;

    bound_argument_texts_for_slot(bound, slot_name)
        .first()
        .copied()
}

fn collect_metadata_mutation_reasons(
    sink: ResolvedMetadataMutationSink<'_>,
    cwd: Option<&str>,
    home: Option<&str>,
    bindings: &SessionBindings,
) -> Vec<String> {
    if !sink.recursive {
        return Vec::new();
    }

    let Some(classification) =
        classify_metadata_mutation(sink.raw_operand, sink.normalized_command_name)
    else {
        return Vec::new();
    };
    let command_name = sink.normalized_command_name;
    let target_operands = materialized_host_target_operands(&sink.target_operands, bindings);

    target_operands
        .iter()
        .filter(|target| {
            matches!(
                classify_host_target_with_optional_cwd(target.as_operand(), cwd, home),
                Some(HostTargetKind::CatastrophicDeleteRoot)
            )
        })
        .map(|target| metadata_mutation_reason(command_name, target.text.as_str(), classification))
        .collect()
}

fn collect_partition_table_state_mutation_reasons(
    sink: ResolvedHostRiskSink<'_>,
    cwd: Option<&str>,
    home: Option<&str>,
    target_operands: &[OwnedHostTargetOperand],
) -> Vec<String> {
    target_operands
        .iter()
        .filter(|target| {
            matches!(
                classify_host_target_with_optional_cwd(target.as_operand(), cwd, home),
                Some(HostTargetKind::BlockDevice)
            )
        })
        .map(|target| {
            format!(
                "partition table state mutation target {} via {}",
                target.text, sink.normalized_command_name
            )
        })
        .collect()
}

fn metadata_mutation_reason(
    command_name: &str,
    target: &str,
    classification: MetadataMutationKind,
) -> String {
    match classification {
        MetadataMutationKind::AllUsersRwx => format!(
            "recursive permission mutation target {target} in command {command_name} would grant all-users rwx on a catastrophic system root"
        ),
        MetadataMutationKind::WorldWritable => format!(
            "recursive permission mutation target {target} in command {command_name} would make a catastrophic system root world-writable"
        ),
        MetadataMutationKind::RootOwnership => format!(
            "recursive ownership mutation target {target} in command {command_name} would force a catastrophic system root to root ownership"
        ),
    }
}

fn extend_unique(target: &mut Vec<String>, incoming: Vec<String>) {
    for reason in incoming {
        if !target.contains(&reason) {
            target.push(reason);
        }
    }
}

fn resolved_from_execution_record(
    record: &ExecutionUnitResolveRecord,
) -> Option<&ResolvedInvocationArtifact> {
    match &record.result {
        caushell_profile::ResolveInvocationArtifactResult::Resolved(resolved) => Some(resolved),
        _ => None,
    }
}

fn collect_dispatch_scoped_path_semantics(
    resolved: &ResolvedInvocationArtifact,
) -> Vec<DestructivePathSemantic> {
    collect_destructive_path_semantics(resolved)
}

fn collect_dispatch_scoped_block_device_semantics(
    resolved: &ResolvedInvocationArtifact,
) -> Vec<DestructiveBlockDeviceSemantic> {
    let mut semantics = Vec::new();
    each_resolved_host_risk_sink(resolved, |sink| {
        let Some(semantic_class) = destructive_block_device_semantic_class(sink.semantic_class)
        else {
            return;
        };
        if !sink
            .target_operands
            .iter()
            .any(|operand| operand.text == "{}" && !operand.quoted)
        {
            return;
        }

        let semantic = DestructiveBlockDeviceSemantic {
            semantic_class,
            command_name: sink.normalized_command_name.to_string(),
        };
        if !semantics.contains(&semantic) {
            semantics.push(semantic);
        }
    });
    semantics
}

fn destructive_block_device_semantic_class(
    semantic_class: ResolvedHostRiskSemanticClass,
) -> Option<DestructiveBlockDeviceSemanticClass> {
    match semantic_class {
        ResolvedHostRiskSemanticClass::Catastrophic(CatastrophicSemanticClass::RawWriteTarget) => {
            Some(DestructiveBlockDeviceSemanticClass::RawWriteTarget)
        }
        ResolvedHostRiskSemanticClass::Catastrophic(CatastrophicSemanticClass::FormatTarget) => {
            Some(DestructiveBlockDeviceSemanticClass::FormatTarget)
        }
        ResolvedHostRiskSemanticClass::Catastrophic(
            CatastrophicSemanticClass::FilesystemSignatureWipeTarget,
        ) => Some(DestructiveBlockDeviceSemanticClass::FilesystemSignatureWipeTarget),
        ResolvedHostRiskSemanticClass::Catastrophic(
            CatastrophicSemanticClass::PartitionTableMutationTarget,
        ) => Some(DestructiveBlockDeviceSemanticClass::PartitionTableMutationTarget),
        _ => None,
    }
}

fn bound_argument_texts_for_slot<'a>(bound: &'a BoundInvocation, slot_name: &str) -> Vec<&'a str> {
    bound_argument_operands_for_slot(bound, slot_name)
        .into_iter()
        .map(|operand| operand.text)
        .collect()
}

fn bound_argument_operands_for_slot<'a>(
    bound: &'a BoundInvocation,
    slot_name: &str,
) -> Vec<HostTargetOperand<'a>> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot_name)
        .flat_map(|parameter| parameter.values.iter())
        .filter_map(|value| match value {
            BoundValue::Argument {
                text,
                quoted,
                node_kind,
                ..
            } => Some(HostTargetOperand {
                text: text.as_str(),
                quoted: *quoted,
                node_kind: node_kind.as_str(),
            }),
            BoundValue::ImplicitInput { .. } => None,
        })
        .collect()
}
