//! A metadata query is not a grant to read arbitrary file contents.
use crate::{
    CommandLookupDomain, CommandProfile, Effect, EffectKind, FilesystemNamespaceImpact, Parameter, PathRole,
    PathSemantic, SemanticType, StructuredValueContext,
};
use caushell_types::NativeArgvEffectEnvelope;

pub fn native_effect_contract_allows_effect(
    kind: NativeArgvEffectEnvelope,
    effect: &Effect,
) -> bool {
    let allowed = match effect.kind {
        EffectKind::ReadPath => kind.reads_content(),
        EffectKind::TargetPath => kind.queries_metadata(),
        EffectKind::NetworkEndpoint => kind.queries_network(),
        EffectKind::ConsumeStdin | EffectKind::TransformData => true,
        _ => false,
    };
    allowed && effect.filesystem_namespace_impact() == FilesystemNamespaceImpact::Neutral
}

/// A single unknown chgrp field cannot supply both a recursive option and a
/// group operand. A GNU attached reference still queries metadata, and the
/// final path remains the only possible target of the group change.
pub(crate) fn retain_chgrp_single_field_effects(
    profile: &CommandProfile,
    materialized: &crate::MaterializedProjectedInvocation,
    bound: &mut crate::BoundInvocation,
) {
    use crate::{BoundParameter, EffectTarget, ProfileSourceKind, ResidualKind, ResidualSurface};
    if profile.primary_name() != "chgrp"
        || profile.trust.source != ProfileSourceKind::BuiltIn
        || materialized.invocation.shell_kind != caushell_types::ShellKind::Bash
        || bound.form_id.as_str() != "change_group"
        || !bound.applied_modifiers.is_empty()
        || !bound.operation_semantics_unresolved
        || !matches!(bound.residuals.as_slice(), [gap]
            if gap.kind == ResidualKind::UnboundControlSurface
                && gap.surface == ResidualSurface::Control
                && gap.reason == crate::bind::ARGUMENT_REGION_OWNERSHIP_GAP
                && gap.slot.is_none())
    {
        return;
    }
    let [group, target] = materialized.invocation.args.as_slice() else {
        return;
    };
    let target_shape = crate::argument_structure(target);
    if group.runtime_data
        || group.implicit_input_source.is_some()
        || crate::argument_structure(group).fields != crate::ArgumentFieldCount::ExactlyOne
        || !matches!(
            caushell_parse::scalar_argument_parts(&group.text, group.quoted, &group.node_kind)
                .as_deref(),
            Some([caushell_parse::ScalarArgumentPart::Parameter(_)])
        )
        || !target_shape
            .exact_value()
            .is_some_and(|path| !path.is_empty() && !path.starts_with('-'))
    {
        return;
    }
    let [effect] = bound.effects.as_slice() else {
        return;
    };
    let EffectTarget::Slot(target_slot) = &effect.target else {
        return;
    };
    if effect.kind != EffectKind::ChangeGroup
        || !bound.bound_parameters.iter().any(|parameter| {
            parameter.name == *target_slot
                && matches!(&parameter.values[..], [crate::BoundValue::Argument { span, .. }]
                    if *span == target.span)
        })
    {
        return;
    }
    let Some(group_value) =
        bound
            .bound_parameters
            .iter()
            .find_map(|parameter| match parameter.values.as_slice() {
                [value @ crate::BoundValue::Argument { span, .. }]
                    if parameter.name.as_str() == "group" && *span == group.span =>
                {
                    Some(value.clone())
                }
                _ => None,
            })
    else {
        return;
    };
    let Some(reference) = profile
        .modifiers
        .iter()
        .find(|m| m.id.as_str() == "reference")
    else {
        return;
    };
    let ([reference_parameter], [reference_effect]) =
        (&reference.parameters[..], &reference.effects[..])
    else {
        return;
    };
    let Some(reference_form) = profile
        .forms
        .iter()
        .find(|f| f.id.as_str() == "change_group_from_reference")
    else {
        return;
    };
    let [group_effect] = reference_form.effects.as_slice() else {
        return;
    };
    if group_effect.kind != EffectKind::ChangeGroup
        || group_effect.target != effect.target
        || reference_effect.kind != EffectKind::TargetPath
        || reference_effect.target != EffectTarget::Slot(reference_parameter.name.clone())
    {
        return;
    }
    bound
        .bound_parameters
        .retain(|p| p.name.as_str() != "group");
    bound.bound_parameters.push(
        BoundParameter::new(
            reference_parameter.name.clone(),
            reference_parameter.semantic.clone(),
        )
        .with_value(group_value),
    );
    bound.effects = vec![group_effect.clone(), reference_effect.clone()];
    bound.operation_semantics_unresolved = false;
    bound.residuals.clear();
    bound.stream_contract = None;
    bound.stdout_growth_complete = false;
}

/// A symbolic link with no destination, or with a literal current-directory
/// destination and a proved source operand, can only create a cwd entry.
/// Keep the possible link target as data and retain the write family.
pub(crate) fn retain_standalone_symbolic_link_effects(
    profile: &CommandProfile,
    materialized: &crate::MaterializedProjectedInvocation,
    bound: &mut crate::BoundInvocation,
    positional_capture: Option<&caushell_parse::SourceSpan>,
) {
    use crate::{
        DerivedPathSource, EffectTarget, PathScope, ProfileSourceKind, ResidualKind,
        ResidualSurface, ToolConventionPathTarget,
    };
    if profile.primary_name() != "ln"
        || profile.trust.source != ProfileSourceKind::BuiltIn
        || !native_surface_is_direct(profile)
        || materialized.invocation.shell_kind != caushell_types::ShellKind::Bash
        || materialized.shell_expansion_unresolved
        || !matches!(bound.applied_modifiers.as_slice(), [flag] if flag.as_str() == "symbolic")
        || !bound.operation_semantics_unresolved
        || !matches!(bound.residuals.as_slice(), [gap]
            if gap.kind == ResidualKind::UnboundControlSurface
                && gap.surface == ResidualSurface::Control
                && gap.reason == crate::bind::ARGUMENT_REGION_OWNERSHIP_GAP
                && gap.slot.is_none())
    {
        return;
    }
    let (flag, source, convention) = match (
        bound.form_id.as_str(), materialized.invocation.args.as_slice(), positional_capture,
    ) {
        ("implicit_destination", [flag, source], None)
            if matches!(
                caushell_parse::scalar_argument_parts(&source.text, source.quoted, &source.node_kind)
                    .as_deref(),
                Some([caushell_parse::ScalarArgumentPart::Parameter(_)])
            ) =>
        {
            // If this field is an option, ln has no source operand.
            (flag, source, "implicit_symbolic_link_directory")
        }
        ("link_into_current_directory", [flag, source, destination], Some(span))
            if &source.span == span && source.quoted
                && crate::argument_structure(destination).exact_value() == Some(".") =>
        {
            (flag, source, "explicit_symbolic_link_current_directory")
        }
        _ => return,
    };
    if crate::argument_structure(flag).exact_value() != Some("-s")
        || source.runtime_data
        || source.implicit_input_source.is_some()
        || crate::argument_structure(source).fields != crate::ArgumentFieldCount::ExactlyOne
    {
        return;
    }
    let [link, write] = bound.effects.as_mut_slice() else {
        return;
    };
    let EffectTarget::DerivedPath(target) = &write.target else {
        return;
    };
    if link.kind != EffectKind::TargetPath
        || write.kind != EffectKind::WritePath
        || target.root.is_some()
        || target.rule != caushell_types::DerivedPathRule::Basename
        || !matches!(&target.source, DerivedPathSource::Slot(slot)
            if link.target == EffectTarget::Slot(slot.clone()))
    {
        return;
    }
    write.target = EffectTarget::ToolConventionPath(ToolConventionPathTarget {
        path: ".".into(),
        convention: convention.into(),
        purpose: target.purpose,
    });
    write.path_scope = Some(PathScope::Subtree {
        escape_modifiers: Vec::new(),
        narrowing_modifiers: vec![bound.applied_modifiers[0].clone()],
    });
    bound.operation_semantics_unresolved = false;
    bound.residuals.clear();
    // The field remains unknown. Do not use this effect proof to claim an
    // exact output or forward the possible link target as stream data.
    bound.stream_contract = None;
    bound.stdout_growth_complete = false;
}

pub fn native_effect_contract_allows_parameter(
    kind: NativeArgvEffectEnvelope,
    parameter: &Parameter,
) -> bool {
    match &parameter.semantic {
        SemanticType::PlainValue => true,
        SemanticType::Endpoint(_) => kind.queries_network(),
        SemanticType::Path(PathSemantic { role, .. }) => {
            (*role == PathRole::Read && kind.reads_content())
                || (*role == PathRole::Target && kind.queries_metadata())
        }
        SemanticType::StructuredValue(value) => match value.context {
            // In an explicitly reviewed data-only native surface, numeric
            // operands and format strings are data, not shell evaluation.
            // State writes, dispatch, config and code effects still fail the
            // total closure below (including printf's native variable writes).
            StructuredValueContext::FormatString => {
                kind.queries_metadata() || kind == NativeArgvEffectEnvelope::DataOnly
            }
            StructuredValueContext::NumericQuantity => kind == NativeArgvEffectEnvelope::DataOnly,
            StructuredValueContext::Regex => kind.reads_content(),
            StructuredValueContext::PathExpression => kind == NativeArgvEffectEnvelope::DataOnly,
            _ => false,
        },
        _ => false,
    }
}

fn native_surface_is_direct(profile: &CommandProfile) -> bool {
    profile.subcommands.is_none()
        && profile.dispatch_overrides.is_empty()
        && profile.argument_regions.is_empty()
        && profile.argument_files.is_empty()
        && profile.environment_inputs.is_empty()
        && profile.option_environment.is_none()
        && profile.archive_extraction.is_none()
        && profile.implicit_config_files.is_empty()
        && profile.configuration_files.is_none()
        && profile.native_configuration.is_none()
        && profile.selection_failure_effects.is_empty()
}

/// A fixed batch switch and process filter stay noninteractive when a
/// decimal PID capture is missing, split, or rejected by the native parser.
pub(crate) fn retain_top_batch_pid_fields(
    profile: &CommandProfile,
    command: &caushell_parse::CommandFact,
    argv: &crate::ProjectedInvocation,
    bindings: &crate::SessionBindings,
    proofs: &[(caushell_parse::SourceSpan, crate::SubstitutionOutputProof)],
    bound: &mut crate::BoundInvocation,
) {
    use crate::*;
    if profile.primary_name() != "top"
        || profile.trust.source != ProfileSourceKind::BuiltIn
        || !native_surface_is_direct(profile)
        || argv.shell_kind != caushell_types::ShellKind::Bash
        || command.command_name.as_deref() != Some("top")
        || command.command_name_runtime_data
        || !command.prefix_assignments.is_empty()
        || bindings.get("XDG_CONFIG_HOME").is_some()
        || bound.form_id.as_str() != "batch"
        || !bound.effects.is_empty()
        || !bound.operation_semantics_unresolved
        || !matches!(bound.residuals.as_slice(), [gap]
            if gap.kind == ResidualKind::UnboundControlSurface
                && gap.surface == ResidualSurface::Control
                && gap.reason == crate::bind::ARGUMENT_REGION_OWNERSHIP_GAP
                && gap.slot.is_none())
    {
        return;
    }
    let [batch, process_filter, capture, remaining @ ..] = argv.args.as_slice() else {
        return;
    };
    if argument_structure(batch).exact_value() != Some("-b")
        || argument_structure(process_filter).exact_value() != Some("-p")
        || capture.quoted
        || capture.runtime_data
        || capture.implicit_input_source.is_some()
        || capture.substitution_shape != Some(StdoutScalarShape::ArithmeticText)
        || !matches!(proofs, [(span, SubstitutionOutputProof::DecimalPidFields)]
            if span == &capture.span)
    {
        return;
    }
    match remaining {
        [] => {}
        [flag, count]
            if argument_structure(flag).exact_value() == Some("-n")
                && argument_structure(count).exact_value().is_some_and(|value| {
                    !value.is_empty()
                        && value.bytes().all(|byte| byte.is_ascii_digit())
                        && value.parse::<u32>().is_ok_and(|count| count > 0)
                }) => {}
        _ => return,
    }
    bound.operation_semantics_unresolved = false;
    bound.residuals.clear();
    // Keep the batch form's stream behavior. The bound does not prove
    // an exact process list or a finite successful output.
    bound.stdout_growth_complete = false;
}

/// For an option-free native move the last surviving field is the destination.
/// Earlier split fields may be sources, including the literal prefix directory.
/// Both effects must pass the existing entry-relocation namespace proof.
pub(crate) fn retain_move_path_fields(
    profile: &CommandProfile,
    command: &caushell_parse::CommandFact,
    argv: &crate::ProjectedInvocation,
    proofs: &[(caushell_parse::SourceSpan, crate::SubstitutionOutputProof)],
    bound: &mut crate::BoundInvocation,
) {
    use crate::*;
    let [first, tail] = argv.args.as_slice() else {
        return;
    };
    if profile.primary_name() != "mv"
        || profile.trust.source != ProfileSourceKind::BuiltIn
        || !native_surface_is_direct(profile)
        || argv.shell_kind != caushell_types::ShellKind::Bash
        || command.command_name_runtime_data
        || !command.prefix_assignments.is_empty()
        || !matches!(proofs, [(span, SubstitutionOutputProof::LocalMovePathFields)]
            if span == &tail.span)
        || first.runtime_data
        || first.implicit_input_source.is_some()
        || tail.runtime_data
        || tail.implicit_input_source.is_some()
        || bound.form_id.as_str() != "default_move"
        || !bound.applied_modifiers.is_empty()
        || !bound.operation_semantics_unresolved
        || !matches!(bound.residuals.as_slice(), [gap]
            if gap.kind == ResidualKind::UnboundControlSurface
                && gap.surface == ResidualSurface::Control
                && gap.reason == crate::bind::ARGUMENT_REGION_OWNERSHIP_GAP
                && gap.slot.is_none())
    {
        return;
    }
    let first_shape = argument_structure(first);
    let Some(basename) = first_shape.exact_value() else {
        return;
    };
    if basename.is_empty() || matches!(basename, "." | "..")
        || basename.starts_with(['-', '+']) || basename.contains(['/', '\0'])
    {
        return;
    }

    let [source, destination] = bound.effects.as_slice() else {
        return;
    };
    let (EffectTarget::Slot(source_slot), EffectTarget::Slot(destination_slot)) =
        (&source.target, &destination.target)
    else {
        return;
    };
    if source.kind != EffectKind::MovePath || destination.kind != EffectKind::WritePath
        || [source, destination].iter().any(|effect|
            effect.namespace_effect != Some(caushell_types::PathNamespaceEffect::EntryRelocation))
    {
        return;
    }
    let [source_parameter, destination_parameter] = bound.bound_parameters.as_mut_slice() else {
        return;
    };
    if &source_parameter.name != source_slot || &destination_parameter.name != destination_slot
        || !matches!(source_parameter.values.as_slice(), [BoundValue::Argument { span, .. }]
            if span == &first.span)
        || !matches!(destination_parameter.values.as_slice(), [BoundValue::Argument { span, .. }]
            if span == &tail.span)
    {
        return;
    }

    // A closed directory family covers the fixed source, possible additional
    // sources and native placement into the final entry if it is a directory.
    // Retain the split word's provenance without asserting a field count.
    for parameter in [source_parameter, destination_parameter] {
        parameter.values[0] = BoundValue::ImplicitInput {
            source: ImplicitInputSource::CommandSubstitution,
            domain: Some(caushell_types::RuntimeArgumentDomain::PathSet {
                roots: vec!["./".into()],
                may_escape: false,
                basename_suffix: None,
                no_adjacent_slashes: false,
                dot_relative_components: false,
                execdir_leaf: false,
            }),
            origin: Some(BoundImplicitArgumentOrigin {
                span: tail.span.clone(),
                single_field: false,
            }),
        };
    }
    bound.operation_semantics_unresolved = false;
    bound.residuals.clear();
}

/// The timestamp and Bash PID may both split. None of their fields can
/// become options or the stdout descriptor. Any remaining operand is a
/// decimal name in cwd, the literal PID directory, or a child of that
/// directory. Keep these families subject to normal write-path checks.
pub(crate) fn retain_touch_timestamp_fields(
    profile: &CommandProfile,
    command: &caushell_parse::CommandFact,
    argv: &crate::ProjectedInvocation,
    proofs: &[(caushell_parse::SourceSpan, crate::SubstitutionOutputProof)],
    bound: &mut crate::BoundInvocation,
) {
    use crate::*;
    let [flag, timestamp, target] = argv.args.as_slice() else {
        return;
    };
    if profile.primary_name() != "touch"
        || profile.trust.source != ProfileSourceKind::BuiltIn
        || !native_surface_is_direct(profile)
        || argv.shell_kind != caushell_types::ShellKind::Bash
        || command.command_name_runtime_data
        || !command.prefix_assignments.is_empty()
        || argument_structure(flag).exact_value() != Some("-t")
        || !matches!(proofs, [(span, SubstitutionOutputProof::DecimalCalendarFields)]
            if span == &timestamp.span)
        || [timestamp, target].iter().any(|argument| {
            argument.quoted || argument.runtime_data || argument.implicit_input_source.is_some()
        })
        || bound.form_id.as_str() != "create_or_update_paths"
        || !matches!(bound.applied_modifiers.as_slice(), [id] if id.as_str() == "timestamp")
        || !bound.operation_semantics_unresolved
        || !matches!(bound.residuals.as_slice(), [gap]
            if gap.kind == ResidualKind::UnboundControlSurface
                && gap.surface == ResidualSurface::Control
                && gap.reason == crate::bind::ARGUMENT_REGION_OWNERSHIP_GAP
                && gap.slot.is_none())
    {
        return;
    }
    let Some(directory) = target.text.strip_suffix("$$").filter(|p| p.ends_with('/')) else {
        return;
    };
    if directory.starts_with(['-', '+'])
        || directory.starts_with("//")
        || directory.split('/').any(|component| component == "..")
        || !directory.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
    {
        return;
    }
    let [effect] = bound.effects.as_slice() else {
        return;
    };
    let EffectTarget::Slot(slot) = &effect.target else {
        return;
    };
    if effect.kind != EffectKind::WritePath
        || effect.namespace_effect != Some(caushell_types::PathNamespaceEffect::RegularFileWrite)
    {
        return;
    }
    let Some(paths) = bound.bound_parameters.iter_mut().find(|parameter| &parameter.name == slot)
    else {
        return;
    };
    if !matches!(paths.values.as_slice(), [BoundValue::Argument { span, .. }] if span == &target.span) {
        return;
    }
    paths.values[0] = BoundValue::ImplicitInput {
        source: ImplicitInputSource::CommandSubstitution,
        domain: Some(caushell_types::RuntimeArgumentDomain::PathSet {
            roots: vec![directory.into(), "./".into()],
            may_escape: false,
            basename_suffix: None,
            no_adjacent_slashes: !directory.contains("//"),
            dot_relative_components: false,
            execdir_leaf: false,
        }),
        origin: None,
    };
    bound.operation_semantics_unresolved = false;
    bound.residuals.clear();
    bound.stream_contract = None;
    bound.stdout_growth_complete = false;
}

/// The lone decimal word following pv's rate option can be absent, be the
/// rate, or also yield input filenames. Close that transfer's effect union
/// without assigning the actual argv or dropping any possible content read.
pub(crate) fn retain_pv_read_effects_for_split_rate(
    profile: &CommandProfile,
    command: &caushell_parse::CommandFact,
    projection: &crate::ProjectedInvocation,
    selection: &crate::InvocationSelection<'_>,
    bindings: &crate::SessionBindings,
    bound: &mut crate::BoundInvocation,
) {
    use crate::*;
    let contract = NativeArgvEffectEnvelope::ContentRead;
    if profile.primary_name() != "pv"
        || profile.trust.source != ProfileSourceKind::BuiltIn
        || !native_surface_is_direct(profile)
        || profile.native_variable_writes.is_some()
        || projection.shell_kind != caushell_types::ShellKind::Bash
        || !command.prefix_assignments.is_empty()
        || observed_ifs_value(bindings).is_some()
        || bound.form_id.as_str() != "transfer_stream"
        || !bound.operation_semantics_unresolved
        || bound.residuals.len() != 1
        || bound.residuals != selection.residuals
        || !selection.option_scope.as_ref().is_some_and(|scope| {
            scope.ownership_unresolved && scope.error.is_none()
        })
        || !bound.effects.iter().all(|effect| native_effect_contract_allows_effect(contract, effect))
        || !profile.forms.iter().any(|form| {
            form.id.as_str() == "transfer_files"
                && !form.operation_semantics_unresolved
                && form.payload_projections.is_empty()
                && form.effects.iter().all(|effect| native_effect_contract_allows_effect(contract, effect))
        })
    {
        return;
    }
    let [flag, argument] = projection.args.as_slice() else {
        return;
    };
    if !matches!(argument_structure(flag).exact_value(), Some("-L" | "--rate-limit"))
        || argument.node_kind != "arithmetic_expansion"
        || argument.quoted
        || argument.runtime_data
        || argument.implicit_input_source.is_some()
        || argument.runtime_argument_domain.is_some()
    {
        return;
    }
    let Some(value) = caushell_parse::constant_arithmetic_word(&argument.text)
        .and_then(|number| u32::try_from(number).ok())
    else {
        return;
    };
    let Some(layouts) = crate::field_splitting::decimal_field_layouts(value) else {
        return;
    };

    // The option's first field is its rate, never a filename. Missing/empty
    // rates and empty pathnames add no successful content open. Including the
    // later nonempty fields of every layout is a conservative read union.
    let paths: std::collections::BTreeSet<_> = layouts.into_iter()
        .flat_map(|fields| fields.into_iter().skip(1).filter(|field| !field.is_empty()))
        .collect();
    if !paths.is_empty() {
        let slot = SlotName::new("possible_input_files");
        let mut parameter = BoundParameter::new(
            slot.clone(),
            SemanticType::Path(PathSemantic {
                role: PathRole::Read,
                purpose: Some(PathPurpose::GenericOperand),
            }),
        );
        parameter.values.extend(paths.into_iter().map(|path| {
            BoundValue::argument(path, false, argument.span.clone(), ArgumentBindingSource::RemainingArg)
                .with_materialization(BoundArgumentMaterialization::RuntimeData)
        }));
        let mut read = Effect::new(EffectKind::ReadPath).for_slot(slot.as_str());
        read.path_access = Some(PathAccessKind::ContentOpen);
        bound.bound_parameters.push(parameter);
        bound.effects.push(read);
    }
    bound.form_id = FormId::new("__symbolic_argv_effect_envelope__");
    bound.operation_semantics_unresolved = false;
    bound.residuals.clear();
    retain_symbolic_argv_stream_contract(bound, contract);
}

/// Close the known effects of a single sed operand with a proved expansion.
pub(crate) fn retain_sed_substitution(
    profile: &CommandProfile,
    command: &caushell_parse::CommandFact,
    projection: &crate::ProjectedInvocation,
    proofs: &[(caushell_parse::SourceSpan, crate::SubstitutionOutputProof)],
    bound: &mut crate::BoundInvocation,
) {
    use crate::*;
    if let [(source, SubstitutionOutputProof::SedDecimalAddresses { suffix, max_records })] = proofs {
        retain_sed_decimal_addresses(profile, command, projection, source, suffix, *max_records, bound);
        return;
    }
    let [argument] = projection.args.as_slice() else {
        return;
    };
    let [(source, proof)] = proofs else {
        return;
    };
    if profile.primary_name() != "sed"
        || profile.trust.source != ProfileSourceKind::BuiltIn
        || !native_surface_is_direct(profile)
        || profile.native_variable_writes.is_some()
        || projection.shell_kind != caushell_types::ShellKind::Bash
        || command.command_name_runtime_data
        || !command.prefix_assignments.is_empty()
        || argument.runtime_data
        || argument.implicit_input_source.is_some()
        || argument.span != *source
        || bound.form_id.as_str() != "positional_script_transform_stdin"
    {
        return;
    }
    if let SubstitutionOutputProof::SedDayTemplate { literal_parts } = proof {
        if sed_day_template_only_transforms(literal_parts) {
            let mut transform = BoundInvocation::new(
                bound.command_name.clone(),
                FormId::new("__symbolic_argv_effect_envelope__"),
            );
            let mut stdin = Effect::new(EffectKind::ConsumeStdin);
            stdin.target = EffectTarget::ImplicitInput(ImplicitInputSource::StdinData);
            transform.effects.push(stdin);
            transform.bound_implicit_inputs.push(BoundImplicitInput::new(
                ImplicitInputSource::StdinData,
                SemanticType::PlainValue,
            ));
            transform.effects.push(Effect::new(EffectKind::TransformData));
            retain_symbolic_argv_stream_contract(&mut transform, NativeArgvEffectEnvelope::DataOnly);
            *bound = transform;
        }
        return;
    }
    if argument.quoted || !matches!(proof, SubstitutionOutputProof::LineCountQuit) {
        return;
    }
    // Splitting a decimal count plus q can add filenames or leave an
    // invalid script. It cannot introduce options or sed instructions.
    let mut reads = BoundInvocation::new(
        bound.command_name.clone(),
        FormId::new("__symbolic_argv_effect_envelope__"),
    );
    let slot = "possible_input_files";
    let mut parameter = BoundParameter::new(
        SlotName::new(slot),
        SemanticType::Path(PathSemantic {
            role: PathRole::Read,
            purpose: Some(PathPurpose::GenericOperand),
        }),
    );
    parameter.values.push(BoundValue::argument_with_node_kind(
        argument.text.clone(), false, argument.node_kind.clone(), argument.span.clone(),
        ArgumentBindingSource::RemainingArg,
    ));
    reads.bound_parameters.push(parameter);
    let mut file_read = Effect::new(EffectKind::ReadPath).for_slot(slot);
    file_read.path_access = Some(PathAccessKind::ContentOpen);
    reads.effects.push(file_read);
    retain_symbolic_argv_stream_contract(&mut reads, NativeArgvEffectEnvelope::ContentRead);
    *bound = reads;
}

fn retain_sed_decimal_addresses(
    profile: &CommandProfile,
    command: &caushell_parse::CommandFact,
    projection: &crate::ProjectedInvocation,
    source: &caushell_parse::SourceSpan,
    suffix: &str,
    max_records: Option<u64>,
    bound: &mut crate::BoundInvocation,
) {
    use crate::*;
    if profile.primary_name() != "sed"
        || profile.trust.source != ProfileSourceKind::BuiltIn
        || !native_surface_is_direct(profile)
        || projection.shell_kind != caushell_types::ShellKind::Bash
        || command.command_name_runtime_data
        || !command.prefix_assignments.is_empty()
        || !matches!(bound.form_id.as_str(), "positional_script_transform_quiet" | "positional_script_transform_stdin_quiet")
        || !crate::sed_payload::decimal_range_is_print_only(suffix, max_records)
        || !bound.residuals.iter().all(|residual| {
            residual.kind == ResidualKind::UnboundControlSurface
                && residual.surface == ResidualSurface::Control
                && residual.slot.is_none()
                && residual.reason == crate::bind::ARGUMENT_REGION_OWNERSHIP_GAP
        })
    {
        return;
    }
    let [script_projection] = bound.payload_projections.as_slice() else {
        return;
    };
    let PayloadInputSource::Slot(script) = &script_projection.source else {
        return;
    };
    if script_projection.format != PayloadFormat::SedProgram
        || !bound.bound_parameters.iter().any(|parameter| {
            parameter.name == *script
                && matches!(parameter.values.as_slice(), [BoundValue::Argument { span, quoted: true, .. }] if span == source)
        })
        || projection.args.iter().any(|arg| arg.span != *source && argument_structure(arg).exact_value().is_none())
    {
        return;
    }

    // These slots come exclusively from the script. Preserve input operands
    // and their read effects, and keep stdout dependent on the input data.
    let slots = [
        Some(&script_projection.reads), Some(&script_projection.writes),
        Some(&script_projection.deletes), script_projection.executions.as_ref(),
    ];
    bound.bound_parameters.retain(|parameter| {
        !parameter.payload_generated || !slots.iter().flatten().any(|slot| **slot == parameter.name)
    });
    bound.effects.retain(|effect| {
        !matches!(&effect.target, EffectTarget::Slot(slot) if slots.iter().flatten().any(|s| *s == slot))
    });
    bound.payload_projections.clear();
    bound.operation_semantics_unresolved = false;
    bound.residuals.clear();
}

fn sed_day_template_only_transforms(literal_parts: &[String]) -> bool {
    let [first, suffixes @ ..] = literal_parts else {
        return false;
    };
    if !first.starts_with("s/")
        || !(1..=2).contains(&suffixes.len())
        || literal_parts.iter().map(String::len).sum::<usize>() > 256
    {
        return false;
    }
    // Each capture can fail independently. An empty pattern or a changed
    // parse in any expansion must also pass the same lexical effect decoder.
    let days: Vec<_> = std::iter::once(String::new())
        .chain((1..=31).map(|day| format!("{day:02}")))
        .collect();
    let mut scripts = vec![first.clone()];
    for suffix in suffixes {
        scripts = scripts.iter()
            .flat_map(|prefix| days.iter().map(move |day| format!("{prefix}{day}{suffix}")))
            .collect();
    }
    scripts.iter().all(|script| {
        crate::sed_payload::decode(script, 260, 16).is_ok_and(|targets| {
            targets.reads.is_empty() && targets.writes.is_empty() && targets.executions.is_empty()
        })
    })
}

pub fn native_effect_contract_is_closed(
    profile: &CommandProfile,
    contract: NativeArgvEffectEnvelope,
) -> bool {
    native_effect_contract_is_closed_in_domain(profile, contract, &CommandLookupDomain::Unknown)
}

/// An externally dispatched utility cannot use an owning-shell variable
/// write grammar. All other closure requirements are independent of lookup.
pub fn native_effect_contract_is_closed_in_domain(
    profile: &CommandProfile,
    contract: NativeArgvEffectEnvelope,
    lookup_domain: &CommandLookupDomain,
) -> bool {
    if profile.native_argv_effect_envelope == Some(contract) && !profile.read_only_control_surface {
        return false;
    }

    if profile.native_argv_effect_envelope == Some(contract)
        && (profile
            .forms
            .iter()
            .flat_map(|f| &f.parameters)
            .any(|p| !native_effect_contract_allows_parameter(contract, p))
            || profile
                .modifiers
                .iter()
                .flat_map(|m| &m.parameters)
                .any(|p| !native_effect_contract_allows_parameter(contract, p)))
    {
        return false;
    }
    if !native_surface_is_direct(profile)
        || (profile.native_variable_writes.is_some()
            && !matches!(lookup_domain, CommandLookupDomain::External))
        || profile.forms.iter().any(|f| {
            f.operation_semantics_unresolved
                || !f.payload_projections.is_empty()
                || f.effects
                    .iter()
                    .any(|e| !native_effect_contract_allows_effect(contract, e))
        })
        || profile.modifiers.iter().any(|m| {
            m.effects
                .iter()
                .any(|e| !native_effect_contract_allows_effect(contract, e))
        })
    {
        return false;
    }
    true
}

/// An exact-argv budget gap can be irrelevant to native effects, but only
/// after a fixed prefix has selected a plain-data remainder. Do not infer
/// controls, paths, destinations, exact values, counts or output shapes.
pub(crate) fn budget_gaps_are_data_operands(
    profile: &CommandProfile,
    selection: &crate::InvocationSelection<'_>,
    materialized: &crate::MaterializedProjectedInvocation,
    bound: &crate::BoundInvocation,
    known_printf_format: Option<&caushell_parse::SourceSpan>,
) -> bool {
    use crate::*;
    if !native_surface_is_direct(profile)
        || bound.operation_semantics_unresolved
        || !bound.residuals.is_empty()
        || selection.form.operation_semantics_unresolved
        || !selection.form.payload_projections.is_empty()
        || !bound.payload_projections.is_empty()
        || !bound.argument_regions.is_empty()
        || materialized.shell_expansion_gaps.is_empty()
        || materialized.shell_expansion_gaps.iter().any(|gap| {
            gap.kind != ShellExpansionGapKind::BraceBudgetExhausted
                || gap.bounded_literal_bytes.is_none()
        })
        || bound.effects.is_empty()
        || bound.effects.iter().any(|effect| {
            !native_effect_contract_allows_effect(NativeArgvEffectEnvelope::DataOnly, effect)
        })
    {
        return false;
    }
    let Some(first) = materialized.invocation.args.iter().position(|arg| {
        materialized
            .shell_expansion_gaps
            .iter()
            .any(|gap| gap.span == arg.span)
    }) else {
        return false;
    };
    if first == 0
        || materialized.invocation.args[..first]
            .iter()
            .any(|arg| {
                argument_structure(arg).exact_value().is_none()
                    && known_printf_format != Some(&arg.span)
            })
    {
        return false;
    }
    materialized.shell_expansion_gaps.iter().all(|gap| {
        bound.bound_parameters.iter().any(|parameter| {
            parameter.semantic == SemanticType::PlainValue
                && parameter.structured_projection.is_none()
                && parameter.value_projection.is_none()
                && selection.form.parameters.iter().any(|declared| declared.name == parameter.name && declared.binding == BindingSpec::RemainingArgs)
                && parameter.values.iter().any(|value| matches!(value,
                    BoundValue::Argument { span, binding_source: ArgumentBindingSource::RemainingArg, .. } if span == &gap.span))
        })
    })
}
/// Shared uncertainty contract for native argument interpretation, irrespective
/// of the producer of argv. Never certify records, scalars or output bounds.
pub fn retain_symbolic_argv_stream_contract(
    bound: &mut crate::BoundInvocation,
    contract: NativeArgvEffectEnvelope,
) {
    use crate::*;
    bound.native_argv_effect_envelope = Some(contract);
    bound.stdout_records = None;
    bound.stdout_growth = None;
    bound.stdout_scalar = None;
    bound.stdout_scalar_inputs.clear();
    bound.stdout_scalar_native_variant = None;
    bound.stdout_scalar_complete = false;
    bound.stdout_growth_complete = false;
    bound.stream_contract = Some(StreamContract {
        stdin_mode: StreamInputMode::DataOptional,
        stdout_mode: StreamOutputMode::Data,
        stderr_mode: StreamOutputMode::Data,
        stdout_dependency: caushell_types::StreamDataDependency::Inputs,
        stderr_dependency: caushell_types::StreamDataDependency::Inputs,
        stdout_from_payload: false,
    });
}

/// Certify the exact prefix before symbolic argv. Both selection recovery and
/// binding closure use this same proof: no unknown option ownership is guessed.
/// Literal data after the symbolic word stays a possible input; known controls
/// after it require a separate ownership proof and cannot use this certificate.
pub(crate) fn symbolic_shell_argv_prefix(
    profile: &CommandProfile,
    materialized: &crate::MaterializedProjectedInvocation,
) -> Option<crate::ProjectedInvocation> {
    use crate::*;
    let contract = profile.native_argv_effect_envelope?;
    if materialized.shell_expansion_unresolved
        || !native_effect_contract_is_closed(profile, contract)
    {
        return None;
    }
    let argv = &materialized.invocation;
    if argv.args.len() > 4096 || argv.args.iter().map(|a| a.text.len()).sum::<usize>() > 262_144 {
        return None;
    }

    // Typed tool inputs have their own origin adapter. Do not relabel them as
    // shell words or lose their existing precise field/path certificates.
    if argv.args.iter().any(|a| a.implicit_input_source.is_some()) {
        return None;
    }
    let start = argv
        .args
        .iter()
        .position(|a| argument_structure(a).exact_value().is_none())?;
    // Keep known controls after an uncertain-width word conservative. A future
    // ownership proof must preserve their possible option-operand relations.
    if argv.args[start..].iter().any(|a| {
        argument_structure(a)
            .exact_value()
            .is_some_and(|value| value.starts_with('-') || value.starts_with('+'))
    }) {
        return None;
    }
    let mut prefix = argv.clone();
    prefix.args.truncate(start);
    let mut audited = profile.clone();
    audited.opaque_on_unresolved = true;
    audited.read_only_control_surface = false;
    let Ok(selection) = select_invocation(&audited, &prefix) else {
        return None;
    };
    let prefix_bound = bind_invocation(&audited, &prefix, &selection);
    if prefix_bound.operation_semantics_unresolved
        || !prefix_bound.residuals.is_empty()
        || prefix_bound
            .effects
            .iter()
            .any(|e| !native_effect_contract_allows_effect(contract, e))
    {
        return None;
    }
    Some(prefix)
}

/// A reviewed total native control surface does not depend on knowing the
/// fields produced by a shell word. The shell and all its child effects are
/// analyzed separately. Keep original argv, origins and access effects.
pub(crate) fn close_symbolic_shell_argv(
    profile: &CommandProfile,
    materialized: &crate::MaterializedProjectedInvocation,
    bound: &mut crate::BoundInvocation,
) {
    use crate::*;
    let Some(prefix) = symbolic_shell_argv_prefix(profile, materialized) else {
        return;
    };
    let contract = profile.native_argv_effect_envelope.unwrap();
    if bound
        .effects
        .iter()
        .any(|e| !native_effect_contract_allows_effect(contract, e))
    {
        return;
    }
    let start = prefix.args.len();
    let argv = &materialized.invocation;
    for (slot, role, effect) in [
        (
            "__symbolic_argv_reads__",
            PathRole::Read,
            EffectKind::ReadPath,
        ),
        (
            "__symbolic_argv_metadata__",
            PathRole::Target,
            EffectKind::TargetPath,
        ),
    ] {
        if role == PathRole::Read && !contract.reads_content()
            || role == PathRole::Target && !contract.queries_metadata()
        {
            continue;
        }
        let mut parameter = BoundParameter::new(
            SlotName::new(slot),
            SemanticType::Path(PathSemantic {
                role,
                purpose: Some(PathPurpose::GenericOperand),
            }),
        );
        for (arg, resolution) in argv
            .args
            .iter()
            .zip(&materialized.arg_resolutions)
            .skip(start)
        {
            let origin = match resolution {
                ValueMaterialization::ResolvedExactScalar { variable_name, .. } => {
                    BoundArgumentMaterialization::ResolvedExactScalar {
                        variable_name: variable_name.clone(),
                    }
                }
                ValueMaterialization::ResolvedRuntimeProduced { variable_name, .. } => {
                    BoundArgumentMaterialization::ResolvedRuntimeProduced {
                        variable_name: variable_name.clone(),
                    }
                }
                _ if arg.runtime_data => BoundArgumentMaterialization::RuntimeData,
                _ => BoundArgumentMaterialization::Literal,
            };
            parameter.values.push(
                BoundValue::argument_with_node_kind(
                    arg.text.clone(),
                    arg.quoted,
                    arg.node_kind.clone(),
                    arg.span.clone(),
                    ArgumentBindingSource::RemainingArg,
                )
                .with_materialization(origin),
            );
        }
        let mut access = Effect::new(effect).for_slot(slot);
        if effect == EffectKind::ReadPath {
            // Content-open semantics also preserve /dev/fd and /proc fd aliases.
            access.path_access = Some(PathAccessKind::ContentOpen);
        }
        bound.effects.push(access);
        bound.bound_parameters.push(parameter);
    }

    if contract == NativeArgvEffectEnvelope::DataOnly || contract.queries_network() {
        let slot = SlotName::new(if contract.queries_network() {
            "__symbolic_argv_network__"
        } else {
            "__symbolic_argv_data__"
        });
        let mut parameter = BoundParameter::new(slot.clone(), if contract.queries_network() {
            SemanticType::Endpoint(EndpointSemantic {
                kind: EndpointKind::HostPort,
                usage: EndpointUsage::GenericEndpoint,
            })
        } else { SemanticType::PlainValue });
        // Any symbolic field can become query data or a resolver option.
        // Its spelling is never proof of the recursive resolver's route.
        if contract.queries_network() {
            parameter.value_projection = Some(ValueProjection::Unknown);
        }
        for arg in argv.args.iter().skip(start) {
            let value = BoundValue::argument_with_node_kind(
                arg.text.clone(),
                arg.quoted,
                arg.node_kind.clone(),
                arg.span.clone(),
                ArgumentBindingSource::RemainingArg,
            );
            parameter.values.push(if arg.runtime_data {
                value.with_materialization(BoundArgumentMaterialization::RuntimeData)
            } else {
                value
            });
        }
        if contract.queries_network() {
            crate::refresh_parameter_semantic_values(&mut parameter);
        }
        bound.bound_parameters.push(parameter);
        let mut effect = Effect::new(if contract.queries_network() {
            EffectKind::NetworkEndpoint
        } else { EffectKind::TransformData }).for_slot(slot.as_str());
        if contract.queries_network() {
            effect.input_scope = Some(EndpointInputScope {
                slots: bound.bound_parameters.iter().map(|p| p.name.as_str().to_owned()).collect(),
                stdin: false,
            });
        }
        bound.effects.push(effect);
    }
    // Existing bound parameters retain data/variable and substitution origins,
    // including for data-only commands. No input is manufactured from stdin.
    bound.operation_semantics_unresolved = false;
    bound.residuals.clear();
    bound.form_id = FormId::new("__symbolic_argv_effect_envelope__");
    retain_symbolic_argv_stream_contract(bound, contract);
    let mut stdin = Effect::new(EffectKind::ConsumeStdin);
    stdin.target = EffectTarget::ImplicitInput(ImplicitInputSource::StdinData);
    bound.effects.push(stdin);
    if !bound
        .bound_implicit_inputs
        .iter()
        .any(|i| i.source == ImplicitInputSource::StdinData)
    {
        bound.bound_implicit_inputs.push(BoundImplicitInput::new(
            ImplicitInputSource::StdinData,
            SemanticType::PlainValue,
        ));
    }
}
