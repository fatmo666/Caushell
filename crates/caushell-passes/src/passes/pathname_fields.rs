use caushell_parse::{CommandFact, ParsedCommandArtifact};
use caushell_profile::{
    ArgumentFieldLayout, ArgumentFieldsProof, ArgumentOwnership, BoundInvocation, BoundParameter,
    BoundValue, Effect, EffectKind, EffectTarget, InvocationRuntimeContext, PathnamePattern,
    ProfileRegistry, ProjectedArg, ResolveInvocationArtifactResult, ResolvedInvocationArtifact,
    SemanticType, SessionBindings, ValueProjection,
    resolve_invocation_artifact_with_argument_proofs,
};
use caushell_runner::{EffectiveCwd, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{
    Decision, DirectoryReadLimits, Evidence, EvidenceKind, FilesystemEntry, PathTargetAccess,
    PathnameFieldsEvidence, RuleId, SemanticResolution, ShellEnvironmentValue as V, ShellKind,
};

use crate::path::namespace::NamespaceResolver;

pub(super) fn observe(
    ctx: &mut RunnerContext,
    node_id: &str,
    args: &[ProjectedArg],
    bindings: &SessionBindings,
    shell: ShellKind,
    cwd: &EffectiveCwd,
    frame: Result<(), String>,
    exact_fields_required: bool,
) -> Vec<PathnameFieldsEvidence> {
    let mut proofs = Vec::new();
    for arg in args {
        let parsed = PathnamePattern::from_argument(arg);
        if matches!(parsed, Ok(None)) {
            continue;
        }
        let mut proof = PathnameFieldsEvidence {
            node_id: node_id.into(),
            session_id: ctx.request().session_id.0.clone(),
            sequence_no: ctx.request().sequence_no,
            start_byte: arg.span.start_byte,
            end_byte: arg.span.end_byte,
            source_word: arg.text.clone(),
            cwd: match cwd {
                EffectiveCwd::Known(path) => Some(path.clone()),
                _ => None,
            },
            complete: false,
            exact_fields_required,
            fields: Vec::new(),
            unmatched_literal: None,
            shell_options: bindings.pathname_options().cloned(),
            environment_observations: Vec::new(),
            namespace_observations: Vec::new(),
            directory_observations: Vec::new(),
            gap: None,
        };
        let result = frame.clone().and_then(|_| {
            if shell != ShellKind::Bash {
                return Err("pathname shell dialect is unsupported".into());
            }
            expand(ctx, &parsed?.unwrap(), &mut proof)
        });
        match result {
            Ok(fields) => {
                proof.complete = true;
                proof.fields = fields;
            }
            Err(reason) => proof.gap = Some(reason),
        }
        proofs.push(proof);
    }
    let fixed = args
        .iter()
        .filter(|arg| {
            !proofs.iter().any(|p| {
                p.start_byte == arg.span.start_byte
                    && p.end_byte == arg.span.end_byte
                    && p.source_word == arg.text
            })
        })
        .collect::<Vec<_>>();
    let count = fixed.len() + proofs.iter().map(|p| p.fields.len()).sum::<usize>();
    let bytes = fixed.iter().map(|a| a.text.len()).sum::<usize>()
        + proofs
            .iter()
            .flat_map(|p| &p.fields)
            .map(String::len)
            .sum::<usize>();
    if count > 4096 || bytes > 262_144 {
        for proof in &mut proofs {
            proof.complete = false;
            proof.exact_fields_required = true;
            proof.fields.clear();
            proof.unmatched_literal = None;
            proof.gap = Some("pathname argv budget exceeded".into());
        }
    }
    proofs
}

/// Represent the possible target effects of a simple native invocation.
/// Both argv layouts must bind normally. The failglob outcome has no native
/// effects, and the enclosing shell and pipeline still use the usual analysis.
pub(super) fn unmatched_effects(
    registry: &ProfileRegistry,
    parsed: &ParsedCommandArtifact,
    command: &CommandFact,
    context: InvocationRuntimeContext,
    bindings: &SessionBindings,
    original: &ResolvedInvocationArtifact,
    proofs: &[PathnameFieldsEvidence],
) -> Option<ResolvedInvocationArtifact> {
    if proofs.len() > 256
        || parsed.status != caushell_parse::ParseStatus::Complete
        || command.conditional_execution
        || command.control_flow_span.is_some()
        || command.terminator == Some(caushell_parse::StatementTerminator::Background)
        || !command.prefix_assignments.is_empty()
        || !parsed.shell_evaluations.is_empty()
        || !parsed.status_conditions.is_empty()
        || !parsed.assignment_commands.is_empty()
        || !parsed.declaration_commands.is_empty()
        || !parsed.function_definitions.is_empty()
        || !parsed.for_loops.is_empty()
        || !parsed.unset_commands.is_empty()
        || parsed
            .commands
            .iter()
            .any(|cmd| cmd.conditional_execution || cmd.control_flow_span.is_some())
    {
        return None;
    }
    let profile = registry.lookup(command.command_name.as_deref()?).profile?;
    if profile.trust.source != caushell_profile::ProfileSourceKind::BuiltIn
        || !profile.argument_files.is_empty()
        || !profile.environment_inputs.is_empty()
        || profile.option_environment.is_some()
        || !profile.implicit_config_files.is_empty()
        || profile.configuration_files.is_some()
        || profile.native_configuration.is_some()
    {
        return None;
    }
    // Apply one correlated option choice to every unmatched word in the invocation.
    let mut layouts = proofs
        .iter()
        .map(|proof| {
            let literal = proof.unmatched_literal.as_ref()?;
            let arg = original.projection.args.iter().find(|arg| {
                arg.span.start_byte == proof.start_byte
                    && arg.span.end_byte == proof.end_byte
                    && arg.text == proof.source_word
            })?;
            Some(ArgumentFieldsProof {
                span: arg.span.clone(),
                source_word: proof.source_word.clone(),
                layout: ArgumentFieldLayout::Exact(vec![literal.clone()]),
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let resolve = |layouts: &[ArgumentFieldsProof]| {
        let ResolveInvocationArtifactResult::Resolved(resolved) =
            resolve_invocation_artifact_with_argument_proofs(
                registry,
                command,
                context.clone(),
                bindings,
                &[],
                layouts,
            )
        else {
            return None;
        };
        let bound = &resolved.bound;
        if resolved.proven_stream_contract().is_none()
            || bound.native_argv_effect_envelope.is_some()
            || bound.archive_extraction.is_some()
            || !bound.configured_inputs.is_empty()
            || !bound.configured_execution_sources.is_empty()
            || !bound.payload_projections.is_empty()
            || !bound.argument_regions.is_empty()
            || !bound.bound_implicit_inputs.is_empty()
            || !bound.effects.iter().all(supports_effect_union)
        {
            return None;
        }
        Some(resolved)
    };
    let mut retained = resolve(&layouts)?;
    for layout in &mut layouts {
        layout.layout = ArgumentFieldLayout::Exact(Vec::new());
    }
    let mut removed = resolve(&layouts)?;
    // Ownership certificates for unresolved lexical paths are allocated only
    // when needed. Keep the bound operands, and discard certificates that
    // cannot represent an exact shared argv for both layouts.
    for bound in [&mut retained.bound, &mut removed.bound] {
        for value in bound
            .bound_parameters
            .iter_mut()
            .flat_map(|p| &mut p.values)
        {
            if let BoundValue::Argument { ownership, .. } = value {
                *ownership = ArgumentOwnership::Unproven;
            }
        }
    }
    if !merge_target_effects(&mut retained.bound, &removed.bound) {
        return None;
    }

    // Neither native argv nor output shape is exact. Retain the original
    // projection and never pass a counterfactual argv downstream as observed.
    retained.materialized_projection = original.materialized_projection.clone();
    retained.bound.stream_contract = None;
    retained.bound.stdout_scalar = None;
    retained.bound.stdout_scalar_complete = false;
    retained.bound.stdout_growth = None;
    retained.bound.stdout_growth_complete = false;
    retained.bound.stdout_records = None;
    Some(retained)
}

fn supports_effect_union(effect: &Effect) -> bool {
    if effect.path_list.is_some()
        || effect.runtime_input_binding.is_some()
        || effect.namespace_effect.is_some()
        || effect.resource_namespace.is_some()
    {
        return false;
    }
    match (&effect.kind, &effect.target) {
        (
            EffectKind::ReadPath | EffectKind::ChangeMode | EffectKind::ConsumeStdin,
            EffectTarget::Slot(_),
        ) => true,
        (EffectKind::ReadPath, EffectTarget::ConfiguredPath(target)) => {
            target.only_when_sources_absent
                && target
                    .sources
                    .iter()
                    .all(|source| source.projection == ValueProjection::Identity)
                && target.environment.is_none()
                && target.shell_variable.is_none()
                && target.relative_to.is_none()
                && !target.unresolved_relative_base
                && !target.expand_environment
                && !target.expand_user
                && target.fallback_parent_slots.is_empty()
                && target.default_value.is_some()
        }
        _ => false,
    }
}

fn merge_target_effects(retained: &mut BoundInvocation, removed: &BoundInvocation) -> bool {
    if retained.command_name != removed.command_name
        || retained.subcommand_path != removed.subcommand_path
        || retained.applied_modifiers != removed.applied_modifiers
        || retained.owned_option_flags != removed.owned_option_flags
        || retained.modifier_parameter_flags != removed.modifier_parameter_flags
        || !removed.bound_parameters.iter().all(|smaller| {
            retained
                .bound_parameters
                .iter()
                .any(|larger| includes_parameter(larger, smaller))
        })
        || !removed
            .effects
            .iter()
            .all(|effect| retained.effects.contains(effect))
    {
        return false;
    }
    for effect in &mut retained.effects {
        let EffectTarget::ConfiguredPath(target) = &mut effect.target else {
            continue;
        };
        // Preserve the default read target when field disappearance leaves
        // the native program without a root. Keep the same scope and access.
        if removed.effects.iter().any(|removed_effect| {
            matches!(&removed_effect.target, EffectTarget::ConfiguredPath(removed_target)
                if removed_target == target)
        }) && target.sources.iter().all(|source| {
            removed
                .bound_parameters
                .iter()
                .all(|param| param.name != source.slot || param.values.is_empty())
        }) {
            target.sources.clear();
            target.only_when_sources_absent = false;
        }
    }
    true
}

fn includes_parameter(larger: &BoundParameter, smaller: &BoundParameter) -> bool {
    if larger == smaller {
        return true;
    }
    // A path slot contributes independent targets, unlike a scalar control
    // value, a paired operand, or the output of a structured projection.
    if !matches!(&larger.semantic, SemanticType::Path(_))
        || larger.value_projection.is_some()
        || larger.structured_projection.is_some()
        || larger.structured_source.is_some()
        || larger.projected_values.is_some()
        || !smaller
            .values
            .iter()
            .all(|value| larger.values.contains(value))
    {
        return false;
    }
    let mut with_smaller_values = larger.clone();
    with_smaller_values.values.clone_from(&smaller.values);
    with_smaller_values == *smaller
}

fn c_locale(all: &V, category: &V, lang: &V) -> Option<bool> {
    for value in [all, category, lang] {
        match value {
            V::Present { value } if value.is_empty() => continue,
            V::Present { value } => {
                return match value.as_str() {
                    "C" | "POSIX" => Some(false),
                    "C.UTF-8" | "C.utf8" => Some(true),
                    _ => None,
                };
            }
            V::Absent => continue,
            V::Unknown => return None,
        }
    }
    None
}

fn expand(
    ctx: &mut RunnerContext,
    pattern: &PathnamePattern,
    proof: &mut PathnameFieldsEvidence,
) -> Result<Vec<String>, String> {
    let Some(options) = proof.shell_options.clone() else {
        if pattern.supports_option_independent_match_bound() {
            let matches = collect_matches(
                ctx,
                pattern,
                proof,
                Matching {
                    dotglob: true,
                    nocase: true,
                    unicode: true,
                    skip_dots: false,
                    option_independent: true,
                },
            )?;
            // An absent cwd or a metadata-only view can yield no paths
            // before pathname matching begins. Require a completed read in
            // the execution namespace before using the negative result.
            if matches.is_empty() && !proof.directory_observations.is_empty() {
                proof.unmatched_literal = Some(pattern.literal.clone());
            }
        }
        return Err("pathname shell options are not observed".into());
    };
    if options.noglob {
        return Ok(vec![pattern.literal.clone()]);
    }
    if !match &options.globignore {
        V::Absent => true,
        V::Present { value } => value.is_empty(),
        V::Unknown => false,
    } {
        // GLOBIGNORE is a shell variable, not merely an exported environment key.
        return Err("pathname GLOBIGNORE is unknown or unsupported".into());
    }
    if options.globstar && pattern.recursive_star {
        return Err("recursive pathname generation is unsupported".into());
    }
    let unicode = c_locale(&options.lc_all, &options.lc_ctype, &options.lang)
        .filter(|_| c_locale(&options.lc_all, &options.lc_collate, &options.lang).is_some())
        .ok_or("pathname collation or character locale is unknown or unsupported")?;
    let mut fields = collect_matches(
        ctx,
        pattern,
        proof,
        Matching {
            dotglob: options.dotglob,
            nocase: options.nocaseglob,
            unicode,
            skip_dots: options.globskipdots,
            option_independent: false,
        },
    )?;
    if fields.is_empty() {
        if options.failglob {
            proof.exact_fields_required = true;
            return Err("pathname expansion has no matches with failglob enabled".into());
        }
        if !options.nullglob {
            fields.push(pattern.literal.clone());
        }
    }
    Ok(fields)
}

struct Matching {
    dotglob: bool,
    nocase: bool,
    unicode: bool,
    skip_dots: bool,
    option_independent: bool,
}

fn collect_matches(
    ctx: &mut RunnerContext,
    pattern: &PathnamePattern,
    proof: &mut PathnameFieldsEvidence,
    matching: Matching,
) -> Result<Vec<String>, String> {
    let cwd = proof
        .cwd
        .as_deref()
        .ok_or("pathname shell cwd is unresolved")?;
    let mut namespace = NamespaceResolver::new(ctx.filesystem_view());
    if matching.option_independent {
        // An absolute glob can scan a directory even when the request's
        // executor cwd is fictitious. That is not an observed shell frame.
        let (cwd_resolution, observations) = namespace.resolve(cwd, PathTargetAccess::Follow);
        proof.namespace_observations.extend(observations);
        let SemanticResolution::Resolved { value } = cwd_resolution else {
            return Err("pathname shell cwd namespace is unresolved".into());
        };
        if !value
            .concrete_path()
            .is_some_and(|path| ctx.filesystem_view().entry(path) == FilesystemEntry::Directory)
        {
            return Err("pathname shell cwd directory is not observed".into());
        }
    }
    let mut paths = vec![(
        if pattern.absolute {
            "/".into()
        } else {
            cwd.to_owned()
        },
        String::new(),
    )];
    for (depth, component) in pattern.components.iter().enumerate() {
        if depth == 0 && pattern.absolute {
            continue;
        }
        let last = depth + 1 == pattern.components.len();
        let mut next = Vec::new();
        for (directory, spelling) in paths {
            let joined = |name: &str| {
                if depth == 0 && !pattern.absolute {
                    name.to_owned()
                } else {
                    format!("{spelling}/{name}")
                }
            };
            let (resolved, observations) = namespace.resolve(&directory, PathTargetAccess::Follow);
            proof.namespace_observations.extend(observations);
            let path = match resolved {
                SemanticResolution::Resolved { value } => value.concrete_path().map(str::to_owned),
                _ => None,
            }
            .ok_or("pathname prefix namespace is unresolved")?;
            let view = ctx.filesystem_view();
            match view.entry(&path) {
                FilesystemEntry::Directory => (),
                FilesystemEntry::Missing | FilesystemEntry::File => continue,
                _ => return Err("pathname prefix type is unresolved".into()),
            }
            if let Some(name) = component.literal()
                && (!matching.option_independent
                    || !name.bytes().any(|byte| byte.is_ascii_alphabetic()))
            {
                let target = format!("{}/{name}", path.trim_end_matches('/'));
                let (resolution, observations) = namespace.resolve(
                    &target,
                    if last && !name.is_empty() {
                        PathTargetAccess::Entry
                    } else {
                        PathTargetAccess::Follow
                    },
                );
                proof.namespace_observations.extend(observations);
                let concrete = match resolution {
                    SemanticResolution::Resolved { value } => {
                        value.concrete_path().map(str::to_owned)
                    }
                    _ => None,
                }
                .ok_or("pathname literal suffix is unresolved")?;
                match view.entry(&concrete) {
                    FilesystemEntry::Missing => (),
                    FilesystemEntry::Unavailable { .. } => {
                        return Err("pathname suffix observation is unavailable".into());
                    }
                    _ => next.push((concrete, joined(&name))),
                }
            } else {
                let read = ctx.read_directory(&path, depth);
                proof.directory_observations.push(read.observation.clone());
                let entries = read
                    .complete_entries(&path, DirectoryReadLimits::default())
                    .ok_or("pathname directory observation is incomplete")?;
                for entry in entries {
                    if matching.nocase && matching.unicode && !entry.name.is_ascii() {
                        return Err("non-ASCII case-folded pathname is unsupported".into());
                    }
                    if component.matches_in_locale(
                        &entry.name,
                        matching.dotglob,
                        matching.nocase,
                        matching.unicode,
                    ) {
                        next.push((
                            format!("{}/{}", path.trim_end_matches('/'), entry.name),
                            joined(&entry.name),
                        ));
                    }
                }
                if !matching.skip_dots {
                    for name in [".", ".."] {
                        if component.matches(name, false, matching.nocase) {
                            next.push((
                                format!("{}/{name}", path.trim_end_matches('/')),
                                joined(name),
                            ));
                        }
                    }
                }
            }
            if next.len() > 4096 || next.iter().map(|(_, s)| s.len()).sum::<usize>() > 65_536 {
                return Err("pathname field budget exceeded".into());
            }
        }
        paths = next;
    }
    validate_observations(ctx, proof)?;
    let mut fields = paths.into_iter().map(|(_, s)| s).collect::<Vec<_>>();
    fields.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    Ok(fields)
}

fn validate_observations(
    ctx: &mut RunnerContext,
    proof: &PathnameFieldsEvidence,
) -> Result<(), String> {
    for previous in &proof.directory_observations {
        if ctx.read_directory(&previous.path, 0).observation != *previous {
            return Err("pathname directory changed during analysis".into());
        }
    }
    let view = ctx.filesystem_view();
    if proof
        .namespace_observations
        .iter()
        .any(|o| o.source != view.source() || view.entry(&o.path) != o.entry)
    {
        return Err("pathname prefix namespace changed during analysis".into());
    }
    Ok(())
}

pub struct ValidatePathnameFieldsPass;

impl SessionTransformPass for ValidatePathnameFieldsPass {
    fn name(&self) -> &'static str {
        "validate_pathname_fields"
    }
    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        let proofs = ctx
            .evidence
            .iter()
            .filter_map(|e| match &e.kind {
                EvidenceKind::PathnameFields(p) => Some(p.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        for proof in proofs {
            let used_no_match_bound = proof.unmatched_literal.is_some() && proof.gap.is_none();
            if !proof.complete && !proof.exact_fields_required && !used_no_match_bound {
                continue;
            }
            if let Err(reason) = proof
                .gap
                .clone()
                .map_or_else(|| validate_observations(ctx, &proof), Err)
            {
                ctx.propose_decision(
                    self.name(),
                    RuleId::SelectionError,
                    Decision::NeedApproval,
                    reason.clone(),
                );
                for e in &mut ctx.evidence {
                    if let EvidenceKind::PathnameFields(p) = &mut e.kind
                        && p.node_id == proof.node_id
                        && p.start_byte == proof.start_byte
                    {
                        p.complete = false;
                        p.gap = Some(reason.clone());
                    }
                }
            }
        }
    }
}

pub(super) fn evidence(proof: PathnameFieldsEvidence) -> Evidence {
    Evidence {
        rule_id: RuleId::SelectionError,
        summary: "shell pathname fields".into(),
        kind: EvidenceKind::PathnameFields(proof),
    }
}
