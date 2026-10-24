use caushell_profile::{PathnamePattern, ProjectedArg, SessionBindings};
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
            proof.gap = Some("pathname argv budget exceeded".into());
        }
    }
    proofs
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
    let options = proof
        .shell_options
        .as_ref()
        .ok_or("pathname shell options are not observed")?
        .clone();
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
    let unicode = c_locale(&options.lc_all, &options.lc_ctype, &options.lang);
    if c_locale(&options.lc_all, &options.lc_collate, &options.lang).is_none() || unicode.is_none()
    {
        return Err("pathname collation or character locale is unknown or unsupported".into());
    }
    let cwd = proof
        .cwd
        .as_deref()
        .ok_or("pathname shell cwd is unresolved")?;
    let mut namespace = NamespaceResolver::new(ctx.filesystem_view());
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
            if let Some(name) = component.literal() {
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
                    if options.nocaseglob && unicode.unwrap() && !entry.name.is_ascii() {
                        return Err("non-ASCII case-folded pathname is unsupported".into());
                    }
                    if component.matches_in_locale(
                        &entry.name,
                        options.dotglob,
                        options.nocaseglob,
                        unicode.unwrap(),
                    ) {
                        next.push((
                            format!("{}/{}", path.trim_end_matches('/'), entry.name),
                            joined(&entry.name),
                        ));
                    }
                }
                if !options.globskipdots {
                    for name in [".", ".."] {
                        if component.matches(name, false, options.nocaseglob) {
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
            if !proof.complete && !proof.exact_fields_required {
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
