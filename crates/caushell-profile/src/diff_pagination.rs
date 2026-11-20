//! Preserve read bindings for exact brief diff modes that cannot start pr.
use std::collections::BTreeSet;

use caushell_parse::CommandFact;

use crate::{
    CommandProfile, MaterializedProjectedInvocation, ProfileSourceKind, ProjectedArgKind,
    ProjectedInvocation, argument_structure,
};

pub(crate) fn binding_projection(
    profile: &CommandProfile,
    command: &CommandFact,
    materialized: &MaterializedProjectedInvocation,
) -> Option<ProjectedInvocation> {
    if profile.primary_name() != "diff"
        || profile.trust.source != ProfileSourceKind::BuiltIn
        || !command.prefix_assignments.is_empty()
        || materialized.shell_expansion_unresolved
    {
        return None;
    }

    let argv = &materialized.invocation;
    let mut args = Vec::with_capacity(argv.args.len());
    let mut controls = BTreeSet::new();
    let mut operands = 0;
    let mut excluded = false;
    for arg in &argv.args {
        if arg.implicit_input_source.is_some() {
            return None;
        }
        let structure = argument_structure(arg);
        let word = structure.exact_value()?;
        if word.is_empty() || word.contains('\0') {
            return None;
        }
        if let Some(pattern) = word.strip_prefix("--exclude=") {
            if excluded || pattern.is_empty() {
                return None;
            }
            excluded = true;
        } else if let Some(short) = word.strip_prefix('-') {
            let options = match word {
                "--brief" => "q",
                "--side-by-side" => "y",
                "--paginate" => "l",
                "--recursive" => "r",
                _ => short,
            };
            if operands != 0
                || options.is_empty()
                || !options
                    .chars()
                    .all(|flag| matches!(flag, 'r' | 'q' | 'y' | 'l') && controls.insert(flag))
            {
                return None;
            }
            if options.contains('l') {
                let retained = options.replace('l', "");
                if !retained.is_empty() {
                    let mut binding = arg.clone();
                    binding.text = format!("-{retained}");
                    binding.kind = ProjectedArgKind::Flag;
                    binding.runtime_data = true;
                    args.push(binding);
                }
                continue;
            }
        } else {
            operands += 1;
        }
        args.push(arg.clone());
    }
    if operands != 2 || !['q', 'y', 'l'].iter().all(|flag| controls.contains(flag)) {
        return None;
    }

    // GNU diff emits its brief summary directly. Apple's FreeBSD-derived
    // diff rejects the two output formats at option parsing. Both permit a
    // content-read bound for the explicit operands. Keep source argv intact.
    let mut projection = argv.clone();
    projection.args = args;
    Some(projection)
}
