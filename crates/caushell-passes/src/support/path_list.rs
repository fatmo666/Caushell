use caushell_profile::{BoundInvocation, BoundPathList, PathListSeparator};
use caushell_types::RuntimeArgumentDomain;

use super::StaticStreamEvidence;

const MAX_PATH_LIST_BYTES: usize = 64 * 1024;
const MAX_PATH_LIST_RECORDS: usize = 4096;

pub(crate) fn bind_path_list_targets(
    invocation: &mut BoundInvocation,
    evidence: StaticStreamEvidence,
    domain: Option<RuntimeArgumentDomain>,
) {
    invocation.bound_path_lists.clear();
    let bytes = (evidence.complete
        && evidence
            .known_fragments
            .iter()
            .try_fold(0usize, |n, fragment| n.checked_add(fragment.len()))
            .is_some_and(|n| n <= MAX_PATH_LIST_BYTES))
    .then(|| evidence.known_fragments.concat());
    for (index, effect) in invocation.effects.iter().enumerate() {
        let Some(contract) = &effect.path_list else {
            continue;
        };
        let nul = contract.separator == PathListSeparator::Nul
            || contract.nul_modifier.as_ref().is_some_and(|name| {
                invocation
                    .applied_modifiers
                    .iter()
                    .any(|id| id.as_str() == name)
            });
        let value = if let Some(bytes) = &bytes {
            decode_paths(bytes, nul).map(BoundPathList::Paths)
        } else if !evidence.complete && nul {
            domain.clone().map(BoundPathList::Domain)
        } else {
            None
        };
        if let Some(value) = value {
            invocation.bound_path_lists.insert(index, value);
        }
    }
}

fn decode_paths(bytes: &str, nul: bool) -> Option<Vec<String>> {
    if !nul && bytes.contains('\0') {
        return None;
    }
    let mut paths = Vec::new();
    for record in bytes.split(if nul { '\0' } else { '\n' }) {
        if record.is_empty() {
            continue;
        }
        if paths.len() == MAX_PATH_LIST_RECORDS {
            return None;
        }
        // Native filenames: no shell expansion, trimming, or quote decoding.
        paths.push(record.to_string());
    }
    Some(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_records_preserve_native_spelling_and_empty_streams() {
        assert_eq!(
            decode_paths(" ./a b\n~/$x*\n", false),
            Some(vec![" ./a b".into(), "~/$x*".into()])
        );
        assert_eq!(
            decode_paths("./a\nb\0/etc/file\0", true),
            Some(vec!["./a\nb".into(), "/etc/file".into()])
        );
        assert_eq!(decode_paths("", true), Some(vec![]));
        assert_eq!(decode_paths("a\0b", false), None);
        assert_eq!(
            decode_paths(&"x\0".repeat(MAX_PATH_LIST_RECORDS + 1), true),
            None
        );
    }

    fn consumer(nul: bool) -> BoundInvocation {
        use caushell_profile::*;
        let mut invocation = BoundInvocation::new(
            CommandName::new("arbitrary_consumer"),
            FormId::new("consume"),
        );
        let mut effect = Effect::new(EffectKind::MetadataMutation);
        effect.target = EffectTarget::ImplicitInput(ImplicitInputSource::StdinData);
        effect.path_list = Some(PathListContract {
            separator: if nul {
                PathListSeparator::Nul
            } else {
                PathListSeparator::Newline
            },
            nul_modifier: None,
        });
        invocation.effects.push(effect);
        invocation
    }

    #[test]
    fn partial_over_budget_and_absent_contracts_do_not_become_empty_lists() {
        let mut invocation = consumer(true);
        bind_path_list_targets(
            &mut invocation,
            StaticStreamEvidence {
                known_fragments: vec!["./a\0".into()],
                complete: false,
            },
            None,
        );
        assert!(invocation.bound_path_lists.is_empty());
        bind_path_list_targets(
            &mut invocation,
            StaticStreamEvidence {
                known_fragments: vec!["x".repeat(MAX_PATH_LIST_BYTES + 1)],
                complete: true,
            },
            None,
        );
        assert!(invocation.bound_path_lists.is_empty());
        invocation.effects[0].path_list = None;
        bind_path_list_targets(
            &mut invocation,
            StaticStreamEvidence {
                known_fragments: vec!["./a\0".into()],
                complete: true,
            },
            None,
        );
        assert!(invocation.bound_path_lists.is_empty());
    }

    #[test]
    fn unknown_path_domain_requires_matching_nul_framing() {
        let domain = RuntimeArgumentDomain::PathSet {
            roots: vec![".".into()],
            may_escape: false,
        };
        let mut invocation = consumer(true);
        bind_path_list_targets(
            &mut invocation,
            StaticStreamEvidence {
                known_fragments: vec![],
                complete: false,
            },
            Some(domain.clone()),
        );
        assert_eq!(
            invocation.bound_path_lists.get(&0),
            Some(&BoundPathList::Domain(domain.clone()))
        );
        invocation = consumer(false);
        bind_path_list_targets(
            &mut invocation,
            StaticStreamEvidence {
                known_fragments: vec![],
                complete: false,
            },
            Some(domain),
        );
        assert!(invocation.bound_path_lists.is_empty());
        bind_path_list_targets(
            &mut invocation,
            StaticStreamEvidence {
                known_fragments: vec![],
                complete: true,
            },
            None,
        );
        assert_eq!(
            invocation.bound_path_lists.get(&0),
            Some(&BoundPathList::Paths(vec![]))
        );
    }
}
