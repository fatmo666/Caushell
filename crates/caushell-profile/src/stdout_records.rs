//! Native output-format proofs, enabled only by the selected Profile contract.
use crate::{
    ResolvedInvocationArtifact, SemanticValueResolution, StdoutPathFormatSyntax,
    StdoutRecordProjection, ValueProjection, project_semantic_value,
};

const MAX_FORMAT_BYTES: usize = 4096;
const MAX_PROOF_BYTES: usize = 16384;
const MAX_RECORD_ROOTS: usize = 64;

impl ResolvedInvocationArtifact {
    /// Project complete native records onto their producer-spelling anchors.
    /// No output bytes or filesystem contents are materialized.
    pub fn formatted_stdout_path_roots(&self, roots: &[String]) -> Option<Vec<String>> {
        let contract = self.proven_stdout_records()?;
        let StdoutRecordProjection::FormattedPaths {
            formats_slot,
            syntax,
            ..
        } = &contract.projection
        else {
            return None;
        };
        if roots.is_empty()
            || roots.len() > MAX_RECORD_ROOTS
            || roots.iter().any(|r| r.is_empty() || r.contains('\0'))
        {
            return None;
        }
        let mut result = Vec::new();
        let mut bytes = roots
            .iter()
            .try_fold(0usize, |sum, r| sum.checked_add(r.len()))?;
        if bytes > MAX_PROOF_BYTES {
            return None;
        }
        let mut formats = 0usize;
        for parameter in self
            .bound
            .bound_parameters
            .iter()
            .filter(|p| p.name == *formats_slot)
        {
            for value in parameter.semantic_values() {
                formats += 1;
                if formats > MAX_RECORD_ROOTS {
                    return None;
                }
                let SemanticValueResolution::Known(text) =
                    project_semantic_value(&ValueProjection::Identity, value)?
                else {
                    return None;
                };
                bytes = bytes.checked_add(text.len())?;
                if bytes > MAX_PROOF_BYTES {
                    return None;
                }
                let records = match syntax {
                    StdoutPathFormatSyntax::FindPrintf => find_printf_records(&text)?,
                };
                for record in records {
                    let candidates = match record.source {
                        PathSource::Full => roots
                            .iter()
                            .map(|root| format!("{}{root}", record.prefix))
                            .collect::<Vec<_>>(),
                        // %P removes the entire search-root spelling. Child
                        // components contain no slash or parent traversal;
                        // the root itself contributes the empty relative path.
                        PathSource::RootRelative => vec![record.prefix],
                    };
                    for root in candidates {
                        bytes = bytes.checked_add(root.len())?;
                        if bytes > MAX_PROOF_BYTES || result.len() >= MAX_RECORD_ROOTS {
                            return None;
                        }
                        if !result.contains(&root) {
                            result.push(root);
                        }
                    }
                }
            }
            if parameter.semantic_values().next().is_none() && !parameter.values.is_empty() {
                return None;
            }
        }
        (formats != 0 && !result.is_empty()).then_some(result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathSource {
    Full,
    RootRelative,
}

#[derive(Debug, PartialEq, Eq)]
struct PathRecord {
    prefix: String,
    source: PathSource,
}

/// Each action must independently emit complete NUL records. Boolean find
/// expressions can skip/reorder which actions run, so incomplete fragments
/// cannot borrow a delimiter or a prefix from another action.
fn find_printf_records(format: &str) -> Option<Vec<PathRecord>> {
    if format.len() > MAX_FORMAT_BYTES || format.contains('\0') {
        return None;
    }
    let mut chars = format.chars().peekable();
    let mut prefix = String::new();
    let mut source = None;
    let mut records = Vec::new();
    while let Some(c) = chars.next() {
        let literal = match c {
            '%' => match chars.next()? {
                '%' => '%',
                code @ ('p' | 'P') if source.is_none() => {
                    // A component affix could turn '.' into '..' or change a
                    // root filename into its sibling. Only directory prefixes
                    // preserve the stronger producer-spelling path contract.
                    if !prefix.is_empty() && !prefix.ends_with('/') {
                        return None;
                    }
                    if code == 'P' && prefix.is_empty() {
                        // Bare %P may emit '-rf' (or empty), not './-rf'. That
                        // spelling cannot be represented by a '.' PathSet.
                        return None;
                    }
                    source = Some(if code == 'p' {
                        PathSource::Full
                    } else {
                        PathSource::RootRelative
                    });
                    continue;
                }
                _ => return None,
            },
            '\\' => match chars.next()? {
                '\\' => '\\',
                'a' => '\x07',
                'b' => '\x08',
                'f' => '\x0c',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'v' => '\x0b',
                digit @ '0'..='7' => {
                    let mut octal = digit.to_digit(8)?;
                    for _ in 0..2 {
                        let Some(digit) = chars.peek().and_then(|c| c.to_digit(8)) else {
                            break;
                        };
                        chars.next();
                        octal = octal * 8 + digit;
                    }
                    // Non-ASCII octal bytes are not Unicode scalar literals.
                    if octal > 127 {
                        return None;
                    }
                    char::from_u32(octal)?
                }
                _ => return None,
            },
            other => other,
        };
        if literal == '\0' {
            records.push(PathRecord {
                prefix: std::mem::take(&mut prefix),
                source: source.take()?,
            });
            if records.len() > MAX_RECORD_ROOTS {
                return None;
            }
        } else if source.is_some() {
            // A suffix needs a separate path-template proof, not containment
            // assumed from the original root or a representative filename.
            return None;
        } else {
            prefix.push(literal);
        }
    }
    (!records.is_empty() && source.is_none() && prefix.is_empty()).then_some(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_full_and_root_relative_records_keep_native_prefixes() {
        assert_eq!(
            find_printf_records(r"%p\0"),
            Some(vec![PathRecord {
                prefix: "".into(),
                source: PathSource::Full
            }])
        );
        assert_eq!(
            find_printf_records(r"%p\000newdir/%P\0"),
            Some(vec![
                PathRecord {
                    prefix: "".into(),
                    source: PathSource::Full
                },
                PathRecord {
                    prefix: "newdir/".into(),
                    source: PathSource::RootRelative
                },
            ])
        );
        assert_eq!(
            find_printf_records(r"percent%%/\057%P\0").unwrap()[0].prefix,
            "percent%//"
        );
    }

    #[test]
    fn incomplete_mixed_or_reshaped_records_have_no_path_proof() {
        for format in [
            "",
            r"%p",
            r"%p\n",
            r"%p\0trailing",
            r"\0%p\0",
            r"%P\0",
            r"%f\0",
            r".%p\0",
            r"prefix%P\0",
            r"%p.bak\0",
            r"%p/../../other\0",
            r"%p%p\0",
            r"%.2p\0",
            r"%10p\0",
            r"%p\c",
            r"%p\400",
            r"%p\0000",
            r"%p\0\q",
            r"%p\0\",
        ] {
            assert!(find_printf_records(format).is_none(), "{format}");
        }
        assert!(find_printf_records(&format!("{}%p\\0", "a".repeat(MAX_FORMAT_BYTES))).is_none());
        assert!(find_printf_records(&r"%p\0".repeat(MAX_RECORD_ROOTS + 1)).is_none());
    }
}
