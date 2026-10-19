//! GNU Parallel's single-source native template grammar. Pure and bounded by
//! its caller: no process, filesystem reads or arbitrary Perl replacement eval.

pub(crate) fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(crate) struct RenderedJob {
    pub source: String,
    pub data_ranges: Vec<std::ops::Range<usize>>,
}

pub(crate) struct SymbolicInput {
    pub domain: caushell_types::RuntimeArgumentDomain,
    pub batch: bool,
}

pub(crate) struct SymbolicJob {
    pub rendered: RenderedJob,
    pub inputs: Vec<SymbolicInput>,
}

/// Compile data replacements to typed shell parameters, not example filenames.
/// The existing renderer owns native quoting; its ranges identify holes before
/// the shell parser proves that each hole belongs entirely to an argv operand.
pub(crate) fn symbolic_job(
    words: &[String],
    quoted: bool,
    grouped: bool,
    shell: caushell_types::ShellKind,
    domain: &caushell_types::RuntimeArgumentDomain,
) -> Option<SymbolicJob> {
    use caushell_parse::{ParseStatus, decode_static_shell_argument, parse_command};
    use caushell_types::RuntimeArgumentDomain;

    const MARKER: &str = "__CAUSHELL_NATIVE_INPUT_HOLE__";
    if words.is_empty()
        || words.iter().any(|word| {
            // Synthetic positionals must not change the template's own shell
            // frame. Dynamic shell programs retain the ordinary opaque path.
            word.contains(['$', '`']) || word.contains(MARKER) || word.contains("{#}")
        })
    {
        return None;
    }
    let rendered = if grouped {
        render_group_tracked(words, &[MARKER.into()], quoted, 1)?
    } else {
        render_tracked(words, MARKER, quoted, 1)?
    };
    if rendered.source.len() > 256 * 1024 || rendered.data_ranges.len() > 128 {
        return None;
    }
    let parsed = parse_command(&rendered.source, shell).ok()?;
    if parsed.status != ParseStatus::Complete
        || !parsed.diagnostics.is_empty()
        || !parsed.function_definitions.is_empty()
        || !parsed.assignment_commands.is_empty()
        || !parsed.declaration_commands.is_empty()
        || parsed.commands.iter().any(|command| {
            !command.prefix_assignments.is_empty() || command.control_flow_span.is_some()
        })
    {
        return None;
    }
    // A transform's result is not necessarily in the original path set.
    // Literal surrounding bytes remain useful even after widening its value.
    let identity = !words.iter().any(|word| {
        ["{.}", "{/}", "{/.}", "{//}"]
            .iter()
            .any(|key| word.contains(key))
    });
    let input_domain = if identity {
        domain
    } else {
        &RuntimeArgumentDomain::Unbounded
    };
    let mut edits = Vec::new();
    let mut inputs = Vec::new();
    let mut owned = 0;
    for command in &parsed.commands {
        for token in &command.tokens {
            let ranges: Vec<_> = rendered
                .data_ranges
                .iter()
                .filter(|range| {
                    token.span.start_byte <= range.start && range.end <= token.span.end_byte
                })
                .collect();
            if ranges.is_empty() {
                continue;
            }
            let mut word = String::new();
            let mut cursor = token.span.start_byte;
            for range in &ranges {
                word.push_str(rendered.source.get(cursor..range.start)?);
                word.push_str(MARKER);
                cursor = range.end;
            }
            word.push_str(rendered.source.get(cursor..token.span.end_byte)?);
            let value = decode_static_shell_argument(&word, false, "concatenation")?;
            owned += ranges.len();
            inputs.push(SymbolicInput {
                domain: input_domain.substitute_into(&value, MARKER),
                batch: grouped,
            });
            // -X's single repeated context uses the existing quoted argv-tail
            // representation. Multiple independent groups need a richer frame.
            if grouped && inputs.len() != 1 {
                return None;
            }
            let parameter = if grouped {
                "\"$@\"".to_string()
            } else {
                format!("\"${{{}}}\"", inputs.len())
            };
            edits.push((token.span.start_byte..token.span.end_byte, parameter));
        }
    }
    if owned != rendered.data_ranges.len() || inputs.is_empty() {
        // This also rejects command-position, redirection and assignment holes.
        return None;
    }
    edits.sort_by_key(|(range, _)| range.start);
    let mut source = String::new();
    let mut data_ranges = Vec::new();
    let mut cursor = 0;
    for (range, parameter) in edits {
        source.push_str(rendered.source.get(cursor..range.start)?);
        let start = source.len();
        source.push_str(&parameter);
        data_ranges.push(start..source.len());
        cursor = range.end;
    }
    source.push_str(rendered.source.get(cursor..)?);
    Some(SymbolicJob {
        rendered: RenderedJob {
            source,
            data_ranges,
        },
        inputs,
    })
}

pub(crate) fn render_tracked(
    words: &[String],
    input: &str,
    quoted: bool,
    job: usize,
) -> Option<RenderedJob> {
    render_single(words, input, quoted, job, true, true)
}

fn render_single(
    words: &[String],
    input: &str,
    quoted: bool,
    job: usize,
    command_position: bool,
    append_input: bool,
) -> Option<RenderedJob> {
    if words.is_empty() {
        return Some(RenderedJob {
            source: input.to_owned(),
            data_ranges: vec![0..input.len()],
        });
    } // parallel == cat | sh
    let template = words.join(" ");
    // Command-position replacements disable quoting in GNU Parallel. Preserve
    // their shell-source semantics, rather than making input a literal command.
    let unquoted_input = command_position && template.starts_with("{");
    if unquoted_input && quoted {
        return None;
    }
    let mut has_replacement = false;
    let mut render_word = |word: &str| -> Option<RenderedJob> {
        let mut result = String::new();
        let mut data_ranges = Vec::new();
        let mut rest = word;
        let mut shell_quote = None;
        let mut escaped = false;
        while !rest.is_empty() {
            let replacement = ["{/.}", "{//}", "{.}", "{/}", "{#}", "{1}", "{}"]
                .into_iter()
                .find(|key| rest.starts_with(key));
            if let Some(key) = replacement {
                // Literal quoting around replacements changes the meaning of
                // escaping; do not guess. -q owns the complete token instead.
                if !quoted && (shell_quote.is_some() || escaped) {
                    return None;
                }
                has_replacement = true;
                let base = input.rsplit('/').next().unwrap_or(input);
                let strip = |s: &str| {
                    s.rsplit_once('.')
                        .filter(|(_, extension)| !extension.contains('/'))
                        .map_or(s, |(head, _)| head)
                        .to_owned()
                };
                let value = match key {
                    "{}" | "{1}" => input.to_owned(),
                    "{.}" => strip(input),
                    "{/}" => base.to_owned(),
                    "{/.}" => strip(base),
                    "{//}" => input
                        .rsplit_once('/')
                        .map_or(".", |(dir, _)| if dir.is_empty() { "/" } else { dir })
                        .to_owned(),
                    "{#}" => job.to_string(),
                    _ => unreachable!(),
                };
                let start = result.len();
                result.push_str(&if unquoted_input || quoted {
                    value
                } else {
                    quote(&value)
                });
                if key != "{#}" {
                    data_ranges.push(start..result.len());
                }
                rest = &rest[key.len()..];
                continue;
            }
            // Native Perl, slot, positional and custom replacement syntax is
            // not literal data just because the basic renderer lacks it.
            if rest.starts_with("{=")
                || rest.starts_with("{%")
                || rest.starts_with("{+")
                || (rest.starts_with('{') && rest.as_bytes().get(1).is_some_and(u8::is_ascii_digit))
            {
                return None;
            }
            let ch = rest.chars().next()?;
            if quoted {
                result.push(ch);
            } else {
                result.push(ch);
                if escaped {
                    escaped = false;
                } else if ch == '\\' && shell_quote != Some('\'') {
                    escaped = true;
                } else if matches!(ch, '\'' | '"') {
                    if shell_quote == Some(ch) {
                        shell_quote = None;
                    } else if shell_quote.is_none() {
                        shell_quote = Some(ch);
                    }
                }
            }
            rest = &rest[ch.len_utf8()..];
        }
        if shell_quote.is_some() || escaped {
            return None;
        }
        if quoted {
            // -q quotes each complete resulting argv word, not its characters
            // or replacement chunks. Map decoded byte offsets through the
            // single-quote escape encoding while retaining actual data ranges.
            let encoded_offset = |offset| {
                1 + offset
                    + 3 * result[..offset]
                        .bytes()
                        .filter(|byte| *byte == b'\'')
                        .count()
            };
            data_ranges = data_ranges
                .into_iter()
                .map(|range| encoded_offset(range.start)..encoded_offset(range.end))
                .collect();
            result = quote(&result);
        }
        Some(RenderedJob {
            source: result,
            data_ranges,
        })
    };
    let mut result = if quoted {
        let mut joined = RenderedJob {
            source: String::new(),
            data_ranges: Vec::new(),
        };
        for (index, word) in words.iter().enumerate() {
            if index != 0 {
                joined.source.push(' ');
            }
            let rendered = render_word(word)?;
            let offset = joined.source.len();
            joined.data_ranges.extend(
                rendered
                    .data_ranges
                    .into_iter()
                    .map(|r| (r.start + offset)..(r.end + offset)),
            );
            joined.source.push_str(&rendered.source);
        }
        joined
    } else {
        render_word(&template)?
    };
    if !has_replacement && append_input {
        result.source.push(' ');
        let start = result.source.len();
        result.source.push_str(&quote(input));
        result.data_ranges.push(start..result.source.len());
    }
    Some(result)
}

/// -X repeats each context word separately, not the complete command.
pub(crate) fn render_group_tracked(
    words: &[String],
    inputs: &[String],
    quoted: bool,
    job: usize,
) -> Option<RenderedJob> {
    if words.is_empty() || inputs.is_empty() {
        return None;
    }
    let template = words.join(" ");
    let contexts = if quoted {
        words.to_vec()
    } else {
        context_words(&template)?
    };
    let mut result = RenderedJob {
        source: String::new(),
        data_ranges: Vec::new(),
    };
    let mut replacement = false;
    for (index, word) in contexts.iter().enumerate() {
        // Positional {1} means the first input of the group, not every input.
        // Combining positional and context replacements within one word is a
        // separate grammar; retain its unresolved boundary.
        let context = ["{}", "{.}", "{/}", "{/.}", "{//}"]
            .iter()
            .any(|key| word.contains(key));
        if context && word.contains("{1}") {
            return None;
        }
        replacement |= context || word.contains("{1}") || word.contains("{#}");
        let selected = if context { inputs } else { &inputs[..1] };
        for input in selected {
            let rendered = render_single(&[word.clone()], input, quoted, job, index == 0, false)?;
            join_rendered(&mut result, rendered);
        }
    }
    if !replacement {
        for input in inputs {
            let source = quote(input);
            let len = source.len();
            join_rendered(
                &mut result,
                RenderedJob {
                    source,
                    data_ranges: vec![0..len],
                },
            );
        }
    }
    Some(result)
}

fn join_rendered(result: &mut RenderedJob, item: RenderedJob) {
    if !result.source.is_empty() {
        result.source.push(' ');
    }
    let offset = result.source.len();
    result.data_ranges.extend(
        item.data_ranges
            .into_iter()
            .map(|r| r.start + offset..r.end + offset),
    );
    result.source.push_str(&item.source);
}

fn context_words(template: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut start = None;
    let mut quote = None;
    let mut escaped = false;
    for (i, ch) in template.char_indices() {
        if start.is_none() && ch.is_ascii_whitespace() {
            continue;
        }
        start.get_or_insert(i);
        if escaped {
            escaped = false;
        } else if ch == '\\' && quote != Some('\'') {
            escaped = true;
        } else if matches!(ch, '\'' | '"') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            }
        } else if ch.is_ascii_whitespace() && quote.is_none() {
            words.push(template[start.take()?..i].into());
        }
    }
    if quote.is_some() || escaped {
        return None;
    }
    if let Some(start) = start {
        words.push(template[start..].into());
    }
    Some(words)
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_types::{RuntimeArgumentDomain, ShellKind};

    #[test]
    fn symbolic_jobs_replace_holes_not_fixed_words() {
        let job = symbolic_job(
            &["echo".into(), "pre{}post".into(), "fixed".into()],
            false,
            false,
            ShellKind::Bash,
            &RuntimeArgumentDomain::Unbounded,
        )
        .unwrap();
        assert_eq!(job.rendered.source, "echo \"${1}\" fixed");
        assert_eq!(job.inputs.len(), 1);
        assert_eq!(
            job.inputs[0].domain,
            RuntimeArgumentDomain::TextTemplate {
                prefix: "pre".into(),
                suffix: "post".into(),
            }
        );
        assert_eq!(
            &job.rendered.source[job.rendered.data_ranges[0].clone()],
            "\"${1}\""
        );
        assert!(!job.inputs[0].batch);
    }

    #[test]
    fn symbolic_contexts_retain_batch_width_and_literal_affixes() {
        let job = symbolic_job(
            &["echo".into(), "prefix{}suffix".into()],
            true,
            true,
            ShellKind::Bash,
            &RuntimeArgumentDomain::Unbounded,
        )
        .unwrap();
        assert_eq!(job.rendered.source, "'echo' \"$@\"");
        assert!(job.inputs[0].batch);
        assert_eq!(
            job.inputs[0].domain,
            RuntimeArgumentDomain::TextTemplate {
                prefix: "prefix".into(),
                suffix: "suffix".into(),
            }
        );
    }

    #[test]
    fn symbolic_path_transforms_do_not_borrow_identity_domain() {
        let domain = RuntimeArgumentDomain::PathSet {
            roots: vec!["./cache".into()],
            may_escape: false,
        };
        let identity =
            symbolic_job(&["echo {}".into()], false, false, ShellKind::Bash, &domain).unwrap();
        assert_eq!(identity.inputs[0].domain, domain);
        let basename =
            symbolic_job(&["echo {/}".into()], false, false, ShellKind::Bash, &domain).unwrap();
        assert_eq!(basename.inputs[0].domain, RuntimeArgumentDomain::Unbounded);
    }

    #[test]
    fn symbolic_compilation_rejects_unowned_holes_and_frame_changes() {
        for template in [
            "{}",
            "./{}",
            "echo {} > {}",
            "name={}; echo safe",
            "echo $@ {}",
            "echo {#}",
            "echo {2}",
            "echo {= $_ =}",
            "f(){ echo {}; }; f",
            "for i in a; do echo {}; done",
            "echo __CAUSHELL_NATIVE_INPUT_HOLE__ {}",
        ] {
            assert!(
                symbolic_job(
                    &[template.into()],
                    false,
                    false,
                    ShellKind::Bash,
                    &RuntimeArgumentDomain::Unbounded
                )
                .is_none(),
                "{template}"
            );
        }
        assert!(
            symbolic_job(
                &["echo {} prefix{}".into()],
                false,
                true,
                ShellKind::Bash,
                &RuntimeArgumentDomain::Unbounded
            )
            .is_none()
        );
    }
    #[test]
    fn context_group_repeats_each_word_and_preserves_data_ranges() {
        let inputs = vec!["dir/A.c".into(), "dir/B.c".into()];
        let rendered =
            render_group_tracked(&["mv pre-{}-post out-{.}".into()], &inputs, false, 1).unwrap();
        assert_eq!(
            rendered.source,
            "mv pre-'dir/A.c'-post pre-'dir/B.c'-post out-'dir/A' out-'dir/B'"
        );
        let data: Vec<_> = rendered
            .data_ranges
            .iter()
            .map(|r| &rendered.source[r.clone()])
            .collect();
        assert_eq!(data, ["'dir/A.c'", "'dir/B.c'", "'dir/A'", "'dir/B'"]);
        assert_eq!(
            render_group_tracked(&["echo {1} {#}".into()], &inputs, false, 3)
                .unwrap()
                .source,
            "echo 'dir/A.c' '3'"
        );
        assert_eq!(
            render_group_tracked(&["echo".into(), "fixed".into()], &inputs, false, 1)
                .unwrap()
                .source,
            "echo fixed 'dir/A.c' 'dir/B.c'"
        );
    }
    #[test]
    fn context_group_quotes_only_replacement_data_unless_command_position() {
        let inputs = vec!["a b'c;rm /opt/file".into(), "second".into()];
        let r =
            render_group_tracked(&["echo".into(), "pre{}post".into()], &inputs, true, 1).unwrap();
        assert_eq!(
            r.source,
            "'echo' 'prea b'\\''c;rm /opt/filepost' 'presecondpost'"
        );
        assert!(
            r.data_ranges
                .iter()
                .all(|range| r.source.get(range.clone()).is_some())
        );
        assert!(render_group_tracked(&["echo '{}'".into()], &inputs, false, 1).is_none());
        assert!(render_group_tracked(&["echo {2}".into()], &inputs, false, 1).is_none());
        assert!(render_group_tracked(&["echo {1}-{}".into()], &inputs, false, 1).is_none());
        assert_eq!(
            render_group_tracked(&["{}".into()], &["echo one".into(), "two".into()], false, 1)
                .unwrap()
                .source,
            "echo one two"
        );
    }
    fn render(words: &[String], input: &str, quoted: bool, job: usize) -> Option<String> {
        render_tracked(words, input, quoted, job).map(|r| r.source)
    }
    fn render_text(template: &str, value: &str) -> Option<String> {
        render(&[template.into()], value, false, 1)
    }
    #[test]
    fn native_source_and_data_are_distinct() {
        assert_eq!(
            render(&[], "rm /etc/file", false, 1),
            Some("rm /etc/file".into())
        );
        assert_eq!(
            render_text("{}", "echo safe; rm /etc/file"),
            Some("echo safe; rm /etc/file".into())
        );
        assert_eq!(
            render_text("echo {}", "x; rm /etc/file"),
            Some("echo 'x; rm /etc/file'".into())
        );
        assert_eq!(render_text("echo", "a b"), Some("echo 'a b'".into()));
    }
    #[test]
    fn ordinary_transforms_and_quote_boundaries() {
        assert_eq!(
            render_text("mv {} {.}", "cache/file.gz"),
            Some("mv 'cache/file.gz' 'cache/file'".into())
        );
        assert_eq!(
            render_text("echo {/} {/.} {//}", "a/b.txt"),
            Some("echo 'b.txt' 'b' 'a'".into())
        );
        assert!(render_text("echo '{}'", "x").is_none());
        assert!(render_text("echo {= unlink '/tmp/x' =}", "x").is_none());
        assert!(render_text("echo {%}", "x").is_none());
        assert!(render_text("echo {2}", "x").is_none());
    }
    #[test]
    fn quote_mode_preserves_empty_words_and_tracks_only_replacements() {
        let words = vec!["echo".into(), "".into(), "prefix{}suffix".into()];
        let job = render_tracked(&words, "a b", true, 1).unwrap();
        assert_eq!(job.source, "'echo' '' 'prefixa bsuffix'");
        assert_eq!(job.data_ranges.len(), 1);
        assert_eq!(&job.source[job.data_ranges[0].clone()], "a b");
        let escaped = render_tracked(&words, "a'b", true, 1).unwrap();
        assert_eq!(&escaped.source[escaped.data_ranges[0].clone()], "a'\\''b");
        assert_eq!(
            render(&["echo".into(), "".into()], "item", true, 1),
            Some("'echo' '' 'item'".into())
        );
    }
}
