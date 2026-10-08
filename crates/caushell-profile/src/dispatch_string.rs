//! Pure, bounded tool-string projection. No eval, subprocess or ambient env.
//!
//! GNU wordsplit's default C escapes differ from POSIX shell quoting. Expansion
//! requiring tool environment is deliberately unresolved, not copied from the
//! caller. Shell programs use the existing /bin/sh -c recursive machinery.
use crate::DispatchStringSyntax;

const MAX_COMMAND_BYTES: usize = 64 * 1024;
const MAX_ARGV_WORDS: usize = 4096;

pub(crate) fn project_command_string(
    text: &str,
    syntax: DispatchStringSyntax,
) -> Option<(String, Vec<String>)> {
    if text.len() > MAX_COMMAND_BYTES || text.contains('\0') {
        return None;
    }
    match syntax {
        DispatchStringSyntax::PosixShell => {
            Some(("/bin/sh".into(), vec!["-c".into(), text.into()]))
        }
        DispatchStringSyntax::GnuWordsplit => {
            let mut words = gnu_wordsplit(text)?.into_iter();
            let command = words.next()?;
            if command.is_empty() {
                return None;
            }
            Some((command, words.collect()))
        }
    }
}

fn gnu_wordsplit(text: &str) -> Option<Vec<String>> {
    let mut input = text.chars().peekable();
    let mut quote = None;
    let mut word = String::new();
    let mut started = false;
    let mut words = Vec::new();
    while let Some(ch) = input.next() {
        if quote == Some('\'') {
            if ch == '\'' {
                quote = None;
            } else {
                word.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' if quote.is_none() => {
                quote = Some(ch);
                started = true;
            }
            '"' if quote == Some('"') => quote = None,
            ' ' | '\t' | '\n' if quote.is_none() => {
                if started {
                    if words.len() >= MAX_ARGV_WORDS {
                        return None;
                    }
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            '\\' => {
                started = true;
                let escaped = input.next()?;
                match escaped {
                    'a' => word.push('\x07'),
                    'b' => word.push('\x08'),
                    'f' => word.push('\x0c'),
                    'n' => word.push('\n'),
                    'r' => word.push('\r'),
                    't' => word.push('\t'),
                    'v' => word.push('\x0b'),
                    'x' | 'X' => {
                        let mut number = 0;
                        let mut count = 0;
                        while count < 2 {
                            let Some(digit) = input.peek().and_then(|c| c.to_digit(16)) else {
                                break;
                            };
                            input.next();
                            number = number * 16 + digit;
                            count += 1;
                        }
                        if count == 0 {
                            // GNU preserves invalid hexadecimal escapes.
                            word.push('\\');
                            word.push(escaped);
                        } else {
                            word.push(ascii_escape(number)?);
                        }
                    }
                    '0'..='7' => {
                        let mut number = escaped.to_digit(8)?;
                        for _ in 0..2 {
                            let Some(digit) = input.peek().and_then(|c| c.to_digit(8)) else {
                                break;
                            };
                            input.next();
                            number = number * 8 + digit;
                        }
                        word.push(ascii_escape(number)?);
                    }
                    '8' | '9' => {
                        // Invalid octal escapes are also preserved.
                        word.push('\\');
                        word.push(escaped);
                    }
                    other => word.push(other),
                }
            }
            '$' if input
                .peek()
                .is_some_and(|c| *c == '{' || *c == '_' || c.is_ascii_alphabetic()) =>
            {
                // wordsplit expands environment variables, including defaults
                // and field splitting. Do not treat the unexpanded spelling as
                // literal argv, nor emulate a different shell's expansion.
                return None;
            }
            other => {
                started = true;
                word.push(other);
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if started {
        if words.len() >= MAX_ARGV_WORDS {
            return None;
        }
        words.push(word);
    }
    Some(words)
}

fn ascii_escape(value: u32) -> Option<char> {
    // GNU emits raw bytes. NUL and non-ASCII byte escapes cannot be represented
    // faithfully as Caushell's UTF-8 argv; retain an explicit analysis gap.
    (value > 0 && value < 128).then(|| value as u8 as char)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gnu_quotes_join_fragments_and_keep_empty_arguments() {
        assert_eq!(
            gnu_wordsplit("echo 'two words' a\"b\"c '' \"\""),
            Some(vec![
                "echo".into(),
                "two words".into(),
                "abc".into(),
                "".into(),
                "".into()
            ])
        );
    }

    #[test]
    fn c_escapes_are_not_posix_shell_escapes() {
        assert_eq!(
            gnu_wordsplit(r#"echo "a\nb" \x41\101 a\ b '\n' \xZ \9"#),
            Some(vec![
                "echo".into(),
                "a\nb".into(),
                "AA".into(),
                "a b".into(),
                "\\n".into(),
                "\\xZ".into(),
                "\\9".into()
            ])
        );
    }

    #[test]
    fn operators_globs_and_command_substitutions_are_data() {
        assert_eq!(
            gnu_wordsplit("printf ; && > * $(id) `id` #comment"),
            Some(vec![
                "printf".into(),
                ";".into(),
                "&&".into(),
                ">".into(),
                "*".into(),
                "$(id)".into(),
                "`id`".into(),
                "#comment".into()
            ])
        );
    }

    #[test]
    fn variable_expansion_is_an_analysis_gap_except_when_protected() {
        for text in ["echo $VAR", "echo ${VAR:-fallback}", "echo \"$VAR\""] {
            assert_eq!(gnu_wordsplit(text), None, "{text}");
        }
        assert_eq!(
            gnu_wordsplit(r#"echo '$VAR' \$VAR"#),
            Some(vec!["echo".into(), "$VAR".into(), "$VAR".into()])
        );
    }

    #[test]
    fn invalid_or_oversized_inputs_are_never_partial_successes() {
        for text in [
            "echo '",
            "echo \"",
            "echo \\",
            "echo\0x",
            r"echo \000",
            r"echo \xff",
        ] {
            assert_eq!(
                project_command_string(text, DispatchStringSyntax::GnuWordsplit),
                None,
                "{text}"
            );
        }
        assert!(
            project_command_string(
                &"x".repeat(MAX_COMMAND_BYTES + 1),
                DispatchStringSyntax::PosixShell
            )
            .is_none()
        );
        assert!(gnu_wordsplit(&"x ".repeat(MAX_ARGV_WORDS + 1)).is_none());
        assert!(project_command_string("''", DispatchStringSyntax::GnuWordsplit).is_none());
    }
}
