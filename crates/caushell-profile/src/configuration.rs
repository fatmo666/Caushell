use crate::{CommandProfile, ConfigurationSyntax, FlagOperandMode, declared_options};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationOption {
    pub option: String,
    pub argument: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationParseError {
    pub line: usize,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigurationParse {
    pub options: Vec<ConfigurationOption>,
    pub errors: Vec<ConfigurationParseError>,
}

pub fn parse_configuration(profile: &CommandProfile, bytes: &[u8]) -> ConfigurationParse {
    let mut result = ConfigurationParse::default();
    let mut error = |line, detail: &str| {
        result.errors.push(ConfigurationParseError {
            line,
            detail: detail.into(),
        })
    };
    if profile.configuration_files.as_ref().map(|c| c.syntax) != Some(ConfigurationSyntax::Curl) {
        error(0, "configuration syntax is not declared");
        return result;
    }
    if bytes.len() > 65_536 || bytes.contains(&0) {
        error(0, "configuration exceeds the byte budget or contains NUL");
        return result;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        error(0, "configuration is not UTF-8");
        return result;
    };
    let declarations = match declared_options(profile) {
        Ok(declarations) => declarations,
        Err(_) => {
            error(0, "configuration option ownership is not declared");
            return result;
        }
    };
    for (index, line) in text.split('\n').enumerate() {
        let number = index + 1;
        if number > 4096 || result.options.len() >= 2048 {
            result.errors.push(ConfigurationParseError {
                line: number,
                detail: "configuration option budget exceeded".into(),
            });
            break;
        }
        let line = line.trim_start_matches(space);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parsed = (|| -> Result<ConfigurationOption, &'static str> {
            let dashed = line.starts_with('-');
            let end = line
                .find(|c: char| space(c) || (!dashed && matches!(c, ':' | '=')))
                .unwrap_or(line.len());
            let word = &line[..end];
            if word.len() > 128 {
                return Err("configuration option name exceeds its budget");
            }
            let option = if dashed {
                word.into()
            } else {
                format!("--{word}")
            };
            if matches!(
                option.as_str(),
                "--next" | "-:" | "--help" | "-h" | "--manual" | "-M" | "--version" | "-V"
            ) {
                return Err(
                    "configuration operation boundary or information directive is not supported",
                );
            }
            let mode = declarations
                .get(&option)
                .ok_or("configuration directive is not modeled")?;
            let tail = line[end..]
                .trim_start_matches(|c: char| space(c) || (!dashed && matches!(c, ':' | '=')));
            let argument = argument(tail)?;
            if option == "--engine" && argument.as_deref() == Some("list") {
                return Err("configuration engine-list control is not supported");
            }
            let argument = match mode {
                None => {
                    if argument.as_ref().is_some_and(|a| !a.is_empty()) {
                        result.errors.push(ConfigurationParseError {
                            line: number,
                            detail: "configuration flag has an unused parameter".into(),
                        });
                    }
                    None
                }
                Some(FlagOperandMode::NextArg) => {
                    Some(argument.ok_or("configuration option requires a parameter")?)
                }
                Some(FlagOperandMode::OptionalNextArg) => argument,
                _ => return Err("configuration operand grammar is not supported"),
            };
            Ok(ConfigurationOption {
                option,
                argument,
                line: number,
            })
        })();
        match parsed {
            Ok(option) => result.options.push(option),
            Err(detail) => result.errors.push(ConfigurationParseError {
                line: number,
                detail: detail.into(),
            }),
        }
    }
    result
}

pub fn mark_configuration_pending(bound: &mut crate::BoundInvocation, detail: impl Into<String>) {
    use crate::{Residual, ResidualKind, ResidualSurface};
    if bound.operation_semantics_unresolved && bound.residuals.is_empty() {
        bound.residuals.push(Residual::new(
            ResidualKind::UnboundControlSurface,
            ResidualSurface::Control,
            "operation is incomplete independently of configuration",
        ));
    }
    bound.operation_semantics_unresolved = true;
    bound.residuals.push(Residual::new(
        ResidualKind::ConfigurationInput,
        ResidualSurface::Control,
        detail,
    ));
}

fn argument(tail: &str) -> Result<Option<String>, &'static str> {
    if tail.is_empty() {
        return Ok(None);
    }
    if let Some(quoted) = tail.strip_prefix('"') {
        let mut value = String::new();
        let mut chars = quoted.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => return Ok(Some(value)),
                '\\' => value.push(
                    match chars
                        .next()
                        .ok_or("configuration quote has a trailing escape")?
                    {
                        't' => '\t',
                        'n' => '\n',
                        'r' => '\r',
                        'v' => '\u{b}',
                        c => c,
                    },
                ),
                c => value.push(c),
            }
        }
        return Err("configuration quote is not terminated");
    }
    let end = tail.find(space).unwrap_or(tail.len());
    Ok(Some(tail[..end].into()))
}

fn space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{b}' | '\u{c}')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> ConfigurationParse {
        let registry = crate::ProfileRegistry::built_in().unwrap();
        parse_configuration(registry.lookup("curl").profile.unwrap(), text.as_bytes())
    }

    #[test]
    fn ordered_native_options_preserve_quotes_and_literal_data() {
        let result = parse(
            "# comment\ninsecure\nno-insecure\ncacert = \"/certs/a b.pem\"\nurl: \"https://example.test/$literal\"\nheader = \"A: x\\ty\\nZ\\\\q\"\n",
        );
        assert!(result.errors.is_empty(), "{result:?}");
        assert_eq!(
            result
                .options
                .iter()
                .map(|o| (o.option.as_str(), o.argument.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                ("--insecure", None),
                ("--no-insecure", None),
                ("--cacert", Some("/certs/a b.pem")),
                ("--url", Some("https://example.test/$literal")),
                ("--header", Some("A: x\ty\nZ\\q")),
            ]
        );
        assert_eq!(result.options[2].line, 4);
    }

    #[test]
    fn malformed_and_unmodeled_lines_preserve_partial_options() {
        let result = parse(
            "insecure extra\nunknown-option value\ncacert\nurl \"unterminated\nno-insecure\n",
        );
        assert_eq!(result.errors.len(), 4);
        assert_eq!(
            result
                .options
                .iter()
                .map(|o| o.option.as_str())
                .collect::<Vec<_>>(),
            vec!["--insecure", "--no-insecure"]
        );
    }

    #[test]
    fn operation_boundaries_and_information_controls_are_not_flattened() {
        for text in [
            "next\n",
            "help\n",
            "version\n",
            "engine list\n",
            "-sk\n",
            "--url=https://example.test\n",
        ] {
            let result = parse(text);
            assert!(!result.errors.is_empty(), "{text}: {result:?}");
        }
    }

    #[test]
    fn native_separators_and_empty_values_remain_distinct() {
        let result = parse("cacert=\"\"\n--url https://example.test ignored\n--cacert=wrong\n");
        assert_eq!(result.options[0].argument.as_deref(), Some(""));
        assert_eq!(
            result.options[1].argument.as_deref(),
            Some("https://example.test")
        );
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn invalid_encoding_and_budgets_fail_closed() {
        let registry = crate::ProfileRegistry::built_in().unwrap();
        let profile = registry.lookup("curl").profile.unwrap();
        for bytes in [vec![255], vec![0], vec![b'x'; 65_537]] {
            assert!(!parse_configuration(profile, &bytes).errors.is_empty());
        }
        assert!(!parse(&"insecure\n".repeat(2049)).errors.is_empty());
        assert!(!parse(&"\n".repeat(4097)).errors.is_empty());
    }
}
