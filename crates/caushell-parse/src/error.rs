use std::{error::Error, fmt};

use caushell_types::ShellKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    UnsupportedShell(ShellKind),
    LanguageInit(String),
    ParseCancelled,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedShell(shell_kind) => {
                write!(
                    f,
                    "shell kind {shell_kind:?} is not supported by caushell-parse"
                )
            }
            Self::LanguageInit(message) => {
                write!(f, "failed to initialize parser language: {message}")
            }
            Self::ParseCancelled => write!(f, "tree-sitter returned no parse tree"),
        }
    }
}

impl Error for ParseError {}
