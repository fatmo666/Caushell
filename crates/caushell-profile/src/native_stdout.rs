//! Literal native stdout, with an explicit execution origin and escape site.
//! This is a byte proof, not permission to execute the resulting stream.
use crate::CommandLookupDomain;
use caushell_types::ShellKind;

const MAX_LITERAL_STDOUT_BYTES: usize = 1_048_576;

/// Portable, single-path argument forms with deterministic stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePathStdout {
    Basename,
    Dirname,
}

impl NativePathStdout {
    pub fn output(self, args: &[String]) -> Option<String> {
        let (path, suffix) = match (self, args) {
            (Self::Basename | Self::Dirname, [path]) => (path, None),
            (Self::Basename, [path, suffix]) => (path, Some(suffix.as_str())),
            _ => return None,
        };
        if path.is_empty()
            || path.starts_with("//")
            || args.iter().any(|arg| {
                arg.starts_with('-')
                    || arg.contains(['\0', '\n'])
                    || arg.len() >= MAX_LITERAL_STDOUT_BYTES
            })
        {
            return None;
        }

        let path = path.trim_end_matches('/');
        let value = match self {
            _ if path.is_empty() => "/",
            Self::Basename => {
                let leaf = path.rsplit('/').next()?;
                suffix
                    .and_then(|suffix| leaf.strip_suffix(suffix))
                    .filter(|stem| !stem.is_empty())
                    .unwrap_or(leaf)
            }
            Self::Dirname => match path.rsplit_once('/') {
                Some((parent, _)) => {
                    let parent = parent.trim_end_matches('/');
                    if parent.is_empty() { "/" } else { parent }
                }
                None => ".",
            },
        };
        Some(format!("{value}\n"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeOutputOrigin {
    BashBuiltin,
    /// Only the common printf subset: do not assume a GNU external binary or
    /// that `sh` names Bash. Ambiguous extensions cannot certify exact bytes.
    Portable,
    Unknown,
}
impl NativeOutputOrigin {
    pub fn for_execution(shell: ShellKind, domain: &CommandLookupDomain) -> Self {
        match domain {
            CommandLookupDomain::Shell | CommandLookupDomain::Builtin => match shell {
                ShellKind::Bash => Self::BashBuiltin,
                ShellKind::Sh => Self::Portable,
                _ => Self::Unknown,
            },
            CommandLookupDomain::External => Self::Portable,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeStdoutSource {
    Printf(NativeOutputOrigin),
    Echo(NativeOutputOrigin),
}

/// A missing proof is never an empty or truncated output. Preserve raw bytes
/// until the consumer decides whether its text representation can carry them.
pub fn decode_native_stdout(source: NativeStdoutSource, args: &[String]) -> Option<Vec<u8>> {
    match source {
        NativeStdoutSource::Printf(origin) => printf(origin, args),
        NativeStdoutSource::Echo(origin) => echo(origin, args),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EscapeSite {
    Format,
    PercentB,
    Echo,
}
enum Escape {
    Bytes(Vec<u8>, usize),
    Stop,
}

fn escape(bytes: &[u8], i: usize, site: EscapeSite, origin: NativeOutputOrigin) -> Option<Escape> {
    let Some(&next) = bytes.get(i + 1) else {
        return Some(Escape::Bytes(vec![b'\\'], 1));
    };
    let simple = match next {
        b'a' => Some(7),
        b'b' => Some(8),
        b'f' => Some(12),
        b'n' => Some(10),
        b'r' => Some(13),
        b't' => Some(9),
        b'v' => Some(11),
        b'\\' => Some(b'\\'),
        b'e' | b'E' if origin == NativeOutputOrigin::BashBuiltin => Some(27),
        _ => None,
    };
    if let Some(value) = simple {
        return Some(Escape::Bytes(vec![value], 2));
    }
    if next == b'c' {
        return match site {
            EscapeSite::PercentB | EscapeSite::Echo => Some(Escape::Stop),
            EscapeSite::Format if origin == NativeOutputOrigin::BashBuiltin => {
                Some(Escape::Bytes(b"\\c".to_vec(), 2))
            }
            EscapeSite::Format => None,
        };
    }
    let zero_prefix = next == b'0' && site != EscapeSite::Format;
    let bare_octal = (b'0'..=b'7').contains(&next)
        && (site == EscapeSite::Format
            || (site == EscapeSite::PercentB && origin == NativeOutputOrigin::BashBuiltin));
    if zero_prefix || bare_octal {
        let mut j = i + if zero_prefix { 2 } else { 1 };
        let end = j + 3;
        let mut value = 0u16;
        while j < end && bytes.get(j).is_some_and(|b| (b'0'..=b'7').contains(b)) {
            value = value * 8 + u16::from(bytes[j] - b'0');
            j += 1;
        }
        if value > 255 && origin != NativeOutputOrigin::BashBuiltin {
            return None;
        }
        return Some(Escape::Bytes(vec![value as u8], j - i));
    }
    if next == b'x' && origin == NativeOutputOrigin::BashBuiltin {
        let mut j = i + 2;
        let end = j + 2;
        let mut value = 0u8;
        while j < end && bytes.get(j).is_some_and(u8::is_ascii_hexdigit) {
            value = value * 16 + (bytes[j] as char).to_digit(16)? as u8;
            j += 1;
        }
        if j == i + 2 {
            return None;
        }
        return Some(Escape::Bytes(vec![value], j - i));
    }
    // Unicode escapes depend on locale and implementation. Never emit their
    // spelling as if it were the decoded value, or encode a raw byte as Latin1.
    if matches!(next, b'u' | b'U') {
        return None;
    }
    if origin == NativeOutputOrigin::BashBuiltin {
        // Unknown escapes retain the slash. In FORMAT the next byte may be %;
        // leave it for the format lexer instead of shielding a conversion.
        Some(Escape::Bytes(vec![b'\\'], 1))
    } else {
        None
    }
}

fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    if out.len().checked_add(bytes.len())? > MAX_LITERAL_STDOUT_BYTES {
        return None;
    }
    out.extend_from_slice(bytes);
    Some(())
}
enum Piece {
    Literal(Vec<u8>),
    String,
    EscapedString,
}
fn format_pieces(format: &str, origin: NativeOutputOrigin) -> Option<Vec<Piece>> {
    let bytes = format.as_bytes();
    let mut i = 0;
    let mut literal = Vec::new();
    let mut pieces = Vec::new();
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            match escape(bytes, i, EscapeSite::Format, origin)? {
                Escape::Bytes(value, n) => {
                    append(&mut literal, &value)?;
                    i += n;
                }
                Escape::Stop => return None, // FORMAT is never a %b argument.
            }
        } else if bytes[i] == b'%' {
            let conversion = *bytes.get(i + 1)?;
            i += 2;
            if conversion == b'%' {
                append(&mut literal, b"%")?;
                continue;
            }
            let piece = match conversion {
                b's' => Piece::String,
                b'b' => Piece::EscapedString,
                _ => return None,
            };
            if !literal.is_empty() {
                pieces.push(Piece::Literal(std::mem::take(&mut literal)));
            }
            pieces.push(piece);
        } else {
            append(&mut literal, &bytes[i..i + 1])?;
            i += 1;
        }
    }
    if !literal.is_empty() {
        pieces.push(Piece::Literal(literal));
    }
    Some(pieces)
}
fn escaped(
    out: &mut Vec<u8>,
    text: &str,
    site: EscapeSite,
    origin: NativeOutputOrigin,
) -> Option<bool> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            match escape(bytes, i, site, origin)? {
                Escape::Bytes(value, n) => {
                    append(out, &value)?;
                    i += n;
                }
                Escape::Stop => return Some(true),
            }
        } else {
            append(out, &bytes[i..i + 1])?;
            i += 1;
        }
    }
    Some(false)
}
fn printf(origin: NativeOutputOrigin, args: &[String]) -> Option<Vec<u8>> {
    if origin == NativeOutputOrigin::Unknown {
        return None;
    }
    let separated = args.first().is_some_and(|s| s == "--");
    if separated && origin != NativeOutputOrigin::BashBuiltin {
        return None;
    }
    let args = if separated { &args[1..] } else { args };
    let Some(format) = args.first() else {
        return Some(Vec::new());
    };
    if !separated && format.starts_with('-') && format != "-" {
        return None;
    }
    let pieces = format_pieces(format, origin)?;
    let data = &args[1..];
    let mut offset = 0;
    let mut out = Vec::new();
    let conversions = pieces
        .iter()
        .filter(|p| !matches!(p, Piece::Literal(_)))
        .count();
    loop {
        for piece in &pieces {
            match piece {
                Piece::Literal(bytes) => append(&mut out, bytes)?,
                Piece::String => {
                    if let Some(arg) = data.get(offset) {
                        append(&mut out, arg.as_bytes())?;
                    }
                    offset += 1;
                }
                Piece::EscapedString => {
                    if let Some(arg) = data.get(offset)
                        && escaped(&mut out, arg, EscapeSite::PercentB, origin)?
                    {
                        return Some(out);
                    }
                    offset += 1;
                }
            }
        }
        if conversions == 0 || offset >= data.len() {
            break;
        }
    }
    Some(out)
}
fn echo(origin: NativeOutputOrigin, args: &[String]) -> Option<Vec<u8>> {
    if origin == NativeOutputOrigin::Unknown {
        return None;
    }
    let mut decode = false;
    let mut newline = true;
    let mut first = 0;
    for arg in args {
        if arg.len() > 1 && arg.starts_with('-') && arg[1..].bytes().all(|b| b"neE".contains(&b)) {
            if origin != NativeOutputOrigin::BashBuiltin {
                return None;
            }
            for b in arg[1..].bytes() {
                match b {
                    b'n' => newline = false,
                    b'e' => decode = true,
                    b'E' => decode = false,
                    _ => unreachable!(),
                }
            }
            first += 1;
        } else {
            if first == 0 && arg.starts_with('-') && arg != "--" && arg != "-" {
                return None;
            }
            break;
        }
    }
    // Without an explicit escape mode, backslashes vary with xpg_echo/build
    // defaults. Do not promote that ambiguity to a complete text source.
    let explicit = args[..first]
        .iter()
        .any(|s| s.contains('e') || s.contains('E'));
    if !explicit && args[first..].iter().any(|s| s.contains('\\')) {
        return None;
    }
    let mut out = Vec::new();
    for (i, arg) in args[first..].iter().enumerate() {
        if i > 0 {
            append(&mut out, b" ")?;
        }
        if decode {
            if escaped(&mut out, arg, EscapeSite::Echo, origin)? {
                return Some(out);
            }
        } else {
            append(&mut out, arg.as_bytes())?;
        }
    }
    if newline {
        append(&mut out, b"\n")?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn native_path_stdout_models_only_portable_single_path_forms() {
        use super::NativePathStdout::{Basename, Dirname};

        for (decoder, fields, expected) in [
            (Dirname, &["{}"][..], Some(".\n")),
            (Dirname, &["parent///leaf/"][..], Some("parent\n")),
            (Dirname, &["/leaf"][..], Some("/\n")),
            (Basename, &["{}", ".html"][..], Some("{}\n")),
            (Basename, &["parent/leaf.html/", ".html"][..], Some("leaf\n")),
            (Basename, &["parent/leaf", "leaf"][..], Some("leaf\n")),
            (Basename, &["/"][..], Some("/\n")),
            (Basename, &["-a", "a"][..], None),
            (Basename, &["a", "b", "c"][..], None),
            (Dirname, &["a", "b"][..], None),
            (Dirname, &["//parent"][..], None),
            (Dirname, &[""][..], None),
        ] {
            let args = fields.iter().map(|field| field.to_string()).collect::<Vec<_>>();
            assert_eq!(decoder.output(&args).as_deref(), expected, "{decoder:?} {fields:?}");
        }
    }

    use super::*;
    #[test]
    fn native_stdout_claimed_bytes_match_captured_native_process_output() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/native_stdout_bash_5_2.json"
        ))
        .unwrap();
        for row in fixture["cases"].as_array().unwrap() {
            let source = match row["source"].as_str().unwrap() {
                "printf" => NativeStdoutSource::Printf(NativeOutputOrigin::BashBuiltin),
                "echo" => NativeStdoutSource::Echo(NativeOutputOrigin::BashBuiltin),
                _ => unreachable!(),
            };
            let args = row["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect::<Vec<_>>();
            let decoded = decode_native_stdout(source, &args);
            if row["decoder_proves_exact"] == true {
                let hex = row["stdout_hex"].as_str().unwrap();
                let expected = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(decoded, Some(expected), "{}", row["id"]);
            } else {
                assert!(decoded.is_none(), "{}", row["id"]);
            }
        }
    }
    fn output(args: &[&str]) -> Option<Vec<u8>> {
        decode_native_stdout(
            NativeStdoutSource::Printf(NativeOutputOrigin::BashBuiltin),
            &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    }
    #[test]
    fn native_stdout_escape_site_owns_control_and_octal_width() {
        for (args, expected) in [
            (vec![r"A\cB"], b"A\\cB".to_vec()),
            (vec!["%b", r"A\cB"], b"A".to_vec()),
            (vec![r"\0141"], vec![12, b'1']),
            (vec!["%b", r"\0141"], b"a".to_vec()),
            (vec!["%b", r"\141"], b"a".to_vec()),
            (vec![r"\501"], b"A".to_vec()),
            (vec!["%b", r"\0501"], b"A".to_vec()),
            (vec![r"\%s", "value"], b"\\value".to_vec()),
            (vec![r"A\qB"], b"A\\qB".to_vec()),
            (vec!["%b", r"A\qB"], b"A\\qB".to_vec()),
            (vec!["%s", r"\c%n;data"], b"\\c%n;data".to_vec()),
        ] {
            assert_eq!(output(&args), Some(expected), "{args:?}");
        }
    }
    #[test]
    fn native_stdout_bytes_are_not_latin1_codepoints() {
        assert_eq!(output(&[r"\xc3\xa9"]), Some(vec![0xc3, 0xa9]));
        assert_eq!(output(&["%b", r"\xff"]), Some(vec![255]));
        assert_eq!(output(&[r"\0X"]), Some(vec![0, b'X']));
        assert!(output(&[r"\u0041"]).is_none());
        assert!(output(&[r"\xZ"]).is_none());
    }
    #[test]
    fn native_stdout_origin_does_not_borrow_builtin_extensions() {
        assert_eq!(
            NativeOutputOrigin::for_execution(ShellKind::Bash, &CommandLookupDomain::External),
            NativeOutputOrigin::Portable
        );
        assert_eq!(
            NativeOutputOrigin::for_execution(ShellKind::Sh, &CommandLookupDomain::Shell),
            NativeOutputOrigin::Portable
        );
        for origin in [NativeOutputOrigin::Portable, NativeOutputOrigin::Unknown] {
            assert!(
                decode_native_stdout(NativeStdoutSource::Printf(origin), &[r"A\cB".into()])
                    .is_none()
            );
        }
        assert_eq!(
            decode_native_stdout(
                NativeStdoutSource::Printf(NativeOutputOrigin::Portable),
                &["%s\n".into(), "safe".into()]
            ),
            Some(b"safe\n".to_vec())
        );
    }
    #[test]
    fn native_stdout_only_certifies_complete_bounded_supported_programs() {
        for args in [
            vec!["%n", "target"],
            vec!["-v", "target", "%s", "data"],
            vec!["%10s", "data"],
            vec!["%d", "1"],
        ] {
            assert!(output(&args).is_none());
        }
        assert_eq!(
            output(&["%s\n", "one", "two"]),
            Some(b"one\ntwo\n".to_vec())
        );
        assert_eq!(
            output(&["%b%s", r"done\c", "ignored"]),
            Some(b"done".to_vec())
        );
        let args = vec![
            "%s%s".into(),
            "x".repeat(MAX_LITERAL_STDOUT_BYTES),
            "tail".into(),
        ];
        assert!(
            decode_native_stdout(
                NativeStdoutSource::Printf(NativeOutputOrigin::BashBuiltin),
                &args
            )
            .is_none()
        );
    }

    #[test]
    fn native_stdout_echo_has_its_own_octal_and_escape_mode() {
        for (args, expected) in [
            (vec!["-e", r"A\cB"], Some(b"A".to_vec())),
            (vec!["-e", r"\0141"], Some(b"a\n".to_vec())),
            (vec!["-e", r"\141"], Some(b"\\141\n".to_vec())),
            (vec!["-e", r"\q"], Some(b"\\q\n".to_vec())),
            (vec![r"A\cB"], None),
        ] {
            assert_eq!(
                decode_native_stdout(
                    NativeStdoutSource::Echo(NativeOutputOrigin::BashBuiltin),
                    &args.iter().map(|s| s.to_string()).collect::<Vec<_>>()
                ),
                expected,
                "{args:?}"
            );
        }
    }
}
