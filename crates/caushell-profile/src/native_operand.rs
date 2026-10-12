//! Opt-in native operand grammars. Only decode complete argv bytes; never eval
//! shell strings or read files. Output tags are consumed by declared branches.

fn word<'a>(input: &mut &'a str, comma: bool) -> Option<String> {
    let source = input.trim_start_matches([' ', '\t']);
    let end = |ch| ch == ';' || (comma && ch == ',');
    if let Some(mut rest) = source.strip_prefix('"') {
        let mut value = String::new();
        while let Some(ch) = rest.chars().next() {
            rest = &rest[ch.len_utf8()..];
            match ch {
                '"' => {
                    let pos = rest.find(end).unwrap_or(rest.len());
                    if !rest[..pos].trim_matches([' ', '\t']).is_empty() {
                        return None;
                    }
                    *input = &rest[pos..];
                    return Some(value);
                }
                '\\' if rest.starts_with(['"', '\\']) => {
                    let escaped = rest.chars().next()?;
                    value.push(escaped);
                    rest = &rest[escaped.len_utf8()..];
                }
                _ => value.push(ch),
            }
        }
        return None;
    }
    let pos = source.find(end).unwrap_or(source.len());
    *input = &source[pos..];
    Some(source[..pos].trim_end_matches([' ', '\t']).to_owned())
}

pub(crate) fn passphrase_inputs(operand: &str) -> Option<Vec<String>> {
    if operand.len() > 64 * 1024 || operand.contains('\0') {
        return None;
    }
    if operand.starts_with("pass:") {
        return Some(Vec::new());
    }
    if let Some(path) = operand.strip_prefix("file:") {
        return (!path.is_empty()).then(|| vec![format!("file:{path}")]);
    }
    if let Some(name) = operand.strip_prefix("env:") {
        return (!name.is_empty() && !name.contains('=')).then(|| vec![format!("env:{name}")]);
    }
    if operand == "stdin" {
        return Some(vec!["file:/dev/stdin".into()]);
    }
    if let Some(fd) = operand.strip_prefix("fd:") {
        if fd.is_empty() || !fd.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let fd = fd.parse::<i32>().ok()?;
        return Some(vec![format!("file:/dev/fd/{fd}")]);
    }
    None
}

/// curl's format interpreter consumes percent pairs, brace instructions and
/// backslash pairs before looking for the next directive. A substring match
/// would mistake literal or header-format text for an output file.
pub(crate) fn write_out_paths(format: &str) -> Option<Vec<String>> {
    if format.len() > 64 * 1024 || format.contains('\0') {
        return None;
    }
    if let Some(path) = format.strip_prefix('@') {
        if path.is_empty() {
            return None;
        }
        return Some(vec![
            format!("read:{}", if path == "-" { "/dev/stdin" } else { path }),
            "opaque:format".into(),
        ]);
    }
    let mut paths = Vec::new();
    let bytes = format.as_bytes();
    let mut index = 0;
    let mut scan_work = 0usize;
    while index < bytes.len() {
        scan_work += 1;
        if scan_work > 128 * 1024 {
            return None;
        }
        if bytes[index] == b'\\' && index + 1 < bytes.len() {
            index += 2;
        } else if bytes[index] == b'%' && index + 1 < bytes.len() {
            let rest = &format[index + 1..];
            if rest.starts_with('%') {
                index += 2;
            } else if let Some(tail) = rest.strip_prefix("output{") {
                index += 8;
                if let Some(end) = tail.find('}') {
                    let filename = tail[..end].strip_prefix(">>").unwrap_or(&tail[..end]);
                    // Native curl uses a 512-byte filename buffer. Empty and
                    // oversized names cannot open a file in this instruction.
                    if !filename.is_empty() && filename.len() < 512 {
                        paths.push(format!("write:{filename}"));
                        if paths.len() > 256 {
                            return None;
                        }
                    }
                    index += end + 1;
                } else {
                    // No closing brace remains, so no later output directive
                    // can open a file either. Avoid rescanning the same tail.
                    break;
                }
            } else {
                let (prefix, escaped_close) = if rest.starts_with('{') {
                    (1, false)
                } else if rest.starts_with("header{") {
                    (7, true)
                } else if rest.starts_with("time{") {
                    (5, false)
                } else {
                    index += 2;
                    continue;
                };
                index += prefix + 1;
                let mut end = index;
                while end < bytes.len()
                    && (bytes[end] != b'}' || (escaped_close && bytes[end - 1] == b'\\'))
                {
                    scan_work += 1;
                    if scan_work > 128 * 1024 {
                        return None;
                    }
                    end += 1;
                }
                if end < bytes.len() {
                    index = end + 1;
                }
            }
        } else {
            index += 1;
        }
    }
    Some(paths)
}

pub(crate) fn multipart_inputs(operand: &str) -> Option<Vec<String>> {
    if operand.len() > 64 * 1024 || operand.contains('\0') {
        return None;
    }
    let (_, mut rest) = operand.split_once('=')?;
    let list = rest.starts_with('@');
    let file = list || rest.starts_with('<');
    if file {
        rest = &rest[1..];
    }
    let mut inputs = Vec::new();
    loop {
        let data = word(&mut rest, list)?;
        if file {
            if data.is_empty() {
                return None;
            }
            inputs.push(if data == "-" {
                "stdin:".into()
            } else {
                format!("file:{data}")
            });
            if inputs.len() > 256 {
                return None;
            }
        }
        while let Some(tail) = rest.strip_prefix(';') {
            rest = tail.trim_start_matches([' ', '\t']);
            let key_end = rest.find(['=', ';', ',']).unwrap_or(rest.len());
            if rest.as_bytes().get(key_end) == Some(&b'=') {
                let key = &rest[..key_end];
                rest = &rest[key_end + 1..];
                // headers=@- opens a file named '-', unlike body @-.
                let header_file =
                    key.eq_ignore_ascii_case("headers") && rest.starts_with(['@', '<']);
                if header_file {
                    rest = &rest[1..];
                }
                let value = word(&mut rest, list)?;
                if header_file {
                    if value.is_empty() {
                        return None;
                    }
                    inputs.push(format!("file:{value}"));
                }
            } else {
                let _ = word(&mut rest, list)?;
            }
            if inputs.len() > 256 {
                return None;
            }
        }
        if list && rest.starts_with(',') {
            rest = &rest[1..];
        } else if rest.is_empty() {
            break;
        } else {
            return None;
        }
    }
    Some(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn write_out_follows_native_instruction_boundaries() {
        assert_eq!(write_out_paths("%{http_code}\\n"), Some(vec![]));
        for format in [
            "%%output{/opt/file}",
            "\\%output{/opt/file}",
            "%{output{/opt/file}",
            "%header{X:%output{/opt/file}}",
            "%time{%output{/opt/file}}",
        ] {
            assert_eq!(write_out_paths(format), Some(vec![]), "{format}");
        }
        assert_eq!(
            write_out_paths(
                "%%%output{cache/日志}x%output{>>/opt/log}%{onerror}%output{/opt/error}"
            ),
            Some(vec![
                "write:cache/日志".into(),
                "write:/opt/log".into(),
                "write:/opt/error".into()
            ])
        );
        assert_eq!(
            write_out_paths("@cache/format"),
            Some(vec!["read:cache/format".into(), "opaque:format".into()])
        );
        assert_eq!(
            write_out_paths("@-"),
            Some(vec!["read:/dev/stdin".into(), "opaque:format".into()])
        );
        assert_eq!(
            write_out_paths("%output{}%output{>>}%output{unfinished"),
            Some(vec![])
        );
        assert_eq!(
            write_out_paths(&format!("%output{{{}}}", "x".repeat(512))),
            Some(vec![])
        );
        assert!(write_out_paths(&"%output{cache/file}".repeat(257)).is_none());
        assert!(write_out_paths(&"x".repeat(65537)).is_none());
        assert!(write_out_paths(&"%header{x\\}".repeat(5000)).is_none());
    }
    #[test]
    fn credential_sources_are_complete_and_bounded() {
        assert_eq!(passphrase_inputs("pass:"), Some(vec![]));
        assert_eq!(
            passphrase_inputs("file:name:with:colon"),
            Some(vec!["file:name:with:colon".into()])
        );
        assert_eq!(
            passphrase_inputs("stdin"),
            Some(vec!["file:/dev/stdin".into()])
        );
        assert_eq!(
            passphrase_inputs("fd:03"),
            Some(vec!["file:/dev/fd/3".into()])
        );
        assert_eq!(
            passphrase_inputs("env:PASSWORD"),
            Some(vec!["env:PASSWORD".into()])
        );
        for input in [
            "pass",
            "file:",
            "env:",
            "env:A=B",
            "fd:-1",
            "fd:1junk",
            "fd:2147483648",
            "stdin:0",
            "file:a\0b",
        ] {
            assert!(passphrase_inputs(input).is_none(), "{input}");
        }
        assert!(passphrase_inputs(&format!("pass:{}", "a".repeat(65536))).is_none());
    }
    #[test]
    fn lists_quotes_attributes_and_streams() {
        assert_eq!(
            multipart_inputs(r#"f=@"a,b";filename="not;a;path",.env;type=text/plain;headers=@hdr"#),
            Some(vec![
                "file:a,b".into(),
                "file:.env".into(),
                "file:hdr".into()
            ])
        );
        assert_eq!(
            multipart_inputs("f=<-;type=text/plain"),
            Some(vec!["stdin:".into()])
        );
        assert_eq!(
            multipart_inputs("f=text;headers=@-"),
            Some(vec!["file:-".into()])
        );
        assert_eq!(
            multipart_inputs(r#"f="@.env";filename=/etc/file"#),
            Some(vec![])
        );
        assert_eq!(
            multipart_inputs(r#"f=@"a\\b\"c""#),
            Some(vec!["file:a\\b\"c".into()])
        );
        assert!(multipart_inputs("f=@\"unfinished").is_none());
        assert!(multipart_inputs("f=@good,").is_none());
        assert_eq!(multipart_inputs("f=<a,b"), Some(vec!["file:a,b".into()]));
    }
    #[test]
    fn file_list_budget_does_not_depend_on_attribute_presence() {
        let at_limit = format!("f=@{}", vec!["cache/data"; 256].join(","));
        assert_eq!(multipart_inputs(&at_limit).unwrap().len(), 256);
        let over_limit = format!("{at_limit},cache/data");
        assert!(multipart_inputs(&over_limit).is_none());
    }
}
