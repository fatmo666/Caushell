//! Bounded FFmpeg filter grammar for operators with no external I/O or code load.
//! This validates the whole graph; it is not an AVExpr evaluator. Unknown filters,
//! option-file syntax, labels, multi-input graphs and incomplete quoting stay opaque.
pub(crate) fn data_only(text: &str) -> bool {
    if text.is_empty() || text.len() > 8192 || text.contains(['\0', '/']) {
        return false;
    }
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    let mut count = 0;
    for (i, c) in text.char_indices() {
        if quoted {
            if c == '\'' {
                quoted = false;
            }
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '\'' => quoted = true,
            ';' | '[' | ']' => return false,
            ',' => {
                if !operator(&text[start..i]) {
                    return false;
                }
                count += 1;
                if count > 64 {
                    return false;
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    !quoted && !escaped && operator(&text[start..])
}
fn operator(part: &str) -> bool {
    let name = part.trim().split('=').next().unwrap_or("").trim();
    // No decoding of an operator spelling: escaped names remain unknown.
    let mut pieces = name.split('@');
    let op = pieces.next().unwrap_or("");
    if let Some(id) = pieces.next() {
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return false;
        }
    }
    if pieces.next().is_some() {
        return false;
    }
    matches!(
        op,
        "select"
            | "scale"
            | "crop"
            | "pad"
            | "fps"
            | "format"
            | "setpts"
            | "settb"
            | "trim"
            | "transpose"
            | "hflip"
            | "vflip"
            | "setsar"
            | "setdar"
            | "null"
            | "eq"
            | "negate"
            | "reverse"
            | "unsharp"
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn whole_graph_and_quoting_are_bounded() {
        for graph in [
            "select='not(mod(n,17))'",
            "scale=320:240,crop=100:80",
            "fps=2,format=gray",
            "select=eq(n\\,7)",
            "hflip@horizontal,vflip",
        ] {
            assert!(data_only(graph), "{graph}");
        }
        for graph in [
            "movie=/etc/passwd",
            "scale=2:2,movie=secret",
            "select='bad\\',movie=secret",
            "select=/expr=secret",
            "select='n/2'",
            "scale=2:2;amovie=file",
            "[0:v]scale=2:2[out]",
            "select='unfinished",
            "scale=2:2,",
            "drawtext=textfile=x",
            "frei0r=x",
            "s\\cale=2:2",
        ] {
            assert!(!data_only(graph), "{graph}");
        }
    }
}
