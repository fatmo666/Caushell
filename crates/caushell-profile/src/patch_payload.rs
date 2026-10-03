//! Pure target decoding for the Codex apply-patch protocol. Contents stay data.
//! Grammar reference: codex-rs/apply-patch/{parser,streaming_parser}.rs at
//! f6fd7f17ed2ef4bf28e5b320789d764350ce4529. No filesystem application occurs.
use crate::ProjectionUnknownReason;

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PatchTargets {
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    pub deletes: Vec<String>,
}

#[derive(Clone, Copy)]
enum Mode {
    Start,
    Add,
    Delete,
    Update,
}

/// Linear in input bytes, bounded in both bytes and operation count. An error
/// invalidates the *whole* payload, including any previously decoded prefix.
pub(crate) fn decode(
    text: &str,
    max_bytes: usize,
    max_operations: usize,
) -> Result<PatchTargets, ProjectionUnknownReason> {
    use ProjectionUnknownReason::{InvalidPayload, PayloadBudgetExceeded, UnknownPayloadContext};
    if text.len() > max_bytes {
        return Err(PayloadBudgetExceeded);
    }
    let mut text = text.trim();
    // The reference parser also accepts a heredoc wrapper *inside* an argv value.
    if matches!(text.lines().next(), Some("<<EOF" | "<<'EOF'" | "<<\"EOF\"")) {
        let (_, inner) = text.split_once('\n').ok_or(InvalidPayload)?;
        let (patch, last) = inner.rsplit_once('\n').ok_or(InvalidPayload)?;
        if !last.trim_end().ends_with("EOF") {
            return Err(InvalidPayload);
        }
        text = patch.trim();
    }
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some("*** Begin Patch") {
        return Err(InvalidPayload);
    }
    let mut targets = PatchTargets::default();
    let mut mode = Mode::Start;
    let mut count = 0;
    let mut update_source: Option<String> = None;
    let mut move_target: Option<String> = None;
    let mut chunk_exists = false;
    let mut chunk_has_lines = false;
    let mut at_eof = false;
    for line in lines.by_ref() {
        let marker = if matches!(mode, Mode::Update) {
            line.trim_end()
        } else {
            line.trim()
        };
        let add = marker.strip_prefix("*** Add File: ");
        let delete = marker.strip_prefix("*** Delete File: ");
        let update = marker.strip_prefix("*** Update File: ");
        let boundary =
            marker == "*** End Patch" || add.is_some() || delete.is_some() || update.is_some();
        if boundary {
            if matches!(mode, Mode::Update) {
                if !chunk_exists || !chunk_has_lines {
                    return Err(InvalidPayload);
                }
                let source = update_source.take().ok_or(InvalidPayload)?;
                targets.reads.push(source.clone());
                if let Some(dest) = move_target.take() {
                    targets.deletes.push(source);
                    targets.writes.push(dest);
                } else {
                    targets.writes.push(source);
                }
            }
            if marker == "*** End Patch" {
                if lines.next().is_some() {
                    return Err(InvalidPayload);
                }
                return Ok(targets);
            }
            count += 1;
            if count > max_operations {
                return Err(PayloadBudgetExceeded);
            }
            let path = add.or(delete).or(update).ok_or(InvalidPayload)?;
            // Empty paths cannot identify a modification. Keep literal path bytes:
            // no quoting, tilde, environment or command-substitution interpretation.
            if path.is_empty() || path.contains('\0') {
                return Err(InvalidPayload);
            }
            if add.is_some() {
                targets.writes.push(path.to_string());
                mode = Mode::Add;
            } else if delete.is_some() {
                targets.deletes.push(path.to_string());
                mode = Mode::Delete;
            } else {
                mode = Mode::Update;
                update_source = Some(path.to_string());
                move_target = None;
                chunk_exists = false;
                chunk_has_lines = false;
                at_eof = false;
            }
            continue;
        }
        match mode {
            Mode::Start => {
                // Environment-tagged patches may address a different filesystem.
                // The current shell request contains no proof of that mapping.
                if marker.starts_with("*** Environment ID: ") {
                    return Err(UnknownPayloadContext);
                }
                return Err(InvalidPayload);
            }
            Mode::Add if line.starts_with('+') => {}
            Mode::Add | Mode::Delete => return Err(InvalidPayload),
            Mode::Update => {
                if at_eof && marker.is_empty() {
                    continue;
                }
                let context = marker == "@@" || marker.starts_with("@@ ");
                if at_eof && !context {
                    return Err(InvalidPayload);
                }
                if !chunk_exists && move_target.is_none() {
                    if let Some(dest) = marker.strip_prefix("*** Move to: ") {
                        if dest.is_empty() || dest.contains('\0') {
                            return Err(InvalidPayload);
                        }
                        move_target = Some(dest.to_string());
                        continue;
                    }
                }
                if context {
                    if chunk_exists && !chunk_has_lines {
                        return Err(InvalidPayload);
                    }
                    chunk_exists = true;
                    chunk_has_lines = false;
                    at_eof = false;
                } else if marker == "*** End of File" {
                    if !chunk_exists || !chunk_has_lines {
                        return Err(InvalidPayload);
                    }
                    at_eof = true;
                } else if line.is_empty() || line.starts_with([' ', '+', '-']) {
                    chunk_exists = true;
                    chunk_has_lines = true;
                } else {
                    return Err(InvalidPayload);
                }
            }
        }
    }
    Err(InvalidPayload)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(s: &str) -> Result<PatchTargets, ProjectionUnknownReason> {
        decode(s, 1 << 20, 4096)
    }
    #[test]
    fn all_operations_and_move_endpoints() {
        let p = parse("*** Begin Patch\n*** Add File: 新 file\n+x\n*** Delete File: gone\n*** Update File: old\n*** Move to: /tmp/new\n@@ context\n-old\n+new\n*** Update File: same\n x\n*** End of File\n*** End Patch").unwrap();
        assert_eq!(p.reads, ["old", "same"]);
        assert_eq!(p.writes, ["新 file", "/tmp/new", "same"]);
        assert_eq!(p.deletes, ["gone", "old"]);
    }
    #[test]
    fn content_headers_and_shell_syntax_are_data() {
        let p = parse("*** Begin Patch\n*** Add File: $HOME/$(whoami)\n+*** Delete File: /etc/config\n+$(rm -rf /)\n*** Update File: ~/'literal'\n *** Delete File: /etc/config\n*** End Patch").unwrap();
        assert_eq!(p.writes, ["$HOME/$(whoami)", "~/'literal'"]);
        assert!(p.deletes.is_empty());
    }
    #[test]
    fn accepts_empty_patch_empty_add_crlf_and_wrapper() {
        assert_eq!(
            parse(" \n*** Begin Patch\r\n*** End Patch\r\n ").unwrap(),
            PatchTargets::default()
        );
        assert_eq!(
            parse("*** Begin Patch\n*** Add File: empty\n*** End Patch")
                .unwrap()
                .writes,
            ["empty"]
        );
        for start in ["<<EOF", "<<'EOF'", "<<\"EOF\""] {
            assert!(
                parse(&format!(
                    "{start}\n*** Begin Patch\n*** Delete File: x\n*** End Patch\nEOF"
                ))
                .is_ok()
            );
        }
    }
    #[test]
    fn rejects_incomplete_or_malformed_whole_payload() {
        for body in [
            "*** Delete File: x\nextra",
            "*** Add File: x\nx",
            "*** Update File: x",
            "*** Update File: x\n@@",
            "*** Update File: x\n*** Move to: y",
            "*** Update File: x\n@@\n@@\n+x",
            "*** Update File: x\n*** End of File",
            "*** Update File: x\n+x\n*** End of File\n+y",
            "*** Update File: x\n*** Move to: y\n*** Move to: z\n+x",
            "*** Add File: ",
            "*** Update File: x\n+x\n@@",
        ] {
            assert!(
                parse(&format!("*** Begin Patch\n{body}\n*** End Patch")).is_err(),
                "{body}"
            );
        }
        assert!(parse("*** Begin Patch\n*** Add File: safe\n+x\n*** End Patch\ntrailing").is_err());
        assert!(parse("*** Begin Patch\n*** Add File: safe\n+x").is_err());
    }
    #[test]
    fn later_chunks_after_eof_and_blank_context_are_supported() {
        assert!(parse("*** Begin Patch\n*** Update File: x\n\n*** End of File\n\n@@ next\n+x\n*** End Patch").is_ok());
    }
    #[test]
    fn environment_context_is_not_assumed_local() {
        assert_eq!(
            parse("*** Begin Patch\n*** Environment ID: local\n*** Add File: x\n+x\n*** End Patch"),
            Err(ProjectionUnknownReason::UnknownPayloadContext)
        );
    }
    #[test]
    fn budgets_have_exact_boundaries_and_never_return_prefix() {
        let s = "*** Begin Patch\n*** Delete File: x\n*** Delete File: y\n*** End Patch";
        assert!(decode(s, s.len(), 2).is_ok());
        assert_eq!(
            decode(s, s.len() - 1, 2),
            Err(ProjectionUnknownReason::PayloadBudgetExceeded)
        );
        assert_eq!(
            decode(s, s.len(), 1),
            Err(ProjectionUnknownReason::PayloadBudgetExceeded)
        );
    }
}
