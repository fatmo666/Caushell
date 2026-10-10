//! Bounded lexical effect decoder, not a regex engine or sed interpreter.
//! GNU sed compile.c and the GNU/POSIX command grammar guide delimiters,
//! bracket expressions, text continuations and newline-terminated filenames.
//! Unknown syntax invalidates the whole result; branch reachability is not
//! used to erase writes (GNU sed opens w targets while compiling).
use crate::ProjectionUnknownReason;

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SedTargets {
    pub reads: Vec<(usize, String)>,
    pub writes: Vec<(usize, String)>,
    pub executions: Vec<usize>,
}

pub(crate) fn decode(text: &str, max_bytes: usize, max_operations: usize) -> Result<SedTargets> {
    if text.len() > max_bytes {
        return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
    }
    if text.contains('\0') {
        return Err(ProjectionUnknownReason::InvalidPayload);
    }
    Parser {
        text,
        pos: 0,
        count: 0,
        depth: 0,
        max_operations,
        targets: SedTargets::default(),
    }
    .parse()
}

struct Parser<'a> {
    text: &'a str,
    pos: usize,
    count: usize,
    depth: usize,
    max_operations: usize,
    targets: SedTargets,
}
type Result<T> = std::result::Result<T, ProjectionUnknownReason>;
fn invalid<T>() -> Result<T> {
    Err(ProjectionUnknownReason::InvalidPayload)
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }
    fn take(&mut self) -> Result<u8> {
        let c = self.peek().ok_or(ProjectionUnknownReason::InvalidPayload)?;
        self.pos += 1;
        Ok(c)
    }
    fn blanks(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }
    fn integer(&mut self) -> bool {
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.pos += 1;
        }
        self.pos != start
    }
    fn end_command(&mut self) -> Result<()> {
        self.blanks();
        if matches!(self.peek(), None | Some(b';' | b'\n' | b'}' | b'#')) {
            Ok(())
        } else {
            invalid()
        }
    }
    fn line(&mut self) -> &'_ str {
        let start = self.pos;
        while !matches!(self.peek(), None | Some(b'\n')) {
            self.pos += 1;
        }
        &self.text[start..self.pos]
    }
    // The delimiter inside a bracket expression is regex data, including in
    // a POSIX class/collation/equivalence expression. No regex is evaluated.
    fn bracket(&mut self) -> Result<()> {
        if self.peek() == Some(b'^') {
            self.pos += 1;
        }
        if self.peek() == Some(b']') {
            self.pos += 1;
        }
        loop {
            match self.take()? {
                b']' => return Ok(()),
                b'\n' => return invalid(),
                b'\\' => {
                    self.take()?;
                }
                b'[' if matches!(self.peek(), Some(b':' | b'.' | b'=')) => {
                    let marker = self.take()?;
                    loop {
                        let c = self.take()?;
                        if c == b'\n' {
                            return invalid();
                        }
                        if c == marker && self.peek() == Some(b']') {
                            self.pos += 1;
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    fn delimited(&mut self, delimiter: u8, regex: bool) -> Result<()> {
        if delimiter >= 128 || matches!(delimiter, b'\n' | b'\\' | 0) {
            return invalid();
        }
        loop {
            match self.take()? {
                c if c == delimiter => return Ok(()),
                b'\n' => return invalid(),
                b'\\' => {
                    self.take()?;
                }
                b'[' if regex => self.bracket()?,
                _ => {}
            }
        }
    }
    fn address(&mut self, second: bool) -> Result<bool> {
        self.blanks();
        match self.peek() {
            Some(c) if c.is_ascii_digit() => {
                self.integer();
                self.blanks();
                if self.peek() == Some(b'~') {
                    self.pos += 1;
                    self.blanks();
                    if !self.integer() {
                        return invalid();
                    }
                }
            }
            Some(b'$') => self.pos += 1,
            Some(b'/' | b'\\') => {
                let delimiter = if self.take()? == b'\\' {
                    self.take()?
                } else {
                    b'/'
                };
                self.delimited(delimiter, true)?;
                while matches!(self.peek(), Some(b'I' | b'M')) {
                    self.pos += 1;
                }
            }
            Some(b'+' | b'~') if second => {
                self.pos += 1;
                self.blanks();
                if !self.integer() {
                    return invalid();
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
    fn filename(&mut self) -> Result<String> {
        self.blanks();
        // GNU read_filename retains everything through newline, including
        // quotes, backslashes, spaces, # and ;. Never shell-expand it again.
        let filename = self.line();
        if filename.is_empty() {
            return invalid();
        }
        Ok(filename.to_string())
    }
    fn text_line(&mut self) -> Result<()> {
        self.blanks();
        if self.peek() == Some(b'\\') {
            self.pos += 1;
            if self.peek() == Some(b'\n') {
                self.pos += 1;
            } else if self.peek().is_none() {
                return Ok(());
            } else {
                return invalid();
            }
        }
        while let Some(c) = self.peek() {
            self.pos += 1;
            if c == b'\\' {
                self.take()?;
            } else if c == b'\n' {
                break;
            }
        }
        Ok(())
    }
    fn substitution(&mut self, offset: usize) -> Result<()> {
        let delimiter = self.take()?;
        self.delimited(delimiter, true)?;
        self.delimited(delimiter, false)?;
        loop {
            self.blanks();
            match self.peek() {
                None | Some(b';' | b'\n' | b'}' | b'#') => return Ok(()),
                Some(b'g' | b'p' | b'i' | b'I' | b'm' | b'M') => self.pos += 1,
                Some(b'e') => {
                    self.pos += 1;
                    self.targets.executions.push(offset);
                }
                Some(b'w') => {
                    self.pos += 1;
                    let filename = self.filename()?;
                    self.targets.writes.push((offset, filename));
                    return Ok(());
                }
                Some(c) if c.is_ascii_digit() => {
                    self.integer();
                }
                _ => return invalid(),
            }
        }
    }
    fn label(&mut self) -> Result<()> {
        self.blanks();
        while !matches!(
            self.peek(),
            None | Some(b';' | b'\n' | b'}' | b'#' | b' ' | b'\t')
        ) {
            self.pos += 1;
        }
        self.end_command()
    }
    fn parse(mut self) -> Result<SedTargets> {
        while self.pos < self.text.len() {
            while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b';')) {
                self.pos += 1;
            }
            if self.peek().is_none() {
                break;
            }
            let offset = self.pos;
            if self.address(false)? {
                self.blanks();
                if self.peek() == Some(b',') {
                    self.pos += 1;
                    if !self.address(true)? {
                        return invalid();
                    }
                }
            }
            self.blanks();
            if self.peek() == Some(b'!') {
                self.pos += 1;
                self.blanks();
            }
            let command = self.take()?;
            self.count += 1;
            if self.count > self.max_operations {
                return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
            }
            match command {
                b'#' => {
                    self.line();
                }
                b'{' => self.depth += 1,
                b'}' => {
                    if self.depth == 0 {
                        return invalid();
                    }
                    self.depth -= 1;
                    self.end_command()?;
                }
                b's' => self.substitution(offset)?,
                b'y' => {
                    let delimiter = self.take()?;
                    self.delimited(delimiter, false)?;
                    self.delimited(delimiter, false)?;
                    self.end_command()?;
                }
                b'a' | b'i' | b'c' => self.text_line()?,
                b'e' => {
                    self.targets.executions.push(offset);
                    self.text_line()?;
                }
                b'r' | b'R' => {
                    let filename = self.filename()?;
                    self.targets.reads.push((offset, filename));
                }
                b'w' | b'W' => {
                    let filename = self.filename()?;
                    self.targets.writes.push((offset, filename));
                }
                b':' | b'b' | b't' | b'T' | b'v' => self.label()?,
                b'q' | b'Q' | b'l' | b'L' => {
                    self.blanks();
                    self.integer();
                    self.end_command()?;
                }
                b'd' | b'D' | b'F' | b'g' | b'G' | b'h' | b'H' | b'n' | b'N' | b'p' | b'P'
                | b'z' | b'x' | b'=' => self.end_command()?,
                _ => return invalid(),
            }
        }
        if self.depth != 0 {
            return invalid();
        }
        Ok(self.targets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(s: &str) -> Result<SedTargets> {
        decode(s, 65536, 4096)
    }
    #[test]
    fn ordinary_programs_and_effect_like_data_have_no_hidden_effects() {
        for script in [
            "s/e/w/g",
            r"s|a\|b|e/w|g",
            "/[a/;ew]/p",
            r"\|e;w|p",
            "# e; w /etc/file",
            "a e;w /etc/file",
            "a\\\nw /etc/file",
            "y/ew/we/",
            ":e;s/foo/bar/g;te",
            "1,4!{p;d;}",
            "1~2p",
            "1,+2p",
            "1,~2p",
            "s/[[:alpha:]/]/w;ee/g",
            "s/[]/]/w/g",
            "s/a/b/\np",
        ] {
            assert_eq!(parse(script), Ok(SedTargets::default()), "{script}");
        }
    }
    #[test]
    fn filenames_are_literal_and_newline_terminated_not_shell_or_semicolon_split() {
        let t = parse("1w $X ; # data\nR /etc/hosts\ns/a/b/w output\nW /opt/out ").unwrap();
        assert_eq!(
            t.writes.iter().map(|(_, p)| p.as_str()).collect::<Vec<_>>(),
            ["$X ; # data", "output", "/opt/out "]
        );
        assert_eq!(t.reads[0].1, "/etc/hosts");
        assert!(t.executions.is_empty());
    }
    #[test]
    fn executable_modes_are_marked_without_claiming_pattern_space_is_shell_source() {
        for script in ["e", "1e exec /bin/sh 1>&0", "s/a/b/e", "s/a/b/epw output"] {
            assert!(!parse(script).unwrap().executions.is_empty(), "{script}");
        }
    }
    #[test]
    fn errors_and_limits_never_return_a_safe_partial_result() {
        for script in [
            "s/a/b",
            "s/[abc/a/",
            "{p",
            "p}",
            "w",
            "s/a/b/unknown",
            "w safe\nunknown",
            "p\0",
        ] {
            assert!(parse(script).is_err(), "{script}");
        }
        assert_eq!(
            decode("p;p", 3, 1),
            Err(ProjectionUnknownReason::PayloadBudgetExceeded)
        );
        assert!(decode("p;p", 3, 2).is_ok());
        assert_eq!(
            decode("p;p", 2, 2),
            Err(ProjectionUnknownReason::PayloadBudgetExceeded)
        );
    }
    #[test]
    fn later_writes_are_not_erased_by_quit_or_branches() {
        for script in ["q;w /opt/out", "b end\nw /opt/out\n:end"] {
            assert_eq!(parse(script).unwrap().writes[0].1, "/opt/out");
        }
    }
}
