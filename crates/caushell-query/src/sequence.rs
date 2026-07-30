use caushell_types::CommandSequenceNo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SequenceWindow {
    after_sequence: Option<CommandSequenceNo>,
    before_sequence: Option<CommandSequenceNo>,
}

impl SequenceWindow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn after_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.after_sequence = Some(sequence_no);
        self
    }

    pub fn before_sequence(mut self, sequence_no: CommandSequenceNo) -> Self {
        self.before_sequence = Some(sequence_no);
        self
    }

    pub fn after_bound(&self) -> Option<CommandSequenceNo> {
        self.after_sequence
    }

    pub fn before_bound(&self) -> Option<CommandSequenceNo> {
        self.before_sequence
    }

    pub fn contains(&self, sequence_no: CommandSequenceNo) -> bool {
        self.after_sequence
            .is_none_or(|after_sequence| sequence_no > after_sequence)
            && self
                .before_sequence
                .is_none_or(|before_sequence| sequence_no < before_sequence)
    }
}

#[cfg(test)]
mod tests {
    use super::SequenceWindow;
    use caushell_types::CommandSequenceNo;

    #[test]
    fn empty_sequence_window_accepts_all_sequence_numbers() {
        let window = SequenceWindow::new();

        assert!(window.contains(CommandSequenceNo::new(1)));
        assert!(window.contains(CommandSequenceNo::new(99)));
    }

    #[test]
    fn sequence_window_applies_strict_after_bound() {
        let window = SequenceWindow::new().after_sequence(CommandSequenceNo::new(3));

        assert!(!window.contains(CommandSequenceNo::new(3)));
        assert!(window.contains(CommandSequenceNo::new(4)));
    }

    #[test]
    fn sequence_window_applies_strict_before_bound() {
        let window = SequenceWindow::new().before_sequence(CommandSequenceNo::new(8));

        assert!(window.contains(CommandSequenceNo::new(7)));
        assert!(!window.contains(CommandSequenceNo::new(8)));
    }

    #[test]
    fn sequence_window_combines_after_and_before_bounds() {
        let window = SequenceWindow::new()
            .after_sequence(CommandSequenceNo::new(3))
            .before_sequence(CommandSequenceNo::new(8));

        assert!(!window.contains(CommandSequenceNo::new(3)));
        assert!(window.contains(CommandSequenceNo::new(4)));
        assert!(window.contains(CommandSequenceNo::new(7)));
        assert!(!window.contains(CommandSequenceNo::new(8)));
    }
}
