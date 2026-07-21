use crate::GraphRead;
use caushell_types::SessionSummary;

pub trait SessionRead {
    fn graph(&self) -> &dyn GraphRead;
    fn summary(&self) -> &SessionSummary;
}
