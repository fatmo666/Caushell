mod core;
mod file_content;
mod filesystem;
pub use filesystem::LocalFilesystem;
mod state;

pub use core::{
    AppliedShellStateDelta, CheckOutcome, PreparedRuntimeCheck, ShellQueryCore,
    ShellQueryCoreError, ShellQueryCoreInitError,
};
pub use state::{SessionCommitError, SessionState};
