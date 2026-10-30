//! Recheck archived proposals using recorded metadata only. Never execute commands.
use caushell_runner::FilesystemView;
use caushell_types::*;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::{self, BufRead},
    sync::Arc,
};

#[derive(Deserialize)]
struct Input {
    request: RuntimeCheckRequest,
    #[serde(default)]
    entries: BTreeMap<String, FilesystemEntry>,
}
struct Recorded(BTreeMap<String, FilesystemEntry>);
impl FilesystemView for Recorded {
    fn source(&self) -> FilesystemObservationSource {
        FilesystemObservationSource::SuppliedView
    }
    fn entry(&self, path: &str) -> FilesystemEntry {
        self.0
            .get(path)
            .cloned()
            .unwrap_or(FilesystemEntry::Unavailable {
                reason: "not present in archived metadata; no host fallback".into(),
            })
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = std::env::args().nth(1);
    for line in io::stdin().lock().lines() {
        let mut input: Input = serde_json::from_str(&line?)?;
        input.request.intent = CheckIntent::JudgeOnly;
        let mut runtime = caushell::CliRuntime::new_with_filesystem_view(
            config.as_deref().map(std::path::Path::new),
            None,
            Arc::new(Recorded(input.entries)),
        )?;
        let response = runtime.handle_runtime_request_with_receipt(input.request)?;
        println!("{}", serde_json::to_string(&response)?);
    }
    Ok(())
}
