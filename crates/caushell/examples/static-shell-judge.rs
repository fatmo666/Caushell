//! Offline Bash judgments under the protected default configuration assumption.
use caushell_core::ShellQueryCore;
use caushell_types::{CheckIntent, RuntimeTransportRequest, ShellKind};
use std::io::{self, BufRead, Write};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = std::env::args().nth(1).ok_or("expected a policy configuration path")?;
    let mut core = ShellQueryCore::try_with_config_path(Path::new(&config))?;
    let mut output = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let RuntimeTransportRequest::Check(request) = serde_json::from_str(&line?)? else {
            return Err("static judgment accepts only check requests".into());
        };
        if request.intent != CheckIntent::JudgeOnly
            || request.shell_kind != ShellKind::Bash
            || request.shell_state_before.execution_frame.is_some()
        {
            return Err("static judgment accepts only unframed Bash JudgeOnly requests".into());
        }
        let prepared = core.prepare_runtime_check(request)?;
        let response = core.try_judge_static_shell(prepared.request)?;
        serde_json::to_writer(&mut output, &serde_json::json!({"kind": "static_check", "payload": response}))?;
        output.write_all(b"\n")?;
    }
    Ok(())
}
