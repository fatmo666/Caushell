//! Offline Bash judgments under the protected default configuration assumption.
use caushell_core::ShellQueryCore;
use caushell_types::{CheckIntent, RuntimeTransportRequest, ShellKind};
use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let config = args.next().ok_or("expected a policy configuration path")?;
    let mut native_variants = BTreeMap::new();
    while let Some(flag) = args.next() {
        if flag != "--native-variant" {
            return Err(format!("unexpected argument: {flag}").into());
        }
        let pair = args.next().ok_or("expected a command=variant inventory entry")?;
        let (name, variant) = pair.split_once('=').ok_or("expected command=variant")?;
        let valid_id = |value: &str| {
            !value.is_empty() && value.len() <= 128
                && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        };
        if !valid_id(name) || !valid_id(variant)
            || native_variants.insert(name.to_owned(), variant.to_owned()).is_some()
        {
            return Err("invalid or duplicate native variant".into());
        }
    }
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
        let response = core.try_judge_static_shell_with_native_variants(prepared.request, &native_variants)?;
        serde_json::to_writer(&mut output, &serde_json::json!({"kind": "static_check", "payload": response}))?;
        output.write_all(b"\n")?;
    }
    Ok(())
}
