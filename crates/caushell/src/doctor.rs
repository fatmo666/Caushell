use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::CliError;

const DOCTOR_CLAUDE_PROMPT: &str = "Use the Bash tool exactly once to run: printf caushell-claude-ok. Then report the command output.";
const CODEX_PLUGIN_NAME: &str = "caushell-codex";
const HOOK_SMOKE_COMMAND: &str = "printf caushell-hook-smoke-ok";

#[derive(Debug, Clone, Copy)]
enum DoctorAgent {
    Codex,
    Claude,
}

impl DoctorAgent {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "codex" => Some(Self::Codex),
            "claude" | "claude-code" => Some(Self::Claude),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::Claude => "Claude Code",
        }
    }

    fn plugin_name(self) -> &'static str {
        match self {
            Self::Codex => "caushell-codex",
            Self::Claude => "caushell-claude",
        }
    }

    fn hook_binary(self) -> &'static str {
        match self {
            Self::Codex => "caushell-codex-hook",
            Self::Claude => "caushell-claude-hook",
        }
    }

    fn adapter_binary(self) -> &'static str {
        match self {
            Self::Codex => "caushell-adapter-codex",
            Self::Claude => "caushell-adapter-claude",
        }
    }

    fn agent_binary(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }
}

struct DoctorOptions {
    agent: DoctorAgent,
    smoke: bool,
}

struct DoctorReport {
    failures: usize,
    warnings: usize,
}

impl DoctorReport {
    fn new(agent: DoctorAgent) -> Self {
        println!("Caushell doctor: {}", agent.label());
        Self {
            failures: 0,
            warnings: 0,
        }
    }

    fn ok(&mut self, message: impl AsRef<str>) {
        println!("[ok] {}", message.as_ref());
    }

    fn warn(&mut self, message: impl AsRef<str>) {
        self.warnings += 1;
        println!("[warn] {}", message.as_ref());
    }

    fn fail(&mut self, message: impl AsRef<str>) {
        self.failures += 1;
        println!("[fail] {}", message.as_ref());
    }

    fn finish(self) -> Result<(), CliError> {
        if self.failures == 0 {
            if self.warnings == 0 {
                println!("Result: OK");
            } else {
                println!("Result: OK with {} warning(s)", self.warnings);
            }
            Ok(())
        } else {
            println!(
                "Result: FAILED with {} failure(s), {} warning(s)",
                self.failures, self.warnings
            );
            Err(invalid_cli_input(format!(
                "doctor found {} failure(s)",
                self.failures
            )))
        }
    }
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), CliError> {
    let Some(options) = parse_doctor_options(args)? else {
        return Ok(());
    };
    let mut report = DoctorReport::new(options.agent);
    let status = run_doctor_basic(options.agent, &mut report);

    if options.smoke {
        match status {
            Some(status) => run_doctor_smoke(options.agent, &status, &mut report),
            None => report.fail("skipping smoke test because the basic hook status check failed"),
        }
    }

    report.finish()
}

fn parse_doctor_options(
    mut args: impl Iterator<Item = String>,
) -> Result<Option<DoctorOptions>, CliError> {
    let Some(agent_arg) = args.next() else {
        print_doctor_usage();
        return Err(invalid_cli_input(
            "caushell doctor requires codex or claude",
        ));
    };

    if matches!(agent_arg.as_str(), "--help" | "-h" | "help") {
        print_doctor_usage();
        return Ok(None);
    }

    let Some(agent) = DoctorAgent::parse(&agent_arg) else {
        return Err(invalid_cli_input(format!(
            "unknown doctor target {agent_arg:?}; expected codex or claude"
        )));
    };

    let mut smoke = false;
    for arg in args {
        match arg.as_str() {
            "--smoke" => smoke = true,
            "--help" | "-h" => {
                print_doctor_usage();
                return Ok(None);
            }
            other => {
                return Err(invalid_cli_input(format!(
                    "unexpected caushell doctor argument: {other}"
                )));
            }
        }
    }

    Ok(Some(DoctorOptions { agent, smoke }))
}

fn run_doctor_basic(
    agent: DoctorAgent,
    report: &mut DoctorReport,
) -> Option<BTreeMap<String, String>> {
    match env::current_exe() {
        Ok(path) => report.ok(format!("caushell binary: {}", path.display())),
        Err(error) => report.warn(format!("could not resolve caushell binary path: {error}")),
    }

    let hook_path = match find_executable_on_path(agent.hook_binary()) {
        Some(path) => {
            report.ok(format!(
                "{} on PATH: {}",
                agent.hook_binary(),
                path.display()
            ));
            path
        }
        None => {
            report.fail(format!("{} is not on PATH", agent.hook_binary()));
            return None;
        }
    };

    match find_executable_on_path(agent.adapter_binary()) {
        Some(path) => report.ok(format!(
            "{} on PATH: {}",
            agent.adapter_binary(),
            path.display()
        )),
        None => report.fail(format!("{} is not on PATH", agent.adapter_binary())),
    }

    let output = match Command::new(&hook_path).arg("Status").output() {
        Ok(output) => output,
        Err(error) => {
            report.fail(format!(
                "failed to run {} Status: {error}",
                agent.hook_binary()
            ));
            return None;
        }
    };

    if !output.status.success() {
        report.fail(format!(
            "{} Status failed: {}",
            agent.hook_binary(),
            command_output_summary(&output)
        ));
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let status = parse_key_value_output(&stdout);
    check_status_field(report, &status, "plugin_name", agent.plugin_name());

    if let Some(version) = status.get("plugin_version") {
        report.ok(format!("plugin_version={version}"));
    } else {
        report.fail("hook status did not report plugin_version");
    }

    if let Some(runtime_path) = status.get("runtime_path") {
        let path = PathBuf::from(runtime_path);
        if is_executable(&path) {
            report.ok(format!("runtime binary: {runtime_path}"));
            check_runtime_version(&path, &status, report);
        } else {
            report.fail(format!("runtime_path is not executable: {runtime_path}"));
        }
    } else {
        report.fail("hook status did not report runtime_path");
    }

    if agent.plugin_name() == "caushell-codex" {
        if let Some(adapter_path) = status.get("adapter_path") {
            let path = PathBuf::from(adapter_path);
            if is_executable(&path) {
                report.ok(format!("Codex adapter binary: {adapter_path}"));
            } else {
                report.fail(format!("adapter_path is not executable: {adapter_path}"));
            }
        } else {
            report.fail("Codex hook status did not report adapter_path");
        }
    }

    match status.get("config_load_error") {
        Some(value) if value.is_empty() => report.ok("config loaded"),
        Some(value) => report.fail(format!("config_load_error={value}")),
        None => report.fail("hook status did not report config_load_error"),
    }

    match status.get("runtime_status").map(String::as_str) {
        Some("up") => report.ok("runtime daemon is up"),
        Some("down") => report
            .warn("runtime daemon is down; this is normal before the first agent shell action"),
        Some(other) => report.fail(format!("unexpected runtime_status={other}")),
        None => report.fail("hook status did not report runtime_status"),
    }

    if let Some(last_failure) = status.get("last_failure").filter(|value| !value.is_empty()) {
        report.warn(format!("last recorded hook failure: {last_failure}"));
    }

    Some(status)
}

fn run_doctor_smoke(
    agent: DoctorAgent,
    initial_status: &BTreeMap<String, String>,
    report: &mut DoctorReport,
) {
    if matches!(agent, DoctorAgent::Codex) {
        run_codex_doctor_smoke(initial_status, report);
        return;
    }

    let Some(agent_path) = find_executable_on_path(agent.agent_binary()) else {
        report.fail(format!(
            "{} CLI is not on PATH; cannot run smoke test",
            agent.agent_binary()
        ));
        return;
    };
    report.ok(format!(
        "{} CLI on PATH: {}",
        agent.agent_binary(),
        agent_path.display()
    ));

    let Some(log_path) = initial_status
        .get("plugin_log_path")
        .filter(|value| !value.is_empty())
    else {
        report.fail("hook status did not report plugin_log_path; cannot run smoke test");
        return;
    };
    let log_path = PathBuf::from(log_path);
    let before_lines = count_lines_if_exists(&log_path).unwrap_or(0);

    let output = match agent {
        DoctorAgent::Codex => unreachable!("Codex smoke is handled by run_codex_doctor_smoke"),
        DoctorAgent::Claude => Command::new(&agent_path)
            .arg("-p")
            .arg(DOCTOR_CLAUDE_PROMPT)
            .arg("--allowedTools")
            .arg("Bash")
            .output(),
    };

    match output {
        Ok(output) if output.status.success() => {
            report.ok(format!("{} smoke command completed", agent.label()));
        }
        Ok(output) => {
            report.fail(format!(
                "{} smoke command failed: {}",
                agent.label(),
                command_output_summary(&output)
            ));
            return;
        }
        Err(error) => {
            report.fail(format!(
                "failed to start {} smoke command: {error}",
                agent.label()
            ));
            return;
        }
    }

    let status = match Command::new(agent.hook_binary()).arg("Status").output() {
        Ok(output) if output.status.success() => {
            parse_key_value_output(&String::from_utf8_lossy(&output.stdout))
        }
        Ok(output) => {
            report.fail(format!(
                "{} Status failed after smoke command: {}",
                agent.hook_binary(),
                command_output_summary(&output)
            ));
            return;
        }
        Err(error) => {
            report.fail(format!(
                "failed to run {} Status after smoke command: {error}",
                agent.hook_binary()
            ));
            return;
        }
    };

    match status.get("runtime_status").map(String::as_str) {
        Some("up") => report.ok("runtime daemon is up after smoke command"),
        Some(other) => report.fail(format!("runtime_status={other} after smoke command")),
        None => report.fail("hook status did not report runtime_status after smoke command"),
    }

    let new_log = match read_log_lines_after(&log_path, before_lines) {
        Ok(new_log) => new_log,
        Err(error) => {
            report.fail(format!(
                "failed to read hook log {}: {error}",
                log_path.display()
            ));
            return;
        }
    };

    if new_log.contains("event=PreToolUse") {
        report.ok("smoke log contains event=PreToolUse");
    } else {
        report.fail("smoke log does not contain event=PreToolUse; the agent did not invoke Caushell before Bash");
    }

    if new_log.contains("event=PostToolUse") {
        report.ok("smoke log contains event=PostToolUse");
    } else {
        report.fail("smoke log does not contain event=PostToolUse; the agent did not invoke Caushell after Bash");
    }
}

fn run_codex_doctor_smoke(initial_status: &BTreeMap<String, String>, report: &mut DoctorReport) {
    check_codex_plugin_enabled(report);
    run_direct_hook_smoke(DoctorAgent::Codex, initial_status, report);
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CodexPluginList {
    installed: Vec<CodexPluginEntry>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CodexPluginEntry {
    plugin_id: String,
    name: String,
    marketplace_name: String,
    version: Option<String>,
    installed: bool,
    enabled: bool,
}

fn check_codex_plugin_enabled(report: &mut DoctorReport) {
    let Some(codex_path) = find_executable_on_path("codex") else {
        report.fail("codex CLI is not on PATH; cannot verify Codex plugin installation");
        return;
    };
    report.ok(format!("codex CLI on PATH: {}", codex_path.display()));

    let output = match Command::new(&codex_path)
        .args(["plugin", "list", "--json"])
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            report.fail(format!("failed to run codex plugin list --json: {error}"));
            return;
        }
    };

    if !output.status.success() {
        report.fail(format!(
            "codex plugin list --json failed: {}",
            command_output_summary(&output)
        ));
        return;
    }

    let plugins = match serde_json::from_slice::<CodexPluginList>(&output.stdout) {
        Ok(plugins) => plugins,
        Err(error) => {
            report.fail(format!(
                "failed to parse codex plugin list --json output: {error}"
            ));
            return;
        }
    };

    let matches = plugins
        .installed
        .iter()
        .filter(|plugin| plugin.name == CODEX_PLUGIN_NAME)
        .collect::<Vec<_>>();

    if matches.is_empty() {
        report.fail(format!(
            "{CODEX_PLUGIN_NAME} is not installed in Codex; run `codex plugin add caushell-codex@caushell`"
        ));
        return;
    }

    if matches.len() > 1 {
        report.warn(format!(
            "multiple Codex plugins named {CODEX_PLUGIN_NAME} are installed; using enabled state from all matches"
        ));
    }

    let mut saw_enabled = false;
    for plugin in matches {
        let version = plugin.version.as_deref().unwrap_or("unknown");
        if plugin.installed && plugin.enabled {
            saw_enabled = true;
            report.ok(format!(
                "Codex plugin enabled: {} version={} marketplace={}",
                plugin.plugin_id, version, plugin.marketplace_name
            ));
        } else if !plugin.installed {
            report.fail(format!(
                "Codex plugin is listed but not installed: {} version={} marketplace={}",
                plugin.plugin_id, version, plugin.marketplace_name
            ));
        } else {
            report.fail(format!(
                "Codex plugin is installed but disabled: {} version={} marketplace={}",
                plugin.plugin_id, version, plugin.marketplace_name
            ));
        }
    }

    if !saw_enabled {
        report.fail(format!(
            "no enabled {CODEX_PLUGIN_NAME} plugin found in Codex"
        ));
    }
}

fn run_direct_hook_smoke(
    agent: DoctorAgent,
    initial_status: &BTreeMap<String, String>,
    report: &mut DoctorReport,
) {
    let Some(hook_path) = find_executable_on_path(agent.hook_binary()) else {
        report.fail(format!(
            "{} is not on PATH; cannot run direct hook smoke",
            agent.hook_binary()
        ));
        return;
    };

    let Some(log_path) = initial_status
        .get("plugin_log_path")
        .filter(|value| !value.is_empty())
    else {
        report.fail("hook status did not report plugin_log_path; cannot run direct hook smoke");
        return;
    };
    let log_path = PathBuf::from(log_path);
    let before_lines = count_lines_if_exists(&log_path).unwrap_or(0);
    let session_id = format!("caushell-doctor-{}", std::process::id());
    let cwd = smoke_cwd(initial_status);

    let pre_payload = codex_like_hook_payload(&session_id, &cwd, "PreToolUse");
    let pre_output = match run_hook_event(&hook_path, "PreToolUse", &pre_payload) {
        Ok(output) => output,
        Err(error) => {
            report.fail(format!(
                "failed to run direct PreToolUse hook smoke: {error}"
            ));
            return;
        }
    };

    if pre_output.status.success() {
        report.ok("direct PreToolUse hook completed");
        check_safe_hook_decision("PreToolUse", &pre_output, report);
    } else {
        report.fail(format!(
            "direct PreToolUse hook failed: {}",
            command_output_summary(&pre_output)
        ));
        return;
    }

    let post_output = match run_hook_event(&hook_path, "PostToolUse", "") {
        Ok(output) => output,
        Err(error) => {
            report.fail(format!(
                "failed to run direct PostToolUse hook smoke: {error}"
            ));
            return;
        }
    };

    if post_output.status.success() {
        report.ok("direct PostToolUse hook completed");
    } else {
        report.fail(format!(
            "direct PostToolUse hook failed: {}",
            command_output_summary(&post_output)
        ));
        return;
    }

    let status = match Command::new(&hook_path).arg("Status").output() {
        Ok(output) if output.status.success() => {
            parse_key_value_output(&String::from_utf8_lossy(&output.stdout))
        }
        Ok(output) => {
            report.fail(format!(
                "{} Status failed after direct hook smoke: {}",
                agent.hook_binary(),
                command_output_summary(&output)
            ));
            return;
        }
        Err(error) => {
            report.fail(format!(
                "failed to run {} Status after direct hook smoke: {error}",
                agent.hook_binary()
            ));
            return;
        }
    };

    match status.get("runtime_status").map(String::as_str) {
        Some("up") => report.ok("runtime daemon is up after direct hook smoke"),
        Some(other) => report.fail(format!("runtime_status={other} after direct hook smoke")),
        None => report.fail("hook status did not report runtime_status after direct hook smoke"),
    }

    let new_log = match read_log_lines_after(&log_path, before_lines) {
        Ok(new_log) => new_log,
        Err(error) => {
            report.fail(format!(
                "failed to read hook log {}: {error}",
                log_path.display()
            ));
            return;
        }
    };

    check_smoke_log_event(&new_log, "PreToolUse", report);
    check_smoke_log_event(&new_log, "PostToolUse", report);
}

fn smoke_cwd(status: &BTreeMap<String, String>) -> String {
    status
        .get("workspace_root")
        .filter(|value| !value.is_empty())
        .cloned()
        .or_else(|| {
            env::current_dir()
                .ok()
                .map(|path| path.display().to_string())
        })
        .unwrap_or_else(|| ".".to_string())
}

fn codex_like_hook_payload(session_id: &str, cwd: &str, event_name: &str) -> String {
    serde_json::json!({
        "session_id": session_id,
        "cwd": cwd,
        "hook_event_name": event_name,
        "tool_name": "Bash",
        "tool_input": {
            "command": HOOK_SMOKE_COMMAND
        }
    })
    .to_string()
}

fn run_hook_event(hook_path: &Path, event_name: &str, stdin_text: &str) -> io::Result<Output> {
    if stdin_text.is_empty() {
        return Command::new(hook_path)
            .arg(event_name)
            .stdin(Stdio::null())
            .output();
    }

    let mut child = Command::new(hook_path)
        .arg(event_name)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stdin = child.stdin.take().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("failed to open stdin for {event_name} hook"),
        )
    })?;
    stdin.write_all(stdin_text.as_bytes())?;
    drop(stdin);

    child.wait_with_output()
}

fn check_safe_hook_decision(event_name: &str, output: &Output, report: &mut DoctorReport) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    if stdout.is_empty() {
        report.ok(format!("{event_name} allowed harmless smoke command"));
        return;
    }

    let value = match serde_json::from_str::<serde_json::Value>(stdout) {
        Ok(value) => value,
        Err(error) => {
            report.fail(format!(
                "{event_name} emitted non-empty non-JSON stdout for harmless smoke command: {error}"
            ));
            return;
        }
    };

    let hook_output = value
        .get("hookSpecificOutput")
        .and_then(serde_json::Value::as_object);
    let decision = hook_output
        .and_then(|object| object.get("permissionDecision"))
        .and_then(serde_json::Value::as_str);
    let reason = hook_output
        .and_then(|object| object.get("permissionDecisionReason"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    match decision {
        Some("allow") => report.ok(format!("{event_name} allowed harmless smoke command")),
        Some(decision @ ("deny" | "ask")) => report.fail(format!(
            "{event_name} returned permissionDecision={decision}: {reason}"
        )),
        Some(other) => report.fail(format!(
            "{event_name} returned unsupported permissionDecision={other}"
        )),
        None => report.fail(format!(
            "{event_name} emitted JSON without hookSpecificOutput.permissionDecision"
        )),
    }
}

fn check_smoke_log_event(new_log: &str, event_name: &str, report: &mut DoctorReport) {
    if new_log.contains(&format!("event={event_name}")) {
        report.ok(format!("hook log contains event={event_name}"));
    } else {
        report.fail(format!(
            "hook log does not contain event={event_name}; the Caushell hook did not record the direct smoke event"
        ));
    }
}

fn check_status_field(
    report: &mut DoctorReport,
    status: &BTreeMap<String, String>,
    key: &str,
    expected: &str,
) {
    match status.get(key) {
        Some(value) if value == expected => report.ok(format!("{key}={value}")),
        Some(value) => report.fail(format!("{key}={value}; expected {expected}")),
        None => report.fail(format!("hook status did not report {key}")),
    }
}

fn check_runtime_version(
    runtime_path: &PathBuf,
    status: &BTreeMap<String, String>,
    report: &mut DoctorReport,
) {
    let Some(plugin_version) = status.get("plugin_version") else {
        return;
    };
    let output = match Command::new(runtime_path).arg("--version").output() {
        Ok(output) => output,
        Err(error) => {
            report.fail(format!(
                "failed to run {} --version: {error}",
                runtime_path.display()
            ));
            return;
        }
    };
    if !output.status.success() {
        report.fail(format!(
            "{} --version failed: {}",
            runtime_path.display(),
            command_output_summary(&output)
        ));
        return;
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let expected = format!("caushell {plugin_version}");
    if version == expected {
        report.ok(format!(
            "runtime version matches plugin version: {plugin_version}"
        ));
    } else {
        report.fail(format!(
            "runtime version mismatch: got {version:?}, expected {expected:?}"
        ));
    }
}

fn parse_key_value_output(output: &str) -> BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

fn count_lines_if_exists(path: &Path) -> io::Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    let file = fs::File::open(path)?;
    BufReader::new(file)
        .lines()
        .try_fold(0usize, |count, line| line.map(|_| count + 1))
}

fn read_log_lines_after(path: &Path, before_lines: usize) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut output = String::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if index >= before_lines {
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str(&line);
        }
    }
    Ok(output)
}

fn command_output_summary(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut parts = Vec::new();
    parts.push(format!("exit={}", output.status));
    let stdout = trim_for_report(&stdout);
    if !stdout.is_empty() {
        parts.push(format!("stdout={stdout:?}"));
    }
    let stderr = trim_for_report(&stderr);
    if !stderr.is_empty() {
        parts.push(format!("stderr={stderr:?}"));
    }
    parts.join(" ")
}

fn trim_for_report(value: &str) -> String {
    let mut lines = value.lines().take(12).collect::<Vec<_>>().join("\n");
    if value.lines().count() > 12 {
        lines.push_str("\n...");
    }
    lines
}

fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(name);
    if path.components().count() > 1 {
        return is_executable(&path).then_some(path);
    }

    let paths = env::var_os("PATH")?;
    for root in env::split_paths(&paths) {
        let candidate = root.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

fn invalid_cli_input(message: impl Into<String>) -> CliError {
    CliError::InvalidArguments(message.into())
}

fn print_doctor_usage() {
    eprintln!(
        "usage:\n  caushell doctor codex [--smoke]\n  caushell doctor claude [--smoke]\n\nwithout --smoke, doctor checks installed binaries, hook status, runtime/config compatibility, and daemon state\nwith --smoke, doctor runs a harmless lifecycle smoke test and verifies that Caushell can handle PreToolUse and PostToolUse"
    );
}
