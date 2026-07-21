use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::CliError;

const DOCTOR_CODEX_PROMPT: &str = "Use the Bash tool exactly once to run: printf caushell-codex-ok. Then report the command output.";
const DOCTOR_CLAUDE_PROMPT: &str = "Use the Bash tool exactly once to run: printf caushell-claude-ok. Then report the command output.";

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
        DoctorAgent::Codex => Command::new(&agent_path)
            .arg("exec")
            .arg("--dangerously-bypass-hook-trust")
            .arg(DOCTOR_CODEX_PROMPT)
            .output(),
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
        "usage:\n  caushell doctor codex [--smoke]\n  caushell doctor claude [--smoke]\n\nwithout --smoke, doctor checks installed binaries, hook status, runtime/config compatibility, and daemon state\nwith --smoke, doctor also runs one harmless agent Bash action and verifies that Caushell saw PreToolUse and PostToolUse for that action"
    );
}
