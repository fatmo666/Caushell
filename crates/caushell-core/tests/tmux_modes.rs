//! Static tmux requests; no terminal session/server or sample command runs.
use caushell_core::ShellQueryCore;
use caushell_types::*;
fn expect(command: &str, expected: Decision) {
    let result = ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("tmux-mode"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    });
    assert_eq!(result.decision, expected, "{command}: {result:#?}");
}
#[test]
fn query_and_benign_metadata_modes_are_not_interactive_shells() {
    for command in [
        "tmux -V",
        "tmux -h",
        "tmux list-sessions",
        "tmux show-environment -g | grep RBENV",
        "tmux show-environment -t sessname",
        "tmux showenv -s RBENV_VERSION",
        "tmux show-options -g",
        "tmux -L work show-environment -g",
        "tmux set-environment -gu RBENV_VERSION",
        "tmux setenv -t sessname -u RBENV_VERSION",
        "tmux setenv -g NAME value",
        "tmux set -g history-limit 10000",
        "tmux set-option -g renumber-windows on",
        "tmux movew -s 4 -t 3",
        "tmux movew -r",
    ] {
        expect(command, Decision::Allow);
    }
}
#[test]
fn format_jobs_opaque_controls_and_multiple_commands_keep_approval() {
    for command in [
        "tmux show-options -F '#(touch /opt/shared/out)'",
        "tmux setenv -F NAME '#(touch /opt/shared/out)'",
        "tmux set -F history-limit '#(touch /opt/shared/out)'",
        "tmux set -g default-shell /tmp/script",
        "tmux set -g after-new-session 'run-shell /tmp/script'",
        "tmux movew -k -s 4 -t 3",
        "tmux run-shell 'touch /opt/shared/out'",
        "tmux show-environment ';' run-shell 'touch /opt/shared/out'",
        "tmux show-environment NAME ';' run-shell 'touch /opt/shared/out'",
        "tmux setenv NAME value ';' run-shell 'touch /opt/shared/out'",
        "tmux new-session -d 'touch /opt/shared/out'",
        "tmux new-window 'touch /opt/shared/out'",
        "tmux",
    ] {
        expect(command, Decision::NeedApproval);
    }
}
