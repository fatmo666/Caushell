#![cfg(target_os = "linux")]
#[path = "../../caushell/tests/support/frame_adapter_roundtrip.rs"]
mod support;
use caushell_types::Decision;

#[test]
fn claude_adapter_preserves_executor_observations_and_approval_boundary() {
    for (command, attach, expected) in [
        (
            "find . -iname '*.DATA' | xargs -n1 cat",
            true,
            Decision::Allow,
        ),
        ("tar -cf out.tar -- *", true, Decision::Allow),
        ("tar -cf out.tar -- *", false, Decision::NeedApproval),
        ("python3 -c pass", true, Decision::NeedApproval),
        ("rm -rf /", true, Decision::Deny),
    ] {
        let r = support::roundtrip(
            "claude_code",
            command,
            attach,
            false,
            false,
            |socket, input, output| {
                caushell_adapter_claude::run_pretooluse(socket, input, output).unwrap()
            },
        );
        assert_eq!(r.decision, expected, "{r:#?}");
    }
}
