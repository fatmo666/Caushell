use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ShellKind, StateOperationDomain, StateOperationKind};

fn resolve(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::from_profiles(vec![
        load_command_profile_from_str(include_str!("../profiles/curl.yaml")).unwrap(),
    ])
    .unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(result) => result.bound,
        other => panic!("{command}: {other:?}"),
    }
}

fn mutations(bound: &BoundInvocation) -> usize {
    bound
        .effects
        .iter()
        .filter(|effect| {
            effect.state_operation.is_some_and(|operation| {
                operation.domain == StateOperationDomain::RemoteResource
                    && operation.operation == StateOperationKind::Mutate
            })
        })
        .count()
}

#[test]
fn native_post_and_upload_modes_declare_one_remote_mutation() {
    for option in [
        "-d value",
        "--data-binary @payload",
        "--data-raw value",
        "--data-urlencode name=value",
        "--json '{}'",
        "-F name=value",
        "--form-string name=value",
        "-T payload",
        "--get -T payload",
        "--data value --request POST",
        "-T payload --request PUT",
    ] {
        for endpoint in ["http://127.0.0.1/ingest", "https://example.test/ingest"] {
            let command = format!("curl -q {option} --url {endpoint}");
            let bound = resolve(&command);
            assert!(
                !bound.operation_semantics_unresolved,
                "{command}: {bound:?}"
            );
            assert_eq!(mutations(&bound), 1, "{command}: {bound:?}");
        }
    }
}

#[test]
fn query_and_information_modes_do_not_invent_state_mutations() {
    for command in [
        "curl -q https://example.test",
        "curl -q --get --data name=value https://example.test",
        "curl -q --get --data-binary @payload --url https://example.test",
        "curl -q -T payload --request GET --url https://example.test",
        "curl -q --data value --request GET --url https://example.test",
        "curl -q --help --data value --url https://example.test",
        "curl -q --help -T payload --url https://example.test",
    ] {
        let bound = resolve(command);
        assert_eq!(mutations(&bound), 0, "{command}: {bound:?}");
    }
}
