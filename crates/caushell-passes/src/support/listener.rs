//! Tool defaults are resolved exclusively from supplied facts. No DNS, socket,
//! process, application configuration or host environment is inspected.
use caushell_profile::{
    BoundInvocation, ConfiguredScalar, EffectTarget, EnvironmentValueRef, EnvironmentValueSource,
    SemanticValueResolution, SessionValue, ShellVariableValueSource, ValueProjection,
    VariablePresence, project_value,
};
use caushell_types::{NetworkListenScope, NetworkListener};

use super::ExecutionResolveRecordRef;

pub(crate) fn environment_default(
    source: &EnvironmentValueSource,
    record: Option<ExecutionResolveRecordRef<'_>>,
) -> Option<SemanticValueResolution> {
    variable_default(&source.name, source.empty_is_unset, false, record)
}

/// Shell defaults include unexported locals; unknown presence is not absence.
/// Prefix assignments and scalar materialization use the same supplied-fact
/// query as process environment defaults, without observing the host shell.
pub(crate) fn shell_variable_default(
    source: &ShellVariableValueSource,
    record: Option<ExecutionResolveRecordRef<'_>>,
) -> Option<SemanticValueResolution> {
    variable_default(&source.name, source.empty_is_unset, true, record)
}

fn variable_default(
    name: &str,
    empty_is_unset: bool,
    shell_scope: bool,
    record: Option<ExecutionResolveRecordRef<'_>>,
) -> Option<SemanticValueResolution> {
    let unknown = || {
        Some(SemanticValueResolution::Unknown(
            caushell_profile::ProjectionUnknownReason::DynamicArgument,
        ))
    };
    let Some(record) = record else {
        return unknown();
    };
    // Prefix assignments are exported for this invocation regardless of the
    // variable's previous export attribute. Last assignment wins.
    let prefix = record.command().and_then(|command| {
        command
            .prefix_assignments
            .iter()
            .rev()
            .find(|a| a.name == name)
    });
    let value = if let Some(assignment) = prefix {
        if assignment.operator != caushell_parse::AssignmentOperator::Assign {
            return unknown();
        }
        SessionValue::from_session_variable_value(
            &super::variable_overlay::classify_assignment_value(
                &assignment.value,
                record.bindings(),
            ),
        )
    } else if shell_scope {
        match record.bindings().variable_presence(name) {
            VariablePresence::Absent => return None,
            VariablePresence::Unknown => return unknown(),
            VariablePresence::Present => match record.bindings().get(name) {
                Some(binding) => binding.value.clone(),
                None => return unknown(),
            },
        }
    } else {
        match record.bindings().environment_value(name) {
            EnvironmentValueRef::Absent => return None,
            EnvironmentValueRef::Unknown => return unknown(),
            EnvironmentValueRef::Present(value) => value.clone(),
        }
    };
    match value {
        SessionValue::ExactScalar(value) | SessionValue::RuntimeProduced { value, .. } => {
            if empty_is_unset && value.is_empty() {
                None
            } else {
                Some(SemanticValueResolution::Known(value))
            }
        }
        _ => unknown(),
    }
}

fn scalar_value(
    invocation: &BoundInvocation,
    source: &ConfiguredScalar,
    record: ExecutionResolveRecordRef<'_>,
) -> Option<SemanticValueResolution> {
    invocation
        .bound_parameters
        .iter()
        .find(|p| p.name == source.slot)
        .and_then(|p| p.values.last())
        .and_then(|value| project_value(&ValueProjection::Identity, value))
        .or_else(|| {
            source
                .environment
                .as_ref()
                .and_then(|env| environment_default(env, Some(record)))
        })
        .or_else(|| {
            source
                .default_value
                .as_ref()
                .map(|value| SemanticValueResolution::Known(value.clone()))
        })
}

fn known(value: Option<SemanticValueResolution>) -> Option<String> {
    match value {
        Some(SemanticValueResolution::Known(value)) => Some(value),
        _ => None,
    }
}

pub(crate) fn network_listeners(record: ExecutionResolveRecordRef<'_>) -> Vec<NetworkListener> {
    let caushell_profile::ResolveInvocationArtifactResult::Resolved(resolved) = record.result()
    else {
        return Vec::new();
    };
    resolved
        .bound
        .effects
        .iter()
        .filter_map(|effect| {
            if let EffectTarget::NetworkListener(target) = &effect.target {
                Some(resolve_listener(target, &resolved.bound, record))
            } else {
                None
            }
        })
        .collect()
}

fn resolve_listener(
    target: &caushell_profile::NetworkListenerTarget,
    invocation: &BoundInvocation,
    record: ExecutionResolveRecordRef<'_>,
) -> NetworkListener {
    let value = |scalar: &ConfiguredScalar| scalar_value(invocation, scalar, record);
    let fd = target.inherited_fd.as_ref().and_then(value);
    let uds = target.unix_socket.as_ref().and_then(value);
    // The launch mode may select either transport. Do not state that one
    // actually won; the independent UDS cleanup path effects remain present.
    if fd.is_some() && uds.is_some() {
        return NetworkListener::Unknown { reason: "both inherited-socket and UNIX-socket settings may apply; transport precedence is unresolved".into() };
    }
    if let Some(fd) = fd {
        return match fd {
            SemanticValueResolution::Known(fd) => NetworkListener::InheritedFd { fd: Some(fd) },
            SemanticValueResolution::Unknown(_) => NetworkListener::Unknown {
                reason:
                    "inherited socket setting is unresolved; loopback scope cannot be established"
                        .into(),
            },
        };
    }
    if let Some(uds) = uds {
        return match uds {
            SemanticValueResolution::Known(path) => NetworkListener::Unix { path },
            SemanticValueResolution::Unknown(_) => NetworkListener::Unknown {
                reason:
                    "UNIX socket setting is unresolved; listener transport cannot be established"
                        .into(),
            },
        };
    }
    let host = known(value(&target.host));
    let scope = host
        .as_deref()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .map(|ip| {
            let mapped_loopback = match ip {
                std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
                _ => false,
            };
            if ip.is_loopback() || mapped_loopback {
                NetworkListenScope::Loopback
            } else {
                NetworkListenScope::NonLoopback
            }
        })
        .unwrap_or(NetworkListenScope::Unknown);
    NetworkListener::Internet {
        host,
        port: known(target.port.as_ref().and_then(value)),
        scope,
    }
}
