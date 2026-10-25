//! Private, serial control pipe owned by the executor, not by a tool subprocess.
use crate::{CliError, CliRuntime};
use caushell_runner::{
    ManagedResource, ManagedResourceRegistry, ResourceAuthority, ResourceGrant,
    ResourceInstanceRef, ResourceLocatorScope, ResourceOwner, ResourcePermission,
    ResourceRegistration, ResourceRoute, ResourceRouteRegistration,
};
use caushell_types::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{BufRead, Read, Write},
    sync::Arc,
    time::Duration,
};

const MAX_PACKET_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceHandle {
    pub resource_id: String,
    pub instance_id: String,
    pub generation: u64,
    pub namespace_id: String,
}
impl From<&ResourceInstanceRef> for ResourceHandle {
    fn from(instance: &ResourceInstanceRef) -> Self {
        Self {
            resource_id: instance.resource_id.clone(),
            instance_id: instance.instance_id.clone(),
            generation: instance.generation,
            namespace_id: instance.namespace_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantHandle {
    pub grant_id: String,
    pub resource: ResourceHandle,
    pub serial: u64,
    pub policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteHandle {
    pub route_id: String,
    pub resource: ResourceHandle,
    pub serial: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindResourceRoute {
    pub route_id: String,
    pub resource: ResourceHandle,
    pub endpoint: String,
    pub target: String,
    pub lifetime_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterResource {
    pub resource: ManagedResource,
    pub scope: ResourceLocatorScope,
    pub lifetime_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantResource {
    pub grant_id: String,
    pub resource: ResourceHandle,
    pub domain: StateOperationDomain,
    pub operation: StateOperationKind,
    pub policy_id: String,
    pub lifetime_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCheck {
    pub request: RuntimeCheckRequest,
    pub owner: ResourceOwner,
    pub lifetime_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCompletion {
    pub binding: ExecutionFrameBinding,
    pub executed: bool,
}

/// This protocol must not be forwarded from model input or tool stdout.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum HostRequest {
    Ping,
    ExecutionFramePlan(ExecutionFramePlanRequest),
    ShellStateDelta(RuntimeShellStateDeltaRequest),
    RegisterResource(RegisterResource),
    GrantResource(GrantResource),
    RevokeResource(GrantHandle),
    RetireResource(ResourceHandle),
    BindResourceRoute(BindResourceRoute),
    UnbindResourceRoute(RouteHandle),
    Check(HostCheck),
    Authorize(ApprovalRequest),
    BeginExecution(ExecutionFrameBinding),
    CompleteExecution(ExecutionCompletion),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum HostResponse {
    Ping(RuntimePingResponse),
    ExecutionFramePlan(ExecutionFramePlan),
    ShellStateDelta(RuntimeShellStateDeltaResponse),
    RegisterResource(ResourceHandle),
    GrantResource(GrantHandle),
    RevokeResource(GrantHandle),
    RetireResource(ResourceHandle),
    BindResourceRoute(RouteHandle),
    UnbindResourceRoute(RouteHandle),
    Check(RuntimeCheckResponse),
    Authorize(ApprovalResponse),
    BeginExecution(ExecutionFrameBinding),
    CompleteExecution(ExecutionCompletion),
}

struct Registration {
    lease: ResourceRegistration,
    owner: ResourceOwner,
}
struct Grant {
    handle: GrantHandle,
    _lease: ResourceGrant,
}
struct Route {
    handle: RouteHandle,
    _lease: ResourceRouteRegistration,
}
#[derive(Default)]
struct HostResources {
    registry: Arc<ManagedResourceRegistry>,
    registrations: BTreeMap<String, Registration>,
    grants: BTreeMap<String, Grant>,
    routes: BTreeMap<String, Route>,
    next_grant: u64,
}
impl HostResources {
    fn registration(&self, handle: &ResourceHandle) -> Result<&Registration, CliError> {
        self.registrations
            .get(&handle.resource_id)
            .filter(|r| ResourceHandle::from(r.lease.instance()) == *handle)
            .ok_or_else(|| invalid("resource handle is stale or unknown"))
    }
    fn manage(&mut self, request: HostRequest) -> Result<HostResponse, CliError> {
        match request {
            HostRequest::RegisterResource(request) => {
                let owner = request.resource.owner.clone();
                let lease = self
                    .registry
                    .register_scoped(
                        request.resource,
                        request.scope,
                        lifetime(request.lifetime_ms),
                    )
                    .map_err(invalid)?;
                let handle = ResourceHandle::from(lease.instance());
                self.registrations
                    .insert(handle.resource_id.clone(), Registration { lease, owner });
                Ok(HostResponse::RegisterResource(handle))
            }
            HostRequest::GrantResource(request) => {
                if request.policy_id.is_empty()
                    || request.policy_id.len() > 256
                    || request.policy_id.chars().any(char::is_control)
                {
                    return Err(invalid("grant requires a host policy identity"));
                }
                let registration = self.registration(&request.resource)?;
                let lease = self
                    .registry
                    .grant(
                        ResourcePermission {
                            grant_id: request.grant_id.clone(),
                            resource: registration.lease.instance().clone(),
                            owner: registration.owner.clone(),
                            domain: request.domain,
                            operation: request.operation,
                        },
                        lifetime(request.lifetime_ms),
                    )
                    .map_err(invalid)?;
                self.next_grant = self
                    .next_grant
                    .checked_add(1)
                    .ok_or_else(|| invalid("host grant serial exhausted"))?;
                let handle = GrantHandle {
                    grant_id: request.grant_id,
                    resource: request.resource,
                    serial: self.next_grant,
                    policy_id: request.policy_id,
                };
                self.grants.insert(
                    handle.grant_id.clone(),
                    Grant {
                        handle: handle.clone(),
                        _lease: lease,
                    },
                );
                Ok(HostResponse::GrantResource(handle))
            }
            HostRequest::RevokeResource(handle) => {
                if !self
                    .grants
                    .get(&handle.grant_id)
                    .is_some_and(|g| g.handle == handle)
                {
                    return Err(invalid("grant handle is stale or unknown"));
                }
                self.grants.remove(&handle.grant_id);
                Ok(HostResponse::RevokeResource(handle))
            }
            HostRequest::RetireResource(handle) => {
                self.registration(&handle)?;
                self.grants.retain(|_, g| g.handle.resource != handle);
                self.routes.retain(|_, r| r.handle.resource != handle);
                self.registrations.remove(&handle.resource_id);
                Ok(HostResponse::RetireResource(handle))
            }
            HostRequest::BindResourceRoute(request) => {
                let registration = self.registration(&request.resource)?;
                let lease = self
                    .registry
                    .bind_route(
                        ResourceRoute {
                            route_id: request.route_id,
                            resource: registration.lease.instance().clone(),
                            owner: registration.owner.clone(),
                            endpoint: request.endpoint,
                            target: request.target,
                        },
                        lifetime(request.lifetime_ms),
                    )
                    .map_err(invalid)?;
                let handle = RouteHandle {
                    route_id: lease.route_id().to_owned(),
                    resource: request.resource,
                    serial: lease.revision(),
                };
                self.routes.insert(
                    handle.route_id.clone(),
                    Route {
                        handle: handle.clone(),
                        _lease: lease,
                    },
                );
                Ok(HostResponse::BindResourceRoute(handle))
            }
            HostRequest::UnbindResourceRoute(handle) => {
                if !self
                    .routes
                    .get(&handle.route_id)
                    .is_some_and(|r| r.handle == handle)
                {
                    return Err(invalid("route handle is stale or unknown"));
                }
                self.routes.remove(&handle.route_id);
                Ok(HostResponse::UnbindResourceRoute(handle))
            }
            _ => Err(invalid("unexpected host management request")),
        }
    }
}

/// The owning executor creates resources, sends independent policy grants, and
/// executes only after BeginExecution acknowledges the exact checked binding.
/// It waits for completion, then retires routes before closing/replacing them.
/// EOF or a protocol error ends this authority; the host must stop owned work.
/// Neither this pipe nor its descriptors may be inherited by tool subprocesses.
pub fn serve_host_stdio(
    runtime: &mut CliRuntime,
    mut reader: impl BufRead,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    let mut resources = HostResources::default();
    runtime.set_resource_authority(resources.registry.clone());
    while let Some(request) = read_packet(&mut reader)? {
        let response = match request {
            HostRequest::Ping => {
                match runtime.handle_runtime_transport_request(RuntimeTransportRequest::Ping)? {
                    RuntimeTransportResponse::Ping(response) => HostResponse::Ping(response),
                    _ => unreachable!(),
                }
            }
            HostRequest::ExecutionFramePlan(request) => match runtime
                .handle_runtime_transport_request(RuntimeTransportRequest::ExecutionFramePlan(
                    request,
                ))? {
                RuntimeTransportResponse::ExecutionFramePlan(response) => {
                    HostResponse::ExecutionFramePlan(response)
                }
                _ => unreachable!(),
            },
            HostRequest::ShellStateDelta(request) => match runtime
                .handle_runtime_transport_request(RuntimeTransportRequest::ShellStateDelta(
                    request,
                ))? {
                RuntimeTransportResponse::ShellStateDelta(response) => {
                    HostResponse::ShellStateDelta(response)
                }
                _ => unreachable!(),
            },
            HostRequest::Check(request) => {
                check(runtime, &resources, request, &mut reader, writer)?;
                continue;
            }
            HostRequest::Authorize(_)
            | HostRequest::BeginExecution(_)
            | HostRequest::CompleteExecution(_) => {
                return Err(invalid("no pending host execution"));
            }
            request => resources.manage(request)?,
        };
        write_packet(writer, &response)?;
    }
    Ok(())
}

fn check(
    runtime: &mut CliRuntime,
    resources: &HostResources,
    request: HostCheck,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    let frame = request
        .request
        .shell_state_before
        .execution_frame
        .as_ref()
        .ok_or_else(|| invalid("host check requires an execution frame"))?;
    let binding = frame.binding.clone();
    let RuntimeTransportResponse::ExecutionFramePlan(plan) = runtime
        .handle_runtime_transport_request(RuntimeTransportRequest::ExecutionFramePlan(
            ExecutionFramePlanRequest {
                request: request.request.clone(),
                executor_instance_id: binding.executor_instance_id.clone(),
            },
        ))?
    else {
        unreachable!()
    };
    if plan.binding != binding {
        return Err(invalid("host frame does not match the current check plan"));
    }
    let _admission = resources
        .registry
        .admit_check(
            binding.clone(),
            request.owner,
            lifetime(request.lifetime_ms),
        )
        .map_err(invalid)?;
    let snapshot = resources.registry.snapshot(&binding).map_err(invalid)?;
    resources.registry.with_current_snapshot(&snapshot, &binding, || {
        let intent = request.request.intent;
        let RuntimeTransportResponse::Check(response) =
            runtime.handle_runtime_transport_request(RuntimeTransportRequest::Check(request.request))?
        else { unreachable!() };
        let accepted = response.decision_trace.evidence.iter().any(|e| {
            matches!(&e.kind, EvidenceKind::ExecutionFrame(frame) if frame.accepted && frame.binding == binding)
        });
        if !accepted {
            return Err(invalid("runtime rejected the host execution frame"));
        }
        let decision = response.decision;
        let receipt = response.check_receipt.clone();
        write_packet(writer, &HostResponse::Check(response))?;
        if intent == CheckIntent::JudgeOnly {
            return Ok(());
        }
        let mut authorized = decision == Decision::Allow;
        let mut resolved = false;
        let mut started = false;
        loop {
            let request = read_packet(reader)?.ok_or_else(|| invalid("host disconnected before execution completion"))?;
            match request {
                HostRequest::Authorize(request) => {
                    let matching = receipt.as_ref().is_some_and(|receipt|
                        receipt.check_id == request.check_id && receipt.state_revision == request.state_revision);
                    if decision != Decision::NeedApproval || started || resolved || !matching {
                        return Err(invalid("approval does not match the pending host check"));
                    }
                    let RuntimeTransportResponse::Authorize(response) = runtime.handle_runtime_transport_request(RuntimeTransportRequest::Authorize(request))?
                    else { unreachable!() };
                    authorized = response.approved;
                    resolved = true;
                    write_packet(writer, &HostResponse::Authorize(response))?;
                }
                HostRequest::BeginExecution(expected) => {
                    if expected != binding || started || !authorized || !resources.registry.is_current(&snapshot) {
                        return Err(invalid("execution is denied, stale, or bound to another check"));
                    }
                    started = true;
                    write_packet(writer, &HostResponse::BeginExecution(binding.clone()))?;
                }
                HostRequest::CompleteExecution(completion) => {
                    if completion.binding != binding || completion.executed != started {
                        return Err(invalid("completion does not match the host execution"));
                    }
                    write_packet(writer, &HostResponse::CompleteExecution(completion))?;
                    return Ok(());
                }
                _ => return Err(invalid("complete the pending execution before changing host resources")),
            }
        }
    }).map_err(invalid)?
}

fn lifetime(ms: u64) -> Duration {
    Duration::from_millis(ms)
}
fn invalid(message: impl Into<String>) -> CliError {
    CliError::InvalidArguments(message.into())
}
fn read_packet(reader: &mut impl BufRead) -> Result<Option<HostRequest>, CliError> {
    let mut bytes = Vec::new();
    let n = reader
        .take(MAX_PACKET_BYTES + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(CliError::Io)?;
    if n == 0 {
        return Ok(None);
    }
    if n as u64 > MAX_PACKET_BYTES || bytes.last() != Some(&b'\n') {
        return Err(invalid("host packet exceeds its bound or is incomplete"));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| invalid(format!("invalid host packet: {e}")))
}
fn write_packet(writer: &mut impl Write, response: &HostResponse) -> Result<(), CliError> {
    serde_json::to_writer(&mut *writer, response).map_err(CliError::InvalidResponse)?;
    writer.write_all(b"\n").map_err(CliError::Io)?;
    writer.flush().map_err(CliError::Io)
}
