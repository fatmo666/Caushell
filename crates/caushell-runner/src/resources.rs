use caushell_query::{
    canonical_resource_endpoint, canonical_resource_named_endpoint,
    canonical_resource_named_origin, canonical_resource_origin,
};
use caushell_types::{
    ExecutionFrameBinding, SessionId, StateOperation, StateOperationDomain, StateOperationKind,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

const MAX_RECORDS: usize = 128;
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceOwner {
    pub session_id: SessionId,
    pub runtime_name: String,
    pub executor_instance_id: String,
    pub namespace_id: String,
}

impl ResourceOwner {
    fn matches(&self, binding: &ExecutionFrameBinding) -> bool {
        self.session_id == binding.session_id
            && self.runtime_name == binding.runtime_name
            && self.executor_instance_id == binding.executor_instance_id
    }
    fn valid(&self) -> bool {
        [
            &self.session_id.0,
            &self.runtime_name,
            &self.executor_instance_id,
            &self.namespace_id,
        ]
        .iter()
        .all(|s| identifier(s))
    }
}

/// Registration asserts identity and a manager-maintained route, not permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedResource {
    pub resource_id: String,
    pub instance_id: String,
    pub owner: ResourceOwner,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceLocatorScope {
    ExactEndpoint,
    HttpOrigin,
}

impl ResourceLocatorScope {
    fn contains(self, registered: &str, endpoint: &str) -> bool {
        match self {
            Self::ExactEndpoint => registered == endpoint,
            Self::HttpOrigin => canonical_resource_origin(endpoint).as_deref() == Some(registered),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResourceInstanceRef {
    authority: Arc<()>,
    pub resource_id: String,
    pub instance_id: String,
    pub generation: u64,
    pub namespace_id: String,
}

impl PartialEq for ResourceInstanceRef {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.authority, &other.authority)
            && self.resource_id == other.resource_id
            && self.instance_id == other.instance_id
            && self.generation == other.generation
            && self.namespace_id == other.namespace_id
    }
}
impl Eq for ResourceInstanceRef {}

/// Host policy; neither a Profile declaration nor a check request can mint it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePermission {
    pub grant_id: String,
    pub resource: ResourceInstanceRef,
    pub owner: ResourceOwner,
    pub domain: StateOperationDomain,
    pub operation: StateOperationKind,
}

/// The owning host pins this name-to-instance route through execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRoute {
    pub route_id: String,
    pub resource: ResourceInstanceRef,
    pub owner: ResourceOwner,
    pub endpoint: String,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct ResourceResolution {
    pub instance: ResourceInstanceRef,
    pub endpoint: String,
    pub route_id: Option<String>,
}

#[derive(Debug, Clone)]
struct Instance {
    fact: ManagedResource,
    scope: ResourceLocatorScope,
    generation: u64,
    expires: Instant,
}
#[derive(Debug, Clone)]
struct Grant {
    permission: ResourcePermission,
    expires: Instant,
    revision: u64,
}
#[derive(Debug, Clone)]
struct Route {
    fact: ResourceRoute,
    scope: ResourceLocatorScope,
    expires: Instant,
    revision: u64,
}
#[derive(Debug, Clone)]
struct AdmittedCheck {
    binding: ExecutionFrameBinding,
    owner: ResourceOwner,
    expires: Instant,
}
#[derive(Debug, Default)]
struct Registry {
    identity: Arc<()>,
    revision: u64,
    exhausted: bool,
    instances: BTreeMap<String, Instance>,
    grants: BTreeMap<String, Grant>,
    routes: BTreeMap<String, Route>,
    checks: BTreeMap<u64, AdmittedCheck>,
}

#[derive(Clone, Default)]
pub struct ManagedResourceRegistry {
    inner: Arc<RwLock<Registry>>,
}

pub struct ResourceRegistration {
    registry: ManagedResourceRegistry,
    instance: ResourceInstanceRef,
}
pub struct ResourceGrant {
    registry: ManagedResourceRegistry,
    grant_id: String,
    revision: u64,
}
pub struct ResourceRouteRegistration {
    registry: ManagedResourceRegistry,
    route_id: String,
    revision: u64,
}
pub struct ResourceCheckAdmission {
    registry: ManagedResourceRegistry,
    id: u64,
}

#[derive(Debug, Clone)]
pub struct ResourceAuthoritySnapshot {
    identity: Arc<()>,
    authority: Arc<RwLock<Registry>>,
    binding: ExecutionFrameBinding,
    revision: u64,
    instances: Vec<Instance>,
    grants: Vec<Grant>,
    routes: Vec<Route>,
    expires: Instant,
}

impl PartialEq for ResourceAuthoritySnapshot {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.authority, &other.authority)
            && self.binding == other.binding
            && self.revision == other.revision
            && self.expires == other.expires
    }
}
impl Eq for ResourceAuthoritySnapshot {}

/// Installed by the owning host, independently of the tool-facing protocol.
pub trait ResourceAuthority: Send + Sync {
    fn snapshot(
        &self,
        binding: &ExecutionFrameBinding,
    ) -> Result<ResourceAuthoritySnapshot, String>;
    fn is_current(&self, snapshot: &ResourceAuthoritySnapshot) -> bool;
}

impl ManagedResourceRegistry {
    /// The host admits the exact execution frame on its control channel.
    /// Matching self-reported IDs on a tool request is insufficient.
    pub fn admit_check(
        &self,
        binding: ExecutionFrameBinding,
        owner: ResourceOwner,
        lifetime: Duration,
    ) -> Result<ResourceCheckAdmission, String> {
        let expires = expiry(lifetime)?;
        if !owner.valid()
            || !owner.matches(&binding)
            || binding.protocol != 1
            || binding.command_sha256.len() != 64
            || !binding
                .command_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || !binding.cwd.starts_with('/')
            || binding.cwd.len() > 4096
            || binding.cwd.contains('\0')
        {
            return Err("invalid host execution-frame admission".into());
        }
        let mut state = self
            .inner
            .write()
            .map_err(|_| "resource registry unavailable")?;
        if state.checks.len() >= MAX_RECORDS
            || state.checks.values().any(|check| check.binding == binding)
        {
            return Err("execution frame already admitted or registry full".into());
        }
        let id = next_revision(&mut state)?;
        state.checks.insert(
            id,
            AdmittedCheck {
                binding,
                owner,
                expires,
            },
        );
        Ok(ResourceCheckAdmission {
            registry: self.clone(),
            id,
        })
    }

    pub fn register(
        &self,
        fact: ManagedResource,
        lifetime: Duration,
    ) -> Result<ResourceRegistration, String> {
        self.register_scoped(fact, ResourceLocatorScope::ExactEndpoint, lifetime)
    }

    /// Origin scope is an explicit host contract for the entire owned service.
    /// Origin registrations must name its root, never an inferred path prefix.
    pub fn register_scoped(
        &self,
        mut fact: ManagedResource,
        scope: ResourceLocatorScope,
        lifetime: Duration,
    ) -> Result<ResourceRegistration, String> {
        let expires = expiry(lifetime)?;
        if !identifier(&fact.resource_id)
            || !identifier(&fact.instance_id)
            || !fact.owner.valid()
            || fact.endpoints.is_empty()
            || fact.endpoints.len() > 32
        {
            return Err("invalid managed resource identity or endpoint count".into());
        }
        fact.endpoints = fact
            .endpoints
            .iter()
            .map(|s| {
                canonical_resource_endpoint(s).ok_or_else(|| {
                    "resource endpoint requires an exact numeric HTTP(S) locator".to_owned()
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        fact.endpoints.sort();
        fact.endpoints.dedup();
        if scope == ResourceLocatorScope::HttpOrigin
            && fact
                .endpoints
                .iter()
                .any(|e| canonical_resource_origin(e).as_ref() != Some(e))
        {
            return Err("HTTP origin registration requires a numeric root locator".into());
        }
        let mut state = self
            .inner
            .write()
            .map_err(|_| "resource registry unavailable")?;
        if state.instances.len() >= MAX_RECORDS || state.instances.contains_key(&fact.resource_id) {
            return Err("resource already registered or registry full".into());
        }
        if state.instances.values().any(|i| {
            i.fact.owner == fact.owner
                && i.fact.endpoints.iter().any(|a| {
                    fact.endpoints
                        .iter()
                        .any(|b| i.scope.contains(a, b) || scope.contains(b, a))
                })
        }) {
            return Err("resource endpoint has a conflicting instance".into());
        }
        if state.instances.values().any(|i| {
            i.fact.owner.session_id == fact.owner.session_id
                && i.fact.owner.runtime_name == fact.owner.runtime_name
                && i.fact.owner.executor_instance_id == fact.owner.executor_instance_id
                && i.fact.owner.namespace_id != fact.owner.namespace_id
        }) {
            return Err(
                "executor resource namespace changed without retiring its instances".into(),
            );
        }
        let generation = next_revision(&mut state)?;
        let instance = ResourceInstanceRef {
            authority: state.identity.clone(),
            resource_id: fact.resource_id.clone(),
            instance_id: fact.instance_id.clone(),
            generation,
            namespace_id: fact.owner.namespace_id.clone(),
        };
        state.instances.insert(
            fact.resource_id.clone(),
            Instance {
                fact,
                scope,
                generation,
                expires,
            },
        );
        Ok(ResourceRegistration {
            registry: self.clone(),
            instance,
        })
    }

    pub fn grant(
        &self,
        permission: ResourcePermission,
        lifetime: Duration,
    ) -> Result<ResourceGrant, String> {
        let expires = expiry(lifetime)?;
        if !identifier(&permission.grant_id)
            || !permission.owner.valid()
            || permission.domain != StateOperationDomain::RemoteResource
            || !matches!(
                permission.operation,
                StateOperationKind::Mutate | StateOperationKind::Control
            )
        {
            return Err("invalid resource permission".into());
        }
        let mut state = self
            .inner
            .write()
            .map_err(|_| "resource registry unavailable")?;
        if !Arc::ptr_eq(&state.identity, &permission.resource.authority) {
            return Err("grant belongs to another resource authority".into());
        }
        if state.grants.len() >= MAX_RECORDS || state.grants.contains_key(&permission.grant_id) {
            return Err("grant already registered or registry full".into());
        }
        let instance = state
            .instances
            .get(&permission.resource.resource_id)
            .filter(|i| {
                same_instance(i, &permission.resource)
                    && i.fact.owner == permission.owner
                    && i.expires > Instant::now()
            })
            .ok_or("grant does not name a live owned resource instance")?;
        let expires = expires.min(instance.expires);
        let revision = next_revision(&mut state)?;
        state.grants.insert(
            permission.grant_id.clone(),
            Grant {
                permission: permission.clone(),
                expires,
                revision,
            },
        );
        Ok(ResourceGrant {
            registry: self.clone(),
            grant_id: permission.grant_id,
            revision,
        })
    }

    pub fn bind_route(
        &self,
        mut fact: ResourceRoute,
        lifetime: Duration,
    ) -> Result<ResourceRouteRegistration, String> {
        let expires = expiry(lifetime)?;
        if !identifier(&fact.route_id) || !fact.owner.valid() {
            return Err("invalid resource route identity".into());
        }
        fact.endpoint = canonical_resource_named_endpoint(&fact.endpoint)
            .ok_or("resource route requires an exact named HTTP(S) locator")?;
        fact.target = canonical_resource_endpoint(&fact.target)
            .ok_or("resource route target requires an exact numeric HTTP(S) locator")?;
        if route_shape(&fact.endpoint) != route_shape(&fact.target) {
            return Err("resource routes must preserve scheme, port and path".into());
        }
        let mut state = self
            .inner
            .write()
            .map_err(|_| "resource registry unavailable")?;
        if !Arc::ptr_eq(&state.identity, &fact.resource.authority) {
            return Err("route belongs to another resource authority".into());
        }
        if state.routes.len() >= MAX_RECORDS || state.routes.contains_key(&fact.route_id) {
            return Err("resource route already registered or registry full".into());
        }
        let instance = state
            .instances
            .get(&fact.resource.resource_id)
            .filter(|i| {
                same_instance(i, &fact.resource)
                    && i.fact.owner == fact.owner
                    && i.expires > Instant::now()
            })
            .ok_or("route does not name a live owned resource instance")?;
        if !instance
            .fact
            .endpoints
            .iter()
            .any(|e| instance.scope.contains(e, &fact.target))
            || instance.scope == ResourceLocatorScope::HttpOrigin
                && canonical_resource_named_origin(&fact.endpoint).as_ref() != Some(&fact.endpoint)
        {
            return Err("resource route exceeds the registered locator scope".into());
        }
        let scope = instance.scope;
        let expires = expires.min(instance.expires);
        if state.routes.values().any(|route| {
            route.fact.owner == fact.owner
                && (canonical_resource_named_origin(&route.fact.endpoint)
                    == canonical_resource_named_origin(&fact.endpoint)
                    && canonical_resource_origin(&route.fact.target)
                        != canonical_resource_origin(&fact.target)
                    || named_contains(route.scope, &route.fact.endpoint, &fact.endpoint)
                    || named_contains(scope, &fact.endpoint, &route.fact.endpoint))
        }) {
            return Err("resource name has a conflicting route".into());
        }
        let revision = next_revision(&mut state)?;
        let route_id = fact.route_id.clone();
        state.routes.insert(
            route_id.clone(),
            Route {
                fact,
                scope,
                expires,
                revision,
            },
        );
        Ok(ResourceRouteRegistration {
            registry: self.clone(),
            route_id,
            revision,
        })
    }

    /// The host keeps resource routes alive through execution, not just spawn.
    /// The callback must execute only the already checked request and wait for it.
    pub fn with_current_snapshot<T>(
        &self,
        snapshot: &ResourceAuthoritySnapshot,
        binding: &ExecutionFrameBinding,
        action: impl FnOnce() -> T,
    ) -> Result<T, String> {
        let state = self
            .inner
            .read()
            .map_err(|_| "resource registry unavailable")?;
        if snapshot.binding != *binding
            || !Arc::ptr_eq(&self.inner, &snapshot.authority)
            || !current(&state, snapshot)
        {
            return Err("resource authority snapshot is stale or belongs to another check".into());
        }
        Ok(action())
    }
}

impl ResourceAuthority for ManagedResourceRegistry {
    fn snapshot(
        &self,
        binding: &ExecutionFrameBinding,
    ) -> Result<ResourceAuthoritySnapshot, String> {
        let state = self
            .inner
            .read()
            .map_err(|_| "resource registry unavailable")?;
        let now = Instant::now();
        let check = state
            .checks
            .values()
            .find(|check| check.binding == *binding && check.expires > now)
            .ok_or("execution frame has no live host admission")?;
        let instances: Vec<_> = state
            .instances
            .values()
            .filter(|i| i.fact.owner == check.owner && i.expires > now)
            .cloned()
            .collect();
        let grants: Vec<_> = state
            .grants
            .values()
            .filter(|g| g.permission.owner == check.owner && g.expires > now)
            .cloned()
            .collect();
        let routes: Vec<_> = state
            .routes
            .values()
            .filter(|r| r.fact.owner == check.owner && r.expires > now)
            .cloned()
            .collect();
        let expires = instances
            .iter()
            .map(|i| i.expires)
            .chain(grants.iter().map(|g| g.expires))
            .chain(routes.iter().map(|r| r.expires))
            .chain(std::iter::once(check.expires))
            .min()
            .unwrap_or(now);
        Ok(ResourceAuthoritySnapshot {
            identity: state.identity.clone(),
            authority: self.inner.clone(),
            binding: binding.clone(),
            revision: state.revision,
            instances,
            grants,
            routes,
            expires,
        })
    }
    fn is_current(&self, snapshot: &ResourceAuthoritySnapshot) -> bool {
        Arc::ptr_eq(&self.inner, &snapshot.authority)
            && self
                .inner
                .read()
                .is_ok_and(|state| current(&state, snapshot))
    }
}

impl ResourceAuthoritySnapshot {
    pub fn binding(&self) -> &ExecutionFrameBinding {
        &self.binding
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn resolve(&self, endpoint: &str) -> Option<ResourceInstanceRef> {
        self.resolve_target(endpoint)
            .map(|resolution| resolution.instance)
    }

    pub fn resolve_target(&self, endpoint: &str) -> Option<ResourceResolution> {
        let now = Instant::now();
        if self.expires <= now {
            return None;
        }
        let (endpoint, route) = if let Some(endpoint) = canonical_resource_endpoint(endpoint) {
            (endpoint, None)
        } else {
            let endpoint = canonical_resource_named_endpoint(endpoint)?;
            let route = self.routes.iter().find(|r| {
                r.expires > now
                    && r.fact.owner.matches(&self.binding)
                    && named_contains(r.scope, &r.fact.endpoint, &endpoint)
            })?;
            let translated = match route.scope {
                ResourceLocatorScope::ExactEndpoint => route.fact.target.clone(),
                ResourceLocatorScope::HttpOrigin => format!(
                    "{}{}",
                    route.fact.target,
                    endpoint.strip_prefix(&route.fact.endpoint)?
                ),
            };
            (translated, Some(route))
        };
        let instance = self.instances.iter().find(|i| {
            i.expires > now
                && i.fact.owner.matches(&self.binding)
                && i.fact
                    .endpoints
                    .iter()
                    .any(|e| i.scope.contains(e, &endpoint))
                && route.is_none_or(|r| same_instance(i, &r.fact.resource))
        })?;
        Some(ResourceResolution {
            instance: ResourceInstanceRef {
                authority: self.identity.clone(),
                resource_id: instance.fact.resource_id.clone(),
                instance_id: instance.fact.instance_id.clone(),
                generation: instance.generation,
                namespace_id: instance.fact.owner.namespace_id.clone(),
            },
            endpoint,
            route_id: route.map(|r| r.fact.route_id.clone()),
        })
    }

    pub fn permission(
        &self,
        reference: &ResourceInstanceRef,
        operation: StateOperation,
    ) -> Option<String> {
        let now = Instant::now();
        if self.expires <= now || !Arc::ptr_eq(&self.identity, &reference.authority) {
            return None;
        }
        let instance = self
            .instances
            .iter()
            .find(|i| same_instance(i, reference) && i.expires > now)?;
        let grant = self.grants.iter().find(|g| {
            g.expires > now
                && g.permission.resource == *reference
                && g.permission.owner == instance.fact.owner
                && g.permission.domain == operation.domain
                && g.permission.operation == operation.operation
        })?;
        Some(grant.permission.grant_id.clone())
    }
}

impl ResourceRegistration {
    pub fn instance(&self) -> &ResourceInstanceRef {
        &self.instance
    }
}
impl Drop for ResourceRegistration {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.inner.write() {
            if state
                .instances
                .get(&self.instance.resource_id)
                .is_some_and(|i| same_instance(i, &self.instance))
            {
                state.instances.remove(&self.instance.resource_id);
                state
                    .grants
                    .retain(|_, g| g.permission.resource != self.instance);
                state.routes.retain(|_, r| r.fact.resource != self.instance);
                let _ = next_revision(&mut state);
            }
        }
    }
}
impl Drop for ResourceGrant {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.inner.write() {
            // A handle cannot revoke a later grant after an ID has been reused.
            if state
                .grants
                .get(&self.grant_id)
                .is_some_and(|g| g.revision == self.revision)
            {
                state.grants.remove(&self.grant_id);
                let _ = next_revision(&mut state);
            }
        }
    }
}
impl ResourceRouteRegistration {
    pub fn route_id(&self) -> &str {
        &self.route_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
}
impl Drop for ResourceRouteRegistration {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.inner.write() {
            if state
                .routes
                .get(&self.route_id)
                .is_some_and(|r| r.revision == self.revision)
            {
                state.routes.remove(&self.route_id);
                let _ = next_revision(&mut state);
            }
        }
    }
}
impl Drop for ResourceCheckAdmission {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.inner.write() {
            if state.checks.remove(&self.id).is_some() {
                let _ = next_revision(&mut state);
            }
        }
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn route_shape(endpoint: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = endpoint.split_once("://")?;
    let (authority, path) = rest.split_once('/')?;
    let (_, port) = authority.rsplit_once(':')?;
    Some((scheme, port, path))
}
fn named_contains(scope: ResourceLocatorScope, registered: &str, endpoint: &str) -> bool {
    match scope {
        ResourceLocatorScope::ExactEndpoint => registered == endpoint,
        ResourceLocatorScope::HttpOrigin => {
            canonical_resource_named_origin(endpoint).as_deref() == Some(registered)
        }
    }
}
fn expiry(lifetime: Duration) -> Result<Instant, String> {
    if lifetime.is_zero() || lifetime > MAX_LIFETIME {
        return Err("resource lifetime must be within one hour".into());
    }
    Instant::now()
        .checked_add(lifetime)
        .ok_or_else(|| "resource lifetime overflow".into())
}
fn same_instance(instance: &Instance, reference: &ResourceInstanceRef) -> bool {
    instance.fact.resource_id == reference.resource_id
        && instance.fact.instance_id == reference.instance_id
        && instance.generation == reference.generation
        && instance.fact.owner.namespace_id == reference.namespace_id
}
fn next_revision(state: &mut Registry) -> Result<u64, String> {
    if state.exhausted {
        return Err("resource revision exhausted".into());
    }
    let Some(next) = state.revision.checked_add(1) else {
        state.exhausted = true;
        return Err("resource revision exhausted".into());
    };
    state.revision = next;
    Ok(state.revision)
}
fn current(state: &Registry, snapshot: &ResourceAuthoritySnapshot) -> bool {
    !state.exhausted && state.revision == snapshot.revision && snapshot.expires > Instant::now()
}
