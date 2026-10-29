//! Request-scoped admission supplied on the private executor control boundary.
use crate::{FilesystemView, runtime_file_matches};
use caushell_types::*;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleContractScope {
    binding: ExecutionFrameBinding,
    namespace_id: String,
    identities: Vec<ModuleIdentityFact>,
    permissions: Vec<ModuleContractPermission>,
    expires: Instant,
}

impl ModuleContractScope {
    pub fn new(
        binding: ExecutionFrameBinding,
        namespace_id: String,
        identities: Vec<ModuleIdentityFact>,
        permissions: Vec<ModuleContractPermission>,
        lifetime: Duration,
    ) -> Result<Self, String> {
        if identities.len() > 32
            || permissions.len() > 32
            || namespace_id.is_empty()
            || namespace_id.len() > 256
            || lifetime.is_zero()
            || lifetime > Duration::from_secs(3600)
        {
            return Err("module admission exceeds its bounds".into());
        }
        if identities.iter().map(|f| f.files.len()).sum::<usize>() > 256
            || identities.iter().map(|f| f.namespace.len()).sum::<usize>() > 4096
            || identities
                .iter()
                .map(|f| f.directories.len())
                .sum::<usize>()
                > 64
            || identities
                .iter()
                .flat_map(|f| f.files.values())
                .map(|f| f.size as u128)
                .sum::<u128>()
                > 134_217_728
        {
            return Err("module closure observation budget exceeded".into());
        }
        for f in &identities {
            if f.invocation.binding != binding || f.namespace_id != namespace_id || !hex(&f.loading_contract_sha256)
                || f.invocation.node_id.is_empty() || f.invocation.node_id.len() > 4096
                || f.invocation.runtime.is_empty() || f.invocation.runtime.len() > 128
                || f.invocation.module.is_empty() || f.invocation.module.len() > 256
                || f.invocation.command.len() > 65536 || !crate::directory_path_is_resolved(&f.invocation.cwd)
                || f.files.is_empty() || f.files.len() > 128 || f.namespace.is_empty() || f.namespace.len() > 4096
                || f.directories.len() > 64 || f.environment.len() > 128
                || !f.files.contains_key(&f.executable) || !f.files.contains_key(&f.module_file)
                || f.files.iter().any(|(p, v)| !crate::directory_path_is_resolved(p) || !hex(&v.sha256) || v.size > crate::MAX_RUNTIME_FILE_BYTES as u64)
                || f.environment.iter().any(|(k,v)| k.is_empty() || k.len()>256 || k.contains('\0') || matches!(v,ShellEnvironmentValue::Unknown) || matches!(v,ShellEnvironmentValue::Present{value} if value.len()>65536 || value.contains('\0')))
            { return Err("invalid or incompletely bound module identity".into()); }
        }
        if identities
            .iter()
            .enumerate()
            .any(|(i, f)| identities[..i].iter().any(|p| p.invocation == f.invocation))
        {
            return Err("ambiguous module identity".into());
        }
        for p in &permissions {
            if p.namespace_id != namespace_id
                || p.grant_id.is_empty()
                || p.grant_id.len() > 256
                || !hex(&p.identity_sha256)
                || !hex(&p.loading_contract_sha256)
            {
                return Err("invalid module contract permission".into());
            }
        }
        Ok(Self {
            binding,
            namespace_id,
            identities,
            permissions,
            expires: Instant::now() + lifetime,
        })
    }

    pub fn matches(&self, binding: &ExecutionFrameBinding) -> bool {
        self.expires > Instant::now() && self.binding == *binding
    }
    pub fn identity(&self, invocation: &ModuleInvocation) -> Option<&ModuleIdentityFact> {
        self.matches(&invocation.binding).then_some(())?;
        self.identities
            .iter()
            .find(|f| f.invocation == *invocation && f.namespace_id == self.namespace_id)
    }
    pub fn verify(
        &self,
        invocation: &ModuleInvocation,
        view: &dyn FilesystemView,
    ) -> ModuleContractEvidence {
        let mut evidence = ModuleContractEvidence {
            invocation: invocation.clone(),
            identity_sha256: None,
            identity_verified: false,
            grant_id: None,
            gap: Some("no current host module identity".into()),
        };
        let Some(f) = self.identity(invocation) else {
            return evidence;
        };
        let digest = f.sha256();
        evidence.identity_sha256 = Some(digest.clone());
        if !fresh(f, view) {
            evidence.gap = Some(
                "module files, search namespace or directory observations are stale or incomplete"
                    .into(),
            );
            return evidence;
        }
        evidence.identity_verified = true;
        evidence.grant_id = self
            .permissions
            .iter()
            .find(|p| {
                p.identity_sha256 == digest
                    && p.namespace_id == self.namespace_id
                    && p.loading_contract_sha256 == f.loading_contract_sha256
            })
            .map(|p| p.grant_id.clone());
        evidence.gap = evidence
            .grant_id
            .is_none()
            .then(|| "module identity has no corresponding host CLI permission".into());
        evidence
    }
    pub fn all_fresh(&self, view: &dyn FilesystemView) -> bool {
        self.expires > Instant::now() && self.identities.iter().all(|f| fresh(f, view))
    }
}

fn fresh(f: &ModuleIdentityFact, view: &dyn FilesystemView) -> bool {
    if view.source() == FilesystemObservationSource::Unavailable {
        return false;
    }
    for o in &f.namespace {
        if o.source != view.source()
            || !crate::directory_path_is_resolved(&o.path)
            || matches!(o.entry, FilesystemEntry::Unavailable { .. })
            || view.entry(&o.path) != o.entry
        {
            return false;
        }
    }
    for o in &f.directories {
        if o.source != view.source()
            || o.status != DirectoryReadStatus::Complete
            || !o.limits.is_valid()
        {
            return false;
        }
        let current = view.read_directory(&o.path, o.limits);
        if current.complete_entries(&o.path, o.limits).is_none() || current.observation != *o {
            return false;
        }
    }
    for (path, expected) in &f.files {
        let o = view.runtime_file(path);
        if !matches!(
            (view.source(), o.content.source),
            (
                FilesystemObservationSource::CurrentProcess,
                FileContentSource::CurrentProcess
            ) | (
                FilesystemObservationSource::SuppliedView,
                FileContentSource::SuppliedView
            )
        ) || !runtime_file_matches(&o, path, expected)
            || (path == &f.executable && o.executable != Some(true))
        {
            return false;
        }
    }
    true
}
fn hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}
