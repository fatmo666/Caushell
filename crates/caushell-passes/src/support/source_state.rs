use caushell_parse::{CommandFact, ParsedCommandArtifact};
use caushell_profile::{
    BoundValue, EffectKind, EffectTarget, ResolvedInvocationArtifact, SessionBindings,
};
use caushell_query::QuerySession;
use caushell_types::CheckRequest;

#[derive(Clone)]
pub(super) struct SourceStateScope {
    parsed: ParsedCommandArtifact,
    before: usize,
    observations: Vec<(
        caushell_profile::ResolveInvocationArtifactResult,
        SessionBindings,
    )>,
    cwds: Vec<caushell_runner::EffectiveCwd>,
}

impl SourceStateScope {
    pub(super) fn new(
        parsed: &ParsedCommandArtifact,
        command: &CommandFact,
        request: &CheckRequest,
        entry_cwd: &caushell_runner::EffectiveCwd,
        observations: &[(
            caushell_profile::ResolveInvocationArtifactResult,
            SessionBindings,
        )],
    ) -> Option<Self> {
        let before = parsed
            .commands
            .iter()
            .position(|c| c.span == command.span)?;
        let cwds =
            crate::passes::source_scope_execution_cwds(parsed, request, entry_cwd, observations).1;
        Some(Self {
            parsed: parsed.clone(),
            before,
            observations: observations.to_vec(),
            cwds,
        })
    }

    pub(super) fn cwd(&self) -> caushell_runner::EffectiveCwd {
        self.cwds
            .get(self.before)
            .cloned()
            .unwrap_or(caushell_runner::EffectiveCwd::Unknown)
    }
}

pub(super) fn body(
    session: QuerySession<'_>,
    registry: &caushell_profile::ProfileRegistry,
    request: &CheckRequest,
    resolved: &ResolvedInvocationArtifact,
    bindings: &SessionBindings,
    scope: &SourceStateScope,
    ancestors: &[SourceStateScope],
) -> Option<String> {
    let parsed = &scope.parsed;
    let index = scope.before;
    let slots: Vec<_> = resolved
        .bound
        .effects
        .iter()
        .filter_map(|e| match (&e.kind, &e.target) {
            (EffectKind::SourceScriptIntoCurrentShell, EffectTarget::Slot(slot)) => Some(slot),
            _ => None,
        })
        .collect();
    if slots.len() != 1 || resolved.bound.operation_semantics_unresolved {
        return None;
    }
    let parameter = resolved
        .bound
        .bound_parameters
        .iter()
        .find(|p| &p.name == slots[0])?;
    let [
        BoundValue::Argument {
            text,
            quoted,
            node_kind,
            materialization,
            ..
        },
    ] = parameter.values.as_slice()
    else {
        return None;
    };
    let cwd = match scope.cwds.get(index)? {
        caushell_runner::EffectiveCwd::Known(path) => path.as_str(),
        _ => return None,
    };
    let home = bindings.tilde_home_with_default(request.home.as_deref());
    if node_kind == "process_substitution" {
        return super::process_substitution_evidence(
            session,
            text,
            parsed.shell_kind,
            request.sequence_no,
            bindings,
            cwd,
            true,
            home,
            8,
        )
        .complete_text();
    }
    let kind = if matches!(
        materialization,
        caushell_profile::BoundArgumentMaterialization::Literal
    ) {
        node_kind.as_str()
    } else {
        "raw_string"
    };
    let path = crate::path::resolve_path_operand(text, *quoted, kind, cwd, home)?;
    if path == "/dev/null" || caushell_query::IoTargetQuery::descriptor_alias(&path).is_some() {
        let io = super::content_io_target(
            parsed,
            Some(index),
            None,
            &caushell_types::PathResolution::Concrete { path },
            false,
            cwd,
            home,
            Some(bindings),
        );
        return super::static_io_target_evidence(
            session,
            parsed,
            index,
            &io,
            request.sequence_no,
            bindings,
            bindings,
            cwd,
            home,
            8,
        )
        .complete_text();
    }
    let mut content = None;
    for scope in ancestors.iter().chain(std::iter::once(scope)) {
        content = Some(super::static_file_content_before_scoped_command(
            session,
            registry,
            request,
            &scope.parsed,
            scope.before,
            &path,
            &scope.observations,
            &scope.cwds,
            content,
        ));
    }
    match content? {
        super::StaticFileContent::Known(text) => Some(text),
        _ => None,
    }
}
