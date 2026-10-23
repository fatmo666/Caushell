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
    path_content(session, registry, request, &path, scope, ancestors)
}

fn path_content(
    session: QuerySession<'_>,
    registry: &caushell_profile::ProfileRegistry,
    request: &CheckRequest,
    path: &str,
    scope: &SourceStateScope,
    ancestors: &[SourceStateScope],
) -> Option<String> {
    let mut content = None;
    for scope in ancestors.iter().chain(std::iter::once(scope)) {
        content = Some(super::static_file_content_before_scoped_command(
            session,
            registry,
            request,
            &scope.parsed,
            scope.before,
            path,
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

pub(super) fn read_input(
    session: QuerySession<'_>,
    registry: &caushell_profile::ProfileRegistry,
    request: &CheckRequest,
    bindings: &SessionBindings,
    scope: &SourceStateScope,
    ancestors: &[SourceStateScope],
) -> Option<String> {
    let parsed = &scope.parsed;
    let index = scope.before;
    let super::EffectiveStdinSource::Redirect(redirect) =
        super::effective_stdin_source(parsed, index)
    else {
        return None;
    };
    let redirect = parsed.redirections.get(redirect)?;
    if redirect.parent_command_span.as_ref() != Some(&parsed.commands.get(index)?.span) {
        return None; // A shared stream may already have been consumed.
    }
    let cwd = scope.cwd();
    let caushell_runner::EffectiveCwd::Known(cwd) = cwd else {
        return None;
    };
    let home = bindings.tilde_home_with_default(request.home.as_deref());
    if redirect.kind == caushell_parse::RedirectionKind::HereString {
        let content = redirect.content.as_ref()?;
        if !content.quoted && content.text.starts_with('~') {
            return None;
        }
        let value = caushell_profile::materialize_shell_assignment_value(
            &content.text,
            content.quoted,
            &content.node_kind,
            bindings,
        )?;
        if value.contains('\0') || value.len() > 65535 {
            return None;
        }
        return Some(format!("{value}\n"));
    }
    if redirect.kind == caushell_parse::RedirectionKind::HereDoc
        && !redirect.heredoc_start.as_ref().is_some_and(|s| s.quoted)
        && redirect
            .content
            .as_ref()
            .is_some_and(|c| c.text.contains(['$', '`']))
    {
        return None;
    }
    if redirect.kind == caushell_parse::RedirectionKind::File
        && redirect
            .target
            .as_ref()
            .is_some_and(|t| t.node_kind != "process_substitution")
    {
        if redirect.operator.as_deref() != Some("<") {
            return None;
        }
        let target = redirect.target.as_ref()?;
        if !target.quoted
            && (target.text.contains(['*', '?', '[', '{'])
                || caushell_parse::decode_static_shell_argument(
                    &target.text,
                    false,
                    &target.node_kind,
                )
                .is_none())
        {
            return None;
        }
        let text = caushell_profile::materialize_shell_assignment_value(
            &target.text,
            target.quoted,
            &target.node_kind,
            bindings,
        )?;
        if text.contains('\0') {
            return None;
        }
        let path =
            crate::path::resolve_path_operand(&text, true, "raw_string", cwd.as_str(), home)?;
        if caushell_query::IoTargetQuery::descriptor_alias(&path).is_some() {
            return None;
        }
        return if path == "/dev/null" {
            Some(String::new())
        } else {
            path_content(session, registry, request, &path, scope, ancestors)
        };
    }
    super::static_stdin_evidence_for_scoped_command(
        session,
        parsed,
        index,
        request.sequence_no,
        bindings,
        bindings,
        cwd.as_str(),
        true,
        home,
        8,
    )
    .complete_text()
}
