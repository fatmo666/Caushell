use super::*;
use caushell_profile::{DispatchArgument, PythonEffect, PythonInput, PythonInputs};
use caushell_types::{EvidenceKind, PythonPayloadEvidence, PythonPayloadInputEvidence};

struct Inputs<'a, 's> {
    registry: &'a ProfileRegistry,
    session: SessionView<'s>,
    request: &'a CheckRequest,
    entry: &'a ExpandedFrontierEntry,
    context: &'a ProgramSourceContext,
    cwd: String,
    bindings: SessionBindings,
}
impl PythonInputs for Inputs<'_, '_> {
    fn environment(&mut self, name: &str) -> Result<Option<String>, String> {
        match self.bindings.environment_value(name) {
            caushell_profile::EnvironmentValueRef::Absent => Ok(None),
            caushell_profile::EnvironmentValueRef::Present(
                caushell_profile::SessionValue::ExactScalar(value),
            ) => Ok(Some(value.clone())),
            _ => Err(format!("Python environment {name} is not observed")),
        }
    }
    fn file(&mut self, path: &str) -> Result<Vec<u8>, String> {
        if path.contains('\0') {
            return Err("Python path contains NUL".into());
        }
        let path = crate::path::normalize_shell_path(&resolve_conventional_path(&self.cwd, path));
        let observations = source_scope_observations(
            self.registry,
            self.request,
            &self.entry.parsed_scope,
            program_command_index(self.entry),
            program_scope_bindings(self.entry),
        );
        let cwds = super::super::compute_effective_cwd::source_scope_execution_cwds(
            &self.entry.parsed_scope,
            self.request,
            &self.context.entry_cwd,
            &observations,
        )
        .1;
        match source_visible_file_content(
            self.registry,
            self.session,
            self.request,
            &self.entry.parsed_scope,
            program_command_index(self.entry),
            &path,
            &observations,
            &cwds,
            &self.context.source_scopes,
        ) {
            crate::support::StaticFileContent::Known(text) => Ok(text.into_bytes()),
            _ => Err(format!("Python file bytes are not known: {path}")),
        }
    }
}

pub(super) fn expand(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &mut ExpandedFrontierEntry,
    context: &ProgramSourceContext,
    ctx: &mut RunnerContext,
) -> Vec<ExpandedFrontierEntry> {
    let ResolveInvocationArtifactResult::Resolved(resolved) = &entry.result else {
        return Vec::new();
    };
    let resolved = resolved.clone();
    // This is a declared language boundary, not a launcher-name combination.
    let candidates = caushell_profile::collect_recursive_payload_candidates(&resolved.bound);
    if !candidates
        .iter()
        .any(|c| c.language == PayloadLanguage::Python)
    {
        return Vec::new();
    }
    let isolated = caushell_profile::python_isolated_startup(&resolved);
    let observations = source_scope_observations(
        registry,
        request,
        &entry.parsed_scope,
        program_command_index(entry),
        program_scope_bindings(entry),
    );
    let cwd = super::super::compute_effective_cwd::source_scope_execution_cwds(
        &entry.parsed_scope,
        request,
        &context.entry_cwd,
        &observations,
    )
    .1
    .get(program_command_index(entry))
    .and_then(|c| match c {
        caushell_runner::EffectiveCwd::Known(c) => Some(c.clone()),
        _ => None,
    });
    let mut proof = PythonPayloadEvidence {
        node_id: entry.source_node_id.0.clone(),
        source: None,
        cwd: cwd.clone(),
        complete: false,
        isolated_startup: isolated,
        imports: Vec::new(),
        inputs: Vec::new(),
        native_argv: Vec::new(),
        shell_commands: Vec::new(),
        stdout: Vec::new(),
        stdout_complete: false,
        gap: None,
    };
    let mut children = Vec::new();
    let outcome = (|| -> Result<(), String> {
        if resolved.bound.operation_semantics_unresolved || !resolved.bound.residuals.is_empty() {
            return Err("Python invocation is incomplete".into());
        }
        if entry.inherited_scope.static_input_cwd_unproven
            || entry.bindings.shell_state_uncertainty().is_some()
        {
            return Err("Python execution frame is incomplete".into());
        }
        let cwd = cwd.ok_or("Python execution cwd is unknown")?;
        let bindings = crate::support::command_environment_bindings(
            &entry.bindings,
            &entry.parsed_scope,
            &entry.command_ref,
        );
        let mut inputs = Inputs {
            registry,
            session,
            request,
            entry,
            context,
            cwd,
            bindings,
        };
        let candidate = candidates
            .iter()
            .find(|c| c.language == PayloadLanguage::Python)
            .unwrap();
        let source = match candidate.source {
            PayloadSource::InlineString => one_argument(&resolved.bound, "payload")?,
            PayloadSource::ScriptFileRef => {
                let path = one_argument(&resolved.bound, "script_path")?;
                let bytes = inputs.file(&path)?;
                proof.inputs.push(PythonPayloadInputEvidence::File {
                    path,
                    bytes: bytes.clone(),
                });
                String::from_utf8(bytes).map_err(|_| "Python script is not UTF-8")?
            }
            PayloadSource::Stdin => {
                let recovered = recursive_payload_candidates_for_scoped_command(
                    registry,
                    session,
                    request,
                    &entry.static_payload_scope.parsed_scope,
                    entry.static_payload_scope.command_index,
                    &resolved.bound,
                    &entry.static_payload_scope.bindings,
                    &entry.static_payload_scope.scope_base_bindings,
                    ctx.policy().semantic_expansion.max_nested_parse_depth,
                );
                recovered
                    .into_iter()
                    .find_map(|c| match (c.language, c.source, c.input) {
                        (
                            PayloadLanguage::Python,
                            PayloadSource::Stdin,
                            RecursivePayloadInput::LiteralText { text },
                        ) => Some(text),
                        _ => None,
                    })
                    .ok_or("Python stdin program is unknown")?
            }
            _ => return Err("unsupported Python source boundary".into()),
        };
        proof.source = Some(source.clone());
        if candidate.source != PayloadSource::InlineString
            && !caushell_profile::python_source_encoding_supported(&source)
        {
            return Err("Python source encoding is unsupported".into());
        }
        let mut argv = vec![match candidate.source {
            PayloadSource::InlineString => "-c".into(),
            PayloadSource::Stdin => "-".into(),
            _ => one_argument(&resolved.bound, "script_path")?,
        }];
        argv.extend(
            decoded_task_arguments(&resolved.bound, "script_args")
                .ok_or("Python argv is incomplete")?,
        );
        let analysis = caushell_profile::analyze_python(&source, &argv, &mut inputs);
        proof.imports = analysis.imports;
        proof
            .inputs
            .extend(analysis.inputs.into_iter().map(|input| match input {
                PythonInput::Environment { name, value } => {
                    PythonPayloadInputEvidence::Environment { name, value }
                }
                PythonInput::File { path, bytes } => {
                    PythonPayloadInputEvidence::File { path, bytes }
                }
            }));
        if let Some(gap) = analysis.gap {
            return Err(gap);
        }
        if !isolated {
            return Err(
                "Python startup and module resolution are not proven (-I -S contract required)"
                    .into(),
            );
        }
        proof.shell_commands = analysis
            .effects
            .iter()
            .filter_map(|e| match e {
                PythonEffect::ShellCommand(code) => Some(code.clone()),
                _ => None,
            })
            .collect();
        for (index, effect) in analysis.effects.iter().enumerate() {
            match effect {
                PythonEffect::NativeCommand(argv) => {
                    proof.native_argv.push(argv.clone());
                    children.push(native_child(
                        registry,
                        entry,
                        &inputs.bindings,
                        index,
                        argv,
                    )?);
                }
                PythonEffect::ShellCommand(code) => {
                    // POSIX subprocess uses this executable, independently of
                    // the caller's shell. Its Profile owns parsing and startup.
                    let argv = ["/bin/sh".into(), "-c".into(), code.clone()];
                    children.push(native_child(
                        registry,
                        entry,
                        &inputs.bindings,
                        index,
                        &argv,
                    )?);
                }
                _ => {}
            }
        }
        let services = analysis
            .effects
            .iter()
            .filter_map(|effect| match effect {
                PythonEffect::ListenNetwork { host, port } => Some((false, host.clone(), *port)),
                PythonEffect::RespondNetwork { host, port } => Some((true, host.clone(), *port)),
                _ => None,
            })
            .collect::<Vec<_>>();
        let reads = analysis
            .effects
            .into_iter()
            .filter_map(|effect| match effect {
                PythonEffect::ReadFile(path) => Some(path),
                _ => None,
            })
            .collect::<Vec<_>>();
        proof.stdout = analysis.stdout;
        proof.stdout_complete = analysis.stdout_complete;
        if !proof.stdout.is_ascii() {
            proof.stdout.clear();
            proof.stdout_complete = false;
        }
        let ResolveInvocationArtifactResult::Resolved(resolved) = &mut entry.result else {
            unreachable!()
        };
        if !reads.is_empty() {
            let mut parameter = BoundParameter::new(
                SlotName::new("python_reads"),
                SemanticType::Path(caushell_profile::PathSemantic {
                    role: PathRole::Read,
                    purpose: None,
                }),
            );
            for path in reads {
                parameter.values.push(
                    BoundValue::argument(
                        path,
                        true,
                        entry.command_ref.span.clone(),
                        ArgumentBindingSource::RemainingArg,
                    )
                    .with_materialization(
                        caushell_profile::BoundArgumentMaterialization::RuntimeData,
                    ),
                );
            }
            resolved.bound.bound_parameters.push(parameter);
            resolved
                .bound
                .effects
                .push(caushell_profile::Effect::new(EffectKind::ReadPath).for_slot("python_reads"));
        }
        for (index, (response, host, port)) in services.into_iter().enumerate() {
            if response {
                let slot = format!("python_response_{index}");
                let mut parameter = BoundParameter::new(
                    SlotName::new(&slot),
                    SemanticType::Endpoint(caushell_profile::EndpointSemantic {
                        kind: caushell_profile::EndpointKind::ListenerResponse,
                        usage: caushell_profile::EndpointUsage::UploadTarget,
                    }),
                );
                parameter.payload_generated = true;
                parameter.values.push(runtime_value(
                    &format!("{host}:{port}"),
                    entry.command_ref.span.clone(),
                ));
                resolved.bound.bound_parameters.push(parameter);
                let mut effect =
                    caushell_profile::Effect::new(EffectKind::NetworkEndpoint).for_slot(&slot);
                // A response can include any modeled read. Narrower byte-level
                // lineage must not be inferred from a request/response API.
                effect.input_scope = Some(caushell_profile::EndpointInputScope {
                    slots: vec!["python_reads".into()],
                    stdin: false,
                });
                resolved.bound.effects.push(effect);
            } else {
                let mut effect = caushell_profile::Effect::new(EffectKind::ListenNetwork);
                let scalar = |suffix: &str, value: String| caushell_profile::ConfiguredScalar {
                    slot: SlotName::new(format!("python_listener_{index}_{suffix}")),
                    environment: None,
                    default_value: Some(value),
                };
                effect.target =
                    EffectTarget::NetworkListener(caushell_profile::NetworkListenerTarget {
                        host: scalar("host", host),
                        port: Some(scalar("port", port.to_string())),
                        unix_socket: None,
                        inherited_fd: None,
                    });
                resolved.bound.effects.push(effect);
            }
        }
        Ok(())
    })();
    match outcome {
        Ok(()) => proof.complete = true,
        Err(gap) => {
            children.clear();
            proof.native_argv.clear();
            proof.stdout.clear();
            proof.gap = Some(gap.clone());
            if let ResolveInvocationArtifactResult::Resolved(resolved) = &mut entry.result {
                resolved.bound.operation_semantics_unresolved = true;
                resolved
                    .bound
                    .residuals
                    .push(caushell_profile::Residual::new(
                        caushell_profile::ResidualKind::UnboundPayload,
                        caushell_profile::ResidualSurface::Payload,
                        gap,
                    ));
            }
        }
    }
    ctx.add_evidence(Evidence {
        rule_id: caushell_types::RuleId::NestedPayloadExpansion,
        summary: if proof.complete {
            "Python program modeled".into()
        } else {
            format!(
                "Python analysis incomplete: {}",
                proof.gap.as_deref().unwrap_or("unknown")
            )
        },
        kind: EvidenceKind::PythonPayload(proof),
    });
    children
}

fn runtime_value(text: &str, span: caushell_parse::SourceSpan) -> BoundValue {
    BoundValue::argument(text, true, span, ArgumentBindingSource::RemainingArg)
        .with_materialization(caushell_profile::BoundArgumentMaterialization::RuntimeData)
}

fn one_argument(bound: &caushell_profile::BoundInvocation, slot: &str) -> Result<String, String> {
    let values = decoded_task_arguments(bound, slot)
        .ok_or_else(|| format!("Python {slot} is incomplete"))?;
    if values.len() != 1 {
        return Err(format!("Python {slot} requires one value"));
    }
    Ok(values[0].clone())
}

mod output;
pub(super) use output::materialize_outputs;
fn native_child(
    registry: &ProfileRegistry,
    entry: &ExpandedFrontierEntry,
    bindings: &SessionBindings,
    index: usize,
    argv: &[String],
) -> Result<ExpandedFrontierEntry, String> {
    let argument = |value: &str| DispatchArgument {
        slot: SlotName::new("python_argv"),
        text: value.into(),
        implicit_input_source: None,
        runtime_argument_domain: None,
        runtime_data: true,
        quoted: true,
        node_kind: "python_argv".into(),
        span: entry.command_ref.span.clone(),
        binding_source: ArgumentBindingSource::RemainingArg,
    };
    let candidate = caushell_profile::DispatchCommandCandidate {
        module_runtime: None,
        dispatch_index: index,
        command: argument(&argv[0]),
        argv: argv[1..].iter().map(|s| argument(s)).collect(),
        environment: Vec::new(),
        clear_environment: false,
        unknown_environment: false,
        unknown_environment_from: Vec::new(),
        unknown_environment_names: Vec::new(),
        generated_environment: Vec::new(),
        unset_environment: Vec::new(),
        working_directory: caushell_profile::DispatchWorkingDirectory::Inherit,
        stdin_from_parent: true,
        stdin_from_tool: false,
        stdout_to_parent: true,
    };
    let command = candidate.to_command_fact();
    let (parsed, command) = parsed_dispatch_scope(command, entry.shell_kind)
        .ok_or("Python native argv scope unavailable")?;
    let mut child_bindings = bindings.clone();
    child_bindings.enter_child_shell_environment();
    let result = resolve_invocation_artifact_with_bindings(
        registry,
        &command,
        InvocationRuntimeContext {
            shell_kind: entry.shell_kind,
            stdin_payload_available: false,
            interactive_session: false,
        },
        &child_bindings,
    );
    let mut child = entry.clone();
    child.source_node_id = expanded_virtual_node_id("python", &entry.source_node_id, index);
    child.command_ref = ParsedCommandRef::new(0, command.span.clone());
    child.parsed_scope = parsed.clone();
    child.rendered_command_text = command.text;
    child.result = result;
    child.depth = entry.depth.saturating_add(1);
    child.parent_execution_node_id = entry.source_node_id.clone();
    child.bindings = child_bindings.clone();
    child.origin_kind = ExecutionUnitOriginKind::RecursivePayload;
    child.origin_index = index;
    child.origin_locator = ExecutionUnitOriginLocator::None;
    child.static_payload_scope = StaticPayloadLookupScope {
        parsed_scope: parsed,
        command_index: 0,
        bindings: child_bindings.clone(),
        scope_base_bindings: child_bindings,
        stdin_is_parent_output: false,
    };
    child.inherited_scope.dispatch_working_directory = None;
    child.inherited_scope.dispatch_stdout_to_parent = true;
    // FD routing through Python is not inferred from argv or file reads.
    child.inherited_scope.native_stdin_route_unproven = true;
    Ok(child)
}

pub(super) fn reconcile_payloads(
    records: &[ExecutionUnitResolveRecord],
    payloads: &mut [NestedPayloadRecord],
    evidence: &[Evidence],
) {
    let complete = evidence
        .iter()
        .filter_map(|e| match &e.kind {
            EvidenceKind::PythonPayload(p) if p.complete => Some(p.node_id.as_str()),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    for payload in payloads {
        if payload.candidate.candidate.language != PayloadLanguage::Python {
            continue;
        }
        let owner = match &payload.parent_ref {
            NestedPayloadParentRef::DerivedInvocation { node_id } => Some(node_id.0.as_str()),
            NestedPayloadParentRef::RootCommand { command_index } => records
                .iter()
                .find(|r| {
                    r.origin_kind == ExecutionUnitOriginKind::TopLevel
                        && r.command_ref.command_index == *command_index
                })
                .map(|r| r.source_node_id.0.as_str()),
        };
        if owner.is_some_and(|node| complete.contains(node)) {
            payload.resolution = NestedPayloadResolution::ModeledLanguage;
        }
    }
}
