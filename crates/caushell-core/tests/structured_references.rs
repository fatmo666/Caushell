use caushell_core::ShellQueryCore;
use caushell_graph::SessionGraph;
use caushell_passes::*;
use caushell_profile::{ProfileRegistry, ResolveInvocationArtifactResult};
use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("structured-references"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace")
            .with_variable_knowledge(ShellStateKnowledge::Complete),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn inspect(command: &str) -> RunnerContext {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ExtractAliasBindingsPass);
    runner.register_session_transform_pass(ExtractFunctionBindingsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ExtractVariableBindingsPass);
    runner.register_session_transform_pass(ExtractValueProvenancePass);
    let mut ctx = RunnerContext::new(request(command));
    runner.run(
        SessionView::new(&SessionGraph::new(), &SessionSummary::new()),
        &mut ctx,
    );
    ctx
}

fn printf_args(command: &str) -> Vec<Vec<String>> {
    inspect(command)
        .execution_unit_resolve_records()
        .iter()
        .filter_map(|record| match &record.result {
            ResolveInvocationArtifactResult::Resolved(v)
                if v.normalized_command_name.as_str() == "printf" =>
            {
                Some(
                    v.materialized_projection
                        .invocation
                        .args
                        .iter()
                        .map(|a| a.text.clone())
                        .collect(),
                )
            }
            _ => None,
        })
        .collect()
}

#[test]
fn compound_and_sparse_arrays_preserve_native_argv() {
    for (source, expected) in [
        (
            "a=(one 'two words' ''); printf '%s' \"${a[@]}\"",
            vec!["%s", "one", "two words", ""],
        ),
        (
            "declare -a a=([3]=three [0]=zero [9]=nine); printf '%s' \"${a[@]}\"",
            vec!["%s", "zero", "three", "nine"],
        ),
        ("a=(); printf '%s' \"${a[@]}\" tail", vec!["%s", "tail"]),
        (
            "a=(#comment\n one two); printf '%s' \"${a[@]}\"",
            vec!["%s", "one", "two"],
        ),
        (
            "a=(printf '%s' 'two words'); \"${a[@]}\" tail",
            vec!["%s", "two words", "tail"],
        ),
        (
            "a=(one); b=(\"${a[@]}\" 'two words'); printf '%s' \"${b[@]}\"",
            vec!["%s", "one", "two words"],
        ),
        (
            "a=(one two); a[1]='new value'; printf '%s' \"${a[@]}\"",
            vec!["%s", "one", "new value"],
        ),
    ] {
        assert_eq!(printf_args(source), vec![expected], "{source}");
    }
}

#[test]
fn associative_selection_indirection_and_nameref_follow_current_values() {
    for (source, expected) in [
        (
            "declare -A a=([key]=first ['selected key']='two words'); printf '%s' \"${a['selected key']}\"",
            "two words",
        ),
        (
            "__key__=selected; declare -A a=([$__key__]='two words'); printf '%s' \"${a[selected]}\"",
            "two words",
        ),
        (
            "target=old; pointer=target; target=new; printf '%s' \"${!pointer}\"",
            "new",
        ),
        (
            "a=(zero one); pointer='a[1]'; printf '%s' \"${!pointer}\"",
            "one",
        ),
        ("a=(zero one); slot=1; printf '%s' \"${a[$slot]}\"", "one"),
        (
            "a=(zero one); slot=1; pointer='a[$slot]'; printf '%s' \"${!pointer}\"",
            "one",
        ),
        (
            "target=old; declare -n ref=target; target=new; printf '%s' \"$ref\"",
            "new",
        ),
        (
            "first=one; second=two; declare -n ref=first; declare -n ref=second; printf '%s' \"$ref\"",
            "two",
        ),
        (
            "target=old; declare -n ref=target; ref=new; printf '%s' \"$target\"",
            "new",
        ),
        (
            "a=(old); declare -n ref='a[0]'; ref=new; printf '%s' \"${a[0]}\"",
            "new",
        ),
    ] {
        assert_eq!(printf_args(source), vec![vec!["%s", expected]], "{source}");
    }
}

#[test]
fn local_shadowing_and_global_reference_writes_have_separate_lifetimes() {
    for (source, expected) in [
        (
            "target=outer; declare -n ref=target; f() { local target=inner; printf '%s' \"$ref\"; }; f; printf '%s' \"$ref\"",
            vec![vec!["%s", "inner"], vec!["%s", "outer"]],
        ),
        (
            "target=old; f() { local -n ref=target; ref=new; }; f; printf '%s' \"$target\"",
            vec![vec!["%s", "new"]],
        ),
        (
            "a=(outer); f() { local -a a=(inner); printf '%s' \"${a[@]}\"; }; f; printf '%s' \"${a[@]}\"",
            vec![vec!["%s", "inner"], vec!["%s", "outer"]],
        ),
        (
            "a=(old); f() { a[0]=new; }; f; printf '%s' \"${a[0]}\"",
            vec![vec!["%s", "new"]],
        ),
        (
            "target=old; f() { target=$1; }; command=(f new); \"${command[@]}\"; printf '%s' \"$target\"",
            vec![vec!["%s", "new"]],
        ),
    ] {
        assert_eq!(printf_args(source), expected, "{source}");
    }
}

#[test]
fn unset_reference_and_target_are_not_confused() {
    for (source, expected) in [
        (
            "a=(zero one); unset 'a[0]'; printf '%s' \"${a[@]}\"",
            vec!["%s", "one"],
        ),
        (
            "target=value; declare -n ref=target; unset -n ref; printf '%s' \"$target\"",
            vec!["%s", "value"],
        ),
        (
            "target=value; declare -n ref=target; unset ref; printf '%s' \"$target\"",
            vec!["%s", ""],
        ),
        (
            "target=value; declare -n ref=target; declare +n ref; printf '%s' \"$ref\"",
            vec!["%s", "target"],
        ),
    ] {
        assert_eq!(printf_args(source), vec![expected], "{source}");
    }
}

#[test]
fn risky_and_incomplete_values_do_not_gain_approval_from_expansion() {
    for source in [
        "a=(/outside/file); touch \"${a[0]}\"",
        "a=(/workspace/safe); a[$unknown]=/outside/file; touch \"${a[0]}\"",
        "a=(/workspace/safe); a[18446744073709551615]=/outside/file; touch \"${a[0]}\"",
        "a=(/workspace/safe); if test -f flag; then a[0]=/outside/file; fi; touch \"${a[0]}\"",
        "declare -n a=b; declare -n b=a; touch \"$a\"",
        "target=/workspace/safe; declare -n ref=$unknown; ref=/outside/file; touch \"$target\"",
        "a=(/workspace/safe); a+=(/outside/file); touch \"${a[@]}\"",
        "target=/workspace/safe; if test -f flag; then declare -n ref=target; fi; ref=/outside/file; touch \"$target\"",
        "target=/workspace/safe; declare -n ref=target; export ref=/outside/file; touch \"$target\"",
        "declare -a a=(/outside/file); declare -A a=([0]=/workspace/safe); touch \"${a[0]}\"",
        "target=/outside/file; declare -n ref=target; local +n ref; touch \"$ref\"",
        "target=/workspace/safe; declare -n ref=target; declare +nx ref=/outside/file; touch \"$ref\"",
        "target=/workspace/safe; f() { declare -gn ref=target; ref=/outside/file; }; f; touch \"$target\"",
        "declare -a a=(1) a=('b[$(touch /outside/file)]'); echo $((a[0]))",
        "target=/workspace/safe; declare -n ref=target; for ref in /outside/file; do :; done; touch \"$target\"",
        "declare -n ref=target; : \"${ref:=/outside/file}\"; touch \"$target\"",
        "slot=0; ((slot++)); a=(/workspace/safe /outside/file); touch \"${a[$slot]}\"",
        "slot=0; data=([slot++]=x); a=(/workspace/safe /outside/file); touch \"${a[$slot]}\"",
        "slot=0; data=(\"$((slot++))\"); a=(/workspace/safe /outside/file); touch \"${a[$slot]}\"",
        "slot=0; expression='slot=1'; ((expression)); a=(/workspace/safe /outside/file); touch \"${a[$slot]}\"",
        "slot=0; a=(/workspace/safe /outside/file); declare -n ref='a[$slot]'; slot=1; touch \"$ref\"",
        "target=/workspace/safe; f() { target=/outside/file; }; command=(f); \"${command[@]}\"; touch \"$target\"",
        "a=(/workspace/safe); (a=(/outside/file)); touch \"${a[0]}\" /outside/other",
    ] {
        let result = ShellQueryCore::new().check(request(source));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{source}: {result:#?}"
        );
    }
    for source in [
        "a=(/workspace/file); touch \"${a[0]}\"",
        "target=/workspace/file; declare -n ref=target; touch \"$ref\"",
    ] {
        let result = ShellQueryCore::new().check(request(source));
        assert_eq!(result.decision, Decision::Allow, "{source}: {result:#?}");
    }
}

#[test]
fn persisted_reference_is_a_relation_not_a_frozen_scalar() {
    let ctx = inspect("target=old; declare -n ref=target; target=new");
    assert!(ctx.pending_mutations().iter().any(|m| matches!(m, PendingMutation::UpsertVariableBinding { binding } if binding.name == "ref" && matches!(&binding.value, SessionVariableValue::Structured(StructuredShellValue::NameReference { target: ShellReferenceTarget::Variable { name } }) if name == "target"))));
}

#[test]
fn replacement_keeps_prior_array_candidates_in_the_existing_graph() {
    for source in [
        "a=(/outside/file); a=(/workspace/safe); unset a",
        "declare -a a=(/outside/file) a=(/workspace/safe); unset a",
    ] {
        let ctx = inspect(source);
        for path in ["/outside/file", "/workspace/safe"] {
            assert!(ctx.pending_mutations().iter().any(|m| matches!(m, PendingMutation::AddStateCandidate { fact, .. } if fact.object.name == "a" && matches!(&fact.value, SafetyStateValue::Variable { value: SessionVariableValue::Structured(StructuredShellValue::IndexedArray { elements, .. }), .. } if elements.values().any(|v| matches!(v, ShellScalarValue::Exact { value } if value == path))))), "{path}: {:?}", ctx.pending_mutations());
        }
    }
}

#[test]
fn reference_reads_record_both_relation_and_selected_binding() {
    let ctx = inspect(
        "target=value; declare -n first=target; declare -n second=first; printf '%s' \"$second\"",
    );
    for name in ["target", "first", "second"] {
        assert!(ctx.pending_mutations().iter().any(|m| matches!(m, PendingMutation::AddProvenanceArtifact { artifact: ProvenanceArtifact::VariableValue { name: found, .. }, relation: caushell_graph::EdgeKind::Consumes, .. } if found == name)), "{name}: {:?}", ctx.pending_mutations());
    }
    let ctx = inspect("a=(zero one); slot=1; printf '%s' \"${a[$slot]}\"");
    assert!(ctx.pending_mutations().iter().any(|m| matches!(m, PendingMutation::AddProvenanceArtifact { artifact: ProvenanceArtifact::VariableValue { name, .. }, relation: caushell_graph::EdgeKind::Consumes, .. } if name == "slot")));
}

#[test]
fn snapshot_reload_and_judge_only_keep_reference_relationships() {
    let mut core = ShellQueryCore::new();
    assert_eq!(
        core.check(request("target=/workspace/safe; declare -n ref=target"))
            .decision,
        Decision::Allow
    );
    let before = core
        .session_snapshot(&SessionId::new("structured-references"), 0)
        .unwrap();
    let mut restored = ShellQueryCore::new();
    restored.insert_session_state(
        before.session_id.clone(),
        caushell_core::SessionState::from_snapshot(before.clone()).unwrap(),
    );
    let mut next = request("target=/outside/file; touch \"$ref\"");
    next.sequence_no = CommandSequenceNo(2);
    next.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    assert_eq!(
        restored
            .try_check_with_intent(next, CheckIntent::JudgeOnly)
            .unwrap()
            .response
            .decision,
        Decision::NeedApproval
    );
    let after = restored.session_snapshot(&before.session_id, 0).unwrap();
    assert_eq!(
        after.summary.variable_binding("ref"),
        before.summary.variable_binding("ref")
    );
    assert_eq!(
        after.summary.variable_binding("target"),
        before.summary.variable_binding("target")
    );
}
