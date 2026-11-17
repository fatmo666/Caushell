use caushell_graph::SessionGraph;
use caushell_passes::{ParseCommandPass,ProjectTopLevelCommandsPass,ResolveInvocationPass};
use caushell_profile::ProfileRegistry;
use caushell_runner::{ExecutionUnitOriginKind,NativeStdinRoute,PassRunner,RunnerContext,SessionView};
use caushell_types::*;
fn context(text:&str)->RunnerContext{
 let mut ctx=RunnerContext::new(CheckRequest{session_id:SessionId::new("xargs-route-frame"),sequence_no:CommandSequenceNo(1),command:text.into(),shell_kind:ShellKind::Bash,shell_state_before:ShellStateSnapshot::new("/work"),workspace_root:Some("/work".into()),home:None,runtime:RuntimeMetadata{runtime_name:"static-fixture".into(),tool_name:None,shell_runtime_capabilities:ShellRuntimeCapabilities::request_only()}});
 let mut runner=PassRunner::new();runner.register_request_transform_pass(ParseCommandPass);runner.register_session_transform_pass(ProjectTopLevelCommandsPass);runner.register_session_transform_pass(ResolveInvocationPass::new(ProfileRegistry::built_in().unwrap()));runner.run(SessionView::new(&SessionGraph::new(),&SessionSummary::default()),&mut ctx);ctx
}
#[test]
fn native_route_is_separate_from_the_original_argv_producer(){
 let ctx=context("printf 'file.txt\\0' | xargs -0 awk '{print}'");let r=ctx.execution_unit_resolve_records().iter().find(|r|r.origin_kind==ExecutionUnitOriginKind::StaticXargs).unwrap();
 assert!(matches!(&r.inherited_scope.native_stdin_route,Some(NativeStdinRoute::Null{dispatcher_node_id}) if dispatcher_node_id==&r.parent_execution_node_id));
 assert!(!r.inherited_scope.native_argument_inputs.is_empty());
 assert!(r.inherited_scope.native_argument_inputs.iter().any(|i|i.origin.stdin));
}
#[test]
fn argument_file_does_not_manufacture_a_null_route(){
 let ctx=context("xargs -a unknown-list awk '{print}'");let rs:Vec<_>=ctx.execution_unit_resolve_records().iter().filter(|r|r.origin_kind==ExecutionUnitOriginKind::StaticXargs).collect();assert!(!rs.is_empty());assert!(rs.iter().all(|r|r.inherited_scope.native_stdin_route.is_none()));
}
#[test]
fn transparent_dispatch_keeps_the_descriptor_fact_but_scripts_need_their_own_proof(){
 let ctx=context("printf 'file.txt\\0' | xargs -0 env awk '{print}'");let child=ctx.execution_unit_resolve_records().iter().find(|r|r.origin_kind==ExecutionUnitOriginKind::Dispatch).unwrap();assert!(child.inherited_scope.native_stdin_route.is_some());
 let ctx=context("printf 'name\\0' | xargs -0 sh -c 'exec 0<.env; cat'");let payload:Vec<_>=ctx.execution_unit_resolve_records().iter().filter(|r|r.origin_kind==ExecutionUnitOriginKind::ShellCommandStringPayload).collect();assert!(!payload.is_empty());assert!(payload.iter().all(|r|r.inherited_scope.native_stdin_route.is_none()));
}
