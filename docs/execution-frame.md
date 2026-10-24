# Execution-frame observations

An owning executor can supply request-local environment and Bash pathname facts.
The runtime does not infer them from the hook process or launch another shell to
guess the target frame.

## Protocol

1. Check `ping.execution_frame_protocol == 1`.
2. Send `execution_frame_plan` with a `RuntimeCheckRequest` and the executor
   instance ID. Planning returns a binding and bounded observation requirements;
   it does not check, approve, execute, or advance the command sequence.
3. Collect the requested facts at the owning executor's paused execution boundary
   through `ExecutionFrameObserver` and `ExecutionFrameObservation::collect`.
4. Attach the observation to `shell_state_before.execution_frame` and check the
   original request. Hook adapters accept the executor-owned top-level
   `execution_frame` field; `tool_input` is not an observation source.

The binding covers the executor, session, check sequence, runtime, shell dialect,
cwd, and command SHA-256. If the session advances between planning and checking,
the observation is rejected. A persistent shell instance change requires a new
session. Binding metadata scopes evidence; it is not a signature or independent
authentication of the executor.

## Collection

Requirements come from Profile environment declarations and native Shell inputs.
The first implementation returns the bounded registry-wide union, covering
indirect calls without matching command chains. Collectors read only those names,
not the entire environment. The observer must represent one coherent execution
boundary and preserve the pending action's semantics. It must not run the pending
command or interpret its output as evidence.

Child-environment values distinguish `present`, `absent`, and `unknown`. Shell
pathname facts separately cover glob options, `GLOBIGNORE`, and locale; unexported
Shell variables are not child-environment values. Unavailable observations remain
unknown. Existing external hooks without an owning-executor observation channel
continue without these facts; they do not synthesize defaults.

```rust,ignore
let plan = plan_execution_frame_unix_socket(socket, &plan_request)?;
let frame = ExecutionFrameObservation::collect(
    plan.binding, &plan.requirements, &owning_executor,
)?;
request.shell_state_before.execution_frame = Some(frame);
let result = check_with_receipt_unix_socket(socket, &request)?;
```

## Lifecycle

Frame facts apply only to their check. Raw requests and frame validation evidence
remain available in the event log; snapshots retain executor identity, not a cache
of frame facts. A later request must supply new observations. Contradictions with
retained environment bindings invalidate the old binding instead of allowing it
to reappear after a missing observation or store restore.

Existing same-action scope checks still invalidate pathname proofs when the
action can alter relevant state or names. Missing, stale, conflicting, or invalid
observations cannot authorize an action. Analysis continues after a rejected
frame so independent Deny findings remain effective. Non-Shell scripts still
require approval, including scripts reached through native callbacks.

The legacy unbound `environment` and `pathname` snapshot fields remain available
to trusted embedded callers. External adapters do not populate them implicitly.
