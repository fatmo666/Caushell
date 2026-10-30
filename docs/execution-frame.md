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

The plan also includes environment dependencies of implicit configuration search,
configured outputs and anchors, listener endpoints, and manager-owned dispatch
environments. These names come from declarations, including subcommands and
failure effects, rather than an integration's list of known tools.

### Bash executor collector

`integrations/execution-frame/capture.bash` provides a bounded NUL-framed
collector to source in an **owning executor's paused Bash frame**.
`observation.collect(plan, capture_callback)` supplies a fresh correlation nonce
and the planned names to that executor's private capture channel, validates the
returned frame, and constructs the existing protocol observation.

The callback must collect in the actual pending execution frame and keep it
paused until checking and approval finish. Launching another `docker exec env`
or sampling the hook/guard process is not an implementation of this callback.
The supplied collector is not installed into external hooks automatically.
Native Claude Code integrations without that owning-executor channel retain
unknown observations and Ask where those facts are required.

Collection uses subshell scratch space and positional parameters instead of
overwriting requested target variables. Unexported variables remain absent from
the child environment, while pathname variables are captured separately. Arrays,
namerefs and volatile values remain unknown. Partial, oversized, non-UTF-8,
misdelivered or malformed captures are rejected; callers must not substitute
their own environment or guessed defaults. The nonce detects channel mixups;
it is not authentication of an untrusted executor.

The collector supplies facts only. It does not run the pending command, grant
write or execute authority, modify configuration, or persist observations across
checks. The stdio end-to-end tests pair it with real paused Bash processes and
the guard, including changed configuration, replay rejection and retained Deny.

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
