# Terminal-Bench adapter

This is the canonical entry point for new RQ3 runs. Historical research runners
are frozen evidence, not templates for new executions.

The adapter copies the complete upstream task without rewriting `task.toml`,
Dockerfile, instructions, tests, users, verifier mode, timeouts, workdir, environment
variables or artifacts. An omitted user inherits the image USER. Dependencies the
task asks the agent to install remain part of that task; the harness does not
preinstall them or force a user-local installation.

The only Compose overlay pins the already-resolved upstream image ID, labels
owned resources and mounts immutable client/observer assets read-only in a private
`/tmp` directory. Claude launches directly using a binary matching the image architecture; the
read-only observer may use a private loader. Nothing is installed into
`/lib` or `/usr/local/bin`, and the task PATH is preserved. Incompatible native
client assets fail setup. Privileged tasks that could forge observations are
reported as unsupported; the runner never silently removes their capabilities.

Caushell, policy, store, approvals and authoritative records run outside the task.
The executor observer supplies bounded read-only filesystem facts from the actual
command namespace through private descriptors. Only that observer uses
non-dumpability and no-new-privileges. The task retains its original permissions.
Observation failure stops the run. This is not a runtime sandbox or a new Python
analysis policy. Workspace execution policy, inline Ask and existing Deny remain
unchanged. This transport does not claim to defeat every malicious-root attack.

## Prepare and validate

Do not launch Claude through `ld.so`: its helpers reexecute the client, and
`/proc/self/exe` would identify the loader. Mismatched architectures or libc
requirements fail preparation/setup without modifying the task.

Build `cargo build --locked -p caushell --example trusted-filesystem-host` for the
controller host and target Linux architecture. Supply a pinned, compatible native
Claude binary, observer binary, loader and libraries in an immutable asset folder.
`layout.json` defines two argv arrays (`claude` and `observer`). Claude is
`["{assets}/claude"]`; the observer starts with an executable below `{assets}/`. No policy, store, credentials or evidence belong
in this folder. A pinned RQ3 protocol/telemetry package (`rq3`) and Harbor 0.25.0
are explicit dependencies. `prepare.py` records their source hashes.

```
python prepare.py --source UPSTREAM_TASK --output NEW_RUN --assets ASSETS \
  --runtime-root RQ3_RUNTIME --host-guard HOST_GUARD --guard-config POLICY \
  --system-prompt PROMPT --mode offline --steps FIXTURE_STEPS
python run.py NEW_RUN/plan.json
```

Offline mode uses synthetic responses with the real native CLI, tools, guard,
receipt approvals and native Harbor verifier. It never calls a real model.

Local inference additionally requires `--mode local --provider CONFIG
--authorize-local` when preparing and a successful isolated verifier bootstrap:

```
python run.py NEW_RUN/plan.json --preflight
python run.py NEW_RUN/plan.json
```

Preflight uses a disposable zero-action synthetic trial, not the measured task
container. Standard Terminal-Bench pytest tasks must produce a nonempty CTRF test
report; failing answer assertions are acceptable, failed test collection is not.
Other verifier formats currently need a readiness adapter and remain blocked.
There are no extra model request, turn or spend limits in this adapter. Native
upstream task timeouts still apply. Run plans cannot be replayed.

Records include original/prepared task hashes, context/UID/HOME/PATH, container
configuration, namespace observations, raw native streams, tool and guard timing,
receipted approvals, model transport/usage, store, verifier results and final
workspace/session captures. Harbor deletes trial containers automatically.
Failed attempts remain evidence. Never prune evidence or other experiments.

## Engineering checks

```
PYTHONPATH=RQ3_RUNTIME python -B -m unittest discover -s tests -v
PYTHONPATH=RQ3_RUNTIME python -B tests/namespace_probe.py PLAN NEW_EVIDENCE
```

The namespace regression launches and removes only its own disposable container.
It verifies target-namespace facts, workspace execution, inline/deletion Ask,
Deny, immutable assets, protected observer descriptors and fail-closed channel loss.

## Owning Bash boundary

New plans use the owning-frame gate by default. Add the repository's
`owning-frame.bash` and `integrations/execution-frame/capture.bash` to the immutable
asset directory, together with an observer built from the current `guard-host.rs`
and `frame-submit.rs`. Preparation verifies the helper hashes. `--legacy-hooks`
retains the previous unknown-observation behavior when this executor channel is
unavailable; it does not manufacture defaults.

The native PreToolUse hook registers the logical action and rewrites its command
only to insert the trusted gate. Admission of that gate is not a Caushell Allow.
After the native CLI has initialized its actual Bash, the gate pauses that frame,
collects the declared environment and glob facts in forked copies of that frame,
and submits them through a one-use action ticket. It never launches a probe Shell.
Shell `HOME` is observed separately from exported child environment values; tilde
resolution never falls back to a stale container startup value.
The controller plans/checks the original action with the current sequence binding;
only Caushell Allow or a receipted single-call approval releases the original code.
Deny, declined approval and transport loss cannot execute it. Malformed captures
are discarded, leaving facts unknown; they cannot bypass the original check or
the approval receipt required by that check.
Facts and approvals are distinct records; a known path/hostname never grants access.

The plan also names a bounded, partial set of scalar variables referenced by
the command's shell grammar. Their values use a separate owning-frame channel;
an unexported local is never promoted to a child-process environment value.
Empty, absent and unknown remain distinct. Arrays, namerefs and volatile values
stay unknown. A scalar `PWD` is observed as data rather than inferred from cwd.
These facts expire with the action and cannot authorize an external write,
deletion, or an otherwise incomplete operation.

The inserted gate preserves stdin, caller positional parameters, `$?`, cwd updates
and `errexit`. The native client's own cwd reset policy still applies. Scratch
helper functions stay in subshells; only an unexported,
randomly named status scratch variable exists in the pending Bash. Shell
introspection can observe instrumentation, so this is not an invisible executor.
Original and rewritten inputs, native gate admission, actual frame decisions,
approval receipts, rejection and gate timing remain separately auditable.
Cancellation discards pending tickets; captures are never cached across actions.
The channel assumes the native executor and read-only collector assets are trusted;
its tickets are not a claim of isolation from every malicious-root attack.

### Background task lifecycle

A native Bash result containing `backgroundTaskId` acknowledges task allocation;
it is not a completed command or an authorization. It may arrive before the frame
capture or while the guard RPC is running. The adapter keeps that action's ticket
pending and records the native task identity separately. Only the original check
and, for Ask, a matching single-call receipt can release the pending Bash body.
Cancellation invalidates both unconsumed tickets and checks already in flight.

The adapter correlates native `task_started`, `task_updated`, and
`task_notification` messages by session, task ID, and originating Bash tool-use ID.
Foreground task notifications do not create background work. Terminal updates are
idempotent; late progress cannot resurrect a completed task, and an unapproved
completion cannot overwrite Deny or a declined approval. The native live-task list
alone is not accepted as proof of completion. These message shapes are documented
in the [native SDK reference](https://code.claude.com/docs/en/agent-sdk/typescript#sdktasknotificationmessage)
and have been checked against Claude Code 2.1.284.

If a model turn finishes while a correlated background task is pending, the same
native stream remains open for completion events and follow-up turns. The original
task timeout still bounds the session. Missing completion evidence remains
unresolved; it is never synthesized as a successful execution.

Native session completion, agent-phase failure, and verifier reward are separate
outcomes. A native `result` requires `is_error=false` and a completed session;
the `success` subtype alone does not establish success. The adapter persists
`control/native-outcome.json` and reports failed or incomplete sessions through
Harbor's recoverable agent-failure contract. Harbor can then run the original
verifier and preserve its reward, while the runner exits nonzero for the agent
failure. A failed shell tool that the agent handles is not itself a failed
agent session. This does not retry the task or change its execution authorization.

`test_native_agent_outcome.py` exercises the adapter and Harbor's actual trial
control flow with mocked external boundaries, checking error propagation,
evidence capture, cleanup, and retained verification without Docker or a model.

`test_background_frames.py` controls callback/capture/authorization order with
threading events. `test_owned_frames.py` also verifies the early-callback ordering
with actual Bash bodies held behind the gate, including Allow, receipted Ask,
Deny, and declined approval. `test_background_native_loop.py` drives native stdio
fixtures through intermediate results and terminal task messages without calling
a model.

For the Bash/transport regression suite, set `CAUSHELL_TEST_HOST` to the compiled
host example and `PYTHONPATH` to the pinned RQ3 runtime. These tests use a local
engineering HTTP listener, not a model endpoint. Native-client integration tests
must additionally verify the framework's tool-result/cwd lifecycle in a disposable
container.
