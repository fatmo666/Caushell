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
