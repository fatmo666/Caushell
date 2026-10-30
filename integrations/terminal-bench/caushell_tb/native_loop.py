import json
import os
import select
import signal
import subprocess
import time
import uuid

from rq3.records import save, stamp
from rq3.native_events import observe
from rq3.telemetry import StreamLog


EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionStart", "SessionEnd")


def invocation(folder, model, session, home, options):
    env = dict(PATH=os.environ["PATH"], HOME=str(home), CLAUDE_CONFIG_DIR=str(folder / "claude-config"),
               ANTHROPIC_BASE_URL=model.url, ANTHROPIC_API_KEY="engineering-dummy-key",
               CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", DISABLE_TELEMETRY="1",
               DISABLE_ERROR_REPORTING="1", DISABLE_AUTOUPDATER="1",
               CLAUDE_CODE_SDK_READS_SESSION_STATE="1")
    if options.get("output_tokens") is not None:
        env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] = str(options["output_tokens"])
    if options.get("max_retries") is not None:
        env["CLAUDE_CODE_MAX_RETRIES"] = str(options["max_retries"])
    if options["usage_kind"] != "synthetic":
        env.update(ANTHROPIC_MODEL=options["model"], ANTHROPIC_DEFAULT_OPUS_MODEL=options["model"],
                   ANTHROPIC_DEFAULT_SONNET_MODEL=options["model"], ANTHROPIC_DEFAULT_HAIKU_MODEL=options["model"],
                   CLAUDE_CODE_SUBAGENT_MODEL=options["model"])
        if options.get("thinking") == "disabled":
            env["MAX_THINKING_TOKENS"] = "0"
    env.update(options.get("environment", {}))
    settings_path = folder / "settings.json"
    command = ["claude", "-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose",
               "--permission-mode", "manual", "--permission-prompt-tool", "stdio", "--settings", str(settings_path),
               "--setting-sources", "", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
               "--model", options["model"], "--session-id", session,
               "--tools", options.get("tools", "Bash,Read,Write,Edit"), "--include-partial-messages", "--include-hook-events"]
    if options.get("cli_budget_usd") is not None:
        command.extend(["--max-budget-usd", options["cli_budget_usd"]])
    if options.get("max_turns") is not None:
        command.extend(["--max-turns", str(options["max_turns"])])
    return command, env


def run(folder, model, lifecycle, settings, timeout, home, workspace, sampler=None, options=None):
    journal = lifecycle.journal
    options = dict(dict(model="claude-sonnet-4-5", prompt="Run this isolated engineering fixture.",
                        output_tokens=1024, cli_budget_usd="0.01", usage_kind="synthetic",
                        thinking="disabled", max_retries=0), **(options or {}))
    save(folder / "settings.json", settings)
    command, env = options["command_factory"](folder, model, lifecycle.session, home, options) if "command_factory" in options else invocation(folder, model, lifecycle.session, home, options)
    save(folder / "invocation.json", dict(command=command, environment_keys=sorted(env),
                                         configuration_environment=options.get("environment", {}),
                                         endpoint=model.url, usage_kind=options["usage_kind"]))
    stderr = (folder / "claude.stderr.log").open("xb")
    with journal.span("claude_spawn"):
        proc = subprocess.Popen(command, cwd=workspace, env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=stderr, start_new_session=True)
    journal.emit("agent_process_started", pid=proc.pid)
    if sampler:
        sampler.add(proc.pid, "claude")
    raw_log = StreamLog(folder / "claude.stdout.jsonl", "stdout", journal)
    input_log = StreamLog(folder / "claude.stdin.jsonl", "stdin", journal)
    result, terminal, buffer = None, "controller_error", b""
    began = time.monotonic()

    offset, streams = 0, {}

    def write(value, tool_id=None):
        raw = json.dumps(value).encode() + b"\n"
        input_log.write(raw)
        proc.stdin.write(raw); proc.stdin.flush()
        journal.emit("native_input_sent", tool_use_id=tool_id, type=value["type"],
                     request_id=value.get("request_id") or value.get("response", {}).get("request_id"), bytes=len(raw))

    hooks = {event: [dict(matcher=None, hookCallbackIds=[event], timeout=20)] for event in EVENTS}
    initialize_id = str(uuid.uuid4())
    try:
        write(dict(type="control_request", request_id=initialize_id, request=dict(subtype="initialize", hooks=hooks)))
        initialized = False
        while timeout is None or time.monotonic() - began < timeout:
            if model.stopped.is_set():
                terminal = "budget_exhausted"
                break
            if not select.select([proc.stdout], [], [], .1)[0]:
                if proc.poll() is not None:
                    terminal = "process_exit"
                    break
                continue
            part = os.read(proc.stdout.fileno(), 65536)
            observed = stamp()
            if not part:
                terminal = "process_exit"
                break
            raw_log.write(part, observed)
            buffer += part
            if len(buffer) > 16 * 1024 * 1024:
                raise ValueError("Native stream frame exceeds bound")
            while b"\n" in buffer:
                raw, buffer = buffer.split(b"\n", 1)
                message = json.loads(raw)
                observe(journal, message, observed, offset, len(raw)+1, streams)
                offset += len(raw)+1
                if message["type"] == "control_response" and message.get("response", {}).get("request_id") == initialize_id:
                    if message["response"]["subtype"] != "success":
                        raise ValueError("Claude initialization rejected")
                    initialized = True
                    journal.emit("agent_ready", _stamp=observed)
                    write(dict(type="user", session_id=lifecycle.session,
                               message=dict(role="user", content=options["prompt"]), parent_tool_use_id=None))
                    journal.emit("prompt_submitted")
                elif message["type"] == "control_request":
                    if not initialized:
                        raise ValueError("Native callback before initialization")
                    request = message["request"]
                    payload = request.get("input", {})
                    tool_id = request.get("tool_use_id") or payload.get("tool_use_id")
                    journal.emit("native_control_request", _stamp=observed, request_id=message["request_id"], request=request)
                    with journal.span("native_control_handler", tool_use_id=tool_id, request_id=message["request_id"],
                                      subtype=request["subtype"], hook=request.get("callback_id")):
                        if request["subtype"] == "hook_callback":
                            event = request["callback_id"]
                            if event == "PreToolUse":
                                response = lifecycle.before(tool_id, payload)
                            elif event in ("PostToolUse", "PostToolUseFailure"):
                                lifecycle.after(tool_id, payload, failed=event == "PostToolUseFailure")
                                response = {}
                            elif event in ("SessionStart", "SessionEnd"):
                                response = {}
                            else:
                                raise ValueError("Unexpected hook")
                        elif request["subtype"] == "can_use_tool":
                            response = lifecycle.approve(request["tool_use_id"], request["tool_name"], request["input"])
                        else:
                            raise ValueError("Unsupported native control request")
                        journal.emit("native_control_response", request_id=message["request_id"], response=response)
                        write(dict(type="control_response", response=dict(subtype="success", request_id=message["request_id"], response=response)), tool_id)
                elif message["type"] == "result":
                    result = message
                    lifecycle.native_denials(message)
                    terminal = "agent_error" if message.get("is_error") else "completed"
                    break
            if result is not None:
                break
        else:
            terminal = "timeout"
    finally:
        journal.emit("agent_loop_stopped", terminal=terminal)
        shutdown_began = stamp()
        if not proc.stdin.closed:
            proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=3)
        proc.stdout.close(); stderr.close(); raw_log.close(); input_log.close()
        journal.emit("agent_process_exit", returncode=proc.returncode, terminal=terminal,
                     shutdown_ns=time.monotonic_ns()-shutdown_began["monotonic_ns"])
        save(folder / "stdio-overhead.json", dict(stdout=raw_log.summary(), stdin=input_log.summary()))
        save(folder / "process-exit.json", dict(returncode=proc.returncode, terminal=terminal))
    if terminal == "completed" and proc.returncode != 0:
        terminal = "process_error"
    if terminal == "completed" and any(a["status"] == "background_unresolved" for a in lifecycle.actions.values()):
        terminal = "incomplete_background"
    return dict(terminal=terminal, result=result, elapsed_seconds=time.monotonic()-began,
                actions=lifecycle.finish(), confirmations=lifecycle.confirmations)
