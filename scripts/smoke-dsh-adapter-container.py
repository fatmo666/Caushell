#!/usr/bin/env python3
"""Smoke the DSH adapter in the existing isolated danger-lab container.

The command strings are sent to the adapter process inside the container for
analysis. They are never passed to Bash, and the container has no host
workspace mount or Docker socket.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path


DEFAULT_IMAGE = "debian:bookworm-slim"


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"smoke-dsh-adapter-container: {message}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("adapter", type=Path)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    return parser.parse_args()


def check(response: dict[str, object], request_id: str, expected: str) -> None:
    if response.get("request_id") != request_id:
        fail(f"request id mismatch: expected {request_id!r}, got {response!r}")
    if response.get("decision") != expected:
        fail(f"expected decision={expected}, got {response!r}")


def main() -> None:
    args = parse_args()
    adapter = args.adapter.resolve()
    if not adapter.is_file() or not os.access(adapter, os.X_OK):
        fail(f"adapter is not executable: {adapter}")

    inspect = subprocess.run(
        ["docker", "image", "inspect", args.image],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if inspect.returncode != 0:
        fail(f"container image is unavailable: {args.image}: {inspect.stderr.strip()}")

    command = [
        "docker",
        "run",
        "--rm",
        "-i",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "512m",
        "--cpus",
        "1",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=256m",
        "--entrypoint",
        "/usr/local/bin/caushell-adapter-dsh",
        "-v",
        f"{adapter}:/usr/local/bin/caushell-adapter-dsh:ro",
        args.image,
        "--store",
        "/tmp/caushell-dsh-store",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin is not None
    assert process.stdout is not None

    def run(request_id: str, shell_action: str) -> dict[str, object]:
        process.stdin.write(
            json.dumps(
                {
                    "schema_version": 1,
                    "request_id": request_id,
                    "session_id": "container-smoke",
                    "cwd": "/lab/workspace",
                    "workspace_root": "/lab/workspace",
                    "command": shell_action,
                }
            )
            + "\n"
        )
        process.stdin.flush()
        line = process.stdout.readline()
        if not line:
            stderr = process.stderr.read() if process.stderr is not None else ""
            fail(f"adapter exited without a response: {stderr.strip()}")
        try:
            return json.loads(line)
        except json.JSONDecodeError as error:
            fail(f"invalid adapter response {line!r}: {error}")

    check(run("allow", "printf hello"), "allow", "allow")
    check(
        run("home-path", '"$HOME/.local/bin/dsh" plugin --help'),
        "home-path",
        "allow",
    )
    # This is intentionally analyzed inside the isolated container. It is
    # never executed by Bash.
    check(run("deny", "rm -rf /etc/*"), "deny", "deny")
    check(
        run("dynamic-deny", 'CMD=rm; "$CMD" -rf /etc'),
        "dynamic-deny",
        "deny",
    )
    unresolved = run("unresolved", '"$USER_CMD" --help')
    check(unresolved, "unresolved", "ask")
    reason = str(unresolved.get("reason", ""))
    for expected_fragment in [
        'shell action "\\\"$USER_CMD\\\" --help"',
        'executable token "\\\"$USER_CMD\\\""',
        'variable "USER_CMD"',
    ]:
        if expected_fragment not in reason:
            fail(
                f"unresolved command reason is missing {expected_fragment!r}: {reason!r}"
            )

    process.stdin.close()
    return_code = process.wait(timeout=10)
    if return_code != 0:
        stderr = process.stderr.read() if process.stderr is not None else ""
        fail(f"adapter container exited with {return_code}: {stderr.strip()}")

    print("smoke-dsh-adapter-container: ok")


if __name__ == "__main__":
    main()
