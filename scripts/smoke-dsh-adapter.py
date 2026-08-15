#!/usr/bin/env python3
"""Smoke the native DeepSeek Harness ordinary-Bash adapter."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile


def fail(message: str) -> None:
    raise SystemExit(f"smoke-dsh-adapter: {message}")


def check(response: dict[str, object], expected: str) -> None:
    if response.get("decision") != expected:
        fail(f"expected decision={expected}, got {response!r}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: scripts/smoke-dsh-adapter.py <caushell-adapter-dsh>")

    adapter = os.path.abspath(sys.argv[1])
    if not os.access(adapter, os.X_OK):
        fail(f"adapter is not executable: {adapter}")

    with tempfile.TemporaryDirectory(prefix="caushell-dsh-smoke-") as temp:
        process = subprocess.Popen(
            [adapter, "--store", os.path.join(temp, "store")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdin is not None
        assert process.stdout is not None

        def run(request_id: str, command: str) -> dict[str, object]:
            process.stdin.write(
                json.dumps(
                    {
                        "schema_version": 1,
                        "request_id": request_id,
                        "session_id": "release-smoke",
                        "cwd": temp,
                        "workspace_root": temp,
                        "command": command,
                    }
                )
                + "\n"
            )
            process.stdin.flush()
            line = process.stdout.readline()
            if not line:
                fail("adapter exited without a response")
            response = json.loads(line)
            if response.get("schema_version") != 1:
                fail(f"schema version mismatch: {response!r}")
            if response.get("request_id") != request_id:
                fail(f"request id mismatch: {response!r}")
            return response

        check(run("allow", "printf hello"), "allow")
        check(run("allow-2", "pwd"), "allow")

        process.stdin.close()
        return_code = process.wait(timeout=10)
        if return_code != 0:
            stderr = process.stderr.read() if process.stderr is not None else ""
            fail(f"adapter exited with {return_code}: {stderr}")

    print("smoke-dsh-adapter: ok")


if __name__ == "__main__":
    main()
