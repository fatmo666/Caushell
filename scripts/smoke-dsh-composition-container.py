#!/usr/bin/env python3
"""Run the real DSH ordinary-Bash composition smoke in an isolated container.

The runner uses DSH's real Cordis loader and ToolRuntime. The destructive test
string is submitted to that container-local pipeline and must be denied before
the container Bash executor runs it. No host workspace or Docker socket is
mounted into the container.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


DEFAULT_IMAGE = "node:22-bookworm"
DEFAULT_NODE_MODULES = Path.home() / ".dsh" / "profiles" / "node_modules"
CONTAINER_TIMEOUT_SECONDS = 300


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"smoke-dsh-composition-container: {message}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--node-modules")
    parser.add_argument("--adapter", type=Path, required=True)
    parser.add_argument("--package", dest="package_path", type=Path, required=True)
    parser.add_argument("--plugin-tar", type=Path)
    parser.add_argument("--corepack-cache", type=Path)
    parser.add_argument("--overlay", type=Path, required=True)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    return parser.parse_args()


def resolved_mount(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.exists():
        fail(f"mount source does not exist: {resolved}")
    return resolved


def main() -> None:
    args = parse_args()
    adapter = resolved_mount(args.adapter)
    package_path = resolved_mount(args.package_path)
    plugin_tar = resolved_mount(args.plugin_tar) if args.plugin_tar is not None else None
    corepack_cache = resolved_mount(args.corepack_cache) if args.corepack_cache is not None else None
    if plugin_tar is not None and corepack_cache is None:
        fail("--plugin-tar requires --corepack-cache for offline pnpm resolution")
    overlay = resolved_mount(args.overlay)
    runner = resolved_mount(args.runner)
    driver = resolved_mount(args.driver)
    inspect = subprocess.run(
        ["docker", "image", "inspect", args.image],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if inspect.returncode != 0:
        fail(f"container image is unavailable: {args.image}: {inspect.stderr.strip()}")

    node_modules_candidate = Path(args.node_modules or DEFAULT_NODE_MODULES)

    node_modules_candidate = resolved_mount(node_modules_candidate)
    dsh_package = resolved_mount(node_modules_candidate / "@deepseek-ai/dsh")
    node_modules = dsh_package.parent.parent

    dsh_cli = "/opt/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js"
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "1g",
        "--cpus",
        "1",
        "-e",
        "DSH_TELEMETRY_DISABLED=1",
        "-e",
        "DSH_PERMISSION_MODE=danger-full-access",
        "-e",
        "DSH_HOME=/tmp/dsh-home",
        "-e",
        f"CAUSHELL_DSH_CLI_PATH={dsh_cli}",
        "-e",
        "CAUSHELL_DSH_OVERLAY_PATH=/opt/caushell/real-dsh-overlay.yml",
        "-e",
        "CAUSHELL_DSH_PACKAGE_PATH=/opt/caushell/caushell-dsh-package",
        "-v",
        f"{node_modules}:/opt/dsh/node_modules:ro",
        "-v",
        f"{adapter}:/usr/local/bin/caushell-adapter-dsh:ro",
        "-v",
        f"{package_path}:/opt/caushell/caushell-dsh-package:ro",
        "-v",
        f"{overlay}:/opt/caushell/real-dsh-overlay.yml:ro",
        "-v",
        f"{runner}:/opt/caushell/real-dsh-smoke-runner.mjs:ro",
        "-v",
        f"{driver}:/opt/caushell/real-dsh-runner.mjs:ro",
    ]
    if plugin_tar is not None:
        command.extend([
            "-e",
            "COREPACK_DEFAULT_TO_LATEST=0",
            "-e",
            "COREPACK_HOME=/opt/corepack",
            "-e",
            "CAUSHELL_DSH_INSTALL_PACKAGE_PATH=/opt/caushell/caushell-dsh-bash.tgz",
            "-v",
            f"{plugin_tar}:/opt/caushell/caushell-dsh-bash.tgz:ro",
            "-v",
            f"{corepack_cache}:/opt/corepack:ro",
        ])
    command.extend([
        args.image,
        "node",
        "/opt/caushell/real-dsh-runner.mjs",
    ])
    try:
        result = subprocess.run(command, text=True, check=False, timeout=CONTAINER_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        fail(f"real DSH composition exceeded {CONTAINER_TIMEOUT_SECONDS}s")
    if result.returncode != 0:
        fail(f"real DSH composition exited with {result.returncode}")
    print("smoke-dsh-composition-container: ok")


if __name__ == "__main__":
    main()
