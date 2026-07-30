#!/usr/bin/env python3
"""Validate published agent plugin manifests and bundled hook contracts."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def fail(message: str) -> None:
    print(f"verify-plugin-contracts: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def require_object(value: object, label: str) -> dict[str, object]:
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def require_array(value: object, label: str) -> list[object]:
    require(isinstance(value, list), f"{label} must be an array")
    return value


def require_executable(path: Path) -> None:
    require(path.is_file(), f"{path} must exist")
    require(os.access(path, os.X_OK), f"{path} must be executable")


def verify_codex_marketplace() -> None:
    marketplace_path = REPO_ROOT / ".agents/plugins/marketplace.json"
    marketplace = require_object(load_json(marketplace_path), str(marketplace_path))
    plugins = require_array(marketplace.get("plugins"), "Codex marketplace plugins")
    plugin = next(
        (
            require_object(entry, "Codex marketplace plugin")
            for entry in plugins
            if require_object(entry, "Codex marketplace plugin").get("name")
            == "caushell-codex"
        ),
        None,
    )
    require(plugin is not None, "Codex marketplace must publish caushell-codex")
    source = require_object(plugin.get("source"), "caushell-codex source")
    require(
        source.get("source") == "local",
        "caushell-codex marketplace source must be local",
    )
    require(
        source.get("path") == "./integrations/codex",
        "caushell-codex marketplace path must be ./integrations/codex",
    )
    policy = require_object(plugin.get("policy"), "caushell-codex policy")
    products = require_array(policy.get("products"), "caushell-codex policy products")
    require("CODEX" in products, "caushell-codex must target CODEX")


def verify_codex_plugin() -> None:
    plugin_root = REPO_ROOT / "integrations/codex"
    manifest_path = plugin_root / ".codex-plugin/plugin.json"
    manifest = require_object(load_json(manifest_path), str(manifest_path))

    require(manifest.get("name") == "caushell-codex", "Codex plugin name mismatch")
    require(
        manifest.get("hooks") == "./hooks/hooks.json",
        "Codex plugin must explicitly declare ./hooks/hooks.json",
    )
    require(manifest.get("skills") == "./skills/", "Codex plugin must expose skills")
    require_executable(plugin_root / "bin/caushell-codex-hook")
    require_executable(plugin_root / "bin/caushell-codex-status")

    hooks_path = plugin_root / "hooks/hooks.json"
    hooks_manifest = require_object(load_json(hooks_path), str(hooks_path))
    hooks = require_object(hooks_manifest.get("hooks"), "Codex hooks")
    expected_events = {
        "SessionStart": None,
        "PreToolUse": "Bash",
        "PermissionRequest": "Bash",
        "PostToolUse": "Bash",
        "SessionEnd": None,
    }
    require(
        set(hooks) == set(expected_events),
        f"Codex hooks must define exactly {sorted(expected_events)}",
    )
    for event_name, expected_matcher in expected_events.items():
        groups = require_array(hooks.get(event_name), f"Codex {event_name} groups")
        require(len(groups) == 1, f"Codex {event_name} must define one hook group")
        group = require_object(groups[0], f"Codex {event_name} group")
        if expected_matcher is None:
            require(
                "matcher" not in group,
                f"Codex {event_name} must not define a matcher",
            )
        else:
            require(
                group.get("matcher") == expected_matcher,
                f"Codex {event_name} matcher must be {expected_matcher}",
            )

        commands = require_array(group.get("hooks"), f"Codex {event_name} commands")
        require(len(commands) == 1, f"Codex {event_name} must define one command")
        command = require_object(commands[0], f"Codex {event_name} command")
        require(command.get("type") == "command", f"Codex {event_name} hook type")
        require(
            command.get("command")
            == f"${{PLUGIN_ROOT}}/bin/caushell-codex-hook {event_name}",
            f"Codex {event_name} command must invoke caushell-codex-hook",
        )


def verify_claude_marketplace() -> None:
    marketplace_path = REPO_ROOT / ".claude-plugin/marketplace.json"
    marketplace = require_object(load_json(marketplace_path), str(marketplace_path))
    plugins = require_array(marketplace.get("plugins"), "Claude marketplace plugins")
    plugin = next(
        (
            require_object(entry, "Claude marketplace plugin")
            for entry in plugins
            if require_object(entry, "Claude marketplace plugin").get("name")
            == "caushell-claude"
        ),
        None,
    )
    require(plugin is not None, "Claude marketplace must publish caushell-claude")
    require(
        plugin.get("source") == "./integrations/claude-code",
        "Claude marketplace path must be ./integrations/claude-code",
    )


def verify_claude_plugin() -> None:
    plugin_root = REPO_ROOT / "integrations/claude-code"
    manifest_path = plugin_root / ".claude-plugin/plugin.json"
    manifest = require_object(load_json(manifest_path), str(manifest_path))
    require(manifest.get("name") == "caushell-claude", "Claude plugin name mismatch")
    require_executable(plugin_root / "bin/caushell-claude-hook")
    require_executable(plugin_root / "bin/caushell-claude-status")

    hooks_path = plugin_root / "hooks/hooks.json"
    hooks_manifest = require_object(load_json(hooks_path), str(hooks_path))
    hooks = require_object(hooks_manifest.get("hooks"), "Claude hooks")
    expected_events = {
        "SessionStart": None,
        "PreToolUse": "Bash",
        "PostToolUse": "Bash",
        "PostToolUseFailure": "Bash",
        "SessionEnd": None,
    }
    require(
        set(hooks) == set(expected_events),
        f"Claude hooks must define exactly {sorted(expected_events)}",
    )
    for event_name, expected_matcher in expected_events.items():
        groups = require_array(hooks.get(event_name), f"Claude {event_name} groups")
        require(len(groups) == 1, f"Claude {event_name} must define one hook group")
        group = require_object(groups[0], f"Claude {event_name} group")
        if expected_matcher is None:
            require(
                "matcher" not in group,
                f"Claude {event_name} must not define a matcher",
            )
        else:
            require(
                group.get("matcher") == expected_matcher,
                f"Claude {event_name} matcher must be {expected_matcher}",
            )

        commands = require_array(group.get("hooks"), f"Claude {event_name} commands")
        require(len(commands) == 1, f"Claude {event_name} must define one command")
        command = require_object(commands[0], f"Claude {event_name} command")
        require(command.get("type") == "command", f"Claude {event_name} hook type")
        require(
            command.get("command") == "${CLAUDE_PLUGIN_ROOT}/bin/caushell-claude-hook",
            f"Claude {event_name} command must invoke caushell-claude-hook",
        )
        require(
            command.get("args") == [event_name],
            f"Claude {event_name} args must pass the event name",
        )


def main() -> None:
    verify_codex_marketplace()
    verify_codex_plugin()
    verify_claude_marketplace()
    verify_claude_plugin()
    print("verify-plugin-contracts: ok")


if __name__ == "__main__":
    main()
