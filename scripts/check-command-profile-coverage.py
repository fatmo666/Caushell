#!/usr/bin/env python3
"""Check command profile coverage against command-frequency research data."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def workspace_root() -> Path:
    return repo_root().parent


def parse_identity(profile_path: Path) -> tuple[str, list[str]]:
    canonical_name: str | None = None
    aliases: list[str] = []
    in_identity = False
    in_aliases = False

    for raw_line in profile_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if line == "identity:":
            in_identity = True
            in_aliases = False
            continue

        if in_identity and not raw_line.startswith(" ") and not raw_line.startswith("\t"):
            break

        if not in_identity:
            continue

        if stripped.startswith("canonical_name:"):
            canonical_name = stripped.split(":", 1)[1].strip().strip("'\"")
            in_aliases = False
        elif stripped == "aliases:":
            in_aliases = True
        elif stripped.startswith("aliases:"):
            rhs = stripped.split(":", 1)[1].strip()
            in_aliases = False
            if rhs not in ("", "[]"):
                raise ValueError(f"inline aliases are not supported in {profile_path}")
        elif in_aliases and stripped.startswith("- "):
            aliases.append(stripped[2:].strip().strip("'\""))

    if not canonical_name:
        raise ValueError(f"missing identity.canonical_name in {profile_path}")
    return canonical_name, aliases


def profile_inventory(profiles_dir: Path) -> tuple[dict[str, str], dict[str, str]]:
    file_names: dict[str, str] = {}
    covered_names: dict[str, str] = {}

    for path in sorted(profiles_dir.glob("*.yaml")):
        canonical_name, aliases = parse_identity(path)
        file_names[path.stem] = canonical_name
        for name in [canonical_name, *aliases]:
            previous = covered_names.setdefault(name, canonical_name)
            if previous != canonical_name:
                raise ValueError(
                    f"duplicate covered name {name!r}: {previous!r} and {canonical_name!r}"
                )
    return file_names, covered_names


def built_in_profile_ids(builtin_rs: Path) -> set[str]:
    text = builtin_rs.read_text(encoding="utf-8")
    return set(re.findall(r'profile_id:\s*"([^"]+)"', text))


def load_frequency(cross_matrix: Path) -> dict[str, tuple[int, int]]:
    frequencies: dict[str, tuple[int, int]] = {}
    with cross_matrix.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            frequencies[row["command"]] = (
                int(row["d2_agent_freq"] or 0),
                int(row["d1_realworld_freq"] or 0),
            )
    return frequencies


def sorted_missing(
    commands: list[str],
    covered_names: dict[str, str],
    frequencies: dict[str, tuple[int, int]],
) -> list[str]:
    missing = [command for command in commands if command not in covered_names]
    missing.sort(key=lambda command: (*frequencies.get(command, (0, 0)), command), reverse=True)
    return missing


def print_category_report(
    categories: dict[str, list[str]],
    covered_names: dict[str, str],
    frequencies: dict[str, tuple[int, int]],
) -> None:
    for category in ("A", "B", "C"):
        commands = categories[category]
        covered = [command for command in commands if command in covered_names]
        missing = sorted_missing(commands, covered_names, frequencies)
        coverage = len(covered) / len(commands) if commands else 1.0
        print(
            f"{category}: total={len(commands)} covered={len(covered)} "
            f"missing={len(missing)} coverage={coverage:.1%}"
        )
        if missing:
            print("  missing:", ", ".join(missing))


def print_d4_report(d4_overlap: Path, covered_names: dict[str, str]) -> None:
    missing: list[tuple[str, str, str]] = []
    with d4_overlap.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            command = row["Command"]
            if command not in covered_names:
                missing.append((command, row["Category"], row["Weaponization Capabilities"]))

    print(f"D4 overlap: missing={len(missing)}")
    if missing:
        for command, category, capabilities in missing:
            print(f"  {command}: {category}; {capabilities}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-covered",
        action="append",
        default=[],
        metavar="COMMAND",
        help="fail if COMMAND is not covered by a profile or alias",
    )
    args = parser.parse_args()

    repo = repo_root()
    workspace = workspace_root()
    profiles_dir = repo / "crates/caushell-profile/profiles"
    builtin_rs = repo / "crates/caushell-profile/src/builtin.rs"
    research = workspace / "research/command-frequency"

    file_names, covered_names = profile_inventory(profiles_dir)
    builtin_ids = built_in_profile_ids(builtin_rs)
    profile_ids = set(file_names)

    print(f"profile_files={len(profile_ids)} covered_names={len(covered_names)}")
    if profile_ids != builtin_ids:
        print("ERROR: built-in profile list does not match profiles directory", file=sys.stderr)
        print("  only in profiles:", ", ".join(sorted(profile_ids - builtin_ids)), file=sys.stderr)
        print("  only in builtin:", ", ".join(sorted(builtin_ids - profile_ids)), file=sys.stderr)
        return 1

    missing_required = [name for name in args.require_covered if name not in covered_names]
    if missing_required:
        print(
            "ERROR: required commands are not covered: " + ", ".join(missing_required),
            file=sys.stderr,
        )
        return 1

    categories = json.loads(
        (research / "cross-validation/category_commands.json").read_text(encoding="utf-8")
    )
    frequencies = load_frequency(research / "cross-validation/cross_matrix.csv")
    print_category_report(categories, covered_names, frequencies)
    print_d4_report(research / "D4-security-bash/weaponizable_overlap.csv", covered_names)
    return 0


if __name__ == "__main__":
    sys.exit(main())
