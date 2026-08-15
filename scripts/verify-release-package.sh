#!/usr/bin/env bash
set -euo pipefail

target="${1:-}"
install_root="${2:-}"

if [[ -z "${target}" || -z "${install_root}" ]]; then
  echo "usage: scripts/verify-release-package.sh <rust-target> <install-root>" >&2
  exit 2
fi

bins=(
  caushell
  caushell-adapter-codex
  caushell-codex-hook
  caushell-adapter-claude
  caushell-adapter-dsh
  caushell-claude-hook
)

for binary in "${bins[@]}"; do
  path="${install_root}/${binary}"
  if [[ ! -x "${path}" ]]; then
    echo "verify-release-package: missing executable ${path}" >&2
    exit 1
  fi
done

export PATH="${install_root}:${PATH}"

run_check() {
  echo "verify-release-package: running $*" >&2
  "$@"
}

run_check "${install_root}/caushell" --version
build_info_file="$(mktemp)"
run_check "${install_root}/caushell" build-info | tee "${build_info_file}"
python3 - "${build_info_file}" "${target}" <<'PY'
import json
import os
import sys

build_info_path, target = sys.argv[1:]
with open(build_info_path, "r", encoding="utf-8") as handle:
    build_info = json.load(handle)

def require(condition, message):
    if not condition:
        raise SystemExit(f"verify-release-package: {message}")

require(build_info.get("target") == target, f"build target mismatch: build-info={build_info.get('target')} expected={target}")

expected_release = os.environ.get("CAUSHELL_EXPECT_RELEASE_TAG", "")
if expected_release:
    require(
        build_info.get("release") == expected_release,
        f"release tag mismatch: build-info={build_info.get('release')} expected={expected_release}",
    )

expected_version = os.environ.get("CAUSHELL_EXPECT_VERSION", "")
if expected_version:
    require(
        build_info.get("version") == expected_version,
        f"version mismatch: build-info={build_info.get('version')} expected={expected_version}",
    )

expected_commit = os.environ.get("CAUSHELL_EXPECT_COMMIT", "")
if expected_commit:
    require(
        build_info.get("commit") == expected_commit,
        f"commit mismatch: build-info={build_info.get('commit')} expected={expected_commit}",
    )
PY
rm -f "${build_info_file}"
run_check "${install_root}/caushell" update --help
run_check "${install_root}/caushell" --update --help
run_check "${install_root}/caushell-codex-hook" Status
run_check "${install_root}/caushell-claude-hook" Status
run_check "${install_root}/caushell-adapter-dsh" --help
run_check "${install_root}/caushell" doctor codex
run_check "${install_root}/caushell" doctor claude

case "${target}" in
  x86_64-unknown-linux-musl)
    if [[ "$(uname -s)" != "Linux" ]]; then
      echo "verify-release-package: Linux musl target must be verified on Linux" >&2
      exit 1
    fi

    for binary in "${bins[@]}"; do
      path="${install_root}/${binary}"

      if command -v file >/dev/null 2>&1; then
        description="$(file "${path}")"
        if [[ "${description}" != *"statically linked"* && "${description}" != *"static-pie linked"* ]]; then
          echo "verify-release-package: ${binary} is not statically linked" >&2
          echo "${description}" >&2
          exit 1
        fi
      fi

      if command -v ldd >/dev/null 2>&1; then
        ldd_output="$(ldd "${path}" 2>&1 || true)"
        if [[ "${ldd_output}" != *"statically linked"* && "${ldd_output}" != *"not a dynamic executable"* ]]; then
          echo "verify-release-package: ldd did not report ${binary} as static" >&2
          echo "${ldd_output}" >&2
          exit 1
        fi
      fi

      if command -v readelf >/dev/null 2>&1; then
        if readelf -d "${path}" 2>/dev/null | grep -q '(NEEDED)'; then
          echo "verify-release-package: ${binary} has dynamic NEEDED entries" >&2
          readelf -d "${path}" >&2
          exit 1
        fi
      fi

      if command -v strings >/dev/null 2>&1; then
        if strings "${path}" | grep -Eq 'GLIBC_[0-9]'; then
          echo "verify-release-package: ${binary} contains GLIBC symbol requirements" >&2
          strings "${path}" | grep -E 'GLIBC_[0-9]' | sort -u >&2
          exit 1
        fi
      fi
    done
    ;;
esac

echo "verify-release-package: ${target} ok"
