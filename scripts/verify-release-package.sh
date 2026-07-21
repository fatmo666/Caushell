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
  caushell-claude-hook
)

for binary in "${bins[@]}"; do
  path="${install_root}/${binary}"
  if [[ ! -x "${path}" ]]; then
    echo "verify-release-package: missing executable ${path}" >&2
    exit 1
  fi
done

"${install_root}/caushell" --version >/dev/null
"${install_root}/caushell-codex-hook" Status >/dev/null
"${install_root}/caushell-claude-hook" Status >/dev/null
PATH="${install_root}:${PATH}" "${install_root}/caushell" doctor codex >/dev/null
PATH="${install_root}:${PATH}" "${install_root}/caushell" doctor claude >/dev/null

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
