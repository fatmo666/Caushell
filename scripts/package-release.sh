#!/usr/bin/env bash
set -euo pipefail

target="${1:-}"
if [[ -z "${target}" ]]; then
  echo "usage: scripts/package-release.sh <rust-target>" >&2
  exit 2
fi

repo_root="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
dist_root="${repo_root}/target/dist"
package_name="caushell-${target}"
package_dir="${dist_root}/${package_name}"

bins=(
  caushell
  caushell-adapter-codex
  caushell-codex-hook
  caushell-adapter-claude
  caushell-adapter-dsh
  caushell-claude-hook
)

cd "${repo_root}"

git_head="$(git rev-parse HEAD 2>/dev/null || true)"

build_commit="${CAUSHELL_BUILD_COMMIT:-}"
if [[ -z "${build_commit}" ]]; then
  build_commit="${git_head:-${GITHUB_SHA:-}}"
fi
if [[ -z "${build_commit}" ]]; then
  build_commit="unknown"
fi

build_release="${CAUSHELL_RELEASE_TAG:-${RELEASE_TAG:-}}"
if [[ -z "${build_release}" ]]; then
  if [[ "${GITHUB_REF_NAME:-}" == v* ]]; then
    build_release="${GITHUB_REF_NAME}"
  else
    build_release="source"
  fi
fi

export CAUSHELL_BUILD_COMMIT="${build_commit}"
export CAUSHELL_RELEASE_TAG="${build_release}"
echo "package-release: build commit=${CAUSHELL_BUILD_COMMIT} release=${CAUSHELL_RELEASE_TAG}" >&2
cargo build --release --locked --target "${target}" \
  -p caushell \
  -p caushell-adapter-codex \
  -p caushell-codex-hook \
  -p caushell-adapter-claude \
  -p caushell-adapter-dsh \
  -p caushell-claude-hook

rm -rf "${package_dir}"
mkdir -p "${package_dir}/bin"

for binary in "${bins[@]}"; do
  source_path="${repo_root}/target/${target}/release/${binary}"
  if [[ ! -x "${source_path}" ]]; then
    echo "package-release: missing built binary ${source_path}" >&2
    exit 1
  fi
  install -m 0755 "${source_path}" "${package_dir}/bin/${binary}"
done

cp README.md "${package_dir}/README.md"
cp README.zh-CN.md "${package_dir}/README.zh-CN.md"
cp LICENSE "${package_dir}/LICENSE"
cp NOTICE "${package_dir}/NOTICE"
cp -R assets "${package_dir}/assets"

mkdir -p "${dist_root}"
tarball="${dist_root}/${package_name}.tar.gz"
tar -C "${dist_root}" -czf "${tarball}" "${package_name}"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "${dist_root}" && sha256sum "${package_name}.tar.gz" > "${package_name}.tar.gz.sha256")
elif command -v shasum >/dev/null 2>&1; then
  (cd "${dist_root}" && shasum -a 256 "${package_name}.tar.gz" > "${package_name}.tar.gz.sha256")
else
  echo "package-release: missing required command: sha256sum or shasum" >&2
  exit 1
fi

checksum="$(awk 'NF { print $1; exit }' "${dist_root}/${package_name}.tar.gz.sha256")"
manifest="${dist_root}/${package_name}.manifest.json"
python3 - "${target}" "${package_name}.tar.gz" "${checksum}" "${package_dir}/bin/caushell" "${manifest}" <<'PY'
import json
import subprocess
import sys

target, asset, checksum, caushell, manifest = sys.argv[1:]
build_info = json.loads(subprocess.check_output([caushell, "build-info"], text=True))
payload = {
    "schema_version": 1,
    "build_info": build_info,
    "package": {
        "target": target,
        "asset": asset,
        "sha256": checksum.lower(),
    },
}
with open(manifest, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

echo "${tarball}"
