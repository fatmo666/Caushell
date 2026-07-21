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
  caushell-claude-hook
)

cd "${repo_root}"
cargo build --release --locked --target "${target}" \
  -p caushell \
  -p caushell-adapter-codex \
  -p caushell-codex-hook \
  -p caushell-adapter-claude \
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
fi

echo "${tarball}"
