#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
dist_root="${repo_root}/target/dist"
output_name="caushell-dsh-bash.tgz"

cd "${repo_root}"
mkdir -p "${dist_root}"
rm -f "${dist_root}/${output_name}" "${dist_root}/${output_name}.sha256"

package_version="$(node -p "require('./integrations/deepseek-harness/package.json').version")"
runtime_version="$(cargo metadata --no-deps --format-version 1 | python3 -c '
import json
import sys

metadata = json.load(sys.stdin)
versions = {package["version"] for package in metadata["packages"] if package["name"] == "caushell"}
if len(versions) != 1:
    raise SystemExit(f"expected one caushell package version, got {sorted(versions)}")
print(next(iter(versions)))
')"
if [[ "${package_version}" != "${runtime_version}" ]]; then
  echo "package-dsh-plugin: package version ${package_version} does not match runtime version ${runtime_version}" >&2
  exit 1
fi

pack_output="$(mktemp)"
cleanup() {
  rm -f "${pack_output}"
}
trap cleanup EXIT

npm pack ./integrations/deepseek-harness \
  --pack-destination "${dist_root}" \
  --json >"${pack_output}"
packed_name="$(python3 - "${pack_output}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    records = json.load(handle)
if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
    raise SystemExit("npm pack returned an unexpected result")
filename = records[0].get("filename")
if not isinstance(filename, str) or not filename.endswith(".tgz"):
    raise SystemExit("npm pack did not return a tarball filename")
print(filename)
PY
)"

mv "${dist_root}/${packed_name}" "${dist_root}/${output_name}"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "${dist_root}" && sha256sum "${output_name}" > "${output_name}.sha256")
else
  (cd "${dist_root}" && shasum -a 256 "${output_name}" > "${output_name}.sha256")
fi

echo "${dist_root}/${output_name}"
