#!/usr/bin/env bash
set -euo pipefail

repo="${CAUSHELL_REPO:-fatmo666/Caushell}"
version="${CAUSHELL_VERSION:-latest}"
install_dir="${CAUSHELL_INSTALL_DIR:-${HOME}/.local/bin}"
download_base_url="${CAUSHELL_DOWNLOAD_BASE_URL:-}"

usage() {
  cat <<'USAGE'
Install Caushell runtime binaries from a GitHub release.

Environment:
  CAUSHELL_REPO         GitHub repo, default: fatmo666/Caushell
  CAUSHELL_VERSION      Release tag, default: latest. Use v0.0.7 to pin a stable build.
  CAUSHELL_INSTALL_DIR  Install directory, default: ~/.local/bin
  CAUSHELL_DOWNLOAD_BASE_URL
                        Override release download base URL, mostly for mirrors/tests
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

need_command() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "caushell install: missing required command: ${name}" >&2
    exit 1
  fi
}

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "${os}:${arch}" in
    Linux:x86_64|Linux:amd64)
      printf 'x86_64-unknown-linux-musl\n'
      ;;
    Darwin:x86_64|Darwin:amd64)
      printf 'x86_64-apple-darwin\n'
      ;;
    Darwin:arm64|Darwin:aarch64)
      printf 'aarch64-apple-darwin\n'
      ;;
    *)
      echo "caushell install: unsupported platform ${os}/${arch}" >&2
      echo "caushell install: use a supported release asset or build from source" >&2
      exit 1
      ;;
  esac
}

need_command tar
need_command mktemp
need_command install

if command -v curl >/dev/null 2>&1; then
  download_to_file() {
    curl -fsSL "$1" -o "$2"
  }
elif command -v wget >/dev/null 2>&1; then
  download_to_file() {
    wget -qO "$2" "$1"
  }
else
  echo "caushell install: missing required command: curl or wget" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  checksum_for_file() {
    sha256sum "$1" | awk '{print $1}'
  }
elif command -v shasum >/dev/null 2>&1; then
  checksum_for_file() {
    shasum -a 256 "$1" | awk '{print $1}'
  }
else
  echo "caushell install: missing required command: sha256sum or shasum" >&2
  exit 1
fi

verify_checksum() {
  local archive="$1"
  local checksum="$2"
  local expected checksum_name extra actual line_count

  line_count="$(awk 'NF { count++ } END { print count + 0 }' "${checksum}")"
  if [[ "${line_count}" != "1" ]]; then
    echo "caushell install: checksum file must contain exactly one entry" >&2
    return 1
  fi

  read -r expected checksum_name extra < <(awk 'NF { print; exit }' "${checksum}")
  checksum_name="${checksum_name#\*}"
  if [[ -n "${checksum_name}" && "${checksum_name}" != "$(basename "${archive}")" ]]; then
    echo "caushell install: checksum names ${checksum_name}, expected $(basename "${archive}")" >&2
    return 1
  fi
  if [[ -n "${extra:-}" || ! "${expected}" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "caushell install: invalid SHA-256 checksum entry" >&2
    return 1
  fi

  actual="$(checksum_for_file "${archive}")"
  expected="$(printf '%s' "${expected}" | tr '[:upper:]' '[:lower:]')"
  actual="$(printf '%s' "${actual}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "caushell install: checksum mismatch for $(basename "${archive}")" >&2
    return 1
  fi
}

target="$(detect_target)"
asset="caushell-${target}.tar.gz"
package_name="caushell-${target}"
if [[ -n "${download_base_url}" ]]; then
  url="${download_base_url%/}/${asset}"
elif [[ "${version}" == "latest" ]]; then
  url="https://github.com/${repo}/releases/latest/download/${asset}"
else
  url="https://github.com/${repo}/releases/download/${version}/${asset}"
fi
checksum_url="${url}.sha256"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

echo "caushell install: downloading ${url}" >&2
archive_path="${tmp_dir}/${asset}"
checksum_path="${archive_path}.sha256"
download_to_file "${url}" "${archive_path}"
download_to_file "${checksum_url}" "${checksum_path}"

echo "caushell install: verifying ${asset}" >&2
verify_checksum "${archive_path}" "${checksum_path}"

validate_archive() {
  local entry kind listing verbose
  if ! listing="$(tar -tzf "${archive_path}")"; then
    echo "caushell install: could not list release archive" >&2
    return 1
  fi
  while IFS= read -r entry; do
    entry="${entry%/}"
    if [[ "${entry}" != "${package_name}" && "${entry}" != "${package_name}/"* ]]; then
      echo "caushell install: release archive contains an unsafe path: ${entry}" >&2
      return 1
    fi
    if [[ "${entry}" == /* || "${entry}" == *"/../"* || "${entry}" == ../* || "${entry}" == */.. ]]; then
      echo "caushell install: release archive contains an unsafe path: ${entry}" >&2
      return 1
    fi
  done <<< "${listing}"

  if ! verbose="$(tar -tvzf "${archive_path}")"; then
    echo "caushell install: could not inspect release archive entries" >&2
    return 1
  fi
  while IFS= read -r entry; do
    [[ -z "${entry}" ]] && continue
    kind="${entry:0:1}"
    if [[ "${kind}" != "-" && "${kind}" != "d" ]]; then
      echo "caushell install: release archive contains a non-file entry: ${entry}" >&2
      return 1
    fi
  done <<< "${verbose}"
}

validate_archive
tar -xzf "${archive_path}" -C "${tmp_dir}"

package_dir="${tmp_dir}/${package_name}"
if [[ ! -d "${package_dir}/bin" ]]; then
  echo "caushell install: release package is missing bin/" >&2
  exit 1
fi

mkdir -p "${install_dir}"
for binary in caushell caushell-adapter-codex caushell-codex-hook caushell-adapter-claude caushell-adapter-dsh caushell-claude-hook; do
  if [[ ! -f "${package_dir}/bin/${binary}" || -L "${package_dir}/bin/${binary}" ]]; then
    echo "caushell install: release package is missing ${binary}" >&2
    exit 1
  fi
  install -m 0755 "${package_dir}/bin/${binary}" "${install_dir}/${binary}"
done

build_info="$(${install_dir}/caushell build-info 2>/dev/null || true)"

cat <<EOF
Caushell runtime binaries installed to:
  ${install_dir}

Build identity:
${build_info:-  unavailable}

Make sure this directory is on PATH before starting Codex, Claude Code, or DeepSeek Harness:
  export PATH="${install_dir}:\$PATH"

For future updates:
  caushell update
EOF
