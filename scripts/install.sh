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
  CAUSHELL_VERSION      Release tag, default: latest
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
  verify_checksum() {
    sha256sum -c "$1"
  }
elif command -v shasum >/dev/null 2>&1; then
  verify_checksum() {
    shasum -a 256 -c "$1"
  }
else
  echo "caushell install: missing required command: sha256sum or shasum" >&2
  exit 1
fi

target="$(detect_target)"
asset="caushell-${target}.tar.gz"
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
(
  cd "${tmp_dir}"
  verify_checksum "${asset}.sha256"
)

tar -xzf "${archive_path}" -C "${tmp_dir}"

package_dir="${tmp_dir}/caushell-${target}"
if [[ ! -d "${package_dir}/bin" ]]; then
  echo "caushell install: release package is missing bin/" >&2
  exit 1
fi

mkdir -p "${install_dir}"
for binary in caushell caushell-adapter-codex caushell-codex-hook caushell-adapter-claude caushell-claude-hook; do
  if [[ ! -f "${package_dir}/bin/${binary}" ]]; then
    echo "caushell install: release package is missing ${binary}" >&2
    exit 1
  fi
  install -m 0755 "${package_dir}/bin/${binary}" "${install_dir}/${binary}"
done

cat <<EOF
Caushell runtime binaries installed to:
  ${install_dir}

Make sure this directory is on PATH before starting Codex or Claude Code:
  export PATH="${install_dir}:\$PATH"
EOF
