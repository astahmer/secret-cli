#!/bin/sh
# Install the `secret` CLI from GitHub releases. No clone, no build.
#
#   curl -sSfL https://raw.githubusercontent.com/astahmer/secret-cli/main/install.sh | sh
#
# Options (environment):
#   SECRET_VERSION=v2.1.0       install a specific tag (default: latest)
#   SECRET_INSTALL_DIR=...      destination directory (default: /usr/local/bin
#                               when writable, else ~/.local/bin)
#   SECRET_NO_VERIFY=1          skip the SHA256SUMS check (not recommended)
set -eu

REPO="astahmer/secret-cli"
VERSION="${SECRET_VERSION:-latest}"

fail() {
  printf 'secret install: %s\n' "$1" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"

os=$(uname -s)
case "$os" in
  Darwin) ;;
  *) fail "prebuilt releases are macOS-only for now (found $os) — build from source: https://github.com/$REPO" ;;
esac

arch=$(uname -m)
case "$arch" in
  arm64|x86_64) ;;
  *) fail "unsupported architecture: $arch" ;;
esac

if [ "$VERSION" = "latest" ]; then
  tag=$(curl -sSfL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -m1 '"tag_name"' | cut -d'"' -f4)
  [ -n "$tag" ] || fail "could not resolve the latest release tag"
else
  tag=$VERSION
  case "$tag" in v*) ;; *) tag="v$tag" ;; esac
fi
version=${tag#v}

asset="secret-${version}-universal.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/secret-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

printf 'secret install: downloading %s\n' "$asset"
curl -sSfL -o "$tmp/$asset" "$base/$asset" || fail "download failed: $base/$asset"

if [ "${SECRET_NO_VERIFY:-0}" != "1" ]; then
  if curl -sSfL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"; then
    expected=$(grep " $asset\$" "$tmp/SHA256SUMS" | awk '{print $1}')
    if [ -n "$expected" ]; then
      actual=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
      [ "$expected" = "$actual" ] || fail "checksum mismatch for $asset"
      printf 'secret install: checksum verified\n'
    fi
  else
    printf 'secret install: no SHA256SUMS in the release, skipping verification\n' >&2
  fi
fi

tar -xzf "$tmp/$asset" -C "$tmp"
staged="$tmp/secret-$version-universal/secret"
[ -x "$staged" ] || fail "archive did not contain the expected binary"

dest=${SECRET_INSTALL_DIR:-}
if [ -z "$dest" ]; then
  if [ -w /usr/local/bin ] || { [ ! -e /usr/local/bin ] && mkdir -p /usr/local/bin 2>/dev/null && [ -w /usr/local/bin ]; }; then
    dest=/usr/local/bin
  else
    dest="$HOME/.local/bin"
  fi
fi
mkdir -p "$dest"

if [ -w "$dest" ]; then
  install -m 755 "$staged" "$dest/secret"
else
  printf 'secret install: %s is not writable; re-run with sudo or set SECRET_INSTALL_DIR\n' "$dest" >&2
  exit 1
fi

printf 'secret install: %s/secret (%s)\n' "$dest" "$("$dest/secret" version)"
case ":$PATH:" in
  *":$dest:"*) ;;
  *) printf 'secret install: add %s to PATH\n' "$dest" >&2 ;;
esac
