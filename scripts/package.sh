#!/usr/bin/env bash
# Package the `secret` CLI for a release: a versioned tarball per architecture
# plus a Homebrew formula body that installs the prebuilt binary.
#
#   scripts/package.sh                  # current architecture
#   scripts/package.sh --universal      # arm64 + x86_64 fat binary (needs both SDK slices)
#   scripts/package.sh --formula        # also print the Homebrew formula
#
# Output: build/dist/secret-<version>-<arch>.tar.gz, build/dist/SHA256SUMS,
# and build/dist/secret.rb when --formula is passed.
#
# SecretBar.app is NOT packaged here: the menu-bar app needs a full Xcode
# toolchain for SwiftUI macros, which the Command Line Tools cannot provide.
# Keep shipping it from nixfiles, or build it from an Xcode checkout.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIST="$ROOT/build/dist"
FORMULA=0
ARCHS=()

for argument in "$@"; do
  case "$argument" in
    --universal) ARCHS=(arm64 x86_64) ;;
    --formula) FORMULA=1 ;;
    *) echo "unknown flag: $argument" >&2; exit 2 ;;
  esac
done
if [ "${#ARCHS[@]}" -eq 0 ]; then
  ARCHS=("$(uname -m)")
fi

clean_env() {
  # A Nix dev shell exports SDKROOT/DEPLOYMENT_TARGET that make swift build
  # pick the store SDK; strip them so the system toolchain is used.
  env -u SDKROOT -u NIX_CFLAGS_COMPILE -u NIX_LDFLAGS -u NIX_APPLE_SDK_VERSION \
      -u MACOSX_DEPLOYMENT_TARGET -u DEVELOPER_DIR "$@"
}

SWIFT_FLAGS=()
for arch in "${ARCHS[@]}"; do
  SWIFT_FLAGS+=(--arch "$arch")
done

echo "==> building secret (${ARCHS[*]})"
(cd "$ROOT/secret" && clean_env swift build -c release "${SWIFT_FLAGS[@]}")

SECRET_BIN="$ROOT/secret/.build/apple/Products/Release/secret"
if [ ! -x "$SECRET_BIN" ]; then
  SECRET_BIN="$ROOT/secret/.build/release/secret"
fi
VERSION=$("$SECRET_BIN" version | awk '{print $2}')
if [ -n "${SECRET_EXPECTED_VERSION:-}" ] && [ "$VERSION" != "$SECRET_EXPECTED_VERSION" ]; then
  echo "error: binary reports $VERSION but the release tag is $SECRET_EXPECTED_VERSION — bump secretVersion in secret/Sources/secret/audit.swift" >&2
  exit 1
fi
LABEL=$(printf '%s-' "${ARCHS[@]}")
LABEL=${LABEL%-}
if [ "${#ARCHS[@]}" -gt 1 ]; then LABEL=universal; fi

rm -rf "$DIST"
mkdir -p "$DIST"
NAME="secret-$VERSION-$LABEL"
STAGE=$(mktemp -d)
mkdir -p "$STAGE/$NAME"
cp "$SECRET_BIN" "$STAGE/$NAME/secret"
chmod 755 "$STAGE/$NAME/secret"
cp "$ROOT/LICENSE" "$STAGE/$NAME/LICENSE" 2>/dev/null || true
cp "$ROOT/README.md" "$STAGE/$NAME/README.md" 2>/dev/null || true
if [ -f "$ROOT/secret/secret.1" ]; then
  mkdir -p "$STAGE/$NAME/share/man/man1"
  cp "$ROOT/secret/secret.1" "$STAGE/$NAME/share/man/man1/secret.1"
fi
tar -czf "$DIST/$NAME.tar.gz" -C "$STAGE" "$NAME"
rm -rf "$STAGE"

SHA=$(shasum -a 256 "$DIST/$NAME.tar.gz" | awk '{print $1}')
printf '%s  %s\n' "$SHA" "$NAME.tar.gz" > "$DIST/SHA256SUMS"
echo "==> $DIST/$NAME.tar.gz"
cat "$DIST/SHA256SUMS"

if [ "$FORMULA" -eq 1 ]; then
  # The asset name carries the LABEL, not the raw architecture: a universal
  # build ships secret-<version>-universal.tar.gz and nothing else, so both
  # architecture branches must point at it.
  URL_ARM="https://github.com/astahmer/secret-cli/releases/download/v$VERSION/secret-$VERSION-$LABEL.tar.gz"
  URL_INTEL=$URL_ARM
  if [ "$LABEL" != "universal" ]; then
    URL_INTEL="https://github.com/astahmer/secret-cli/releases/download/v$VERSION/secret-$VERSION-x86_64.tar.gz"
  fi
  cat > "$DIST/secret.rb" <<RUBY
class Secret < Formula
  desc "Value-minimizing secret manager for configured aliases"
  homepage "https://github.com/astahmer/secret-cli"
  version "$VERSION"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "$URL_ARM"
      sha256 "$SHA"
    else
      url "$URL_INTEL"
      sha256 "$SHA"
    end
  end

  def install
    bin.install "secret-$VERSION-$LABEL/secret" => "secret"
    man1.install "secret-$VERSION-$LABEL/share/man/man1/secret.1"
  end

  def caveats
    <<~EOS
      The `bw` CLI (Bitwarden) or the macOS Keychain backend is required to store
      values. Run `secret status` to check the backend, `secret list` to see aliases.
    EOS
  end

  test do
    assert_match "secret $VERSION", shell_output("#{bin}/secret version")
  end
end
RUBY
  echo "==> $DIST/secret.rb (copy into the homebrew tap as Formula/secret.rb)"
fi
