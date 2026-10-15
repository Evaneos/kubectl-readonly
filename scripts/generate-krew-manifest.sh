#!/bin/bash
# Generate Krew plugin manifest with actual SHA256 checksums from a release
#
# Usage: ./scripts/generate-krew-manifest.sh v0.2.0 [readonly|readonly-strict|readonly-leaky]
#
# This script:
# 1. Downloads checksums.txt from the GitHub release
# 2. Generates the manifest from .krew/<plugin>.yaml with correct SHA256 values
# 3. Outputs to stdout (redirect to file as needed)

set -euo pipefail

VERSION="${1:-}"
PLUGIN="${2:-readonly}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version> [plugin]" >&2
    echo "Example: $0 v0.2.0 readonly-strict" >&2
    exit 1
fi

if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "Error: invalid version ${VERSION}" >&2
    exit 1
fi
case "$PLUGIN" in
    readonly|readonly-strict|readonly-leaky) ;;
    *) echo "Error: unknown plugin ${PLUGIN}" >&2; exit 1 ;;
esac

TEMPLATE="$(dirname "$0")/../.krew/${PLUGIN}.yaml"

# Remove 'v' prefix for archive names (GoReleaser convention)
VERSION_NUM="${VERSION#v}"
BIN="kubectl-${PLUGIN}"

REPO="Evaneos/kubectl-readonly"
RELEASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

# Download checksums
CHECKSUMS=$(curl -fsSL "${RELEASE_URL}/checksums.txt")

if [[ -z "$CHECKSUMS" ]]; then
    echo "Error: Could not download checksums from ${RELEASE_URL}/checksums.txt" >&2
    exit 1
fi

# Function to get SHA256 for a specific archive
get_sha256() {
    local archive="$1"
    echo "$CHECKSUMS" | awk -v a="$archive" '$2 == a {print $1}'
}

echo "# yaml-language-server: \$schema=https://raw.githubusercontent.com/kubernetes-sigs/krew/master/pkg/index/spec/embedded_plugin_schema.json"
# Metadata and description come from the krew-release-bot template.
sed -n '/^  platforms:/q; s/{{ \.TagName }}/'"${VERSION}"'/g; p' "$TEMPLATE"
echo "  platforms:"

for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64 windows_arm64; do
    os="${platform%_*}"
    arch="${platform#*_}"
    ext="tar.gz"
    bin="$BIN"
    if [[ "$os" == "windows" ]]; then
        ext="zip"
        bin="${BIN}.exe"
    fi
    archive="${BIN}_${VERSION_NUM}_${platform}.${ext}"
    sha=$(get_sha256 "$archive")
    if [[ -z "$sha" ]]; then
        echo "Error: Could not find checksum for $archive" >&2
        exit 1
    fi
    cat <<ENTRY
  - selector:
      matchLabels:
        os: ${os}
        arch: ${arch}
    uri: ${RELEASE_URL}/${archive}
    sha256: "${sha}"
    bin: ${bin}
ENTRY
done
