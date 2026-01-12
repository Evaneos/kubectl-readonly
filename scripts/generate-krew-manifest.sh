#!/bin/bash
# Generate Krew plugin manifest with actual SHA256 checksums from a release
#
# Usage: ./scripts/generate-krew-manifest.sh v0.2.0
#
# This script:
# 1. Downloads checksums.txt from the GitHub release
# 2. Generates the Krew manifest with correct SHA256 values
# 3. Outputs to stdout (redirect to file as needed)

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>" >&2
    echo "Example: $0 v0.2.0" >&2
    exit 1
fi

# Remove 'v' prefix for archive names (GoReleaser convention)
VERSION_NUM="${VERSION#v}"

REPO="Evaneos/kubectl-readonly"
RELEASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

# Download checksums
CHECKSUMS=$(curl -sL "${RELEASE_URL}/checksums.txt")

if [[ -z "$CHECKSUMS" ]]; then
    echo "Error: Could not download checksums from ${RELEASE_URL}/checksums.txt" >&2
    exit 1
fi

# Function to get SHA256 for a specific archive
get_sha256() {
    local archive="$1"
    echo "$CHECKSUMS" | grep "$archive" | awk '{print $1}'
}

# Get checksums for each platform
SHA_LINUX_AMD64=$(get_sha256 "kubectl-readonly_${VERSION_NUM}_linux_amd64.tar.gz")
SHA_LINUX_ARM64=$(get_sha256 "kubectl-readonly_${VERSION_NUM}_linux_arm64.tar.gz")
SHA_DARWIN_AMD64=$(get_sha256 "kubectl-readonly_${VERSION_NUM}_darwin_amd64.tar.gz")
SHA_DARWIN_ARM64=$(get_sha256 "kubectl-readonly_${VERSION_NUM}_darwin_arm64.tar.gz")
SHA_WINDOWS_AMD64=$(get_sha256 "kubectl-readonly_${VERSION_NUM}_windows_amd64.zip")
SHA_WINDOWS_ARM64=$(get_sha256 "kubectl-readonly_${VERSION_NUM}_windows_arm64.zip")

# Verify we got all checksums
for var in SHA_LINUX_AMD64 SHA_LINUX_ARM64 SHA_DARWIN_AMD64 SHA_DARWIN_ARM64 SHA_WINDOWS_AMD64 SHA_WINDOWS_ARM64; do
    if [[ -z "${!var}" ]]; then
        echo "Error: Could not find checksum for $var" >&2
        exit 1
    fi
done

# Generate the manifest
cat <<EOF
# yaml-language-server: \$schema=https://raw.githubusercontent.com/kubernetes-sigs/krew/master/pkg/index/spec/embedded_plugin_schema.json
apiVersion: krew.googlecontainertools.github.com/v1alpha2
kind: Plugin
metadata:
  name: readonly
spec:
  version: ${VERSION}
  homepage: https://github.com/${REPO}
  shortDescription: Read-only kubectl wrapper to prevent accidental modifications
  description: |
    A kubectl wrapper that only allows read-only commands.
    Designed to prevent accidental modifications when AI assistants (like Claude)
    explore Kubernetes clusters, including production.

    Features:
    - Allowlist-based: Only explicitly allowed commands can run
    - Secrets protection: Can list secrets but not view their values
    - Context switching: Can switch contexts without side effects
    - No side effects: All allowed commands are read-only

    Allowed commands include: get, describe, logs, top, explain, api-resources,
    api-versions, cluster-info, version, events, wait, diff, and read-only subcommands
    of config, auth, and rollout.
  caveats: |
    This plugin requires kubectl to be installed and available in your PATH.

    Usage:
      kubectl readonly get pods
      kubectl readonly describe deployment nginx
      kubectl readonly logs my-pod -f

    Or use the binary directly:
      kubectl-readonly get pods
  platforms:
  - selector:
      matchLabels:
        os: linux
        arch: amd64
    uri: ${RELEASE_URL}/kubectl-readonly_${VERSION_NUM}_linux_amd64.tar.gz
    sha256: "${SHA_LINUX_AMD64}"
    bin: kubectl-readonly
  - selector:
      matchLabels:
        os: linux
        arch: arm64
    uri: ${RELEASE_URL}/kubectl-readonly_${VERSION_NUM}_linux_arm64.tar.gz
    sha256: "${SHA_LINUX_ARM64}"
    bin: kubectl-readonly
  - selector:
      matchLabels:
        os: darwin
        arch: amd64
    uri: ${RELEASE_URL}/kubectl-readonly_${VERSION_NUM}_darwin_amd64.tar.gz
    sha256: "${SHA_DARWIN_AMD64}"
    bin: kubectl-readonly
  - selector:
      matchLabels:
        os: darwin
        arch: arm64
    uri: ${RELEASE_URL}/kubectl-readonly_${VERSION_NUM}_darwin_arm64.tar.gz
    sha256: "${SHA_DARWIN_ARM64}"
    bin: kubectl-readonly
  - selector:
      matchLabels:
        os: windows
        arch: amd64
    uri: ${RELEASE_URL}/kubectl-readonly_${VERSION_NUM}_windows_amd64.zip
    sha256: "${SHA_WINDOWS_AMD64}"
    bin: kubectl-readonly.exe
  - selector:
      matchLabels:
        os: windows
        arch: arm64
    uri: ${RELEASE_URL}/kubectl-readonly_${VERSION_NUM}_windows_arm64.zip
    sha256: "${SHA_WINDOWS_ARM64}"
    bin: kubectl-readonly.exe
EOF
