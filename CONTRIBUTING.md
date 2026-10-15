# Contributing

## Requirements

- Go 1.27 or later
- kubectl (for integration tests)
- kind and Docker (for full integration tests)

## Development Setup

```bash
git clone https://github.com/Evaneos/kubectl-readonly.git
cd kubectl-readonly
```

## Running Tests

```bash
# Unit tests only
make test

# Smoke tests (fast, no cluster needed, uses --readonly-check-ok)
make test-smoke

# Full integration tests (requires kind and Docker)
make test-integration

# All tests: unit -> smoke -> integration
make test-all
```

### Test Pyramid

1. **Unit tests** (`kubepolicy/check_test.go`, `main_test.go`): Test the command validation logic directly
2. **Smoke tests** (`smoke_test.go`): Test the binary with `--readonly-check-ok` flag (fast, no cluster)
3. **Integration tests** (`integration_test.go`): Test against a real kind cluster

## Building

```bash
# Build binary
make build

# Install to $GOPATH/bin
make install
```

## Linting

Requires golangci-lint v2.

```bash
golangci-lint run ./...
# or
make lint
```

## Philosophy

**When in doubt, block.** This tool prefers false negatives (blocking legitimate commands) over false positives (allowing dangerous commands). If a command isn't explicitly in the allowlist, it's blocked.

This tool prevents *accidental* destructive operations, not *malicious* attacks. See the README for the full threat model.

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Add tests for any new functionality
4. Ensure all tests pass (`make test-all`)
5. Submit a pull request

---

## Creating a Release

Releases are automated via GitHub Actions when a tag is pushed.

### Steps

1. **Update version** (if needed in code):
   ```bash
   # Version is injected via ldflags from git tags, no code change needed
   ```

2. **Create and push a tag**:
   ```bash
   # List existing tags
   git tag -l

   # Create a new tag (follow semver)
   git tag v0.3.0

   # Push the tag to trigger the release
   git push origin v0.3.0
   ```

3. **Wait for CI**: GitHub Actions will:
   - Run all tests
   - Build binaries for all platforms (Linux, macOS, Windows × amd64, arm64)
   - Create a GitHub release with binaries and checksums
   - Generate changelog from commits

4. **Verify the release**: Check the [releases page](https://github.com/Evaneos/kubectl-readonly/releases)

### Version Naming

Follow [Semantic Versioning](https://semver.org/):
- `v1.0.0` - Major: breaking changes
- `v1.1.0` - Minor: new features, backward compatible
- `v1.1.1` - Patch: bug fixes

---

## Publishing to Krew

[Krew](https://krew.sigs.k8s.io/) is the kubectl plugin manager. Publishing allows users to install with `kubectl krew install readonly`.

### Releases

Each tag triggers [krew-release-bot](https://github.com/rajatjindal/krew-release-bot) in the release workflow, once per plugin. It opens the krew-index PR for each plugin, including the first one for a new plugin: that PR adds `plugins/<plugin>.yaml` and waits for review by the krew maintainers, while version bumps are merged automatically.

### Manual submission

If the bot cannot open the PR, submit the manifest by hand:

1. **Create a release** (see above)

2. **Generate the Krew manifest**:
   ```bash
   # This downloads checksums from the release and generates the manifest
   make krew-manifest VERSION=v0.3.0 > readonly.yaml
   # Other plugins: make krew-manifest VERSION=v0.3.0 PLUGIN=readonly-strict > readonly-strict.yaml
   ```

3. **Fork and clone krew-index**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/krew-index.git
   cd krew-index
   ```

4. **Add the plugin manifest**:
   ```bash
   cp /path/to/readonly.yaml plugins/readonly.yaml
   ```

5. **Test locally**:
   ```bash
   kubectl krew install --manifest=plugins/readonly.yaml
   kubectl readonly get pods
   kubectl krew uninstall readonly
   ```

6. **Submit a PR** to [kubernetes-sigs/krew-index](https://github.com/kubernetes-sigs/krew-index):
   - Title: `Add readonly plugin`
   - Include a description of what the plugin does

### Krew Manifest Location

The krew-release-bot templates live in `.krew/`, one per plugin (`readonly`, `readonly-strict`, `readonly-leaky`). The `make krew-manifest` command renders one of them (`PLUGIN=`, default `readonly`) with the SHA256 checksums of a GitHub release.

---

## Security

If you discover a security vulnerability, please open an issue or contact the maintainers directly.

## Local Testing Tips

### Testing as a kubectl plugin

```bash
# Build and test plugin mode
make build
export PATH="$PWD:$PATH"
kubectl readonly get pods
```

### Testing with kind

```bash
# Create a test cluster
kind create cluster --name test

# Run tests
make test-integration

# Cleanup
kind delete cluster --name test
# or
make clean-kind
```
