# kubectl-readonly

[![CI](https://github.com/Evaneos/kubectl-readonly/actions/workflows/ci.yml/badge.svg)](https://github.com/Evaneos/kubectl-readonly/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Evaneos/kubectl-readonly)](https://goreportcard.com/report/github.com/Evaneos/kubectl-readonly)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod-go-version/Evaneos/kubectl-readonly)](https://go.dev/)

A safe kubectl wrapper that only allows read-only commands. Ideal for giving AI assistants (like Claude) unrestricted access to explore Kubernetes clusters, including production, without risk of accidental modifications.

## Requirements

- `kubectl` must be installed and available in your PATH

## Installation

### Via Krew (recommended)

If you have [Krew](https://krew.sigs.k8s.io/) installed:

```bash
kubectl krew install readonly
```

Then use it as a kubectl plugin:

```bash
kubectl readonly get pods
kubectl readonly describe deployment nginx
kubectl readonly logs my-pod -f
```

### From binary

Download the latest binary from the [releases page](https://github.com/Evaneos/kubectl-readonly/releases) and add it to your PATH.

### From source

Requires Go 1.25+:

```bash
go install github.com/Evaneos/kubectl-readonly@latest
```

### Supported platforms

| OS | Architecture |
|----|--------------|
| Linux | amd64, arm64 |
| macOS | amd64, arm64 |
| Windows | amd64, arm64 |

## Usage

Use `kubectl readonly` (as a plugin) or `kubectl-readonly` (standalone) exactly like `kubectl`:

```bash
# As a kubectl plugin
kubectl readonly get pods
kubectl readonly describe deployment nginx
kubectl readonly logs my-pod -f

# Or standalone
kubectl-readonly get pods
kubectl-readonly get pods -n kube-system -o wide
kubectl-readonly describe deployment nginx
kubectl-readonly logs my-pod -f --tail=100
kubectl-readonly top nodes
kubectl-readonly config use-context production
```

If you try a command that's not read-only, it will be blocked:

```bash
$ kubectl-readonly delete pod my-pod
This command is not safe for read-only access; use kubectl directly instead.

Reason: Command 'delete' is not in the read-only allowlist
```

### Check mode

Use `--readonly-check-ok` to verify if a command would be allowed without executing it:

```bash
$ kubectl-readonly --readonly-check-ok get pods
OK: This command is allowed by kubectl-readonly

$ kubectl-readonly --readonly-check-ok delete pod my-pod
BLOCKED: Command 'delete' is not in the read-only allowlist
```

## Allowed Commands

### Simple commands (no subcommand needed)

| Command | Description |
|---------|-------------|
| `get` | Display resources |
| `describe` | Show detailed resource info |
| `logs` | View container logs |
| `top` | Display resource usage (CPU/memory) |
| `explain` | Documentation for resources |
| `api-resources` | List available API resources |
| `api-versions` | List available API versions |
| `cluster-info` | Display cluster information |
| `version` | Show client/server versions |
| `events` | View cluster events |
| `wait` | Wait for a condition |
| `diff` | Show differences without applying |

### Commands with specific subcommands

| Command | Allowed subcommands |
|---------|---------------------|
| `config` | `view`, `get-contexts`, `current-context`, `use-context` |
| `auth` | `can-i`, `whoami` |
| `rollout` | `status`, `history` |

## Secrets Protection

`kubectl-readonly` allows you to see that secrets exist (metadata) but blocks access to their actual values:

```bash
# Allowed - shows secret names, types, and ages (no values)
kubectl-readonly get secrets
kubectl-readonly get secrets -o wide
kubectl-readonly get secrets -o name
kubectl-readonly describe secret my-secret  # shows size, not values

# Blocked - these formats expose the base64-encoded values
kubectl-readonly get secrets -o yaml
kubectl-readonly get secrets -o json
kubectl-readonly get secret my-secret -o jsonpath='{.data}'
kubectl-readonly get --raw /api/v1/secrets
```

This lets you investigate which secrets exist and how they're configured, without risk of accidentally exposing credentials in logs or terminal history.

## Long-running commands

Some read-only commands can run indefinitely. These are allowed:

```bash
kubectl-readonly get pods --watch      # Watch for changes
kubectl-readonly logs my-pod -f        # Follow logs (stream)
kubectl-readonly top pods --watch      # Continuous resource monitoring
```

These commands are safe (read-only) but will run until interrupted with Ctrl+C.

## Claude Code Integration

This tool was designed to let AI assistants safely explore Kubernetes clusters.

### Step 1: Add to allowlist

Add `kubectl-readonly` to Claude Code's permission allowlist.

**For a single user** (applies to all projects), edit `~/.claude/settings.local.json`:

```json
{
  "permissions": {
    "allow": [
      "Bash(kubectl-readonly:*)"
    ]
  }
}
```

**For a specific project** (shared with the team via git), edit `.claude/settings.json` at the project root:

```json
{
  "permissions": {
    "allow": [
      "Bash(kubectl-readonly:*)"
    ]
  }
}
```

### Step 2: Add instructions (optional but recommended)

Tell Claude to prefer `kubectl-readonly` for read-only operations.

**For a single user**, create or edit `~/CLAUDE.md`:

```markdown
# Kubernetes

When exploring Kubernetes clusters, always use `kubectl-readonly` instead of `kubectl` for read-only operations (get, describe, logs, top, etc.). This command is pre-approved and safe for production.

Only use `kubectl` directly for write operations (create, apply, delete, exec, etc.) which require explicit approval.
```

**For a specific project**, create or edit `CLAUDE.md` at the project root with the same content.

### Result

Claude can then run any read-only kubectl command without asking for permission, while dangerous commands like `delete`, `apply`, or `exec` will be blocked.

## Philosophy

**When in doubt, block.** This tool prefers false negatives (blocking safe commands) over false positives (allowing dangerous commands). If a command isn't explicitly in the allowlist, it's blocked. Environment variables are filtered to prevent bypasses via kubectl control variables.

## Releases

This project uses [GoReleaser](https://goreleaser.com/) to automate releases. When a new tag is pushed, GitHub Actions automatically builds binaries for all supported platforms and creates a GitHub release.

To create a new release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Each release includes:
- Pre-built binaries for all platforms
- SHA256 checksums (`checksums.txt`)
- Automatically generated changelog

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
