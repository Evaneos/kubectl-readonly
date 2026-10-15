# AGENTS.md

## Language

Write everything in English: code, comments, docs, commit messages, PR descriptions, issue replies and any other GitHub comment. This is a public repository.

## Layout

- `kubepolicy/` — the read-only policy, importable as a library. `Check(args)` is the single entry point; the allowlists and blocked flags live in `kubepolicy/policy.go`.
- `main.go` — CLI wrapper: runs `kubepolicy.Check`, then execs `kubectl`.
- `plugins/readonly.yaml` — krew manifest template.

## Policy changes

- Deny by default: when in doubt, block. Refusing a safe command is tolerable; letting a write command through is a bug.
- Any allowlist change comes with allowed and denied cases in `kubepolicy/check_test.go`.
- A denied command that can be fixed (e.g. dropping `-o yaml` on secrets) returns a corrective hint from `Check`.

## Build and test

- `make test` runs unit tests. Smoke and integration tests need the `integration` build tag: `make test-smoke` (no cluster), `make test-integration` (kind + Docker).
- `make lint` requires golangci-lint v2.
- Commit messages follow Conventional Commits.

## Release

Push a semver tag `vX.Y.Z`: GoReleaser builds the binaries and the krew-release-bot opens the krew-index PR.

## Kubernetes cluster access

When exploring or investigating Kubernetes clusters, use `kubectl-readonly` instead of `kubectl` for read-only operations. It is pre-approved, blocks write commands and hides secret values. Use `kubectl` directly, with explicit user approval, only for write operations, `exec`, `port-forward` and other interactive commands, or reading secret values.
