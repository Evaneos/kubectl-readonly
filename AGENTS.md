# AGENTS.md

## Language

Write everything in English: code, comments, docs, commit messages, PR descriptions, issue replies and any other GitHub comment. This is a public repository.

## Voice of the docs

- Honest, a little self-deprecating, never a false sense of security: the tool is anti-footgun, not anti-hacking. `Philosophy & Limitations` in the README is the model.
- Say plainly that the code is written by LLMs with humans directing; do not stage a human reviewer who is not there.

## Layout

- `kubepolicy/` — the read-only policy, importable as a library. `Evaluate(args, mode)` is the entry point, `Check(args)` its moderate shorthand; the allowlists and blocked flags live in `kubepolicy/policy.go`.
- `internal/cli/` — shared CLI: help, check mode, environment sanitization, exec of `kubectl`.
- `main.go` (moderate), `cmd/kubectl-readonly-strict/`, `cmd/kubectl-readonly-leaky/` — one binary per profile, each calling `cli.Main` with its mode.
- `.krew/<plugin>.yaml` — krew-release-bot templates, one per plugin.

## Profiles

- One parser for every mode: a mode changes what is allowed, never how arguments are read.
- Writes, exec and the kustomize flag blocks hold in every mode. Leaky only skips secret masking; strict only adds environment sanitization at exec time.
- A new rule says which modes it applies to, and `kubepolicy/mode_test.go` covers it in each.

## Policy changes

- Deny by default: when in doubt, block. Refusing a safe command is tolerable; letting a write command through is a bug.
- Any allowlist change comes with allowed and denied cases in `kubepolicy/check_test.go`.
- A denied command that can be fixed (e.g. dropping `-o yaml` on secrets) returns a corrective hint from `Check`.

## Build and test

- `make test` runs unit tests. Smoke and integration tests need the `integration` build tag: `make test-smoke` (no cluster), `make test-integration` (kind + Docker). `make build` builds the three binaries.
- Integration tests run against the current kubectl context: point `KUBECONFIG` at a throwaway file so they only see the kind cluster.
- `make lint` requires golangci-lint v2.
- Commit messages follow Conventional Commits.

## Release

Push a semver tag `vX.Y.Z`: GoReleaser builds the three binaries (one archive each) and the krew-release-bot opens one krew-index PR per plugin. A new plugin is submitted to krew-index by hand the first time.

## Kubernetes cluster access

When exploring or investigating Kubernetes clusters, use `kubectl-readonly` instead of `kubectl` for read-only operations. It is pre-approved, blocks write commands and hides secret values. Use `kubectl` directly, with explicit user approval, only for write operations, `exec`, `port-forward` and other interactive commands, or reading secret values.
