# Instructions for Claude

## Kubernetes cluster access

When exploring or investigating Kubernetes clusters, **always use `kubectl-readonly`** instead of `kubectl` for read-only operations:

```bash
kubectl-readonly get pods
kubectl-readonly describe deployment nginx
kubectl-readonly logs my-pod -f
kubectl-readonly top nodes
```

### Why?

- `kubectl-readonly` is pre-approved in the allowlist - no user confirmation needed
- It only allows safe, read-only commands (get, describe, logs, top, etc.)
- Dangerous commands (delete, apply, exec, etc.) are blocked automatically
- Safe to use on production clusters

### When to use `kubectl` instead

Only use `kubectl` directly when:
- You need to perform a write operation (create, apply, delete, patch, scale, etc.)
- You need to exec into a pod
- You need port-forward or other interactive commands

These operations require explicit user approval.

### Available read-only commands

Simple commands: `get`, `describe`, `logs`, `top`, `explain`, `api-resources`, `api-versions`, `cluster-info`, `version`, `events`, `wait`, `diff`

With subcommands:
- `config view`, `config get-contexts`, `config current-context`, `config use-context`
- `auth can-i`, `auth whoami`
- `rollout status`, `rollout history`
