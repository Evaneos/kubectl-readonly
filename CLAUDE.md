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
- Secret values are protected (you can list secrets but not see their contents)
- Safe to use on production clusters

### When to use `kubectl` instead

Only use `kubectl` directly when:
- You need to perform a write operation (create, apply, delete, patch, scale, etc.)
- You need to exec into a pod
- You need port-forward or other interactive commands
- You need to see the actual values of secrets (requires explicit approval)

These operations require explicit user approval.

### Available read-only commands

Simple commands: `get`, `describe`, `logs`, `top`, `explain`, `api-resources`, `api-versions`, `cluster-info`, `version`, `events`, `wait`, `diff`

With subcommands:
- `config view`, `config get-contexts`, `config current-context`, `config use-context`
- `auth can-i`, `auth whoami`
- `rollout status`, `rollout history`

### Secrets handling

You can see secret metadata (names, types, ages) but not their values:

```bash
# Allowed - metadata only
kubectl-readonly get secrets
kubectl-readonly describe secret my-secret

# Blocked - these expose values
kubectl-readonly get secrets -o yaml
kubectl-readonly get secrets -o json
```

If you need to see secret values for debugging, use `kubectl` (requires user approval).
