# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in kubectl-readonly, please report it responsibly.

### How to Report

1. **Do NOT open a public issue** for security vulnerabilities
2. Email the maintainers directly or use [GitHub's private vulnerability reporting](https://github.com/Evaneos/kubectl-readonly/security/advisories/new)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Resolution timeline**: Depends on severity, typically within 30 days

### Scope

Security issues we care about:

- **Command injection** - Bypassing the allowlist to execute dangerous commands
- **Secret exposure** - Ways to extract secret values despite protections
- **Privilege escalation** - Using kubectl-readonly to gain unintended access

Out of scope:

- Issues that require the attacker to already have shell access
- Denial of service (this tool is not a network service)
- Issues in kubectl itself (report those to Kubernetes)

## Security Design

kubectl-readonly is designed with a **"deny by default"** philosophy:

- Only explicitly allowlisted commands can execute
- Secret values are protected even for read operations
- No shell interpretation of arguments (prevents injection)
- Control characters in arguments are blocked
- Environment variables are filtered to prevent control variable bypasses

For more details, see the [Philosophy section](README.md#philosophy) in the README.
