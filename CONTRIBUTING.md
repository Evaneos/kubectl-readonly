# Contributing

## Development Setup

```bash
git clone https://github.com/evaneos/kubectl-readonly.git
cd kubectl-readonly
uv sync
```

## Running Tests

```bash
uv run pytest -v
```

## Test Structure

- `tests/test_allowlist.py` - Core allowlist functionality tests
- `tests/test_security_bypass.py` - Security tests for sandbox escape attempts
- `tests/test_secrets_protection.py` - Tests for secrets value protection

## Philosophy

**When in doubt, block.** This tool prefers false negatives (blocking safe commands) over false positives (allowing dangerous commands). If a command isn't explicitly in the allowlist, it's blocked.

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Add tests for any new functionality
4. Ensure all tests pass (`uv run pytest -v`)
5. Submit a pull request

## Security

If you discover a security vulnerability, please open an issue or contact the maintainers directly.
