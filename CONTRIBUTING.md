# Contributing

## Requirements

- Go 1.25 or later

## Development Setup

```bash
git clone https://github.com/Evaneos/kubectl-readonly.git
cd kubectl-readonly
```

## Running Tests

```bash
go test -v ./...
```

## Building

```bash
go build -o kubectl-readonly .
```

## Linting

```bash
golangci-lint run ./...
```

## Philosophy

**When in doubt, block.** This tool prefers false negatives (blocking safe commands) over false positives (allowing dangerous commands). If a command isn't explicitly in the allowlist, it's blocked.

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Add tests for any new functionality
4. Ensure all tests pass (`go test -v ./...`)
5. Submit a pull request

## Security

If you discover a security vulnerability, please open an issue or contact the maintainers directly.
