"""CLI entry point for kubectl-readonly."""

import subprocess
import sys

from kubectl_readonly.allowlist import is_command_allowed

# Special flag for checking if a command would be allowed
CHECK_FLAG = "--check-readonly-ok"

# Error message when command is blocked
BLOCKED_MESSAGE = """This command is not safe for read-only access; use kubectl directly instead.

Reason: {reason}

kubectl-readonly only allows read-only commands without side effects.
For a list of allowed commands, see: kubectl-readonly --help
"""


def print_help() -> None:
    """Print help message."""
    help_text = """\
kubectl-readonly - A safe kubectl wrapper that only allows read-only commands

USAGE:
    kubectl-readonly [kubectl args...]
    kubectl-readonly --check-readonly-ok [kubectl args...]

DESCRIPTION:
    This tool wraps kubectl and only allows commands that are read-only
    (no side effects on the cluster). Use this to safely explore Kubernetes
    clusters, including production environments.

    If a command is not allowed, an error message is displayed and the
    command is NOT executed.

SPECIAL FLAGS:
    --check-readonly-ok    Check if a command would be allowed without
                           executing it. Returns exit code 0 if allowed,
                           1 if blocked.

ALLOWED COMMANDS:
    Simple commands (no subcommand needed):
        get, describe, logs, top, explain, api-resources, api-versions,
        cluster-info, version, events, wait, diff

    Commands with specific subcommands:
        config view, config get-contexts, config current-context,
        config use-context
        auth can-i, auth whoami
        rollout status, rollout history

EXAMPLES:
    kubectl-readonly get pods
    kubectl-readonly get pods -n kube-system
    kubectl-readonly describe pod my-pod
    kubectl-readonly logs my-pod -f
    kubectl-readonly top nodes
    kubectl-readonly config use-context production
    kubectl-readonly --check-readonly-ok delete pod my-pod  # Returns 1

ALIAS:
    For convenience, you can create an alias:
        alias kro='kubectl-readonly'
"""
    print(help_text)


def main() -> int:
    """Main entry point."""
    args = sys.argv[1:]

    # Handle our special --help case
    if not args or (len(args) == 1 and args[0] in ("-h", "--help")):
        print_help()
        return 0

    # Check for --check-readonly-ok flag
    check_mode = False
    if CHECK_FLAG in args:
        check_mode = True
        args = [arg for arg in args if arg != CHECK_FLAG]

    # Validate the command
    is_allowed, reason = is_command_allowed(args)

    if check_mode:
        # In check mode, just report if the command would be allowed
        if is_allowed:
            print("OK: This command is allowed by kubectl-readonly")
            return 0
        else:
            print(f"BLOCKED: {reason}")
            return 1

    if not is_allowed:
        # Command not allowed - print error to stderr
        print(BLOCKED_MESSAGE.format(reason=reason), file=sys.stderr)
        return 1

    # Command is allowed - pass through to kubectl
    try:
        result = subprocess.run(
            ["kubectl"] + args,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        return result.returncode
    except FileNotFoundError:
        print("Error: kubectl not found in PATH", file=sys.stderr)
        return 127
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
