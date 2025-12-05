"""Allowlist of read-only kubectl commands.

Philosophy: When in doubt, block. Better to have false negatives (blocking safe
commands) than false positives (allowing dangerous commands).
"""

# Commands that are always safe (no subcommand validation needed)
SAFE_COMMANDS: frozenset[str] = frozenset({
    "get",
    "describe",
    "logs",
    "top",
    "explain",
    "api-resources",
    "api-versions",
    "cluster-info",
    "version",
    "events",
    "wait",
    "diff",
})

# Commands that require subcommand validation
# Format: command -> set of allowed subcommands
SAFE_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "config": frozenset({
        "view",
        "get-contexts",
        "current-context",
        "use-context",
    }),
    "auth": frozenset({
        "can-i",
        "whoami",
    }),
    "rollout": frozenset({
        "status",
        "history",
    }),
}

# Global flags that can appear anywhere (before or after command)
# These are safe and don't affect the read-only nature of commands
SAFE_GLOBAL_FLAGS: frozenset[str] = frozenset({
    "-n", "--namespace",
    "-A", "--all-namespaces",
    "--context",
    "--kubeconfig",
    "-o", "--output",
    "-l", "--selector",
    "--field-selector",
    "-w", "--watch",
    "--watch-only",
    "-v", "--v",
    "--request-timeout",
    "--server", "-s",
    "--token",
    "--user",
    "--cluster",
    "--certificate-authority",
    "--client-certificate",
    "--client-key",
    "--insecure-skip-tls-verify",
    "--tls-server-name",
    "--as",
    "--as-group",
    "--as-uid",
    "--cache-dir",
    "--disable-compression",
    "--help", "-h",
    "--show-labels",
    "--show-kind",
    "--sort-by",
    "--no-headers",
    "--chunk-size",
    "--allow-missing-template-keys",
    "--template",
    "--raw",
    "--ignore-not-found",
    "--show-managed-fields",
    "-f", "--filename",  # Safe for diff, get -f, etc.
    "-k", "--kustomize",  # Safe for get -k, diff -k (read-only)
    "-R", "--recursive",
    "--all",
    "--since",
    "--since-time",
    "--tail",
    "--timestamps",
    "-c", "--container",
    "-p", "--previous",
    "--prefix",
    "--limit-bytes",
    "--pod-running-timeout",
    "--follow",
    "--containers",
    "--max-log-requests",
    "--timeout",
    "--for",
})


def is_flag(arg: str) -> bool:
    """Check if an argument is a flag (starts with -)."""
    return arg.startswith("-")


def is_flag_with_value(flag: str) -> bool:
    """Check if a flag typically takes a value as the next argument."""
    # Flags that take values (not boolean flags)
    flags_with_values = {
        "-n", "--namespace",
        "--context",
        "--kubeconfig",
        "-o", "--output",
        "-l", "--selector",
        "--field-selector",
        "-v", "--v",
        "--request-timeout",
        "--server", "-s",
        "--token",
        "--user",
        "--cluster",
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--tls-server-name",
        "--as",
        "--as-group",
        "--as-uid",
        "--cache-dir",
        "--sort-by",
        "--chunk-size",
        "--template",
        "-f", "--filename",
        "-k", "--kustomize",
        "--since",
        "--since-time",
        "--tail",
        "-c", "--container",
        "--limit-bytes",
        "--pod-running-timeout",
        "--timeout",
        "--for",
        "--max-log-requests",
    }
    return flag in flags_with_values


def extract_command_and_subcommand(args: list[str]) -> tuple[str | None, str | None]:
    """Extract the kubectl command and subcommand from arguments.

    Handles global flags that can appear before the command.

    Returns:
        Tuple of (command, subcommand) where subcommand may be None.
    """
    command = None
    subcommand = None

    i = 0
    while i < len(args):
        arg = args[i]

        if is_flag(arg):
            # Skip flag and its value if applicable
            if "=" in arg:
                # Flag with value like --namespace=default
                i += 1
            elif is_flag_with_value(arg):
                # Skip next arg which is the value
                i += 2
            else:
                # Boolean flag
                i += 1
        else:
            # This is a positional argument (command or subcommand)
            if command is None:
                command = arg
                i += 1
            elif subcommand is None:
                subcommand = arg
                break
            else:
                break

    return command, subcommand


def is_command_allowed(args: list[str]) -> tuple[bool, str]:
    """Check if a kubectl command is allowed.

    Args:
        args: The arguments passed to kubectl (without 'kubectl' itself).

    Returns:
        Tuple of (is_allowed, reason).
        If allowed, reason is empty string.
        If not allowed, reason explains why.
    """
    if not args:
        # Just running kubectl with no args shows help, which is safe
        return True, ""

    command, subcommand = extract_command_and_subcommand(args)

    if command is None:
        # Only flags, no command - shows help or version, safe
        return True, ""

    # Check if it's a simple safe command
    if command in SAFE_COMMANDS:
        return True, ""

    # Check if it's a command that requires subcommand validation
    if command in SAFE_SUBCOMMANDS:
        allowed_subcommands = SAFE_SUBCOMMANDS[command]
        if subcommand is None:
            # Just the command without subcommand - block to be safe
            return False, f"Command '{command}' requires a subcommand. Allowed: {', '.join(sorted(allowed_subcommands))}"
        if subcommand in allowed_subcommands:
            return True, ""
        else:
            return False, f"Subcommand '{command} {subcommand}' is not allowed. Allowed subcommands for '{command}': {', '.join(sorted(allowed_subcommands))}"

    # Unknown command - block by default (safe approach)
    return False, f"Command '{command}' is not in the read-only allowlist"
