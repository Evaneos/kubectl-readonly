"""Allowlist of read-only kubectl commands.

Philosophy: When in doubt, block. Better to have false negatives (blocking safe
commands) than false positives (allowing dangerous commands).
"""

# Secret resource types - accessing VALUES requires special handling
SECRET_RESOURCES: frozenset[str] = frozenset({
    "secret",
    "secrets",
})

# Output formats that expose secret values (base64 encoded data)
# These formats include the .data field which contains actual secret values
SECRET_EXPOSING_OUTPUT_FORMATS: frozenset[str] = frozenset({
    "yaml",
    "json",
    "jsonpath",
    "jsonpath-as-json",
    "jsonpath-file",
    "go-template",
    "go-template-file",
    "template",
    "templatefile",
})

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


def extract_resource_types(args: list[str]) -> list[str]:
    """Extract resource types from kubectl arguments.

    Resource types can appear in various forms:
    - kubectl get pods
    - kubectl get pod/nginx
    - kubectl get pods,services
    - kubectl get pod nginx
    - kubectl describe secret my-secret

    Returns:
        List of resource type names (lowercase, singular or plural).
    """
    resources = []
    command, _ = extract_command_and_subcommand(args)

    if command not in ("get", "describe", "wait", "events"):
        return resources

    i = 0
    found_command = False

    while i < len(args):
        arg = args[i]

        if is_flag(arg):
            # Skip flag and its value if applicable
            if "=" in arg:
                i += 1
            elif is_flag_with_value(arg):
                i += 2
            else:
                i += 1
            continue

        if not found_command:
            if arg == command:
                found_command = True
            i += 1
            continue

        # After the command, look for resource types
        # Handle comma-separated resources: pods,secrets,configmaps
        for part in arg.split(","):
            # Handle type/name format: secret/my-secret
            if "/" in part:
                resource_type = part.split("/")[0]
            else:
                resource_type = part

            # Normalize to lowercase
            resource_type = resource_type.lower()

            # Skip if it looks like a name (contains certain patterns)
            # Resource types are typically simple words
            if resource_type and not resource_type.startswith("-"):
                resources.append(resource_type)

        i += 1

    return resources


def get_output_format(args: list[str]) -> str | None:
    """Extract the output format from arguments.

    Returns:
        The output format (e.g., 'yaml', 'json', 'jsonpath={...}') or None.
    """
    for i, arg in enumerate(args):
        if arg in ("-o", "--output") and i + 1 < len(args):
            return args[i + 1]
        elif arg.startswith("-o="):
            return arg[3:]
        elif arg.startswith("--output="):
            return arg[9:]
        elif arg.startswith("-o") and len(arg) > 2:
            # Handle -ojson, -oyaml format
            return arg[2:]

    return None


def is_secret_value_exposing_format(output_format: str | None) -> bool:
    """Check if the output format would expose secret values.

    Args:
        output_format: The output format string (e.g., 'yaml', 'jsonpath={.data}')

    Returns:
        True if this format would expose the secret's .data field.
    """
    if output_format is None:
        return False

    # Normalize and check base format
    format_lower = output_format.lower()

    # Check for exact matches or prefix matches (e.g., 'jsonpath={...}')
    for exposing_format in SECRET_EXPOSING_OUTPUT_FORMATS:
        if format_lower == exposing_format or format_lower.startswith(exposing_format + "="):
            return True

    return False


def contains_secret_resource(args: list[str]) -> tuple[bool, str | None]:
    """Check if the command targets a secret resource type.

    Returns:
        Tuple of (targets_secret, resource_name).
    """
    resources = extract_resource_types(args)

    for resource in resources:
        if resource in SECRET_RESOURCES:
            return True, resource

    return False, None


def contains_raw_secrets_access(args: list[str]) -> bool:
    """Check if --raw flag is used to access secrets API endpoints.

    The --raw flag allows direct API access and can bypass resource type checks.
    We need to block any --raw access to secrets endpoints.
    """
    raw_value = None

    for i, arg in enumerate(args):
        if arg == "--raw" and i + 1 < len(args):
            raw_value = args[i + 1]
            break
        elif arg.startswith("--raw="):
            raw_value = arg[6:]  # Remove "--raw=" prefix
            break

    if raw_value is None:
        return False

    # Check if the raw path contains secrets
    raw_lower = raw_value.lower()
    sensitive_patterns = [
        "/secrets",
        "/secret/",
        "secrets/",
    ]

    for pattern in sensitive_patterns:
        if pattern in raw_lower:
            return True

    return False


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
        # Check if accessing secrets
        targets_secret, resource = contains_secret_resource(args)
        if targets_secret:
            # Allow listing/describing secrets (metadata only)
            # Block output formats that expose the actual secret values
            output_format = get_output_format(args)
            if is_secret_value_exposing_format(output_format):
                return False, f"Output format '{output_format}' exposes secret values. Use default format or '-o name' to see secret metadata only."

        # Block --raw access to secrets API endpoints (always exposes values)
        if contains_raw_secrets_access(args):
            return False, "Access to secrets via --raw is not allowed (exposes secret values)"

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
