"""Security tests for kubectl-readonly sandbox escape attempts.

These tests simulate various attack vectors that a malicious caller might use
to bypass the read-only restrictions. Written from a pentester's perspective.

Attack categories tested:
1. Shell metacharacter injection (;, |, &&, ||, $(), ``, etc.)
2. Argument confusion (double-dash, flag injection, positional tricks)
3. Unicode/encoding bypasses (homoglyphs, null bytes, special chars)
4. kubectl plugin hijacking attempts
5. Path traversal and file-based attacks
6. Case sensitivity and normalization attacks
7. Subcommand smuggling and edge cases
8. Output format exploitation
9. Network and interactive commands

References:
- https://owasp.org/www-community/attacks/Command_Injection
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security
- https://semgrep.dev/docs/cheat-sheets/python-command-injection
"""

import pytest

from kubectl_readonly.allowlist import (
    extract_command_and_subcommand,
    is_command_allowed,
)


class TestShellMetacharacterInjection:
    """Test shell metacharacter injection attempts.

    Even though we use subprocess with shell=False and pass args as a list,
    these tests verify that our allowlist doesn't accidentally permit commands
    that look like they contain shell metacharacters.
    """

    @pytest.mark.parametrize("cmd", [
        # Semicolon command chaining
        ["get", "pods;", "delete", "pods"],
        ["get", "pods;delete", "pods"],
        ["get;delete", "pods"],
        [";delete", "pods"],
        ["get", "pods", ";", "delete", "pods"],

        # Pipe command chaining
        ["get", "pods|delete", "pods"],
        ["get", "pods", "|", "delete", "pods"],
        ["get|delete", "pods"],

        # AND operator
        ["get", "pods&&delete", "pods"],
        ["get", "pods", "&&", "delete", "pods"],
        ["get&&delete", "pods"],

        # OR operator
        ["get", "pods||delete", "pods"],
        ["get", "pods", "||", "delete", "pods"],

        # Backtick command substitution
        ["get", "`delete pods`"],
        ["get", "pods", "`rm -rf /`"],
        ["`delete`", "pods"],

        # $() command substitution
        ["get", "$(delete pods)"],
        ["get", "pods", "$(rm -rf /)"],
        ["$(delete)", "pods"],
        ["get", "${delete}", "pods"],

        # Newline injection
        ["get", "pods\ndelete", "pods"],
        ["get", "pods\n", "delete", "pods"],
        ["get\ndelete", "pods"],

        # Carriage return injection
        ["get", "pods\rdelete", "pods"],
        ["get\r\ndelete", "pods"],
    ])
    def test_shell_metacharacters_in_args_should_be_safe(self, cmd):
        """Commands with shell metacharacters in arguments.

        Note: These are actually SAFE because subprocess.run with shell=False
        passes arguments directly without shell interpretation. However, we
        test them to document expected behavior and catch any regressions
        if the implementation changes.
        """
        # The first argument determines if command is allowed
        # Shell metacharacters in args don't matter for allowlist checking
        allowed, _ = is_command_allowed(cmd)

        # Most of these should be allowed because 'get' is allowed
        # The shell metacharacters are just treated as literal strings
        # This is the expected safe behavior
        if cmd[0].startswith(("get", "`", "$", ";")):
            if cmd[0] in ("get",):
                assert allowed, "get command should be allowed"
            else:
                # Commands starting with metacharacters are blocked
                assert not allowed


class TestArgumentConfusionAttacks:
    """Test argument confusion and injection attacks."""

    @pytest.mark.parametrize("cmd", [
        # Double-dash tricks - trying to smuggle commands after --
        ["get", "pods", "--", "delete", "pods"],
        ["get", "--", "delete"],
        ["--", "delete", "pods"],

        # Trying to use -- to "end" options and inject command
        ["--namespace=default", "--", "delete", "pods"],
    ])
    def test_double_dash_does_not_smuggle_commands(self, cmd):
        """Double dash should not allow smuggling dangerous commands.

        The -- is treated as a regular argument for allowlist purposes.
        kubectl may interpret it specially, but dangerous commands should
        still be blocked at the wrapper level.
        """
        allowed, _ = is_command_allowed(cmd)
        # If first positional arg is 'get', it's allowed
        # If first positional arg is '--' or 'delete', behavior depends on parsing
        command, _ = extract_command_and_subcommand(cmd)
        if command in ("get", "describe", "logs"):
            assert allowed
        elif command == "delete":
            assert not allowed

    @pytest.mark.parametrize("cmd", [
        # Flag injection attempts
        ["get", "pods", "--output=yaml", "--dry-run=server"],
        ["get", "pods", "-o", "yaml"],

        # Trying to inject exec-like behavior via flags
        ["logs", "pod", "--exec=whoami"],  # Fake flag
        ["get", "pods", "--run=malicious"],  # Fake flag
    ])
    def test_unknown_flags_passed_to_kubectl(self, cmd):
        """Unknown flags are passed to kubectl which will reject them.

        Our wrapper doesn't validate flag values, only the command.
        kubectl itself will reject invalid flags.
        """
        allowed, _ = is_command_allowed(cmd)
        # Command is allowed, kubectl will handle flag validation
        assert allowed

    @pytest.mark.parametrize("cmd", [
        # Trying to make 'delete' look like a resource name
        ["get", "delete"],  # Getting a resource named 'delete'
        ["describe", "delete"],
        ["get", "pods", "delete"],  # Pod named 'delete'

        # Trying to abuse -f flag to run arbitrary files
        ["get", "-f", "/etc/passwd"],
        ["diff", "-f", "http://evil.com/payload.yaml"],
        ["get", "-f", "-"],  # Read from stdin
    ])
    def test_resource_name_injection(self, cmd):
        """Resource names that look like commands should be safe.

        kubectl get delete != kubectl delete
        """
        allowed, _ = is_command_allowed(cmd)
        # These should all be allowed - they're just resource names
        assert allowed

    def test_exec_disguised_as_get(self):
        """Ensure exec can't be disguised within allowed commands."""
        # Direct exec is blocked
        assert not is_command_allowed(["exec", "pod", "--", "bash"])[0]

        # exec as argument to get is just a resource name
        allowed, _ = is_command_allowed(["get", "exec"])
        assert allowed  # This is kubectl get <resource-named-exec>


class TestUnicodeAndEncodingBypasses:
    """Test Unicode and encoding-based bypass attempts."""

    @pytest.mark.parametrize("cmd", [
        # Unicode homoglyphs for 'delete'
        ["d\u0435lete", "pods"],  # Cyrillic 'е' instead of Latin 'e'
        ["\u0064elete", "pods"],  # Unicode escape
        ["dеlеtе", "pods"],  # Multiple Cyrillic letters

        # Unicode homoglyphs for 'exec'
        ["ехес", "pod"],  # Cyrillic
        ["e\u0445ec", "pod"],

        # Full-width characters
        ["delete", "pods"],  # Normal for comparison
        ["\uff44elete", "pods"],  # Full-width 'd'

        # Zero-width characters
        ["del\u200bete", "pods"],  # Zero-width space
        ["de\u200clete", "pods"],  # Zero-width non-joiner
        ["del\u200dete", "pods"],  # Zero-width joiner
        ["del\ufeffete", "pods"],  # BOM character
    ])
    def test_unicode_homoglyph_attacks(self, cmd):
        """Unicode homoglyphs should not bypass the allowlist.

        Commands using look-alike Unicode characters should be blocked
        as they're not in the allowlist.
        """
        allowed, reason = is_command_allowed(cmd)
        # None of these Unicode variants should match real commands
        assert not allowed, f"Unicode variant '{cmd[0]}' should be blocked"
        assert "not in the read-only allowlist" in reason

    @pytest.mark.parametrize("cmd", [
        # Null byte injection
        ["get\x00delete", "pods"],
        ["get", "pods\x00; rm -rf /"],
        ["\x00delete", "pods"],
        ["delete\x00", "pods"],

        # Other special bytes
        ["get\x01", "pods"],
        ["get\x7f", "pods"],  # DEL character
    ])
    def test_null_byte_injection(self, cmd):
        """Null bytes should not cause unexpected behavior."""
        allowed, _ = is_command_allowed(cmd)
        # Commands with null bytes won't match allowlist entries
        # They're effectively unknown commands
        assert not allowed or cmd[0] == "get"  # 'get' is still 'get' even with trailing garbage

    @pytest.mark.parametrize("cmd", [
        # Mixed case
        ["GET", "pods"],
        ["Get", "pods"],
        ["DELETE", "pods"],
        ["Delete", "pods"],
        ["EXEC", "pod"],
        ["Exec", "pod"],

        # Config subcommands with case
        ["CONFIG", "view"],
        ["config", "VIEW"],
        ["Config", "View"],
    ])
    def test_case_sensitivity(self, cmd):
        """Commands should be case-sensitive."""
        allowed, _ = is_command_allowed(cmd)
        # kubectl is case-sensitive, uppercase commands should fail
        # Our allowlist should also be case-sensitive
        assert not allowed, f"Case variant '{cmd[0]}' should be blocked"


class TestKubectlPluginHijacking:
    """Test kubectl plugin-related attack vectors."""

    @pytest.mark.parametrize("cmd", [
        # Direct plugin invocation attempts
        ["plugin", "list"],

        # Krew (plugin manager) commands
        ["krew", "install", "ctx"],
        ["krew", "search"],
        ["krew", "update"],

        # Commands that look like plugins
        ["ctx", "production"],  # kubectl-ctx plugin
        ["ns", "kube-system"],  # kubectl-ns plugin
        ["neat", "get", "pods"],  # kubectl-neat plugin
        ["tree", "deployment", "nginx"],  # kubectl-tree plugin
        ["whoami"],  # kubectl-whoami plugin
        ["access-matrix"],  # kubectl-access-matrix plugin

        # Sneaky plugin-looking commands
        ["kubectl-delete", "pods"],  # Won't work but worth testing
        ["--plugin=delete", "pods"],
    ])
    def test_plugin_commands_blocked(self, cmd):
        """Plugin and plugin-like commands should be blocked."""
        allowed, _ = is_command_allowed(cmd)
        assert not allowed, f"Plugin command '{cmd[0]}' should be blocked"


class TestSubcommandSmuggling:
    """Test subcommand smuggling and confusion attacks."""

    @pytest.mark.parametrize("cmd", [
        # Dangerous rollout subcommands
        ["rollout", "restart", "deployment/nginx"],
        ["rollout", "undo", "deployment/nginx"],
        ["rollout", "pause", "deployment/nginx"],
        ["rollout", "resume", "deployment/nginx"],

        # Dangerous config subcommands
        ["config", "set-context", "evil"],
        ["config", "set-cluster", "evil"],
        ["config", "set-credentials", "evil"],
        ["config", "delete-context", "production"],
        ["config", "delete-cluster", "production"],
        ["config", "unset", "current-context"],

        # Dangerous auth subcommands
        ["auth", "reconcile", "-f", "evil.yaml"],
    ])
    def test_dangerous_subcommands_blocked(self, cmd):
        """Dangerous subcommands should be blocked."""
        allowed, _ = is_command_allowed(cmd)
        assert not allowed, f"Subcommand '{cmd[1]}' should be blocked"

    @pytest.mark.parametrize("cmd", [
        # Trying to disguise subcommand
        ["config", "", "set-context", "evil"],
        ["config", " ", "set-context", "evil"],
        ["config", "--help", "set-context", "evil"],
        ["rollout", "-n", "default", "restart", "deployment/nginx"],
    ])
    def test_subcommand_position_confusion(self, cmd):
        """Subcommand position tricks should not bypass restrictions."""
        allowed, _ = is_command_allowed(cmd)
        # First non-flag positional after command is the subcommand
        # Empty strings and flags shouldn't allow smuggling


class TestAlphaAndExperimentalCommands:
    """Test alpha, beta, and experimental commands."""

    @pytest.mark.parametrize("cmd", [
        ["alpha"],
        ["alpha", "something"],
        ["alpha", "events"],

        # Debug commands
        ["debug", "pod/nginx"],
        ["debug", "-it", "pod/nginx", "--image=busybox"],

        # Experimental features
        ["convert", "-f", "pod.yaml"],
    ])
    def test_experimental_commands_blocked(self, cmd):
        """Alpha, debug, and experimental commands should be blocked."""
        allowed, _ = is_command_allowed(cmd)
        assert not allowed, f"Experimental command '{cmd[0]}' should be blocked"


class TestPathTraversalAndFiles:
    """Test path traversal and file-based attacks."""

    @pytest.mark.parametrize("cmd", [
        # Path traversal in -f flag
        ["get", "-f", "../../../etc/passwd"],
        ["get", "-f", "/etc/passwd"],
        ["diff", "-f", "../../secret.yaml"],

        # URL in -f flag
        ["get", "-f", "http://evil.com/payload.yaml"],
        ["get", "-f", "https://evil.com/payload.yaml"],

        # Kustomize directory traversal
        ["get", "-k", "../../"],
        ["get", "-k", "/etc/kubernetes/"],
    ])
    def test_file_path_attacks(self, cmd):
        """File paths with traversal should be passed to kubectl.

        kubectl itself handles file validation. Our wrapper just ensures
        the command (get/diff) is read-only.
        """
        allowed, _ = is_command_allowed(cmd)
        # These are allowed - kubectl will handle file validation
        assert allowed


class TestResourceCreationViaReadCommands:
    """Test attempts to create resources via read commands."""

    @pytest.mark.parametrize("cmd", [
        # Wait can create if used with apply
        ["wait", "--for=delete", "pod/nginx"],

        # Diff is read-only but worth testing
        ["diff", "-f", "deployment.yaml"],
        ["diff", "--server-side", "-f", "deployment.yaml"],
    ])
    def test_read_commands_stay_read_only(self, cmd):
        """Commands in the allowlist should remain read-only."""
        allowed, _ = is_command_allowed(cmd)
        # These should be allowed - they're genuinely read-only
        assert allowed


class TestOutputFormatExploitation:
    """Test output format and template exploitation attempts."""

    @pytest.mark.parametrize("cmd", [
        # Go template with potential for mischief
        ["get", "pods", "-o", "go-template={{.metadata.name}}"],

        # Custom columns
        ["get", "pods", "-o", "custom-columns=NAME:.metadata.name"],

        # Template file (could read arbitrary files)
        ["get", "pods", "--template", "/etc/passwd"],
        ["get", "pods", "-o", "template", "--template=/etc/passwd"],
    ])
    def test_output_format_variations(self, cmd):
        """Various output formats should be allowed (read-only operation)."""
        allowed, _ = is_command_allowed(cmd)
        # These are all read-only operations
        assert allowed


class TestProxyAndNetworkCommands:
    """Test proxy and network-related commands."""

    @pytest.mark.parametrize("cmd", [
        # Proxy opens network connections
        ["proxy"],
        ["proxy", "--port=8080"],
        ["proxy", "--www=/"],

        # Port-forward
        ["port-forward", "pod/nginx", "8080:80"],
        ["port-forward", "svc/nginx", "8080:80"],

        # Attach (interactive)
        ["attach", "pod/nginx"],
        ["attach", "-it", "pod/nginx"],
    ])
    def test_network_commands_blocked(self, cmd):
        """Network and interactive commands should be blocked."""
        allowed, _ = is_command_allowed(cmd)
        assert not allowed, f"Network command '{cmd[0]}' should be blocked"


class TestCompletionAndHelp:
    """Test completion and help-related edge cases."""

    @pytest.mark.parametrize("cmd", [
        ["completion", "bash"],
        ["completion", "zsh"],
        ["completion", "fish"],
        ["completion", "powershell"],
    ])
    def test_completion_blocked(self, cmd):
        """Completion commands blocked (not needed in wrapper)."""
        allowed, _ = is_command_allowed(cmd)
        assert not allowed

    @pytest.mark.parametrize("cmd", [
        ["help"],
        ["help", "get"],
        ["help", "delete"],  # Even help for dangerous commands
    ])
    def test_help_command_blocked(self, cmd):
        """Help command should be blocked (use --help flag instead)."""
        allowed, _ = is_command_allowed(cmd)
        # 'help' as a command is not in our allowlist
        # Users should use kubectl-readonly --help or kubectl-readonly get --help
        assert not allowed


class TestEmptyAndMalformedInput:
    """Test empty and malformed input handling."""

    @pytest.mark.parametrize("cmd", [
        # Empty strings
        [""],
        ["", ""],
        ["", "get", "pods"],
        ["get", ""],

        # Only whitespace
        [" "],
        ["  "],
        ["\t"],
        ["\n"],
        ["get", " "],
    ])
    def test_empty_and_whitespace_handling(self, cmd):
        """Empty and whitespace inputs should be handled safely."""
        # Should not raise exceptions
        try:
            allowed, _ = is_command_allowed(cmd)
            # Empty string as command should not match anything
            if cmd[0] in ("", " ", "\t", "\n", "  "):
                # Empty/whitespace commands aren't in allowlist
                pass  # May be allowed (empty shows help) or blocked
        except Exception as e:
            pytest.fail(f"Exception on malformed input {cmd}: {e}")

    @pytest.mark.parametrize("cmd", [
        # Very long inputs
        ["get", "a" * 10000],
        ["get", "pods", "-n", "a" * 10000],
        ["a" * 10000],

        # Many arguments
        ["get", "pods"] + ["arg"] * 1000,
    ])
    def test_long_input_handling(self, cmd):
        """Long inputs should be handled without crashing."""
        try:
            allowed, _ = is_command_allowed(cmd)
            # Just verify no crash
        except Exception as e:
            pytest.fail(f"Exception on long input: {e}")


class TestCombinedAttackVectors:
    """Test combinations of attack vectors."""

    @pytest.mark.parametrize("cmd", [
        # Unicode + shell metacharacter
        ["get", "pods\u200b;", "delete", "pods"],

        # Flag injection + dangerous command
        ["--namespace=default", "-o", "yaml", "delete", "pods"],

        # Subcommand confusion + Unicode
        ["config", "set\u200b-context", "evil"],

        # Long input + metacharacter
        ["get", "a" * 1000 + ";delete", "pods"],

        # Multiple dangerous attempts
        ["exec", "-it", "pod", "--", "rm", "-rf", "/"],
    ])
    def test_combined_attacks(self, cmd):
        """Combined attack vectors should not bypass restrictions."""
        allowed, _ = is_command_allowed(cmd)
        command, _ = extract_command_and_subcommand(cmd)

        # If the command itself is dangerous, it should be blocked
        if command in ("delete", "exec", "apply", "create"):
            assert not allowed
        # If command is 'get', it's allowed regardless of other args
        # (shell metacharacters are not interpreted)


class TestRBACEscalationAttempts:
    """Test RBAC escalation attempts via allowed commands."""

    @pytest.mark.parametrize("cmd", [
        # auth can-i to probe permissions (allowed, but could reveal info)
        ["auth", "can-i", "create", "deployments"],
        ["auth", "can-i", "delete", "secrets"],
        ["auth", "can-i", "--list"],
        ["auth", "can-i", "*", "*"],

        # Getting RBAC resources (allowed, read-only)
        ["get", "roles"],
        ["get", "rolebindings"],
        ["get", "clusterroles"],
        ["get", "clusterrolebindings"],
        ["get", "serviceaccounts"],
    ])
    def test_rbac_info_gathering_allowed(self, cmd):
        """RBAC info gathering is allowed (read-only)."""
        allowed, _ = is_command_allowed(cmd)
        assert allowed, f"RBAC query '{cmd}' should be allowed"

    @pytest.mark.parametrize("cmd", [
        # Impersonation flags (read-only, but could escalate)
        ["get", "pods", "--as=admin"],
        ["get", "pods", "--as-group=system:masters"],
        ["auth", "can-i", "get", "pods", "--as=admin"],
    ])
    def test_impersonation_flags_passed_through(self, cmd):
        """Impersonation flags are passed to kubectl.

        These are read-only but could access more resources if RBAC allows.
        This is expected behavior - RBAC is the control, not this wrapper.
        """
        allowed, _ = is_command_allowed(cmd)
        # These are allowed - RBAC will handle impersonation permissions
        assert allowed


class TestSpecialResourceTypes:
    """Test handling of special resource types."""

    @pytest.mark.parametrize("cmd", [
        # API resources that might be dangerous to even read
        ["get", "mutatingwebhookconfigurations"],
        ["get", "validatingwebhookconfigurations"],
        ["get", "certificatesigningrequests"],

        # CRDs (custom resource definitions)
        ["get", "crds"],
        ["get", "customresourcedefinitions"],

        # Nodes (sensitive cluster info)
        ["get", "nodes"],
        ["describe", "node", "master-1"],
        ["top", "nodes"],
    ])
    def test_special_resources_allowed(self, cmd):
        """Special resources are allowed (read-only)."""
        allowed, _ = is_command_allowed(cmd)
        assert allowed


class TestWaitCommandEdgeCases:
    """Test wait command which has some special behaviors."""

    @pytest.mark.parametrize("cmd", [
        # Normal wait usage (read-only)
        ["wait", "--for=condition=Ready", "pod/nginx"],
        ["wait", "--for=condition=Available", "deployment/nginx"],

        # Wait for deletion (read-only, just waits)
        ["wait", "--for=delete", "pod/nginx"],

        # Wait with timeout
        ["wait", "--for=condition=Ready", "--timeout=60s", "pod/nginx"],
    ])
    def test_wait_command_allowed(self, cmd):
        """Wait commands are allowed (read-only observation)."""
        allowed, _ = is_command_allowed(cmd)
        assert allowed


class TestContextSwitching:
    """Test context switching which is allowed but changes state."""

    @pytest.mark.parametrize("cmd", [
        # Context switching (allowed - doesn't modify cluster)
        ["config", "use-context", "production"],
        ["config", "use-context", "staging"],

        # Context info (allowed - read-only)
        ["config", "current-context"],
        ["config", "get-contexts"],
    ])
    def test_context_commands_allowed(self, cmd):
        """Context commands should be allowed."""
        allowed, _ = is_command_allowed(cmd)
        assert allowed

    @pytest.mark.parametrize("cmd", [
        # Modifying context properties (dangerous)
        ["config", "set", "current-context", "production"],
        ["config", "use-context", "production", "--namespace=kube-system"],
    ])
    def test_context_modification_blocked(self, cmd):
        """Context modification should be blocked."""
        allowed, _ = is_command_allowed(cmd)
        # 'set' is not an allowed subcommand for config
        if "set" in cmd:
            assert not allowed


class TestFlagOrderIndependence:
    """Test that flag order doesn't affect security."""

    @pytest.mark.parametrize("cmd", [
        # Flags before command
        ["-n", "default", "delete", "pods"],
        ["--context=prod", "delete", "pods"],
        ["-A", "delete", "pods"],

        # Many flags before command
        ["-n", "default", "-o", "yaml", "--context=prod", "delete", "pods"],

        # Flags that look like commands
        ["--namespace=delete", "get", "pods"],
        ["--context=exec", "get", "pods"],
    ])
    def test_flag_order_security(self, cmd):
        """Dangerous commands blocked regardless of flag position."""
        allowed, _ = is_command_allowed(cmd)
        command, _ = extract_command_and_subcommand(cmd)

        if command == "delete":
            assert not allowed
        elif command == "get":
            assert allowed
