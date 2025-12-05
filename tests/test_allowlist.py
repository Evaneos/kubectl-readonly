"""Tests for the allowlist module."""

import pytest

from kubectl_readonly.allowlist import (
    extract_command_and_subcommand,
    is_command_allowed,
)


class TestExtractCommandAndSubcommand:
    """Tests for extract_command_and_subcommand function."""

    def test_simple_command(self):
        assert extract_command_and_subcommand(["get"]) == ("get", None)

    def test_command_with_args(self):
        assert extract_command_and_subcommand(["get", "pods"]) == ("get", "pods")

    def test_command_with_namespace_before(self):
        assert extract_command_and_subcommand(["-n", "default", "get", "pods"]) == ("get", "pods")

    def test_command_with_namespace_after(self):
        assert extract_command_and_subcommand(["get", "pods", "-n", "default"]) == ("get", "pods")

    def test_command_with_equals_flag(self):
        assert extract_command_and_subcommand(["--namespace=default", "get", "pods"]) == ("get", "pods")

    def test_config_subcommand(self):
        assert extract_command_and_subcommand(["config", "view"]) == ("config", "view")

    def test_config_subcommand_with_flags(self):
        assert extract_command_and_subcommand(["--kubeconfig=/path/to/config", "config", "use-context", "prod"]) == ("config", "use-context")

    def test_empty_args(self):
        assert extract_command_and_subcommand([]) == (None, None)

    def test_only_flags(self):
        assert extract_command_and_subcommand(["--help"]) == (None, None)

    def test_auth_subcommand(self):
        assert extract_command_and_subcommand(["auth", "can-i", "get", "pods"]) == ("auth", "can-i")

    def test_rollout_subcommand(self):
        assert extract_command_and_subcommand(["rollout", "status", "deployment/nginx"]) == ("rollout", "status")


class TestIsCommandAllowed:
    """Tests for is_command_allowed function."""

    # --- Allowed simple commands ---

    @pytest.mark.parametrize("cmd", [
        ["get", "pods"],
        ["get", "pods", "-n", "kube-system"],
        ["get", "pods", "--all-namespaces"],
        ["get", "pods", "-A"],
        ["get", "pods", "-o", "yaml"],
        ["get", "pods", "-o", "json"],
        ["get", "pods", "-w"],
        ["get", "deployment", "nginx", "-o", "wide"],
        ["describe", "pod", "my-pod"],
        ["describe", "node", "worker-1"],
        ["logs", "my-pod"],
        ["logs", "my-pod", "-f"],
        ["logs", "my-pod", "--tail=100"],
        ["logs", "my-pod", "-c", "container-name"],
        ["logs", "my-pod", "--previous"],
        ["top", "pods"],
        ["top", "nodes"],
        ["explain", "pods"],
        ["explain", "pods.spec"],
        ["api-resources"],
        ["api-versions"],
        ["cluster-info"],
        ["version"],
        ["events"],
        ["events", "-n", "default"],
        ["wait", "--for=condition=Ready", "pod/my-pod"],
        ["diff", "-f", "deployment.yaml"],
    ])
    def test_allowed_simple_commands(self, cmd):
        allowed, reason = is_command_allowed(cmd)
        assert allowed, f"Command {cmd} should be allowed but was blocked: {reason}"

    # --- Allowed subcommands ---

    @pytest.mark.parametrize("cmd", [
        ["config", "view"],
        ["config", "get-contexts"],
        ["config", "current-context"],
        ["config", "use-context", "production"],
        ["auth", "can-i", "get", "pods"],
        ["auth", "can-i", "create", "deployments"],
        ["auth", "whoami"],
        ["rollout", "status", "deployment/nginx"],
        ["rollout", "history", "deployment/nginx"],
    ])
    def test_allowed_subcommands(self, cmd):
        allowed, reason = is_command_allowed(cmd)
        assert allowed, f"Command {cmd} should be allowed but was blocked: {reason}"

    # --- Blocked dangerous commands ---

    @pytest.mark.parametrize("cmd", [
        ["delete", "pod", "my-pod"],
        ["delete", "pods", "--all"],
        ["create", "-f", "deployment.yaml"],
        ["apply", "-f", "deployment.yaml"],
        ["edit", "deployment", "nginx"],
        ["patch", "deployment", "nginx", "-p", '{"spec":{"replicas":3}}'],
        ["scale", "deployment", "nginx", "--replicas=5"],
        ["exec", "my-pod", "--", "ls"],
        ["exec", "-it", "my-pod", "--", "bash"],
        ["cp", "my-pod:/path/to/file", "/local/path"],
        ["port-forward", "my-pod", "8080:80"],
        ["attach", "my-pod"],
        ["run", "nginx", "--image=nginx"],
        ["expose", "deployment", "nginx", "--port=80"],
        ["set", "image", "deployment/nginx", "nginx=nginx:1.19"],
        ["label", "pod", "my-pod", "app=test"],
        ["annotate", "pod", "my-pod", "description=test"],
        ["taint", "node", "worker-1", "key=value:NoSchedule"],
        ["cordon", "worker-1"],
        ["uncordon", "worker-1"],
        ["drain", "worker-1"],
        ["autoscale", "deployment", "nginx", "--min=1", "--max=10"],
        ["debug", "my-pod"],
        ["replace", "-f", "deployment.yaml"],
    ])
    def test_blocked_dangerous_commands(self, cmd):
        allowed, reason = is_command_allowed(cmd)
        assert not allowed, f"Command {cmd} should be blocked but was allowed"
        assert reason, "Blocked commands should have a reason"

    # --- Blocked subcommands ---

    @pytest.mark.parametrize("cmd", [
        ["config", "set-context", "my-context"],
        ["config", "set-cluster", "my-cluster"],
        ["config", "set-credentials", "my-user"],
        ["config", "delete-context", "my-context"],
        ["config", "rename-context", "old", "new"],
        ["rollout", "restart", "deployment/nginx"],
        ["rollout", "undo", "deployment/nginx"],
        ["rollout", "pause", "deployment/nginx"],
        ["rollout", "resume", "deployment/nginx"],
    ])
    def test_blocked_subcommands(self, cmd):
        allowed, reason = is_command_allowed(cmd)
        assert not allowed, f"Command {cmd} should be blocked but was allowed"

    # --- Edge cases ---

    def test_empty_args_allowed(self):
        """Empty args just show help."""
        allowed, _ = is_command_allowed([])
        assert allowed

    def test_only_help_flag(self):
        """Just --help is allowed."""
        allowed, _ = is_command_allowed(["--help"])
        assert allowed

    def test_config_without_subcommand_blocked(self):
        """config without subcommand should be blocked."""
        allowed, reason = is_command_allowed(["config"])
        assert not allowed
        assert "requires a subcommand" in reason

    def test_unknown_command_blocked(self):
        """Unknown commands should be blocked."""
        allowed, reason = is_command_allowed(["unknown-command"])
        assert not allowed
        assert "not in the read-only allowlist" in reason

    def test_flags_before_command(self):
        """Flags before command should work."""
        allowed, _ = is_command_allowed(["--context=prod", "-n", "default", "get", "pods"])
        assert allowed

    def test_blocked_command_with_flags(self):
        """Blocked commands stay blocked even with flags."""
        allowed, _ = is_command_allowed(["--context=prod", "delete", "pod", "my-pod"])
        assert not allowed


class TestSecurityEdgeCases:
    """Security-focused edge case tests."""

    def test_plugin_commands_blocked(self):
        """Plugin commands (anything not in allowlist) should be blocked."""
        allowed, _ = is_command_allowed(["my-plugin", "arg1"])
        assert not allowed

    def test_krew_commands_blocked(self):
        """Krew plugin commands should be blocked."""
        allowed, _ = is_command_allowed(["krew", "install", "ctx"])
        assert not allowed

    def test_alpha_commands_blocked(self):
        """Alpha commands should be blocked."""
        allowed, _ = is_command_allowed(["alpha", "something"])
        assert not allowed

    def test_certificate_commands_blocked(self):
        """Certificate commands should be blocked."""
        allowed, _ = is_command_allowed(["certificate", "approve", "csr-name"])
        assert not allowed

    def test_proxy_command_blocked(self):
        """proxy command should be blocked (opens network connection)."""
        allowed, _ = is_command_allowed(["proxy"])
        assert not allowed

    def test_completion_blocked(self):
        """completion command is blocked (not needed, but safe to be cautious)."""
        allowed, _ = is_command_allowed(["completion", "bash"])
        assert not allowed
