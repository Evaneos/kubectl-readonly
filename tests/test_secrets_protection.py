"""Security tests for secrets protection in kubectl-readonly.

These tests verify that secret VALUES are blocked while metadata is allowed.
The goal is to prevent credential leakage while still allowing investigation
of which secrets exist and how they're configured.

Allowed (metadata only):
- kubectl-readonly get secrets          -> shows NAME, TYPE, DATA, AGE
- kubectl-readonly get secrets -o wide  -> same as above
- kubectl-readonly get secrets -o name  -> shows secret names only
- kubectl-readonly describe secret X    -> shows size, not values

Blocked (exposes values):
- kubectl-readonly get secrets -o yaml  -> exposes base64 .data
- kubectl-readonly get secrets -o json  -> exposes base64 .data
- kubectl-readonly get secrets -o jsonpath=... -> can extract .data
- kubectl-readonly get --raw /api/v1/secrets -> raw API access
"""

import pytest

from kubectl_readonly.allowlist import is_command_allowed


class TestSecretsMetadataAllowed:
    """Test that secrets metadata (list, describe) is allowed."""

    @pytest.mark.parametrize("cmd", [
        # Basic listing - shows NAME, TYPE, DATA count, AGE
        ["get", "secrets"],
        ["get", "secret"],
        ["get", "secrets", "--all-namespaces"],
        ["get", "secrets", "-A"],
        ["get", "secrets", "-n", "kube-system"],
        ["get", "secrets", "--show-labels"],

        # With flags before command
        ["-n", "default", "get", "secrets"],
        ["--context=prod", "get", "secrets"],

        # Describe shows metadata only (size, not values)
        ["describe", "secret", "my-secret"],
        ["describe", "secrets"],

        # Safe output formats
        ["get", "secrets", "-o", "name"],
        ["get", "secrets", "-o", "wide"],
        ["get", "secret", "my-secret", "-o", "name"],

        # Case variations (resource names are case-insensitive)
        ["get", "SECRETS"],
        ["get", "Secret"],
        ["get", "Secrets"],
    ])
    def test_secrets_metadata_allowed(self, cmd):
        """Secrets metadata (list, describe) should be allowed."""
        allowed, reason = is_command_allowed(cmd)
        assert allowed, f"Command {cmd} should be ALLOWED (metadata only): {reason}"


class TestSecretsValuesBlocked:
    """Test that output formats exposing secret values are blocked."""

    @pytest.mark.parametrize("cmd", [
        # YAML exposes .data field with base64 values
        ["get", "secrets", "-o", "yaml"],
        ["get", "secret", "my-secret", "-o", "yaml"],
        ["get", "secret/my-secret", "-o", "yaml"],

        # JSON exposes .data field with base64 values
        ["get", "secrets", "-o", "json"],
        ["get", "secret", "my-secret", "-o", "json"],

        # Compact forms
        ["get", "secrets", "-ojson"],
        ["get", "secrets", "-oyaml"],

        # jsonpath can extract .data
        ["get", "secrets", "-o", "jsonpath={.data}"],
        ["get", "secret", "my-secret", "-o", "jsonpath={.items[*].data}"],
        ["get", "secrets", "-o", "jsonpath-as-json={.data}"],

        # go-template can extract data
        ["get", "secrets", "-o", "go-template={{.data}}"],
        ["get", "secrets", "-o", "go-template-file=template.txt"],

        # template format
        ["get", "secrets", "-o", "template", "--template={{.data}}"],
        ["get", "secrets", "-o", "templatefile=template.txt"],

        # Comma-separated resources with secrets
        ["get", "pods,secrets", "-o", "yaml"],
        ["get", "secrets,pods", "-o", "json"],
        ["get", "configmaps,secrets,pods", "-o", "yaml"],
    ])
    def test_secrets_values_blocked(self, cmd):
        """Secrets VALUES (via -o yaml/json/jsonpath) must be blocked."""
        allowed, reason = is_command_allowed(cmd)
        assert not allowed, f"Command {cmd} should be BLOCKED (exposes secret values)"
        assert "secret" in reason.lower() or "format" in reason.lower()


class TestSecretsRawApiBlocked:
    """Test that --raw access to secrets API endpoints is blocked."""

    @pytest.mark.parametrize("cmd", [
        # Direct API access to secrets
        ["get", "--raw", "/api/v1/secrets"],
        ["get", "--raw", "/api/v1/namespaces/default/secrets"],
        ["get", "--raw=/api/v1/secrets"],
        ["get", "--raw=/api/v1/namespaces/kube-system/secrets"],
        ["get", "--raw", "/api/v1/namespaces/default/secrets/my-secret"],

        # Case variations in path
        ["get", "--raw", "/api/v1/SECRETS"],
        ["get", "--raw", "/api/v1/Secrets"],
    ])
    def test_raw_secrets_blocked(self, cmd):
        """--raw access to secrets endpoints must be blocked."""
        allowed, reason = is_command_allowed(cmd)
        assert not allowed, f"--raw access to secrets should be blocked: {cmd}"
        assert "secrets" in reason.lower() or "raw" in reason.lower()

    @pytest.mark.parametrize("cmd", [
        # Non-sensitive --raw endpoints - allowed
        ["get", "--raw", "/api/v1/pods"],
        ["get", "--raw=/api/v1/namespaces"],
        ["get", "--raw", "/api/v1/nodes"],
        ["get", "--raw", "/healthz"],
        ["get", "--raw", "/api/v1/configmaps"],
    ])
    def test_raw_non_sensitive_allowed(self, cmd):
        """--raw access to non-sensitive endpoints is allowed."""
        allowed, _ = is_command_allowed(cmd)
        assert allowed, f"--raw access to non-sensitive endpoint should be allowed: {cmd}"


class TestSecretsWithImpersonation:
    """Test that impersonation doesn't bypass secrets protection."""

    def test_impersonation_with_secrets_values_blocked(self):
        """Impersonation doesn't bypass secrets value blocking."""
        cmd = ["get", "secrets", "-o", "yaml", "--as=system:admin"]
        allowed, _ = is_command_allowed(cmd)
        assert not allowed, "Secrets values blocked even with impersonation"

    def test_impersonation_with_secrets_metadata_allowed(self):
        """Impersonation allows secrets metadata (list)."""
        cmd = ["get", "secrets", "--as=system:admin"]
        allowed, _ = is_command_allowed(cmd)
        assert allowed, "Secrets metadata allowed with impersonation"


class TestConfigMapsNotBlocked:
    """Test that ConfigMaps are not affected by secrets protection."""

    @pytest.mark.parametrize("cmd", [
        # ConfigMaps with -o yaml/json should be allowed
        ["get", "configmaps"],
        ["get", "cm", "my-config", "-o", "yaml"],
        ["get", "configmap", "my-config", "-o", "json"],
        ["get", "configmaps", "-o", "yaml"],
        ["get", "configmaps", "-o", "json"],
        ["describe", "configmap", "my-config"],

        # jsonpath on configmaps
        ["get", "configmaps", "-o", "jsonpath={.data}"],
    ])
    def test_configmaps_fully_allowed(self, cmd):
        """ConfigMaps are allowed with any output format."""
        allowed, _ = is_command_allowed(cmd)
        assert allowed, f"ConfigMaps should be allowed: {cmd}"


class TestSecretsBypassAttempts:
    """Test various attempts to bypass secrets protection."""

    @pytest.mark.parametrize("cmd", [
        # Different flag orderings
        ["-o", "yaml", "get", "secrets"],
        ["get", "-o", "yaml", "secrets"],
        ["get", "secrets", "-n", "default", "-o", "yaml"],

        # With other flags
        ["get", "secrets", "-o", "yaml", "--show-labels"],
        ["get", "secrets", "-o", "json", "-l", "app=test"],
        ["get", "secrets", "--output=yaml"],
        ["get", "secrets", "--output", "yaml"],
    ])
    def test_flag_ordering_doesnt_bypass(self, cmd):
        """Different flag orderings don't bypass protection."""
        allowed, _ = is_command_allowed(cmd)
        assert not allowed, f"Command {cmd} should be blocked"

    @pytest.mark.parametrize("cmd", [
        # Type/name format
        ["get", "secret/my-secret", "-o", "yaml"],
        ["get", "secret/my-secret", "-o", "json"],

        # Multiple resources
        ["get", "secret/a", "secret/b", "-o", "yaml"],
    ])
    def test_type_name_format_blocked(self, cmd):
        """secret/name format with value-exposing output is blocked."""
        allowed, _ = is_command_allowed(cmd)
        assert not allowed, f"Command {cmd} should be blocked"


class TestOutputFormatParsing:
    """Test that output format is correctly parsed in various forms."""

    @pytest.mark.parametrize("cmd,should_block", [
        # Blocked formats
        (["get", "secrets", "-o", "yaml"], True),
        (["get", "secrets", "-o=yaml"], True),
        (["get", "secrets", "-oyaml"], True),
        (["get", "secrets", "--output", "yaml"], True),
        (["get", "secrets", "--output=yaml"], True),

        # Allowed formats
        (["get", "secrets", "-o", "name"], False),
        (["get", "secrets", "-o=name"], False),
        (["get", "secrets", "-oname"], False),
        (["get", "secrets", "--output", "name"], False),
        (["get", "secrets", "--output=name"], False),
        (["get", "secrets", "-o", "wide"], False),
        (["get", "secrets", "-o", "custom-columns=NAME:.metadata.name"], False),
    ])
    def test_output_format_parsing(self, cmd, should_block):
        """Output format is correctly parsed in all forms."""
        allowed, _ = is_command_allowed(cmd)
        if should_block:
            assert not allowed, f"Command {cmd} should be blocked"
        else:
            assert allowed, f"Command {cmd} should be allowed"
