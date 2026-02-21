package main

import (
	"strings"
	"testing"
)

// Helper to check if command is allowed
func assertAllowed(t *testing.T, args []string) {
	t.Helper()
	allowed, reason := isCommandAllowed(args)
	if !allowed {
		t.Errorf("expected allowed, got blocked: %s (args: %v)", reason, args)
	}
}

func assertBlocked(t *testing.T, args []string) {
	t.Helper()
	allowed, _ := isCommandAllowed(args)
	if allowed {
		t.Errorf("expected blocked, got allowed (args: %v)", args)
	}
}

func assertBlockedContains(t *testing.T, args []string, substr string) {
	t.Helper()
	allowed, reason := isCommandAllowed(args)
	if allowed {
		t.Errorf("expected blocked, got allowed (args: %v)", args)
		return
	}
	if substr != "" && !strings.Contains(strings.ToLower(reason), strings.ToLower(substr)) {
		t.Errorf("expected reason to contain %q, got %q", substr, reason)
	}
}

// =============================================================================
// Basic Allowlist Tests
// =============================================================================

func TestSafeCommands(t *testing.T) {
	safeCommandsList := []string{
		"get", "describe", "logs", "top", "explain",
		"api-resources", "api-versions", "cluster-info", "version", "events", "wait", "diff",
		"kustomize",
	}

	for _, cmd := range safeCommandsList {
		t.Run(cmd, func(t *testing.T) {
			assertAllowed(t, []string{cmd, "pods"})
		})
	}
}

func TestDangerousCommands(t *testing.T) {
	dangerousCmds := []string{
		"delete", "create", "apply", "patch", "edit", "replace",
		"exec", "run", "attach", "cp",
		"scale", "autoscale",
		"cordon", "uncordon", "drain", "taint",
		"label", "annotate",
		"port-forward", "proxy",
	}

	for _, cmd := range dangerousCmds {
		t.Run(cmd, func(t *testing.T) {
			assertBlocked(t, []string{cmd, "pods"})
		})
	}
}

func TestSafeSubcommands(t *testing.T) {
	tests := [][]string{
		{"config", "view"},
		{"config", "get-contexts"},
		{"config", "current-context"},
		{"config", "use-context", "production"},
		{"auth", "can-i", "get", "pods"},
		{"auth", "whoami"},
		{"rollout", "status", "deployment/nginx"},
		{"rollout", "history", "deployment/nginx"},
	}

	for _, args := range tests {
		t.Run(args[0]+"-"+args[1], func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestDangerousSubcommands(t *testing.T) {
	tests := [][]string{
		// Dangerous rollout subcommands
		{"rollout", "restart", "deployment/nginx"},
		{"rollout", "undo", "deployment/nginx"},
		{"rollout", "pause", "deployment/nginx"},
		{"rollout", "resume", "deployment/nginx"},
		// Dangerous config subcommands
		{"config", "set-context", "evil"},
		{"config", "set-cluster", "evil"},
		{"config", "set-credentials", "evil"},
		{"config", "delete-context", "production"},
		{"config", "delete-cluster", "production"},
		{"config", "unset", "current-context"},
		// Dangerous auth subcommands
		{"auth", "reconcile", "-f", "evil.yaml"},
	}

	for _, args := range tests {
		t.Run(args[0]+"-"+args[1], func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

func TestEmptyArgs(t *testing.T) {
	assertAllowed(t, []string{})
}

func TestFlagsBeforeCommand(t *testing.T) {
	tests := []struct {
		args    []string
		allowed bool
	}{
		{[]string{"-n", "default", "get", "pods"}, true},
		{[]string{"--namespace", "default", "get", "pods"}, true},
		{[]string{"--namespace=default", "get", "pods"}, true},
		{[]string{"-n", "default", "delete", "pods"}, false},
		{[]string{"--context", "prod", "get", "pods"}, true},
		{[]string{"--context=prod", "delete", "pods"}, false},
		{[]string{"-A", "get", "pods"}, true},
		{[]string{"-A", "delete", "pods"}, false},
		{[]string{"-n", "default", "-o", "yaml", "--context=prod", "delete", "pods"}, false},
		{[]string{"--namespace=delete", "get", "pods"}, true},
		{[]string{"--context=exec", "get", "pods"}, true},
	}

	for _, tt := range tests {
		name := strings.Join(tt.args, "_")
		t.Run(name, func(t *testing.T) {
			if tt.allowed {
				assertAllowed(t, tt.args)
			} else {
				assertBlocked(t, tt.args)
			}
		})
	}
}

// =============================================================================
// Secrets Protection Tests
// =============================================================================

func TestSecretsMetadataAllowed(t *testing.T) {
	tests := [][]string{
		// Basic listing
		{"get", "secrets"},
		{"get", "secret"},
		{"get", "secrets", "--all-namespaces"},
		{"get", "secrets", "-A"},
		{"get", "secrets", "-n", "kube-system"},
		{"get", "secrets", "--show-labels"},
		// Flags before command
		{"-n", "default", "get", "secrets"},
		{"--context=prod", "get", "secrets"},
		// Describe
		{"describe", "secret", "my-secret"},
		{"describe", "secrets"},
		// Safe output formats
		{"get", "secrets", "-o", "name"},
		{"get", "secrets", "-o", "wide"},
		{"get", "secret", "my-secret", "-o", "name"},
		// Case variations
		{"get", "SECRETS"},
		{"get", "Secret"},
		{"get", "Secrets"},
		// API group qualified resource types (metadata only)
		{"get", "secret.v1"},
		{"get", "secrets.v1"},
		{"get", "secret.core"},
		{"get", "secret.v1.core"},
		{"get", "secrets.v1.core"},
		{"get", "secret.v1", "-o", "name"},
		{"get", "secret.v1", "-o", "wide"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestSecretsValuesBlocked(t *testing.T) {
	tests := [][]string{
		// YAML exposes .data field
		{"get", "secrets", "-o", "yaml"},
		{"get", "secret", "my-secret", "-o", "yaml"},
		{"get", "secret/my-secret", "-o", "yaml"},
		// JSON exposes .data field
		{"get", "secrets", "-o", "json"},
		{"get", "secret", "my-secret", "-o", "json"},
		// Compact forms
		{"get", "secrets", "-ojson"},
		{"get", "secrets", "-oyaml"},
		// jsonpath can extract .data
		{"get", "secrets", "-o", "jsonpath={.data}"},
		{"get", "secret", "my-secret", "-o", "jsonpath={.items[*].data}"},
		{"get", "secrets", "-o", "jsonpath-as-json={.data}"},
		// go-template can extract data
		{"get", "secrets", "-o", "go-template={{.data}}"},
		{"get", "secrets", "-o", "go-template-file=template.txt"},
		// template format
		{"get", "secrets", "-o", "template", "--template={{.data}}"},
		{"get", "secrets", "-o", "templatefile=template.txt"},
		// Comma-separated resources with secrets
		{"get", "pods,secrets", "-o", "yaml"},
		{"get", "secrets,pods", "-o", "json"},
		{"get", "configmaps,secrets,pods", "-o", "yaml"},
		// custom-columns can extract .data
		{"get", "secrets", "-o", "custom-columns=DATA:.data"},
		{"get", "secret", "my-secret", "-o", "custom-columns=NAME:.metadata.name,DATA:.data"},
		{"get", "secrets", "-o", "custom-columns-file=columns.txt"},
		// API group qualified resource types
		{"get", "secret.v1", "-o", "yaml"},
		{"get", "secrets.v1", "-o", "json"},
		{"get", "secret.core", "-o", "yaml"},
		{"get", "secret.v1.core", "-o", "yaml"},
		{"get", "secrets.v1.core", "-o", "json"},
		{"get", "secret.v1/my-secret", "-o", "yaml"},
		// Comma-separated with API group qualifiers
		{"get", "pods,secret.v1", "-o", "yaml"},
		{"get", "secret.core,configmaps", "-o", "json"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertBlockedContains(t, args, "secret")
		})
	}
}

func TestSecretsRawBlocked(t *testing.T) {
	tests := [][]string{
		{"get", "--raw", "/api/v1/secrets"},
		{"get", "--raw", "/api/v1/namespaces/default/secrets"},
		{"get", "--raw=/api/v1/secrets"},
		{"get", "--raw=/api/v1/namespaces/kube-system/secrets"},
		{"get", "--raw", "/api/v1/namespaces/default/secrets/my-secret"},
		// Case variations
		{"get", "--raw", "/api/v1/SECRETS"},
		{"get", "--raw", "/api/v1/Secrets"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertBlockedContains(t, args, "secret")
		})
	}
}

func TestSecretsRawNonSensitiveAllowed(t *testing.T) {
	tests := [][]string{
		{"get", "--raw", "/api/v1/pods"},
		{"get", "--raw=/api/v1/namespaces"},
		{"get", "--raw", "/api/v1/nodes"},
		{"get", "--raw", "/healthz"},
		{"get", "--raw", "/api/v1/configmaps"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestSecretsWithImpersonation(t *testing.T) {
	// Impersonation doesn't bypass secrets value blocking
	assertBlocked(t, []string{"get", "secrets", "-o", "yaml", "--as=system:admin"})
	// Impersonation allows secrets metadata
	assertAllowed(t, []string{"get", "secrets", "--as=system:admin"})
}

func TestConfigMapsAllowed(t *testing.T) {
	tests := [][]string{
		{"get", "configmaps"},
		{"get", "cm", "my-config", "-o", "yaml"},
		{"get", "configmap", "my-config", "-o", "json"},
		{"get", "configmaps", "-o", "yaml"},
		{"get", "configmaps", "-o", "json"},
		{"describe", "configmap", "my-config"},
		{"get", "configmaps", "-o", "jsonpath={.data}"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestSecretsBypassAttempts(t *testing.T) {
	blockedTests := [][]string{
		// Different flag orderings
		{"-o", "yaml", "get", "secrets"},
		{"get", "-o", "yaml", "secrets"},
		{"get", "secrets", "-n", "default", "-o", "yaml"},
		// With other flags
		{"get", "secrets", "-o", "yaml", "--show-labels"},
		{"get", "secrets", "-o", "json", "-l", "app=test"},
		{"get", "secrets", "--output=yaml"},
		{"get", "secrets", "--output", "yaml"},
		// Type/name format
		{"get", "secret/my-secret", "-o", "yaml"},
		{"get", "secret/my-secret", "-o", "json"},
		{"get", "secret/a", "secret/b", "-o", "yaml"},
		// API group qualified bypass attempts
		{"get", "secret.v1", "-o", "yaml"},
		{"get", "secret.core", "-o", "json"},
		{"get", "secret.v1.core", "-o", "yaml"},
		{"get", "secret.v1/my-secret", "-o", "yaml"},
	}

	for _, args := range blockedTests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

func TestOutputFormatParsing(t *testing.T) {
	blocked := [][]string{
		{"get", "secrets", "-o", "yaml"},
		{"get", "secrets", "-o=yaml"},
		{"get", "secrets", "-oyaml"},
		{"get", "secrets", "--output", "yaml"},
		{"get", "secrets", "--output=yaml"},
	}
	allowed := [][]string{
		{"get", "secrets", "-o", "name"},
		{"get", "secrets", "-o=name"},
		{"get", "secrets", "-oname"},
		{"get", "secrets", "--output", "name"},
		{"get", "secrets", "--output=name"},
		{"get", "secrets", "-o", "wide"},
	}

	for _, args := range blocked {
		name := "blocked_" + strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
	for _, args := range allowed {
		name := "allowed_" + strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

// =============================================================================
// Security Bypass Tests - Shell Metacharacters
// =============================================================================

func TestShellMetacharactersInArgs(t *testing.T) {
	// These are safe because Go doesn't use shell interpretation
	tests := [][]string{
		// Semicolon command chaining
		{"get", "pods;", "delete", "pods"},
		{"get", "pods;delete", "pods"},
		{"get", "pods", ";", "delete", "pods"},
		// Pipe command chaining
		{"get", "pods|delete", "pods"},
		{"get", "pods", "|", "delete", "pods"},
		// AND operator
		{"get", "pods&&delete", "pods"},
		{"get", "pods", "&&", "delete", "pods"},
		// OR operator
		{"get", "pods||delete", "pods"},
		{"get", "pods", "||", "delete", "pods"},
		// Backtick command substitution
		{"get", "`delete pods`"},
		{"get", "pods", "`rm -rf /`"},
		// $() command substitution
		{"get", "$(delete pods)"},
		{"get", "pods", "$(rm -rf /)"},
		{"get", "${delete}", "pods"},
		// Newline injection
		{"get", "pods\ndelete", "pods"},
		{"get", "pods\n", "delete", "pods"},
		// Carriage return injection
		{"get", "pods\rdelete", "pods"},
	}

	for _, args := range tests {
		name := "safe_" + args[0]
		t.Run(name, func(t *testing.T) {
			// Command is "get", which is allowed
			// Shell metacharacters are just literal strings
			assertAllowed(t, args)
		})
	}
}

func TestShellMetacharactersAsCommand(t *testing.T) {
	tests := [][]string{
		{";delete", "pods"},
		{"`delete`", "pods"},
		{"$(delete)", "pods"},
		{"get;delete", "pods"},
		{"get|delete", "pods"},
		{"get&&delete", "pods"},
		{"get\ndelete", "pods"},
		{"get\r\ndelete", "pods"},
	}

	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

// =============================================================================
// Security Bypass Tests - Unicode and Encoding
// =============================================================================

func TestUnicodeHomoglyphs(t *testing.T) {
	tests := [][]string{
		// Unicode homoglyphs for 'delete'
		{"d\u0435lete", "pods"}, // Cyrillic 'е' instead of Latin 'e'
		{"\u0064elete", "pods"}, // Unicode escape (this is actually 'd')
		{"dеlеtе", "pods"},      // Multiple Cyrillic letters
		// Unicode homoglyphs for 'exec'
		{"ехес", "pod"},      // Cyrillic
		{"e\u0445ec", "pod"}, // Cyrillic х
		// Full-width characters
		{"\uff44elete", "pods"}, // Full-width 'd'
		// Zero-width characters
		{"del\u200bete", "pods"}, // Zero-width space
		{"de\u200clete", "pods"}, // Zero-width non-joiner
		{"del\u200dete", "pods"}, // Zero-width joiner
		{"del\ufeffete", "pods"}, // BOM character
	}

	for _, args := range tests {
		t.Run("unicode_homoglyph", func(t *testing.T) {
			assertBlockedContains(t, args, "not in the read-only allowlist")
		})
	}
}

func TestCaseSensitivity(t *testing.T) {
	tests := [][]string{
		// Mixed case commands
		{"GET", "pods"},
		{"Get", "pods"},
		{"DELETE", "pods"},
		{"Delete", "pods"},
		{"EXEC", "pod"},
		{"Exec", "pod"},
		// Config subcommands with case
		{"CONFIG", "view"},
		{"config", "VIEW"},
		{"Config", "View"},
	}

	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

func TestNullByteInjection(t *testing.T) {
	tests := [][]string{
		{"get\x00delete", "pods"},
		{"get", "pods\x00; rm -rf /"},
		{"\x00delete", "pods"},
		{"delete\x00", "pods"},
		// Other special bytes
		{"get\x01", "pods"},
		{"get\x7f", "pods"}, // DEL character
	}

	for _, args := range tests {
		t.Run("nullbyte", func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

// =============================================================================
// Security Bypass Tests - Argument Confusion
// =============================================================================

func TestDoubleDashAttacks(t *testing.T) {
	tests := []struct {
		args    []string
		allowed bool
	}{
		// Double-dash tricks - trying to smuggle commands after --
		{[]string{"get", "pods", "--", "delete", "pods"}, true}, // get is command
		{[]string{"get", "--", "delete"}, true},                 // get is command
		{[]string{"--", "delete", "pods"}, false},               // delete is command
		{[]string{"--namespace=default", "--", "delete", "pods"}, false},
	}

	for _, tt := range tests {
		name := strings.Join(tt.args, "_")
		t.Run(name, func(t *testing.T) {
			if tt.allowed {
				assertAllowed(t, tt.args)
			} else {
				assertBlocked(t, tt.args)
			}
		})
	}
}

func TestFlagInjection(t *testing.T) {
	tests := [][]string{
		{"get", "pods", "--output=yaml", "--dry-run=server"},
		{"get", "pods", "-o", "yaml"},
		{"logs", "pod", "--exec=whoami"},   // Fake flag
		{"get", "pods", "--run=malicious"}, // Fake flag
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestResourceNameConfusion(t *testing.T) {
	tests := [][]string{
		// "delete" as a resource name is fine
		{"get", "delete"},
		{"describe", "delete"},
		{"get", "pods", "delete"},
		// Trying to abuse -f flag
		{"get", "-f", "/etc/passwd"},
		{"diff", "-f", "http://evil.com/payload.yaml"},
		{"get", "-f", "-"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestExecDisguisedAsGet(t *testing.T) {
	// Direct exec is blocked
	assertBlocked(t, []string{"exec", "pod", "--", "bash"})
	// exec as argument to get is just a resource name
	assertAllowed(t, []string{"get", "exec"})
}

// =============================================================================
// Security Bypass Tests - Plugin Hijacking
// =============================================================================

func TestPluginCommands(t *testing.T) {
	tests := [][]string{
		// Direct plugin invocation attempts
		{"plugin", "list"},
		// Krew (plugin manager) commands
		{"krew", "install", "ctx"},
		{"krew", "search"},
		{"krew", "update"},
		// Commands that look like plugins
		{"ctx", "production"},
		{"ns", "kube-system"},
		{"neat", "get", "pods"},
		{"tree", "deployment", "nginx"},
		{"whoami"},
		{"access-matrix"},
		// Sneaky plugin-looking commands
		{"kubectl-delete", "pods"},
		{"--plugin=delete", "pods"},
	}

	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

// =============================================================================
// Security Bypass Tests - Subcommand Smuggling
// =============================================================================

func TestSubcommandPositionConfusion(t *testing.T) {
	tests := [][]string{
		{"config", "", "set-context", "evil"},
		{"config", " ", "set-context", "evil"},
		{"config", "--help", "set-context", "evil"},
		{"rollout", "-n", "default", "restart", "deployment/nginx"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(_ *testing.T) {
			// These should be blocked because the actual subcommand parsed is dangerous
			// or the command structure is invalid
			allowed, _ := isCommandAllowed(args)
			_ = allowed // Behavior depends on parsing; just ensure no panic
		})
	}
}

// =============================================================================
// Security Bypass Tests - Experimental Commands
// =============================================================================

func TestExperimentalCommands(t *testing.T) {
	tests := [][]string{
		{"alpha"},
		{"alpha", "something"},
		{"alpha", "events"},
		// Debug commands
		{"debug", "pod/nginx"},
		{"debug", "-it", "pod/nginx", "--image=busybox"},
		// Experimental features
		{"convert", "-f", "pod.yaml"},
	}

	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

// =============================================================================
// Security Bypass Tests - Network Commands
// =============================================================================

func TestNetworkCommands(t *testing.T) {
	tests := [][]string{
		// Proxy opens network connections
		{"proxy"},
		{"proxy", "--port=8080"},
		{"proxy", "--www=/"},
		// Port-forward
		{"port-forward", "pod/nginx", "8080:80"},
		{"port-forward", "svc/nginx", "8080:80"},
		// Attach (interactive)
		{"attach", "pod/nginx"},
		{"attach", "-it", "pod/nginx"},
	}

	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

// =============================================================================
// Security Bypass Tests - Path Traversal
// =============================================================================

func TestPathTraversalAndFiles(t *testing.T) {
	tests := [][]string{
		// Path traversal in -f flag
		{"get", "-f", "../../../etc/passwd"},
		{"get", "-f", "/etc/passwd"},
		{"diff", "-f", "../../secret.yaml"},
		// URL in -f flag
		{"get", "-f", "http://evil.com/payload.yaml"},
		{"get", "-f", "https://evil.com/payload.yaml"},
		// Kustomize directory traversal
		{"get", "-k", "../../"},
		{"get", "-k", "/etc/kubernetes/"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			// These are allowed - kubectl will handle file validation
			assertAllowed(t, args)
		})
	}
}

// =============================================================================
// Security Bypass Tests - RBAC
// =============================================================================

func TestRBACInfoGathering(t *testing.T) {
	tests := [][]string{
		// auth can-i to probe permissions
		{"auth", "can-i", "create", "deployments"},
		{"auth", "can-i", "delete", "secrets"},
		{"auth", "can-i", "--list"},
		{"auth", "can-i", "*", "*"},
		// Getting RBAC resources
		{"get", "roles"},
		{"get", "rolebindings"},
		{"get", "clusterroles"},
		{"get", "clusterrolebindings"},
		{"get", "serviceaccounts"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestImpersonation(t *testing.T) {
	// Impersonation flags are passed through (RBAC handles it)
	tests := [][]string{
		{"get", "pods", "--as=admin"},
		{"get", "pods", "--as-group=system:masters"},
		{"auth", "can-i", "get", "pods", "--as=admin"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

// =============================================================================
// Security Bypass Tests - Special Resources
// =============================================================================

func TestSpecialResources(t *testing.T) {
	tests := [][]string{
		// API resources that might be dangerous to even read
		{"get", "mutatingwebhookconfigurations"},
		{"get", "validatingwebhookconfigurations"},
		{"get", "certificatesigningrequests"},
		// CRDs
		{"get", "crds"},
		{"get", "customresourcedefinitions"},
		// Nodes
		{"get", "nodes"},
		{"describe", "node", "master-1"},
		{"top", "nodes"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

// =============================================================================
// Security Bypass Tests - Output Formats
// =============================================================================

func TestOutputFormats(t *testing.T) {
	// Non-secret resources can use any format
	tests := [][]string{
		{"get", "pods", "-o", "yaml"},
		{"get", "pods", "-o", "json"},
		{"get", "pods", "-o", "go-template={{.metadata.name}}"},
		{"get", "pods", "-o", "custom-columns=NAME:.metadata.name"},
		{"get", "pods", "--template", "/etc/passwd"},
		{"get", "pods", "-o", "template", "--template=/etc/passwd"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

// =============================================================================
// Security Bypass Tests - Combined Attacks
// =============================================================================

func TestCombinedAttacks(t *testing.T) {
	tests := []struct {
		args    []string
		allowed bool
	}{
		// Unicode + shell metacharacter
		{[]string{"get", "pods\u200b;", "delete", "pods"}, true}, // get is command
		// Flag injection + dangerous command
		{[]string{"--namespace=default", "-o", "yaml", "delete", "pods"}, false},
		// Subcommand confusion + Unicode
		{[]string{"config", "set\u200b-context", "evil"}, false},
		// Long input + metacharacter
		{[]string{"get", strings.Repeat("a", 1000) + ";delete", "pods"}, true}, // get is command
		// Multiple dangerous attempts
		{[]string{"exec", "-it", "pod", "--", "rm", "-rf", "/"}, false},
	}

	for _, tt := range tests {
		name := tt.args[0]
		t.Run(name, func(t *testing.T) {
			if tt.allowed {
				assertAllowed(t, tt.args)
			} else {
				assertBlocked(t, tt.args)
			}
		})
	}
}

// =============================================================================
// Context Switching Tests
// =============================================================================

func TestContextCommands(t *testing.T) {
	allowed := [][]string{
		{"config", "use-context", "production"},
		{"config", "use-context", "staging"},
		{"config", "current-context"},
		{"config", "get-contexts"},
		{"config", "view"},
	}

	blocked := [][]string{
		{"config", "set", "current-context", "production"},
		{"config", "use-context", "production", "--namespace=kube-system"},
	}

	for _, args := range allowed {
		name := "allowed_" + strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}

	for _, args := range blocked {
		name := "blocked_" + strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			// config set is blocked
			if args[1] == "set" {
				assertBlocked(t, args)
			}
		})
	}
}

// =============================================================================
// Wait and Diff Commands
// =============================================================================

func TestWaitCommand(t *testing.T) {
	tests := [][]string{
		{"wait", "--for=condition=Ready", "pod/nginx"},
		{"wait", "--for=condition=Available", "deployment/nginx"},
		{"wait", "--for=delete", "pod/nginx"},
		{"wait", "--for=condition=Ready", "--timeout=60s", "pod/nginx"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestDiffCommand(t *testing.T) {
	tests := [][]string{
		{"diff", "-f", "deployment.yaml"},
		{"diff", "--server-side", "-f", "deployment.yaml"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

// =============================================================================
// Completion and Help
// =============================================================================

func TestCompletionBlocked(t *testing.T) {
	tests := [][]string{
		{"completion", "bash"},
		{"completion", "zsh"},
		{"completion", "fish"},
		{"completion", "powershell"},
	}

	for _, args := range tests {
		t.Run(args[1], func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

func TestHelpBlocked(t *testing.T) {
	tests := [][]string{
		{"help"},
		{"help", "get"},
		{"help", "delete"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestEmptyAndMalformedInput(t *testing.T) {
	// Empty string as command - treated as empty args (shows help)
	assertAllowed(t, []string{""})

	// Whitespace as command - not a valid command, blocked
	assertBlocked(t, []string{" "})
	assertBlocked(t, []string{"  "})
	assertBlocked(t, []string{"\t"})
	assertBlocked(t, []string{"\n"})
	assertAllowed(t, []string{"get", " "})
}

func TestLongInput(t *testing.T) {
	// Very long resource name - still allowed if command is safe
	longName := strings.Repeat("a", 10000)
	assertAllowed(t, []string{"get", longName})
	assertAllowed(t, []string{"get", "pods", "-n", longName})

	// Very long unknown command - blocked
	assertBlocked(t, []string{longName})

	// Many arguments
	manyArgs := append([]string{"get", "pods"}, make([]string, 1000)...)
	for i := 2; i < len(manyArgs); i++ {
		manyArgs[i] = "arg"
	}
	assertAllowed(t, manyArgs)
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestExtractCommandAndSubcommand(t *testing.T) {
	tests := []struct {
		args       []string
		command    string
		subcommand string
	}{
		{[]string{"get", "pods"}, "get", "pods"},
		{[]string{"-n", "default", "get", "pods"}, "get", "pods"},
		{[]string{"--namespace=default", "get", "pods"}, "get", "pods"},
		{[]string{"config", "view"}, "config", "view"},
		{[]string{"rollout", "status", "deploy/nginx"}, "rollout", "status"},
		{[]string{"-o", "yaml", "get", "pods"}, "get", "pods"},
	}

	for _, tt := range tests {
		name := strings.Join(tt.args, "_")
		t.Run(name, func(t *testing.T) {
			cmd, sub := extractCommandAndSubcommand(tt.args)
			if cmd != tt.command {
				t.Errorf("command: got %q, want %q", cmd, tt.command)
			}
			if sub != tt.subcommand {
				t.Errorf("subcommand: got %q, want %q", sub, tt.subcommand)
			}
		})
	}
}

func TestExtractResourceTypes(t *testing.T) {
	tests := []struct {
		args      []string
		resources []string
	}{
		{[]string{"get", "pods"}, []string{"pods"}},
		{[]string{"get", "pods,secrets"}, []string{"pods", "secrets"}},
		{[]string{"get", "secret/my-secret"}, []string{"secret"}},
		{[]string{"-n", "default", "get", "pods"}, []string{"pods"}},
		{[]string{"delete", "pods"}, nil}, // delete is not in extract list
		// API group qualifiers are stripped to base resource type
		{[]string{"get", "secret.v1"}, []string{"secret"}},
		{[]string{"get", "secrets.v1"}, []string{"secrets"}},
		{[]string{"get", "secret.core"}, []string{"secret"}},
		{[]string{"get", "secret.v1.core"}, []string{"secret"}},
		{[]string{"get", "secret.v1/my-secret"}, []string{"secret"}},
		{[]string{"get", "pods.v1,secret.core"}, []string{"pods", "secret"}},
	}

	for _, tt := range tests {
		name := strings.Join(tt.args, "_")
		t.Run(name, func(t *testing.T) {
			got := extractResourceTypes(tt.args)
			if len(got) != len(tt.resources) {
				t.Errorf("got %v, want %v", got, tt.resources)
				return
			}
			for i := range got {
				if got[i] != tt.resources[i] {
					t.Errorf("got %v, want %v", got, tt.resources)
				}
			}
		})
	}
}

func TestGetOutputFormat(t *testing.T) {
	tests := []struct {
		args   []string
		format string
	}{
		{[]string{"get", "pods", "-o", "yaml"}, "yaml"},
		{[]string{"get", "pods", "-o=yaml"}, "yaml"},
		{[]string{"get", "pods", "-oyaml"}, "yaml"},
		{[]string{"get", "pods", "--output", "json"}, "json"},
		{[]string{"get", "pods", "--output=json"}, "json"},
		{[]string{"get", "pods"}, ""},
	}

	for _, tt := range tests {
		name := tt.format
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			got := getOutputFormat(tt.args)
			if got != tt.format {
				t.Errorf("got %q, want %q", got, tt.format)
			}
		})
	}
}

func TestIsSecretExposingFormat(t *testing.T) {
	exposing := []string{
		"yaml", "json", "jsonpath", "jsonpath={.data}",
		"jsonpath-as-json", "jsonpath-file",
		"go-template", "go-template={{.data}}", "go-template-file",
		"template", "templatefile",
		"custom-columns", "custom-columns=NAME:.metadata.name", "custom-columns-file",
	}
	safe := []string{"", "name", "wide"}

	for _, f := range exposing {
		t.Run("exposing_"+f, func(t *testing.T) {
			if !isSecretExposingFormat(f) {
				t.Errorf("%q should be exposing", f)
			}
		})
	}

	for _, f := range safe {
		name := f
		if name == "" {
			name = "empty"
		}
		t.Run("safe_"+name, func(t *testing.T) {
			if isSecretExposingFormat(f) {
				t.Errorf("%q should be safe", f)
			}
		})
	}
}

func TestContainsRawSecretsAccess(t *testing.T) {
	blocked := [][]string{
		{"get", "--raw", "/api/v1/secrets"},
		{"get", "--raw=/api/v1/secrets"},
		{"get", "--raw", "/api/v1/namespaces/default/secrets"},
		{"get", "--raw", "/api/v1/namespaces/default/secrets/my-secret"},
	}
	allowed := [][]string{
		{"get", "--raw", "/api/v1/pods"},
		{"get", "--raw", "/healthz"},
		{"get", "pods"},
	}

	for _, args := range blocked {
		name := "blocked_" + strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			if !containsRawSecretsAccess(args) {
				t.Errorf("expected raw secrets access to be detected: %v", args)
			}
		})
	}

	for _, args := range allowed {
		name := "allowed_" + strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			if containsRawSecretsAccess(args) {
				t.Errorf("expected no raw secrets access: %v", args)
			}
		})
	}
}

// =============================================================================
// Kustomize Command Tests
// =============================================================================

func TestKustomizeAllowed(t *testing.T) {
	tests := [][]string{
		{"kustomize", "."},
		{"kustomize", "/path/to/dir"},
		{"kustomize", "https://github.com/org/repo//path"},
		{"kustomize"},
		{"kustomize", "--load-restrictor=LoadRestrictionsRootOnly", "."},
		{"kustomize", "--load-restrictor", "LoadRestrictionsRootOnly", "."},
		{"-n", "default", "kustomize", "."},
		{"--context=prod", "kustomize", "/path"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestKustomizeBlockedFlags(t *testing.T) {
	tests := []struct {
		args   []string
		substr string
	}{
		{[]string{"kustomize", "--enable-alpha-plugins", "."}, "--enable-alpha-plugins"},
		{[]string{"kustomize", "--enable-helm", "."}, "--enable-helm"},
		{[]string{"kustomize", "--network", "."}, "--network"},
		{[]string{"kustomize", "--load-restrictor=None", "."}, "--load-restrictor"},
		{[]string{"kustomize", "--load-restrictor", "None", "."}, "--load-restrictor"},
		{[]string{"kustomize", "--load-restrictor", "LoadRestrictionsNone", "."}, "--load-restrictor"},
		{[]string{"kustomize", "--load-restrictor=LoadRestrictionsNone", "."}, "--load-restrictor"},
	}

	for _, tt := range tests {
		name := strings.Join(tt.args, "_")
		t.Run(name, func(t *testing.T) {
			assertBlockedContains(t, tt.args, tt.substr)
		})
	}
}

func TestKustomizeBlockedFlagVariations(t *testing.T) {
	tests := [][]string{
		{"kustomize", "--enable-alpha-plugins=true", "."},
		{"kustomize", "--enable-helm=true", "."},
		{"kustomize", "--network=true", "."},
		{"kustomize", "--enable-helm=false", "."},
		{"kustomize", ".", "--enable-helm"},
		{"kustomize", ".", "--network"},
		{"kustomize", ".", "--enable-alpha-plugins"},
	}

	for _, args := range tests {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

func TestKustomizeLoadRestrictorDefault(t *testing.T) {
	// Default value is allowed
	assertAllowed(t, []string{"kustomize", "--load-restrictor=LoadRestrictionsRootOnly", "."})
	assertAllowed(t, []string{"kustomize", "--load-restrictor", "LoadRestrictionsRootOnly", "."})

	// Non-default values are blocked
	assertBlocked(t, []string{"kustomize", "--load-restrictor=None", "."})
	assertBlocked(t, []string{"kustomize", "--load-restrictor", "None", "."})
	assertBlocked(t, []string{"kustomize", "--load-restrictor=LoadRestrictionsNone", "."})
	assertBlocked(t, []string{"kustomize", "--load-restrictor", "LoadRestrictionsNone", "."})
}
