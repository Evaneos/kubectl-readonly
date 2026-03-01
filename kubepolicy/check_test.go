package kubepolicy

import (
	"strings"
	"testing"
)

func assertAllowed(t *testing.T, args []string) {
	t.Helper()
	if !Check(args) {
		t.Errorf("expected allowed, got blocked (args: %v)", args)
	}
}

func assertBlocked(t *testing.T, args []string) {
	t.Helper()
	if Check(args) {
		t.Errorf("expected blocked, got allowed (args: %v)", args)
	}
}

// =============================================================================
// Basic Allowlist Tests
// =============================================================================

func TestSafeCommands(t *testing.T) {
	for _, cmd := range []string{
		"get", "describe", "logs", "top", "explain",
		"api-resources", "api-versions", "cluster-info", "version", "events", "wait", "diff",
		"kustomize",
	} {
		t.Run(cmd, func(t *testing.T) {
			assertAllowed(t, []string{cmd, "pods"})
		})
	}
}

func TestDangerousCommands(t *testing.T) {
	for _, cmd := range []string{
		"delete", "create", "apply", "patch", "edit", "replace",
		"exec", "run", "attach", "cp",
		"scale", "autoscale",
		"cordon", "uncordon", "drain", "taint",
		"label", "annotate",
		"port-forward", "proxy",
	} {
		t.Run(cmd, func(t *testing.T) {
			assertBlocked(t, []string{cmd, "pods"})
		})
	}
}

func TestSafeSubcommands(t *testing.T) {
	tests := [][]string{
		{"config", "view"},
		{"config", "get-contexts"},
		{"config", "get-clusters"},
		{"config", "get-users"},
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
		{"rollout", "restart", "deployment/nginx"},
		{"rollout", "undo", "deployment/nginx"},
		{"rollout", "pause", "deployment/nginx"},
		{"rollout", "resume", "deployment/nginx"},
		{"config", "set-context", "evil"},
		{"config", "set-cluster", "evil"},
		{"config", "set-credentials", "evil"},
		{"config", "delete-context", "production"},
		{"config", "delete-cluster", "production"},
		{"config", "unset", "current-context"},
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
		t.Run(strings.Join(tt.args, "_"), func(t *testing.T) {
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
		{"get", "secrets"},
		{"get", "secret"},
		{"get", "secrets", "--all-namespaces"},
		{"get", "secrets", "-A"},
		{"get", "secrets", "-n", "kube-system"},
		{"get", "secrets", "--show-labels"},
		{"-n", "default", "get", "secrets"},
		{"--context=prod", "get", "secrets"},
		{"describe", "secret", "my-secret"},
		{"describe", "secrets"},
		{"get", "secrets", "-o", "name"},
		{"get", "secrets", "-o", "wide"},
		{"get", "secret", "my-secret", "-o", "name"},
		{"get", "SECRETS"},
		{"get", "Secret"},
		{"get", "Secrets"},
		{"get", "secret.v1"},
		{"get", "secrets.v1"},
		{"get", "secret.core"},
		{"get", "secret.v1.core"},
		{"get", "secrets.v1.core"},
		{"get", "secret.v1", "-o", "name"},
		{"get", "secret.v1", "-o", "wide"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestSecretsValuesBlocked(t *testing.T) {
	tests := [][]string{
		{"get", "secrets", "-o", "yaml"},
		{"get", "secret", "my-secret", "-o", "yaml"},
		{"get", "secret/my-secret", "-o", "yaml"},
		{"get", "secrets", "-o", "json"},
		{"get", "secret", "my-secret", "-o", "json"},
		{"get", "secrets", "-ojson"},
		{"get", "secrets", "-oyaml"},
		{"get", "secrets", "-o", "jsonpath={.data}"},
		{"get", "secret", "my-secret", "-o", "jsonpath={.items[*].data}"},
		{"get", "secrets", "-o", "jsonpath-as-json={.data}"},
		{"get", "secrets", "-o", "go-template={{.data}}"},
		{"get", "secrets", "-o", "go-template-file=template.txt"},
		{"get", "secrets", "-o", "template", "--template={{.data}}"},
		{"get", "secrets", "-o", "templatefile=template.txt"},
		{"get", "pods,secrets", "-o", "yaml"},
		{"get", "secrets,pods", "-o", "json"},
		{"get", "configmaps,secrets,pods", "-o", "yaml"},
		{"get", "secrets", "-o", "custom-columns=DATA:.data"},
		{"get", "secret", "my-secret", "-o", "custom-columns=NAME:.metadata.name,DATA:.data"},
		{"get", "secrets", "-o", "custom-columns-file=columns.txt"},
		{"get", "secret.v1", "-o", "yaml"},
		{"get", "secrets.v1", "-o", "json"},
		{"get", "secret.core", "-o", "yaml"},
		{"get", "secret.v1.core", "-o", "yaml"},
		{"get", "secrets.v1.core", "-o", "json"},
		{"get", "secret.v1/my-secret", "-o", "yaml"},
		{"get", "pods,secret.v1", "-o", "yaml"},
		{"get", "secret.core,configmaps", "-o", "json"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertBlocked(t, args)
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
		{"get", "--raw", "/api/v1/SECRETS"},
		{"get", "--raw", "/api/v1/Secrets"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertBlocked(t, args)
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
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestSecretsWithImpersonation(t *testing.T) {
	assertBlocked(t, []string{"get", "secrets", "-o", "yaml", "--as=system:admin"})
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
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestSecretsBypassAttempts(t *testing.T) {
	tests := [][]string{
		{"-o", "yaml", "get", "secrets"},
		{"get", "-o", "yaml", "secrets"},
		{"get", "secrets", "-n", "default", "-o", "yaml"},
		{"get", "secrets", "-o", "yaml", "--show-labels"},
		{"get", "secrets", "-o", "json", "-l", "app=test"},
		{"get", "secrets", "--output=yaml"},
		{"get", "secrets", "--output", "yaml"},
		{"get", "secret/my-secret", "-o", "yaml"},
		{"get", "secret/my-secret", "-o", "json"},
		{"get", "secret/a", "secret/b", "-o", "yaml"},
		{"get", "secret.v1", "-o", "yaml"},
		{"get", "secret.core", "-o", "json"},
		{"get", "secret.v1.core", "-o", "yaml"},
		{"get", "secret.v1/my-secret", "-o", "yaml"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
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
		t.Run("blocked_"+strings.Join(args, "_"), func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
	for _, args := range allowed {
		t.Run("allowed_"+strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

// =============================================================================
// Security Bypass Tests
// =============================================================================

func TestShellMetacharactersInArgs(t *testing.T) {
	tests := [][]string{
		{"get", "pods;", "delete", "pods"},
		{"get", "pods;delete", "pods"},
		{"get", "pods", ";", "delete", "pods"},
		{"get", "pods|delete", "pods"},
		{"get", "pods", "|", "delete", "pods"},
		{"get", "pods&&delete", "pods"},
		{"get", "pods", "&&", "delete", "pods"},
		{"get", "pods||delete", "pods"},
		{"get", "pods", "||", "delete", "pods"},
		{"get", "`delete pods`"},
		{"get", "pods", "`rm -rf /`"},
		{"get", "$(delete pods)"},
		{"get", "pods", "$(rm -rf /)"},
		{"get", "${delete}", "pods"},
		{"get", "pods\ndelete", "pods"},
		{"get", "pods\n", "delete", "pods"},
		{"get", "pods\rdelete", "pods"},
	}
	for _, args := range tests {
		t.Run("safe_"+args[0], func(t *testing.T) {
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

func TestUnicodeHomoglyphs(t *testing.T) {
	tests := [][]string{
		{"d\u0435lete", "pods"},
		{"\u0064elete", "pods"},
		{"dеlеtе", "pods"},
		{"ехес", "pod"},
		{"e\u0445ec", "pod"},
		{"\uff44elete", "pods"},
		{"del\u200bete", "pods"},
		{"de\u200clete", "pods"},
		{"del\u200dete", "pods"},
		{"del\ufeffete", "pods"},
	}
	for _, args := range tests {
		t.Run("unicode_homoglyph", func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

func TestCaseSensitivity(t *testing.T) {
	tests := [][]string{
		{"GET", "pods"},
		{"Get", "pods"},
		{"DELETE", "pods"},
		{"Delete", "pods"},
		{"EXEC", "pod"},
		{"Exec", "pod"},
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
		{"get\x01", "pods"},
		{"get\x7f", "pods"},
	}
	for _, args := range tests {
		t.Run("nullbyte", func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

func TestDoubleDashAttacks(t *testing.T) {
	tests := []struct {
		args    []string
		allowed bool
	}{
		{[]string{"get", "pods", "--", "delete", "pods"}, true},
		{[]string{"get", "--", "delete"}, true},
		{[]string{"--", "delete", "pods"}, false},
		{[]string{"--namespace=default", "--", "delete", "pods"}, false},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, "_"), func(t *testing.T) {
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
		{"logs", "pod", "--exec=whoami"},
		{"get", "pods", "--run=malicious"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestResourceNameConfusion(t *testing.T) {
	tests := [][]string{
		{"get", "delete"},
		{"describe", "delete"},
		{"get", "pods", "delete"},
		{"get", "-f", "/etc/passwd"},
		{"diff", "-f", "http://evil.com/payload.yaml"},
		{"get", "-f", "-"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestExecDisguisedAsGet(t *testing.T) {
	assertBlocked(t, []string{"exec", "pod", "--", "bash"})
	assertAllowed(t, []string{"get", "exec"})
}

func TestKrewReadOnlyAllowed(t *testing.T) {
	tests := [][]string{
		{"krew", "list"},
		{"krew", "search"},
		{"krew", "search", "ctx"},
		{"krew", "info", "ctx"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestPluginCommands(t *testing.T) {
	tests := [][]string{
		{"plugin", "list"},
		{"krew", "install", "ctx"},
		{"krew", "update"},
		{"krew", "upgrade"},
		{"krew", "uninstall", "ctx"},
		{"ctx", "production"},
		{"ns", "kube-system"},
		{"neat", "get", "pods"},
		{"tree", "deployment", "nginx"},
		{"whoami"},
		{"access-matrix"},
		{"kubectl-delete", "pods"},
		{"--plugin=delete", "pods"},
	}
	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

func TestExperimentalCommands(t *testing.T) {
	tests := [][]string{
		{"alpha"},
		{"alpha", "something"},
		{"alpha", "events"},
		{"debug", "pod/nginx"},
		{"debug", "-it", "pod/nginx", "--image=busybox"},
		{"convert", "-f", "pod.yaml"},
	}
	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

func TestNetworkCommands(t *testing.T) {
	tests := [][]string{
		{"proxy"},
		{"proxy", "--port=8080"},
		{"proxy", "--www=/"},
		{"port-forward", "pod/nginx", "8080:80"},
		{"port-forward", "svc/nginx", "8080:80"},
		{"attach", "pod/nginx"},
		{"attach", "-it", "pod/nginx"},
	}
	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

func TestPathTraversalAndFiles(t *testing.T) {
	tests := [][]string{
		{"get", "-f", "../../../etc/passwd"},
		{"get", "-f", "/etc/passwd"},
		{"diff", "-f", "../../secret.yaml"},
		{"get", "-f", "http://evil.com/payload.yaml"},
		{"get", "-f", "https://evil.com/payload.yaml"},
		{"get", "-k", "../../"},
		{"get", "-k", "/etc/kubernetes/"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestRBACInfoGathering(t *testing.T) {
	tests := [][]string{
		{"auth", "can-i", "create", "deployments"},
		{"auth", "can-i", "delete", "secrets"},
		{"auth", "can-i", "--list"},
		{"auth", "can-i", "*", "*"},
		{"get", "roles"},
		{"get", "rolebindings"},
		{"get", "clusterroles"},
		{"get", "clusterrolebindings"},
		{"get", "serviceaccounts"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestImpersonation(t *testing.T) {
	tests := [][]string{
		{"get", "pods", "--as=admin"},
		{"get", "pods", "--as-group=system:masters"},
		{"auth", "can-i", "get", "pods", "--as=admin"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestSpecialResources(t *testing.T) {
	tests := [][]string{
		{"get", "mutatingwebhookconfigurations"},
		{"get", "validatingwebhookconfigurations"},
		{"get", "certificatesigningrequests"},
		{"get", "crds"},
		{"get", "customresourcedefinitions"},
		{"get", "nodes"},
		{"describe", "node", "master-1"},
		{"top", "nodes"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestOutputFormats(t *testing.T) {
	tests := [][]string{
		{"get", "pods", "-o", "yaml"},
		{"get", "pods", "-o", "json"},
		{"get", "pods", "-o", "go-template={{.metadata.name}}"},
		{"get", "pods", "-o", "custom-columns=NAME:.metadata.name"},
		{"get", "pods", "--template", "/etc/passwd"},
		{"get", "pods", "-o", "template", "--template=/etc/passwd"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestCombinedAttacks(t *testing.T) {
	tests := []struct {
		args    []string
		allowed bool
	}{
		{[]string{"get", "pods\u200b;", "delete", "pods"}, true},
		{[]string{"--namespace=default", "-o", "yaml", "delete", "pods"}, false},
		{[]string{"config", "set\u200b-context", "evil"}, false},
		{[]string{"get", strings.Repeat("a", 1000) + ";delete", "pods"}, true},
		{[]string{"exec", "-it", "pod", "--", "rm", "-rf", "/"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.args[0], func(t *testing.T) {
			if tt.allowed {
				assertAllowed(t, tt.args)
			} else {
				assertBlocked(t, tt.args)
			}
		})
	}
}

func TestContextCommands(t *testing.T) {
	allowed := [][]string{
		{"config", "use-context", "production"},
		{"config", "use-context", "staging"},
		{"config", "current-context"},
		{"config", "get-contexts"},
		{"config", "get-clusters"},
		{"config", "get-users"},
		{"config", "view"},
	}
	blocked := [][]string{
		{"config", "set", "current-context", "production"},
	}
	for _, args := range allowed {
		t.Run("allowed_"+strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
	for _, args := range blocked {
		t.Run("blocked_"+strings.Join(args, "_"), func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

func TestWaitCommand(t *testing.T) {
	tests := [][]string{
		{"wait", "--for=condition=Ready", "pod/nginx"},
		{"wait", "--for=condition=Available", "deployment/nginx"},
		{"wait", "--for=delete", "pod/nginx"},
		{"wait", "--for=condition=Ready", "--timeout=60s", "pod/nginx"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
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
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestCompletionBlocked(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			assertBlocked(t, []string{"completion", shell})
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
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
}

func TestEmptyAndMalformedInput(t *testing.T) {
	assertAllowed(t, []string{""})
	assertBlocked(t, []string{" "})
	assertBlocked(t, []string{"  "})
	assertBlocked(t, []string{"\t"})
	assertBlocked(t, []string{"\n"})
	assertAllowed(t, []string{"get", " "})
}

func TestLongInput(t *testing.T) {
	longName := strings.Repeat("a", 10000)
	assertAllowed(t, []string{"get", longName})
	assertAllowed(t, []string{"get", "pods", "-n", longName})
	assertBlocked(t, []string{longName})

	manyArgs := append([]string{"get", "pods"}, make([]string, 1000)...)
	for i := 2; i < len(manyArgs); i++ {
		manyArgs[i] = "arg"
	}
	assertAllowed(t, manyArgs)
}

// =============================================================================
// Kustomize Tests
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
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertAllowed(t, args)
		})
	}
}

func TestKustomizeBlockedFlags(t *testing.T) {
	tests := [][]string{
		{"kustomize", "--enable-alpha-plugins", "."},
		{"kustomize", "--enable-helm", "."},
		{"kustomize", "--network", "."},
		{"kustomize", "--load-restrictor=None", "."},
		{"kustomize", "--load-restrictor", "None", "."},
		{"kustomize", "--load-restrictor", "LoadRestrictionsNone", "."},
		{"kustomize", "--load-restrictor=LoadRestrictionsNone", "."},
		{"kustomize", "--enable-alpha-plugins=true", "."},
		{"kustomize", "--enable-helm=true", "."},
		{"kustomize", "--network=true", "."},
		{"kustomize", "--enable-helm=false", "."},
		{"kustomize", ".", "--enable-helm"},
		{"kustomize", ".", "--network"},
		{"kustomize", ".", "--enable-alpha-plugins"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			assertBlocked(t, args)
		})
	}
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
		t.Run(strings.Join(tt.args, "_"), func(t *testing.T) {
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
		{[]string{"delete", "pods"}, nil},
		{[]string{"get", "secret.v1"}, []string{"secret"}},
		{[]string{"get", "secrets.v1"}, []string{"secrets"}},
		{[]string{"get", "secret.core"}, []string{"secret"}},
		{[]string{"get", "secret.v1.core"}, []string{"secret"}},
		{[]string{"get", "secret.v1/my-secret"}, []string{"secret"}},
		{[]string{"get", "pods.v1,secret.core"}, []string{"pods", "secret"}},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, "_"), func(t *testing.T) {
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
		t.Run("blocked_"+strings.Join(args, "_"), func(t *testing.T) {
			if !containsRawSecretsAccess(args) {
				t.Errorf("expected raw secrets access detected: %v", args)
			}
		})
	}
	for _, args := range allowed {
		t.Run("allowed_"+strings.Join(args, "_"), func(t *testing.T) {
			if containsRawSecretsAccess(args) {
				t.Errorf("expected no raw secrets access: %v", args)
			}
		})
	}
}
