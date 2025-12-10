//go:build integration

// Smoke tests for kubectl-readonly
//
// These tests run quickly without a Kubernetes cluster.
// They verify the command validation logic using --readonly-check-ok.
// Run these as a fast fail-fast check before the full integration tests.
//
// Run with: go test -tags=integration -v -run TestSmoke ./...

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// smokeEnv holds the smoke test environment (no cluster needed)
type smokeEnv struct {
	binaryPath string
	pluginDir  string
	t          *testing.T
}

// setupSmokeEnv prepares the smoke test environment
func setupSmokeEnv(t *testing.T) *smokeEnv {
	t.Helper()

	env := &smokeEnv{t: t}

	// Find the binary
	binaryPath := "./kubectl-readonly"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		if path, err := exec.LookPath("kubectl-readonly"); err == nil {
			binaryPath = path
		} else {
			t.Fatal("kubectl-readonly binary not found. Run 'make build' first.")
		}
	}

	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}
	env.binaryPath = absPath

	// Create plugin directory with symlink
	env.pluginDir = t.TempDir()
	pluginPath := filepath.Join(env.pluginDir, "kubectl-readonly")
	if err := os.Symlink(absPath, pluginPath); err != nil {
		t.Fatalf("Failed to create plugin symlink: %v", err)
	}

	return env
}

// runCheck runs kubectl-readonly --readonly-check-ok
func (e *smokeEnv) runCheck(args ...string) (stdout string, exitCode int) {
	e.t.Helper()
	checkArgs := append([]string{"--readonly-check-ok"}, args...)
	cmd := exec.Command(e.binaryPath, checkArgs...)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}
	return outBuf.String(), exitCode
}

// runPluginCheck runs kubectl readonly --readonly-check-ok
func (e *smokeEnv) runPluginCheck(args ...string) (stdout string, exitCode int) {
	e.t.Helper()

	kubectlPath, err := exec.LookPath("kubectl")
	if err != nil {
		e.t.Skip("kubectl not found")
	}

	env := os.Environ()
	for i, v := range env {
		if strings.HasPrefix(v, "PATH=") {
			env[i] = "PATH=" + e.pluginDir + ":" + v[5:]
			break
		}
	}

	checkArgs := append([]string{"readonly", "--readonly-check-ok"}, args...)
	cmd := exec.Command(kubectlPath, checkArgs...)
	cmd.Env = env
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	err = cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return outBuf.String(), exitCode
}

// assertAllowed verifies a command is allowed
func (e *smokeEnv) assertAllowed(mode string, args []string) {
	e.t.Helper()
	var stdout string
	var exitCode int

	if mode == "direct" {
		stdout, exitCode = e.runCheck(args...)
	} else {
		stdout, exitCode = e.runPluginCheck(args...)
	}

	if exitCode != 0 {
		e.t.Errorf("[%s] Expected allowed, got exit code %d for: %v\nOutput: %s", mode, exitCode, args, stdout)
	}
	if !strings.Contains(stdout, "OK") {
		e.t.Errorf("[%s] Expected 'OK' in output for: %v\nGot: %s", mode, args, stdout)
	}
}

// assertBlocked verifies a command is blocked
func (e *smokeEnv) assertBlocked(mode string, args []string) {
	e.t.Helper()
	var stdout string
	var exitCode int

	if mode == "direct" {
		stdout, exitCode = e.runCheck(args...)
	} else {
		stdout, exitCode = e.runPluginCheck(args...)
	}

	if exitCode == 0 {
		e.t.Errorf("[%s] Expected blocked, got allowed for: %v", mode, args)
	}
	if !strings.Contains(stdout, "BLOCKED") {
		e.t.Errorf("[%s] Expected 'BLOCKED' in output for: %v\nGot: %s", mode, args, stdout)
	}
}

// =============================================================================
// Smoke Tests - Direct Mode (kubectl-readonly)
// =============================================================================

func TestSmoke_Direct_SafeCommands(t *testing.T) {
	env := setupSmokeEnv(t)

	safeCommands := [][]string{
		{"get", "pods"},
		{"get", "deployments", "-A"},
		{"get", "services", "-n", "default"},
		{"describe", "pod", "my-pod"},
		{"describe", "deployment", "nginx"},
		{"logs", "my-pod"},
		{"logs", "my-pod", "-f", "--tail=100"},
		{"top", "pods"},
		{"top", "nodes"},
		{"explain", "pods"},
		{"api-resources"},
		{"api-versions"},
		{"cluster-info"},
		{"version"},
		{"version", "--client"},
		{"events"},
		{"events", "-n", "kube-system"},
		{"wait", "--for=condition=Ready", "pod/nginx"},
		{"diff", "-f", "file.yaml"},
		{"config", "view"},
		{"config", "get-contexts"},
		{"config", "current-context"},
		{"config", "use-context", "my-context"},
		{"auth", "can-i", "get", "pods"},
		{"auth", "can-i", "--list"},
		{"auth", "whoami"},
		{"rollout", "status", "deployment/nginx"},
		{"rollout", "history", "deployment/nginx"},
	}

	for _, args := range safeCommands {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			env.t = t
			env.assertAllowed("direct", args)
		})
	}
}

func TestSmoke_Direct_DangerousCommands(t *testing.T) {
	env := setupSmokeEnv(t)

	dangerousCommands := [][]string{
		{"delete", "pod", "my-pod"},
		{"delete", "deployment", "nginx", "-n", "default"},
		{"create", "deployment", "nginx", "--image=nginx"},
		{"apply", "-f", "file.yaml"},
		{"apply", "-k", "kustomize/"},
		{"patch", "deployment", "nginx", "-p", "{}"},
		{"edit", "deployment", "nginx"},
		{"replace", "-f", "file.yaml"},
		{"exec", "my-pod", "--", "bash"},
		{"exec", "-it", "my-pod", "--", "sh"},
		{"run", "test", "--image=nginx"},
		{"attach", "my-pod"},
		{"cp", "my-pod:/tmp/file", "./file"},
		{"scale", "deployment", "nginx", "--replicas=3"},
		{"autoscale", "deployment", "nginx", "--min=1", "--max=10"},
		{"cordon", "my-node"},
		{"uncordon", "my-node"},
		{"drain", "my-node"},
		{"taint", "node", "my-node", "key=value:NoSchedule"},
		{"label", "pod", "my-pod", "app=test"},
		{"annotate", "pod", "my-pod", "desc=test"},
		{"port-forward", "my-pod", "8080:80"},
		{"proxy"},
		{"rollout", "restart", "deployment/nginx"},
		{"rollout", "undo", "deployment/nginx"},
		{"rollout", "pause", "deployment/nginx"},
		{"rollout", "resume", "deployment/nginx"},
		{"config", "set-context", "my-context"},
		{"config", "set-cluster", "my-cluster"},
		{"config", "set-credentials", "my-user"},
		{"config", "delete-context", "my-context"},
		{"config", "unset", "current-context"},
		{"auth", "reconcile", "-f", "rbac.yaml"},
	}

	for _, args := range dangerousCommands {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			env.t = t
			env.assertBlocked("direct", args)
		})
	}
}

func TestSmoke_Direct_SecretsProtection(t *testing.T) {
	env := setupSmokeEnv(t)

	// Metadata access should be allowed
	allowedSecretCommands := [][]string{
		{"get", "secrets"},
		{"get", "secret", "my-secret"},
		{"get", "secrets", "-n", "kube-system"},
		{"get", "secrets", "-o", "name"},
		{"get", "secrets", "-o", "wide"},
		{"describe", "secret", "my-secret"},
	}

	for _, args := range allowedSecretCommands {
		name := "allowed_" + strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			env.t = t
			env.assertAllowed("direct", args)
		})
	}

	// Value access should be blocked
	blockedSecretCommands := [][]string{
		{"get", "secrets", "-o", "yaml"},
		{"get", "secrets", "-o", "json"},
		{"get", "secret", "my-secret", "-o", "yaml"},
		{"get", "secret", "my-secret", "-o", "json"},
		{"get", "secrets", "-oyaml"},
		{"get", "secrets", "-ojson"},
		{"get", "secrets", "--output=yaml"},
		{"get", "secrets", "--output", "json"},
		{"get", "secret", "my-secret", "-o", "jsonpath={.data}"},
		{"get", "secret", "my-secret", "-o", "go-template={{.data}}"},
		{"get", "secrets", "-o", "custom-columns=DATA:.data"},
		{"get", "--raw", "/api/v1/secrets"},
		{"get", "--raw", "/api/v1/namespaces/default/secrets"},
		{"get", "--raw=/api/v1/secrets"},
	}

	for _, args := range blockedSecretCommands {
		name := "blocked_" + strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			env.t = t
			env.assertBlocked("direct", args)
		})
	}
}

func TestSmoke_Direct_FlagsBeforeCommand(t *testing.T) {
	env := setupSmokeEnv(t)

	// Safe commands with flags before
	allowed := [][]string{
		{"-n", "default", "get", "pods"},
		{"--namespace", "kube-system", "get", "pods"},
		{"--namespace=default", "get", "deployments"},
		{"--context", "my-context", "get", "pods"},
		{"--context=prod", "get", "services"},
		{"-A", "get", "pods"},
		{"-o", "yaml", "get", "pods"},
		{"--kubeconfig=/path/to/config", "get", "pods"},
	}

	for _, args := range allowed {
		name := "allowed_" + strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			env.t = t
			env.assertAllowed("direct", args)
		})
	}

	// Dangerous commands with flags before
	blocked := [][]string{
		{"-n", "default", "delete", "pods"},
		{"--namespace=kube-system", "delete", "pods"},
		{"--context", "prod", "apply", "-f", "file.yaml"},
		{"-A", "delete", "pods"},
	}

	for _, args := range blocked {
		name := "blocked_" + strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			env.t = t
			env.assertBlocked("direct", args)
		})
	}
}

// =============================================================================
// Smoke Tests - Plugin Mode (kubectl readonly)
// =============================================================================

func TestSmoke_Plugin_SafeCommands(t *testing.T) {
	env := setupSmokeEnv(t)

	safeCommands := [][]string{
		{"get", "pods"},
		{"get", "deployments", "-A"},
		{"describe", "pod", "my-pod"},
		{"logs", "my-pod"},
		{"top", "pods"},
		{"version", "--client"},
		{"config", "view"},
		{"config", "get-contexts"},
		{"auth", "can-i", "get", "pods"},
		{"rollout", "status", "deployment/nginx"},
	}

	for _, args := range safeCommands {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			env.t = t
			env.assertAllowed("plugin", args)
		})
	}
}

func TestSmoke_Plugin_DangerousCommands(t *testing.T) {
	env := setupSmokeEnv(t)

	dangerousCommands := [][]string{
		{"delete", "pod", "my-pod"},
		{"create", "deployment", "nginx"},
		{"apply", "-f", "file.yaml"},
		{"exec", "my-pod", "--", "bash"},
		{"run", "test", "--image=nginx"},
		{"rollout", "restart", "deployment/nginx"},
		{"config", "set-context", "evil"},
	}

	for _, args := range dangerousCommands {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			env.t = t
			env.assertBlocked("plugin", args)
		})
	}
}

func TestSmoke_Plugin_SecretsProtection(t *testing.T) {
	env := setupSmokeEnv(t)

	// Allowed
	t.Run("get_secrets_metadata", func(t *testing.T) {
		env.t = t
		env.assertAllowed("plugin", []string{"get", "secrets"})
	})

	t.Run("describe_secret", func(t *testing.T) {
		env.t = t
		env.assertAllowed("plugin", []string{"describe", "secret", "my-secret"})
	})

	// Blocked
	t.Run("get_secrets_yaml", func(t *testing.T) {
		env.t = t
		env.assertBlocked("plugin", []string{"get", "secrets", "-o", "yaml"})
	})

	t.Run("get_secrets_json", func(t *testing.T) {
		env.t = t
		env.assertBlocked("plugin", []string{"get", "secrets", "-o", "json"})
	})
}

// =============================================================================
// Smoke Tests - Mode Consistency
// =============================================================================

func TestSmoke_Consistency(t *testing.T) {
	env := setupSmokeEnv(t)

	testCases := []struct {
		args        []string
		shouldAllow bool
	}{
		{[]string{"get", "pods"}, true},
		{[]string{"get", "secrets"}, true},
		{[]string{"get", "secrets", "-o", "yaml"}, false},
		{[]string{"delete", "pods"}, false},
		{[]string{"config", "view"}, true},
		{[]string{"config", "set-context", "test"}, false},
		{[]string{"exec", "pod", "--", "sh"}, false},
		{[]string{"-n", "default", "get", "pods"}, true},
		{[]string{"--namespace=kube-system", "delete", "pods"}, false},
	}

	for _, tc := range testCases {
		name := strings.Join(tc.args, "_")
		t.Run(name, func(t *testing.T) {
			env.t = t

			directOut, directExit := env.runCheck(tc.args...)
			pluginOut, pluginExit := env.runPluginCheck(tc.args...)

			// Both modes should have same exit code
			if directExit != pluginExit {
				t.Errorf("Exit codes differ: direct=%d, plugin=%d", directExit, pluginExit)
			}

			// Both should have same result (OK or BLOCKED)
			directOK := strings.Contains(directOut, "OK")
			pluginOK := strings.Contains(pluginOut, "OK")
			if directOK != pluginOK {
				t.Errorf("Results differ: direct=%v, plugin=%v", directOK, pluginOK)
			}

			// Verify expected result
			if tc.shouldAllow && !directOK {
				t.Errorf("Expected allowed, but was blocked")
			}
			if !tc.shouldAllow && directOK {
				t.Errorf("Expected blocked, but was allowed")
			}
		})
	}
}

// =============================================================================
// Smoke Tests - Special Flags
// =============================================================================

func TestSmoke_VersionFlag(t *testing.T) {
	env := setupSmokeEnv(t)

	// Direct mode
	cmd := exec.Command(env.binaryPath, "--readonly-version")
	out, err := cmd.Output()
	if err != nil {
		t.Errorf("Version flag failed: %v", err)
	}
	if !strings.Contains(string(out), "kubectl-readonly") {
		t.Errorf("Expected 'kubectl-readonly' in output, got: %s", out)
	}
}

func TestSmoke_HelpFlag(t *testing.T) {
	env := setupSmokeEnv(t)

	// Direct mode
	cmd := exec.Command(env.binaryPath, "--help")
	out, err := cmd.Output()
	if err != nil {
		t.Errorf("Help flag failed: %v", err)
	}
	if !strings.Contains(string(out), "USAGE") {
		t.Errorf("Expected 'USAGE' in help output, got: %s", out)
	}
	if !strings.Contains(string(out), "kubectl readonly") {
		t.Errorf("Expected plugin mode mention in help, got: %s", out)
	}
}
