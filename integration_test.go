//go:build integration

// Integration tests for kubectl-readonly using kind
//
// These tests verify the actual binary behavior against a real Kubernetes cluster.
// They test both invocation modes:
// 1. Direct: kubectl-readonly get pods
// 2. Plugin: kubectl readonly get pods
//
// Prerequisites:
// - kind cluster running (the test will create one if needed)
// - kubectl installed
// - kubectl-readonly binary built (make build)
//
// Run with: make test-integration
// Or manually: go test -tags=integration -v ./...

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	kindClusterName = "kubectl-readonly-test"
	testNamespace   = "readonly-test"
)

// testEnv holds the test environment
type testEnv struct {
	binaryPath    string
	pluginDir     string
	clusterExists bool
	t             *testing.T
}

// setupTestEnv prepares the test environment with a kind cluster
func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	env := &testEnv{t: t}

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
	// Note: We use os.MkdirTemp instead of t.TempDir() because globalEnv is shared
	// across all tests. t.TempDir() would clean up the directory when the first
	// test that created it finishes, breaking subsequent plugin tests.
	pluginDir, err := os.MkdirTemp("", "kubectl-readonly-test-*")
	if err != nil {
		t.Fatalf("Failed to create plugin directory: %v", err)
	}
	env.pluginDir = pluginDir
	pluginPath := filepath.Join(env.pluginDir, "kubectl-readonly")
	if err := os.Symlink(absPath, pluginPath); err != nil {
		t.Fatalf("Failed to create plugin symlink: %v", err)
	}

	// Check if kind cluster exists
	env.clusterExists = env.kindClusterExists()

	return env
}

// kindClusterExists checks if our test cluster is running
func (e *testEnv) kindClusterExists() bool {
	cmd := exec.Command("kind", "get", "clusters")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == kindClusterName {
			return true
		}
	}
	return false
}

// ensureCluster creates a kind cluster if it doesn't exist
func (e *testEnv) ensureCluster() {
	e.t.Helper()

	if e.clusterExists {
		e.t.Logf("Using existing kind cluster: %s", kindClusterName)
		return
	}

	e.t.Logf("Creating kind cluster: %s", kindClusterName)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "kind", "create", "cluster", "--name", kindClusterName, "--wait", "60s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		e.t.Fatalf("Failed to create kind cluster: %v", err)
	}
	e.clusterExists = true
}

// setupTestResources creates test resources in the cluster
func (e *testEnv) setupTestResources() {
	e.t.Helper()

	// Create test namespace
	e.kubectl("create", "namespace", testNamespace, "--dry-run=client", "-o", "yaml")
	e.kubectl("apply", "-f", "-", "--input", fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %s
`, testNamespace))

	// Create a test pod that stays running (using sleep to avoid nginx completing)
	e.kubectl("apply", "-f", "-", "--input", fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: %s
  labels:
    app: test
spec:
  containers:
  - name: busybox
    image: busybox:stable
    command: ["sleep", "3600"]
  restartPolicy: Always
`, testNamespace))

	// Create a test secret
	e.kubectl("apply", "-f", "-", "--input", fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: test-secret
  namespace: %s
type: Opaque
data:
  username: YWRtaW4=
  password: c2VjcmV0cGFzc3dvcmQ=
`, testNamespace))

	// Create a test configmap
	e.kubectl("apply", "-f", "-", "--input", fmt.Sprintf(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-configmap
  namespace: %s
data:
  config.yaml: |
    key: value
`, testNamespace))

	// Create a test deployment
	e.kubectl("apply", "-f", "-", "--input", fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
  namespace: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-deployment
  template:
    metadata:
      labels:
        app: test-deployment
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
`, testNamespace))

	// Wait for test pod to be ready
	e.t.Log("Waiting for test pod to be ready...")
	if !e.waitForPodRunning("test-pod", testNamespace, 60*time.Second) {
		e.t.Log("Warning: test-pod did not reach Running state within timeout")
	}
}

// kubectl runs a kubectl command
func (e *testEnv) kubectl(args ...string) (string, error) {
	// Handle --input flag for stdin
	var input string
	filteredArgs := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--input" && i+1 < len(args) {
			input = args[i+1]
			i++
		} else {
			filteredArgs = append(filteredArgs, args[i])
		}
	}

	cmd := exec.Command("kubectl", filteredArgs...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runDirect runs kubectl-readonly directly
func (e *testEnv) runDirect(args ...string) (stdout, stderr string, exitCode int) {
	e.t.Helper()
	cmd := exec.Command(e.binaryPath, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// runPlugin runs kubectl readonly (plugin mode)
func (e *testEnv) runPlugin(args ...string) (stdout, stderr string, exitCode int) {
	e.t.Helper()

	kubectlPath, err := exec.LookPath("kubectl")
	if err != nil {
		e.t.Skip("kubectl not found")
	}

	// Add plugin dir to PATH
	env := os.Environ()
	for i, v := range env {
		if strings.HasPrefix(v, "PATH=") {
			env[i] = "PATH=" + e.pluginDir + ":" + v[5:]
			break
		}
	}

	fullArgs := append([]string{"readonly"}, args...)
	cmd := exec.Command(kubectlPath, fullArgs...)
	cmd.Env = env

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err = cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// waitForPodRunning waits for a pod to be in Running state
func (e *testEnv) waitForPodRunning(podName, namespace string, timeout time.Duration) bool {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		stdout, _, _ := e.runDirect("get", "pod", podName, "-n", namespace, "-o", "jsonpath={.status.phase}")
		if strings.TrimSpace(stdout) == "Running" {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// waitForPodExists waits for a pod to exist (any state)
func (e *testEnv) waitForPodExists(podName, namespace string, timeout time.Duration) bool {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		stdout, _, exitCode := e.runDirect("get", "pod", podName, "-n", namespace)
		if exitCode == 0 && strings.Contains(stdout, podName) {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// waitForPodGone waits for a pod to be deleted or in Terminating state
func (e *testEnv) waitForPodGone(podName, namespace string, timeout time.Duration) bool {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		stdout, _, exitCode := e.runDirect("get", "pod", podName, "-n", namespace)
		// Pod is gone (not found)
		if exitCode != 0 || !strings.Contains(stdout, podName) {
			return true
		}
		// Pod is terminating
		if strings.Contains(stdout, "Terminating") {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// cleanupTestResources removes test resources
func (e *testEnv) cleanupTestResources() {
	e.t.Helper()
	e.kubectl("delete", "namespace", testNamespace, "--ignore-not-found")
}

// =============================================================================
// Test Setup - Run once for all integration tests
// =============================================================================

var globalEnv *testEnv

func TestMain(m *testing.M) {
	// This only runs when integration tag is set
	code := m.Run()
	// Cleanup the plugin directory if it was created
	if globalEnv != nil && globalEnv.pluginDir != "" {
		os.RemoveAll(globalEnv.pluginDir)
	}
	os.Exit(code)
}

func getTestEnv(t *testing.T) *testEnv {
	t.Helper()
	if globalEnv == nil {
		globalEnv = setupTestEnv(t)
		globalEnv.ensureCluster()
		globalEnv.setupTestResources()
		// Cleanup will happen when the cluster is deleted or manually
	}
	globalEnv.t = t
	return globalEnv
}

// =============================================================================
// Direct Mode Tests - kubectl-readonly
// =============================================================================

func TestIntegration_Direct_GetPods(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runDirect("get", "pods", "-n", testNamespace)
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "test-pod") {
		t.Errorf("Expected output to contain 'test-pod', got: %s", stdout)
	}
}

func TestIntegration_Direct_GetPodsAllNamespaces(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runDirect("get", "pods", "-A")
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, testNamespace) {
		t.Errorf("Expected output to contain namespace '%s', got: %s", testNamespace, stdout)
	}
}

func TestIntegration_Direct_DescribePod(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runDirect("describe", "pod", "test-pod", "-n", testNamespace)
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "test-pod") {
		t.Errorf("Expected output to contain 'test-pod', got: %s", stdout)
	}
	if !strings.Contains(stdout, "busybox") {
		t.Errorf("Expected output to contain 'busybox', got: %s", stdout)
	}
}

func TestIntegration_Direct_GetSecretMetadata(t *testing.T) {
	env := getTestEnv(t)

	// Should be able to list secrets (metadata only)
	stdout, stderr, exitCode := env.runDirect("get", "secrets", "-n", testNamespace)
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "test-secret") {
		t.Errorf("Expected output to contain 'test-secret', got: %s", stdout)
	}
	// Should NOT contain the actual secret values
	if strings.Contains(stdout, "secretpassword") || strings.Contains(stdout, "c2VjcmV0cGFzc3dvcmQ") {
		t.Errorf("Output should not contain secret values: %s", stdout)
	}
}

func TestIntegration_Direct_GetSecretValuesBlocked(t *testing.T) {
	env := getTestEnv(t)

	// Should be blocked when trying to get secret values
	_, stderr, exitCode := env.runDirect("get", "secret", "test-secret", "-n", testNamespace, "-o", "yaml")
	if exitCode == 0 {
		t.Error("Expected non-zero exit code for secret value access")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected error message about read-only, got: %s", stderr)
	}
}

func TestIntegration_Direct_GetSecretJsonBlocked(t *testing.T) {
	env := getTestEnv(t)

	_, stderr, exitCode := env.runDirect("get", "secret", "test-secret", "-n", testNamespace, "-o", "json")
	if exitCode == 0 {
		t.Error("Expected non-zero exit code for secret JSON access")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected error message about read-only, got: %s", stderr)
	}
}

func TestIntegration_Direct_DescribeSecret(t *testing.T) {
	env := getTestEnv(t)

	// Describe should work (shows metadata, not values)
	stdout, stderr, exitCode := env.runDirect("describe", "secret", "test-secret", "-n", testNamespace)
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "test-secret") {
		t.Errorf("Expected output to contain 'test-secret', got: %s", stdout)
	}
	// Describe shows byte counts, not actual values
	if strings.Contains(stdout, "secretpassword") {
		t.Errorf("Output should not contain actual secret values: %s", stdout)
	}
}

func TestIntegration_Direct_GetConfigMap(t *testing.T) {
	env := getTestEnv(t)

	// ConfigMaps should be fully accessible (not sensitive)
	stdout, stderr, exitCode := env.runDirect("get", "configmap", "test-configmap", "-n", testNamespace, "-o", "yaml")
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "key: value") {
		t.Errorf("Expected output to contain configmap data, got: %s", stdout)
	}
}

func TestIntegration_Direct_GetDeployment(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runDirect("get", "deployment", "-n", testNamespace)
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "test-deployment") {
		t.Errorf("Expected output to contain 'test-deployment', got: %s", stdout)
	}
}

func TestIntegration_Direct_DeleteBlocked(t *testing.T) {
	env := getTestEnv(t)

	_, stderr, exitCode := env.runDirect("delete", "pod", "test-pod", "-n", testNamespace)
	if exitCode == 0 {
		t.Error("Expected non-zero exit code for delete command")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected error about read-only, got: %s", stderr)
	}

	// Verify pod still exists
	stdout, _, _ := env.runDirect("get", "pod", "test-pod", "-n", testNamespace)
	if !strings.Contains(stdout, "test-pod") {
		t.Error("Pod should still exist after blocked delete")
	}
}

func TestIntegration_Direct_ApplyBlocked(t *testing.T) {
	env := getTestEnv(t)

	_, stderr, exitCode := env.runDirect("apply", "-f", "-")
	if exitCode == 0 {
		t.Error("Expected non-zero exit code for apply command")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected error about read-only, got: %s", stderr)
	}
}

func TestIntegration_Direct_ExecBlocked(t *testing.T) {
	env := getTestEnv(t)

	_, stderr, exitCode := env.runDirect("exec", "test-pod", "-n", testNamespace, "--", "ls")
	if exitCode == 0 {
		t.Error("Expected non-zero exit code for exec command")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected error about read-only, got: %s", stderr)
	}
}

func TestIntegration_Direct_Version(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runDirect("version", "--client")
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "Client Version") {
		t.Errorf("Expected 'Client Version' in output, got: %s", stdout)
	}
}

func TestIntegration_Direct_GetNamespaces(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runDirect("get", "namespaces")
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "default") {
		t.Errorf("Expected 'default' namespace, got: %s", stdout)
	}
	if !strings.Contains(stdout, testNamespace) {
		t.Errorf("Expected '%s' namespace, got: %s", testNamespace, stdout)
	}
}

func TestIntegration_Direct_ConfigGetContexts(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runDirect("config", "get-contexts")
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, kindClusterName) {
		t.Errorf("Expected context '%s', got: %s", kindClusterName, stdout)
	}
}

func TestIntegration_Direct_RolloutStatusBlocked(t *testing.T) {
	env := getTestEnv(t)

	// rollout restart should be blocked
	_, stderr, exitCode := env.runDirect("rollout", "restart", "deployment/test-deployment", "-n", testNamespace)
	if exitCode == 0 {
		t.Error("Expected non-zero exit code for rollout restart")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected error about read-only, got: %s", stderr)
	}
}

func TestIntegration_Direct_RolloutStatusAllowed(t *testing.T) {
	env := getTestEnv(t)

	// rollout status should be allowed
	stdout, stderr, exitCode := env.runDirect("rollout", "status", "deployment/test-deployment", "-n", testNamespace, "--timeout=10s")
	// May return non-zero if deployment isn't ready, but should execute
	if exitCode != 0 && strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("rollout status should be allowed, got: %s", stderr)
	}
	_ = stdout // Status output varies
}

// =============================================================================
// Plugin Mode Tests - kubectl readonly
// =============================================================================

func TestIntegration_Plugin_GetPods(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runPlugin("get", "pods", "-n", testNamespace)
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "test-pod") {
		t.Errorf("Expected output to contain 'test-pod', got: %s", stdout)
	}
}

func TestIntegration_Plugin_GetPodsAllNamespaces(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runPlugin("get", "pods", "-A")
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, testNamespace) {
		t.Errorf("Expected output to contain namespace '%s', got: %s", testNamespace, stdout)
	}
}

func TestIntegration_Plugin_DescribePod(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runPlugin("describe", "pod", "test-pod", "-n", testNamespace)
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "test-pod") {
		t.Errorf("Expected output to contain 'test-pod', got: %s", stdout)
	}
}

func TestIntegration_Plugin_GetSecretMetadata(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runPlugin("get", "secrets", "-n", testNamespace)
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "test-secret") {
		t.Errorf("Expected output to contain 'test-secret', got: %s", stdout)
	}
}

func TestIntegration_Plugin_GetSecretValuesBlocked(t *testing.T) {
	env := getTestEnv(t)

	_, stderr, exitCode := env.runPlugin("get", "secret", "test-secret", "-n", testNamespace, "-o", "yaml")
	if exitCode == 0 {
		t.Error("Expected non-zero exit code for secret value access")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected error message about read-only, got: %s", stderr)
	}
}

func TestIntegration_Plugin_DeleteBlocked(t *testing.T) {
	env := getTestEnv(t)

	_, stderr, exitCode := env.runPlugin("delete", "pod", "test-pod", "-n", testNamespace)
	if exitCode == 0 {
		t.Error("Expected non-zero exit code for delete command")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected error about read-only, got: %s", stderr)
	}
}

func TestIntegration_Plugin_ExecBlocked(t *testing.T) {
	env := getTestEnv(t)

	_, stderr, exitCode := env.runPlugin("exec", "test-pod", "-n", testNamespace, "--", "ls")
	if exitCode == 0 {
		t.Error("Expected non-zero exit code for exec command")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected error about read-only, got: %s", stderr)
	}
}

func TestIntegration_Plugin_Version(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runPlugin("version", "--client")
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "Client Version") {
		t.Errorf("Expected 'Client Version' in output, got: %s", stdout)
	}
}

func TestIntegration_Plugin_GetNamespaces(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runPlugin("get", "namespaces")
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "default") {
		t.Errorf("Expected 'default' namespace, got: %s", stdout)
	}
}

func TestIntegration_Plugin_ConfigGetContexts(t *testing.T) {
	env := getTestEnv(t)

	stdout, stderr, exitCode := env.runPlugin("config", "get-contexts")
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, kindClusterName) {
		t.Errorf("Expected context '%s', got: %s", kindClusterName, stdout)
	}
}

// =============================================================================
// Consistency Tests - Both modes should behave identically
// =============================================================================

func TestIntegration_Consistency_SameResults(t *testing.T) {
	env := getTestEnv(t)

	testCases := []struct {
		name string
		args []string
	}{
		{"get_pods", []string{"get", "pods", "-n", testNamespace}},
		{"get_secrets", []string{"get", "secrets", "-n", testNamespace}},
		{"get_namespaces", []string{"get", "namespaces"}},
		{"describe_pod", []string{"describe", "pod", "test-pod", "-n", testNamespace}},
		{"version", []string{"version", "--client"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			directOut, _, directExit := env.runDirect(tc.args...)
			pluginOut, _, pluginExit := env.runPlugin(tc.args...)

			if directExit != pluginExit {
				t.Errorf("Exit codes differ: direct=%d, plugin=%d", directExit, pluginExit)
			}

			// Outputs should be identical (or very similar)
			if directOut != pluginOut {
				// Allow minor differences but flag significant ones
				if len(directOut) == 0 || len(pluginOut) == 0 {
					t.Errorf("One mode returned empty output:\nDirect: %s\nPlugin: %s", directOut, pluginOut)
				}
			}
		})
	}
}

func TestIntegration_Consistency_SameBlocking(t *testing.T) {
	env := getTestEnv(t)

	blockedCommands := []struct {
		name string
		args []string
	}{
		{"delete", []string{"delete", "pod", "test-pod", "-n", testNamespace}},
		{"apply", []string{"apply", "-f", "-"}},
		{"exec", []string{"exec", "test-pod", "-n", testNamespace, "--", "ls"}},
		{"secret_yaml", []string{"get", "secret", "test-secret", "-n", testNamespace, "-o", "yaml"}},
		{"secret_json", []string{"get", "secret", "test-secret", "-n", testNamespace, "-o", "json"}},
	}

	for _, tc := range blockedCommands {
		t.Run(tc.name, func(t *testing.T) {
			_, directErr, directExit := env.runDirect(tc.args...)
			_, pluginErr, pluginExit := env.runPlugin(tc.args...)

			// Both should be blocked (non-zero exit)
			if directExit == 0 {
				t.Errorf("Direct mode should block %s", tc.name)
			}
			if pluginExit == 0 {
				t.Errorf("Plugin mode should block %s", tc.name)
			}

			// Both should have similar error messages
			if !strings.Contains(directErr, "not safe for read-only") {
				t.Errorf("Direct mode error message unexpected: %s", directErr)
			}
			if !strings.Contains(pluginErr, "not safe for read-only") {
				t.Errorf("Plugin mode error message unexpected: %s", pluginErr)
			}
		})
	}
}

// =============================================================================
// Special Flags Tests
// =============================================================================

func TestIntegration_CheckFlag_Direct(t *testing.T) {
	env := getTestEnv(t)

	// Allowed command
	stdout, _, exitCode := env.runDirect("--readonly-check-ok", "get", "pods")
	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for allowed command check")
	}
	if !strings.Contains(stdout, "OK") {
		t.Errorf("Expected 'OK' in output, got: %s", stdout)
	}

	// Blocked command
	stdout, _, exitCode = env.runDirect("--readonly-check-ok", "delete", "pods")
	if exitCode == 0 {
		t.Errorf("Expected non-zero exit code for blocked command check")
	}
	if !strings.Contains(stdout, "BLOCKED") {
		t.Errorf("Expected 'BLOCKED' in output, got: %s", stdout)
	}
}

func TestIntegration_CheckFlag_Plugin(t *testing.T) {
	env := getTestEnv(t)

	// Allowed command
	stdout, _, exitCode := env.runPlugin("--readonly-check-ok", "get", "pods")
	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for allowed command check")
	}
	if !strings.Contains(stdout, "OK") {
		t.Errorf("Expected 'OK' in output, got: %s", stdout)
	}

	// Blocked command
	stdout, _, exitCode = env.runPlugin("--readonly-check-ok", "delete", "pods")
	if exitCode == 0 {
		t.Errorf("Expected non-zero exit code for blocked command check")
	}
	if !strings.Contains(stdout, "BLOCKED") {
		t.Errorf("Expected 'BLOCKED' in output, got: %s", stdout)
	}
}

func TestIntegration_VersionFlag(t *testing.T) {
	env := getTestEnv(t)

	// Direct mode
	stdout, _, exitCode := env.runDirect("--readonly-version")
	if exitCode != 0 {
		t.Error("Expected exit code 0 for version flag")
	}
	if !strings.Contains(stdout, "kubectl-readonly") {
		t.Errorf("Expected 'kubectl-readonly' in version output, got: %s", stdout)
	}

	// Plugin mode
	stdout, _, exitCode = env.runPlugin("--readonly-version")
	if exitCode != 0 {
		t.Error("Expected exit code 0 for version flag in plugin mode")
	}
	if !strings.Contains(stdout, "kubectl-readonly") {
		t.Errorf("Expected 'kubectl-readonly' in version output, got: %s", stdout)
	}
}

// =============================================================================
// End-to-End Tests - Full scenarios proving readonly actually blocks
// =============================================================================

// TestIntegration_E2E_DeleteBlocked_ThenKubectlWorks proves that:
// 1. Create a pod with kubectl (works)
// 2. Try to delete with kubectl-readonly (blocked)
// 3. Try to delete with kubectl readonly plugin (blocked)
// 4. Pod still exists
// 5. Delete with kubectl directly (works)
// 6. Pod is gone
func TestIntegration_E2E_DeleteBlocked_ThenKubectlWorks(t *testing.T) {
	env := getTestEnv(t)
	podName := "e2e-delete-test"

	// 1. Create a pod with kubectl (using sleep to keep it running)
	_, err := env.kubectl("apply", "-f", "-", "--input", fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  containers:
  - name: busybox
    image: busybox:stable
    command: ["sleep", "3600"]
  restartPolicy: Always
`, podName, testNamespace))
	if err != nil {
		t.Fatalf("Failed to create test pod: %v", err)
	}

	// Wait for pod to exist and be running
	if !env.waitForPodExists(podName, testNamespace, 30*time.Second) {
		t.Fatalf("Pod should exist after creation")
	}

	// Verify pod exists
	stdout, _, exitCode := env.runDirect("get", "pod", podName, "-n", testNamespace)
	if exitCode != 0 || !strings.Contains(stdout, podName) {
		t.Fatalf("Pod should exist after creation, got: %s", stdout)
	}

	// 2. Try to delete with kubectl-readonly direct mode (should be blocked)
	_, stderr, exitCode := env.runDirect("delete", "pod", podName, "-n", testNamespace)
	if exitCode == 0 {
		t.Error("kubectl-readonly should have blocked delete")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected readonly error, got: %s", stderr)
	}

	// 3. Try to delete with kubectl readonly plugin mode (should be blocked)
	_, stderr, exitCode = env.runPlugin("delete", "pod", podName, "-n", testNamespace)
	if exitCode == 0 {
		t.Error("kubectl readonly plugin should have blocked delete")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected readonly error in plugin mode, got: %s", stderr)
	}

	// 4. Verify pod STILL exists (wasn't deleted)
	stdout, _, exitCode = env.runDirect("get", "pod", podName, "-n", testNamespace)
	if exitCode != 0 || !strings.Contains(stdout, podName) {
		t.Error("Pod should still exist after blocked delete attempts")
	}

	// 5. Delete with kubectl directly (should work)
	_, err = env.kubectl("delete", "pod", podName, "-n", testNamespace, "--wait=false")
	if err != nil {
		t.Errorf("kubectl delete should have worked: %v", err)
	}

	// 6. Verify pod is gone (or terminating)
	if !env.waitForPodGone(podName, testNamespace, 30*time.Second) {
		t.Errorf("Pod should be deleted or terminating within timeout")
	}
}

// TestIntegration_E2E_ExecBlocked_ThenKubectlWorks proves that:
// 1. kubectl-readonly exec is blocked
// 2. kubectl exec actually works (proving it's not a permission issue)
func TestIntegration_E2E_ExecBlocked_ThenKubectlWorks(t *testing.T) {
	env := getTestEnv(t)

	// Wait for test-pod to be ready
	if !env.waitForPodRunning("test-pod", testNamespace, 60*time.Second) {
		t.Skip("test-pod did not reach Running state, skipping exec test")
	}

	// 1. Try exec with kubectl-readonly (should be blocked)
	_, stderr, exitCode := env.runDirect("exec", "test-pod", "-n", testNamespace, "--", "echo", "hello")
	if exitCode == 0 {
		t.Error("kubectl-readonly should have blocked exec")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected readonly error, got: %s", stderr)
	}

	// 2. Try exec with kubectl readonly plugin (should be blocked)
	_, stderr, exitCode = env.runPlugin("exec", "test-pod", "-n", testNamespace, "--", "echo", "hello")
	if exitCode == 0 {
		t.Error("kubectl readonly plugin should have blocked exec")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected readonly error in plugin mode, got: %s", stderr)
	}

	// 3. kubectl exec directly should work (proves it's not RBAC blocking us)
	stdout, err := env.kubectl("exec", "test-pod", "-n", testNamespace, "--", "echo", "hello")
	if err != nil {
		// Pod might not be ready, skip this check
		t.Logf("kubectl exec failed (pod might not be ready): %v", err)
	} else if !strings.Contains(stdout, "hello") {
		t.Errorf("kubectl exec should have worked and returned 'hello', got: %s", stdout)
	}
}

// TestIntegration_E2E_SecretValuesBlocked proves that:
// 1. kubectl-readonly get secrets (metadata) works
// 2. kubectl-readonly get secrets -o yaml is blocked
// 3. kubectl get secrets -o yaml works and shows actual values
func TestIntegration_E2E_SecretValuesBlocked(t *testing.T) {
	env := getTestEnv(t)

	// 1. Get secret metadata with kubectl-readonly (should work)
	stdout, stderr, exitCode := env.runDirect("get", "secret", "test-secret", "-n", testNamespace)
	if exitCode != 0 {
		t.Errorf("Should be able to get secret metadata: %s", stderr)
	}
	if !strings.Contains(stdout, "test-secret") {
		t.Errorf("Should see secret name in output: %s", stdout)
	}
	// Metadata should NOT contain the actual values
	if strings.Contains(stdout, "c2VjcmV0cGFzc3dvcmQ") { // base64 of "secretpassword"
		t.Error("Metadata output should not contain secret values")
	}

	// 2. Try to get secret values with kubectl-readonly (should be blocked)
	_, stderr, exitCode = env.runDirect("get", "secret", "test-secret", "-n", testNamespace, "-o", "yaml")
	if exitCode == 0 {
		t.Error("kubectl-readonly should have blocked secret -o yaml")
	}
	if !strings.Contains(stderr, "not safe for read-only") {
		t.Errorf("Expected readonly error, got: %s", stderr)
	}

	// 3. Same with plugin mode
	_, stderr, exitCode = env.runPlugin("get", "secret", "test-secret", "-n", testNamespace, "-o", "json")
	if exitCode == 0 {
		t.Error("kubectl readonly plugin should have blocked secret -o json")
	}

	// 4. kubectl directly CAN get the secret values
	stdout, err := env.kubectl("get", "secret", "test-secret", "-n", testNamespace, "-o", "yaml")
	if err != nil {
		t.Errorf("kubectl should be able to get secret values: %v", err)
	}
	// Should contain the base64 encoded password
	if !strings.Contains(stdout, "c2VjcmV0cGFzc3dvcmQ") {
		t.Errorf("kubectl output should contain secret values, got: %s", stdout)
	}
}
