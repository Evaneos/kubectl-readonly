//go:build integration

// Tests for the strict and leaky profile binaries.
//
// Smoke tests (TestSmoke_Profiles_*) need only the built binaries; integration
// tests (TestIntegration_Profiles_*) need the kind cluster of integration_test.go.

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// profileBinary returns the absolute path of ./kubectl-readonly-<profile>,
// or of ./kubectl-readonly for the "moderate" profile.
func profileBinary(t *testing.T, profile string) string {
	t.Helper()
	name := "./kubectl-readonly"
	if profile != "moderate" {
		name += "-" + profile
	}
	path, err := filepath.Abs(name)
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s not found. Run 'make build' first.", path)
	}
	return path
}

func runBinary(t *testing.T, binary string, env []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = env
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("running %s: %v", binary, err)
		}
		exitCode = exitErr.ExitCode()
	}
	return outBuf.String(), errBuf.String(), exitCode
}

func checkVerdict(t *testing.T, binary string, args ...string) bool {
	t.Helper()
	stdout, _, code := runBinary(t, binary, os.Environ(), append([]string{"--readonly-check-ok"}, args...)...)
	return code == 0 && strings.Contains(stdout, "OK")
}

func TestSmoke_Profiles_Verdicts(t *testing.T) {
	allowed := map[string]bool{"moderate": true, "strict": true, "leaky": true}
	blocked := map[string]bool{"moderate": false, "strict": false, "leaky": false}
	allowedInLeaky := map[string]bool{"moderate": false, "strict": false, "leaky": true}
	cases := []struct {
		args []string
		want map[string]bool
	}{
		{[]string{"get", "pods"}, allowed},
		{[]string{"get", "pods", "-o", "yaml"}, allowed},
		{[]string{"diff", "-f", "x.yaml"}, allowed},
		{[]string{"kustomize", "."}, allowed},
		{[]string{"get", "secret", "x", "-o", "yaml"}, allowedInLeaky},
		{[]string{"get", "--raw", "/api/v1/secrets"}, allowedInLeaky},
		{[]string{"config", "view", "--raw"}, allowedInLeaky},
		{[]string{"delete", "pod", "x"}, blocked},
		{[]string{"exec", "pod", "--", "sh"}, blocked},
		{[]string{"kustomize", "--enable-helm", "."}, blocked},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, "_"), func(t *testing.T) {
			for profile, want := range c.want {
				t.Run(profile, func(t *testing.T) {
					if got := checkVerdict(t, profileBinary(t, profile), c.args...); got != want {
						t.Errorf("allowed = %v, want %v", got, want)
					}
				})
			}
		})
	}
}

func TestSmoke_Profiles_Version(t *testing.T) {
	for _, profile := range []string{"strict", "leaky"} {
		stdout, _, code := runBinary(t, profileBinary(t, profile), os.Environ(), "--readonly-version")
		if code != 0 || !strings.Contains(stdout, "profile: "+profile) {
			t.Errorf("%s --readonly-version: exit %d, output %q", profile, code, stdout)
		}
	}
}

// A kuberc default adds flags with no argument on the command line; strict
// disables kuberc. `version --client` needs no cluster.
func TestSmoke_Profiles_StrictDisablesKuberc(t *testing.T) {
	kuberc := filepath.Join(t.TempDir(), "kuberc")
	if err := os.WriteFile(kuberc, []byte(`apiVersion: kubectl.config.k8s.io/v1beta1
kind: Preference
defaults:
- command: version
  options:
  - name: output
    default: json
`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "KUBERC="+kuberc)

	moderate := profileBinary(t, "moderate")
	if stdout, _, _ := runBinary(t, moderate, env, "version", "--client"); !strings.HasPrefix(stdout, "{") {
		t.Skipf("this kubectl ignores kuberc (control case printed %q)", stdout)
	}
	if stdout, _, _ := runBinary(t, profileBinary(t, "strict"), env, "version", "--client"); strings.HasPrefix(stdout, "{") {
		t.Errorf("strict applied the kuberc default: %q", stdout)
	}
}

func TestIntegration_Profiles_LeakyShowsSecretValue(t *testing.T) {
	getTestEnv(t)
	stdout, stderr, code := runBinary(t, profileBinary(t, "leaky"), os.Environ(),
		"get", "secret", "test-secret", "-n", testNamespace, "-o", "jsonpath={.data.password}")
	if code != 0 {
		t.Fatalf("Expected exit code 0, got %d. Stderr: %s", code, stderr)
	}
	if stdout != "c2VjcmV0cGFzc3dvcmQ=" {
		t.Errorf("Expected the secret value, got: %q", stdout)
	}
}

func TestIntegration_Profiles_LeakyStillBlocksWrites(t *testing.T) {
	env := getTestEnv(t)
	_, _, code := runBinary(t, profileBinary(t, "leaky"), os.Environ(),
		"delete", "pod", "test-pod", "-n", testNamespace)
	if code == 0 {
		t.Error("Expected delete to be blocked")
	}
	if _, err := env.kubectl("get", "pod", "test-pod", "-n", testNamespace); err != nil {
		t.Errorf("test-pod should still exist: %v", err)
	}
}

// KUBECTL_EXTERNAL_DIFF makes `kubectl diff` run an arbitrary program. Moderate
// passes the environment through, so the program runs; strict drops it.
func TestIntegration_Profiles_StrictDropsExternalDiff(t *testing.T) {
	getTestEnv(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "external-diff-ran")
	script := filepath.Join(dir, "diff.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "cm.yaml")
	if err := os.WriteFile(manifest, []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: test-configmap
  namespace: `+testNamespace+`
data:
  config.yaml: changed
`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "KUBECTL_EXTERNAL_DIFF="+script)

	moderate := profileBinary(t, "moderate")
	runBinary(t, moderate, env, "diff", "-f", manifest)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("control case: moderate should run KUBECTL_EXTERNAL_DIFF, marker missing: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, _ := runBinary(t, profileBinary(t, "strict"), env, "diff", "-f", manifest)
	if _, err := os.Stat(marker); err == nil {
		t.Error("strict ran the KUBECTL_EXTERNAL_DIFF program")
	}
	if !strings.Contains(stdout, "changed") {
		t.Errorf("strict diff should print the change with the default diff. Stdout: %s Stderr: %s", stdout, stderr)
	}
}
