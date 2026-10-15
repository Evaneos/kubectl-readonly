package kubepolicy

import (
	"slices"
	"strings"
)

// joinSorted returns the sorted keys of m joined with ", ".
func joinSorted(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return strings.Join(keys, ", ")
}

// safeCommands are kubectl commands allowed without subcommand validation.
var safeCommands = map[string]bool{
	"get":           true,
	"describe":      true,
	"logs":          true,
	"top":           true,
	"explain":       true,
	"api-resources": true,
	"api-versions":  true,
	"cluster-info":  true,
	"version":       true,
	"events":        true,
	"wait":          true,
	"diff":          true,
	"kustomize":     true,
}

// safeSubcommands are kubectl commands that require a specific subcommand.
var safeSubcommands = map[string]map[string]bool{
	"config": {
		"view":            true,
		"get-contexts":    true,
		"get-clusters":    true,
		"get-users":       true,
		"current-context": true,
		"use-context":     true,
	},
	"auth": {
		"can-i":  true,
		"whoami": true,
	},
	"rollout": {
		"status":  true,
		"history": true,
	},
	"krew": {
		"list":   true,
		"search": true,
		"info":   true,
	},
}

// secretResources are resource types that contain sensitive data.
var secretResources = map[string]bool{
	"secret":  true,
	"secrets": true,
}

// flagsWithValues are kubectl flags that consume the next argument.
// The global flags are complete as of kubectl 1.37 (`kubectl options`): a missing
// one makes its value read as the command word. Re-check on kubectl upgrades.
var flagsWithValues = map[string]bool{
	"-n": true, "--namespace": true,
	"--context": true, "--kubeconfig": true,
	"-o": true, "--output": true,
	"-l": true, "--selector": true,
	"--field-selector": true,
	"-v":               true, "--v": true,
	"--request-timeout": true,
	"--server":          true, "-s": true,
	"--token": true, "--user": true, "--username": true, "--password": true,
	"--cluster":               true,
	"--certificate-authority": true,
	"--client-certificate":    true, "--client-key": true,
	"--tls-server-name": true, "--proxy-url": true,
	"--as": true, "--as-group": true, "--as-uid": true, "--as-user-extra": true,
	"--profile": true, "--profile-output": true,
	"--vmodule": true, "--log-flush-frequency": true, "--kuberc": true,
	"--cache-dir": true, "--sort-by": true, "--chunk-size": true,
	"--template": true,
	"-f":         true, "--filename": true,
	"-k": true, "--kustomize": true,
	"--since": true, "--since-time": true, "--tail": true,
	"-c": true, "--container": true,
	"--limit-bytes": true, "--pod-running-timeout": true,
	"--timeout": true, "--for": true, "--max-log-requests": true,
}

// kustomizeBlockedFlags are flags that enable code execution, network access,
// or unrestricted file reads when used with the kustomize command.
var kustomizeBlockedFlags = map[string]bool{
	"--enable-alpha-plugins": true,
	"--enable-helm":          true,
	"--network":              true,
}
