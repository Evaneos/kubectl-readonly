package kubepolicy

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

// secretExposingFormats are output formats that expose secret values.
var secretExposingFormats = map[string]bool{
	"yaml":                true,
	"json":                true,
	"jsonpath":            true,
	"jsonpath-as-json":    true,
	"jsonpath-file":       true,
	"go-template":         true,
	"go-template-file":    true,
	"template":            true,
	"templatefile":        true,
	"custom-columns":      true,
	"custom-columns-file": true,
}

// flagsWithValues are kubectl flags that consume the next argument.
var flagsWithValues = map[string]bool{
	"-n": true, "--namespace": true,
	"--context": true, "--kubeconfig": true,
	"-o": true, "--output": true,
	"-l": true, "--selector": true,
	"--field-selector": true,
	"-v":               true, "--v": true,
	"--request-timeout": true,
	"--server":          true, "-s": true,
	"--token": true, "--user": true, "--cluster": true,
	"--certificate-authority": true,
	"--client-certificate":    true, "--client-key": true,
	"--tls-server-name": true,
	"--as":              true, "--as-group": true, "--as-uid": true,
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
