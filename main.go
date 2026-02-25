// kubectl-readonly is a kubectl wrapper that only allows read-only commands.
// It prevents accidental modifications but does not protect against malicious intent.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const (
	checkFlag   = "--readonly-check-ok"
	versionFlag = "--readonly-version"
)

// Version information (injected by GoReleaser via ldflags)
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// Handle help
	if len(args) == 0 || (len(args) == 1 && (args[0] == "-h" || args[0] == "--help")) {
		printHelp()
		return 0
	}

	// Handle version
	if len(args) == 1 && args[0] == versionFlag {
		fmt.Printf("kubectl-readonly %s (commit: %s, built: %s)\n", version, commit, date)
		return 0
	}

	// Check for --readonly-check-ok flag
	checkMode := false
	var filteredArgs []string
	for _, arg := range args {
		if arg == checkFlag {
			checkMode = true
		} else {
			filteredArgs = append(filteredArgs, arg)
		}
	}

	// Validate the command
	allowed, reason := isCommandAllowed(filteredArgs)

	if checkMode {
		if allowed {
			fmt.Println("OK: This command is allowed by kubectl-readonly")
			return 0
		}
		fmt.Printf("BLOCKED: %s\n", reason)
		return 1
	}

	if !allowed {
		fmt.Fprintf(os.Stderr, `This command is not safe for read-only access; use kubectl directly instead.

Reason: %s

kubectl-readonly only allows read-only commands without side effects.
For a list of allowed commands, see: kubectl-readonly --help
`, reason)
		return 1
	}

	// Execute kubectl
	return execKubectl(filteredArgs)
}

func execKubectl(args []string) int {
	kubectlPath, err := exec.LookPath("kubectl")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: kubectl not found in PATH")
		return 127
	}

	// Use syscall.Exec to replace the current process (more efficient)
	execArgs := append([]string{"kubectl"}, args...)
	if err := syscall.Exec(kubectlPath, execArgs, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing kubectl: %v\n", err)
		return 1
	}
	return 0
}

func printHelp() {
	fmt.Print(`kubectl-readonly - A kubectl wrapper that only allows read-only commands

USAGE:
    kubectl-readonly [kubectl args...]
    kubectl-readonly --readonly-check-ok [kubectl args...]

DESCRIPTION:
    This tool wraps kubectl and only allows commands that are read-only
    (no side effects on the cluster). Use this to safely explore Kubernetes
    clusters, including production environments.

    If a command is not allowed, an error message is displayed and the
    command is NOT executed.

SPECIAL FLAGS (for the wrapper, not passed to kubectl):
    --readonly-check-ok    Check if a command would be allowed without
                           executing it. Returns exit code 0 if allowed,
                           1 if blocked.
    --readonly-version     Show version information.

ALLOWED COMMANDS:
    Simple commands (no subcommand needed):
        get, describe, logs, top, explain, api-resources, api-versions,
        cluster-info, version, events, wait, diff, kustomize

    Commands with specific subcommands:
        config view, config get-contexts, config current-context,
        config use-context
        auth can-i, auth whoami
        rollout status, rollout history

KUSTOMIZE RESTRICTIONS:
    The kustomize command is allowed for local manifest rendering, but
    the following flags are blocked (they enable code execution, network
    access, or unrestricted file reads):
        --enable-alpha-plugins    Executes arbitrary local binaries
        --enable-helm             Invokes helm (may fetch remote charts)
        --network                 Enables network access for functions
        --load-restrictor=None    Allows reading files outside root

SECRETS PROTECTION:
    You can list secrets (metadata) but not view their values:
        kubectl-readonly get secrets              # OK - shows names only
        kubectl-readonly describe secret X        # OK - shows size only
        kubectl-readonly get secrets -o yaml      # BLOCKED - exposes values
        kubectl-readonly get secrets -o json      # BLOCKED - exposes values

EXAMPLES:
    kubectl-readonly get pods
    kubectl-readonly get pods -n kube-system
    kubectl-readonly describe pod my-pod
    kubectl-readonly logs my-pod -f
    kubectl-readonly top nodes
    kubectl-readonly config use-context production
    kubectl-readonly --readonly-check-ok delete pod my-pod  # Returns 1

ALIAS:
    For convenience, you can create an alias:
        alias kro='kubectl-readonly'

    Or use as a kubectl plugin (if installed via Krew):
        kubectl readonly get pods
`)
}

// Safe commands that don't require subcommand validation
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

// Commands with allowed subcommands
var safeSubcommands = map[string]map[string]bool{
	"config": {
		"view":            true,
		"get-contexts":    true,
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
}

// Secret resource types
var secretResources = map[string]bool{
	"secret":  true,
	"secrets": true,
}

// Output formats that expose secret values
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

// Flags that take a value as the next argument
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

func isCommandAllowed(args []string) (bool, string) {
	if len(args) == 0 {
		return true, ""
	}

	// Check for control characters (null bytes, etc.) - potential injection attack
	if containsControlCharacters(args) {
		return false, "Arguments contain invalid control characters"
	}

	command, subcommand := extractCommandAndSubcommand(args)
	if command == "" {
		return true, ""
	}

	// Check safe commands
	if safeCommands[command] {
		// Check secrets protection
		if containsSecretResource(args) {
			outputFormat := getOutputFormat(args)
			if isSecretExposingFormat(outputFormat) {
				return false, fmt.Sprintf("Output format '%s' exposes secret values. Use default format or '-o name' to see secret metadata only.", outputFormat)
			}
		}

		// Check --raw access to secrets
		if containsRawSecretsAccess(args) {
			return false, "Access to secrets via --raw is not allowed (exposes secret values)"
		}

		// Check kustomize-specific blocked flags
		if command == "kustomize" {
			if blocked, reason := containsBlockedKustomizeFlags(args); blocked {
				return false, reason
			}
		}

		return true, ""
	}

	// Check commands with subcommands
	if allowedSubs, ok := safeSubcommands[command]; ok {
		if subcommand == "" {
			var allowed []string
			for k := range allowedSubs {
				allowed = append(allowed, k)
			}
			return false, fmt.Sprintf("Command '%s' requires a subcommand. Allowed: %s", command, strings.Join(allowed, ", "))
		}
		if allowedSubs[subcommand] {
			return true, ""
		}
		var allowed []string
		for k := range allowedSubs {
			allowed = append(allowed, k)
		}
		return false, fmt.Sprintf("Subcommand '%s %s' is not allowed. Allowed subcommands for '%s': %s", command, subcommand, command, strings.Join(allowed, ", "))
	}

	return false, fmt.Sprintf("Command '%s' is not in the read-only allowlist", command)
}

func extractCommandAndSubcommand(args []string) (command, subcommand string) {
	i := 0
	for i < len(args) {
		arg := args[i]

		if strings.HasPrefix(arg, "-") {
			// Skip flag and its value if applicable
			if strings.Contains(arg, "=") {
				i++
			} else if flagsWithValues[arg] {
				i += 2
			} else {
				i++
			}
			continue
		}

		// Positional argument
		if command == "" {
			command = arg
			i++
		} else if subcommand == "" {
			subcommand = arg
			break
		} else {
			break
		}
	}
	return
}

func extractResourceTypes(args []string) []string {
	command, _ := extractCommandAndSubcommand(args)
	if command != "get" && command != "describe" && command != "wait" && command != "events" {
		return nil
	}

	var resources []string
	foundCommand := false
	i := 0

	for i < len(args) {
		arg := args[i]

		if strings.HasPrefix(arg, "-") {
			if strings.Contains(arg, "=") {
				i++
			} else if flagsWithValues[arg] {
				i += 2
			} else {
				i++
			}
			continue
		}

		if !foundCommand {
			if arg == command {
				foundCommand = true
			}
			i++
			continue
		}

		// Parse resource types (handles comma-separated, type/name, and type.group formats)
		for _, part := range strings.Split(arg, ",") {
			resourceType := part
			if idx := strings.Index(part, "/"); idx != -1 {
				resourceType = part[:idx]
			}
			// Strip API group qualifiers (e.g., secret.v1, secret.v1.core, secrets.core)
			if idx := strings.Index(resourceType, "."); idx != -1 {
				resourceType = resourceType[:idx]
			}
			resourceType = strings.ToLower(resourceType)
			if resourceType != "" && !strings.HasPrefix(resourceType, "-") {
				resources = append(resources, resourceType)
			}
		}
		i++
	}

	return resources
}

func containsSecretResource(args []string) bool {
	for _, r := range extractResourceTypes(args) {
		if secretResources[r] {
			return true
		}
	}
	return false
}

func getOutputFormat(args []string) string {
	for i, arg := range args {
		if (arg == "-o" || arg == "--output") && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "-o=") {
			return arg[3:]
		}
		if strings.HasPrefix(arg, "--output=") {
			return arg[9:]
		}
		if strings.HasPrefix(arg, "-o") && len(arg) > 2 {
			return arg[2:]
		}
	}
	return ""
}

func isSecretExposingFormat(format string) bool {
	if format == "" {
		return false
	}
	format = strings.ToLower(format)
	for exposing := range secretExposingFormats {
		if format == exposing || strings.HasPrefix(format, exposing+"=") {
			return true
		}
	}
	return false
}

func containsRawSecretsAccess(args []string) bool {
	var rawValue string
	for i, arg := range args {
		if arg == "--raw" && i+1 < len(args) {
			rawValue = args[i+1]
			break
		}
		if strings.HasPrefix(arg, "--raw=") {
			rawValue = arg[6:]
			break
		}
	}

	if rawValue == "" {
		return false
	}

	rawLower := strings.ToLower(rawValue)
	return strings.Contains(rawLower, "/secrets") ||
		strings.Contains(rawLower, "/secret/") ||
		strings.Contains(rawLower, "secrets/")
}

// Flags blocked for the kustomize command.
// kustomize is a local build tool (no cluster interaction), but these flags
// enable code execution, network access, or unrestricted file reads — actions
// that should require explicit user approval via kubectl directly.
var kustomizeBlockedFlags = map[string]bool{
	"--enable-alpha-plugins": true,
	"--enable-helm":          true,
	"--network":              true,
}

func containsBlockedKustomizeFlags(args []string) (bool, string) {
	for i, arg := range args {
		// Exact match: --enable-helm, --network
		if kustomizeBlockedFlags[arg] {
			return true, fmt.Sprintf("Flag '%s' is not allowed with kustomize in read-only mode", arg)
		}
		// Boolean flag with =true: --enable-helm=true, --network=true
		for flag := range kustomizeBlockedFlags {
			if strings.HasPrefix(arg, flag+"=") {
				return true, fmt.Sprintf("Flag '%s' is not allowed with kustomize in read-only mode", flag)
			}
		}
		// --load-restrictor with non-default value
		if arg == "--load-restrictor" && i+1 < len(args) && args[i+1] != "LoadRestrictionsRootOnly" {
			return true, "Flag '--load-restrictor' with non-default value is not allowed with kustomize in read-only mode"
		}
		if strings.HasPrefix(arg, "--load-restrictor=") {
			val := arg[len("--load-restrictor="):]
			if val != "LoadRestrictionsRootOnly" {
				return true, "Flag '--load-restrictor' with non-default value is not allowed with kustomize in read-only mode"
			}
		}
	}
	return false, ""
}

func containsControlCharacters(args []string) bool {
	for _, arg := range args {
		for _, r := range arg {
			// Block null byte and other dangerous control characters
			// Allow common whitespace (tab=0x09, newline=0x0A, carriage return=0x0D)
			// These are handled safely by the OS and don't pose injection risks
			if r == 0x00 || // Null byte - can truncate strings
				(r >= 0x01 && r <= 0x08) || // SOH to BS
				(r >= 0x0E && r <= 0x1F) || // SO to US (excluding common whitespace)
				r == 0x0B || // Vertical tab
				r == 0x0C || // Form feed
				r == 0x7F { // DEL character
				return true
			}
		}
	}
	return false
}
