// kubectl-readonly is a kubectl wrapper that only allows read-only commands.
// It prevents accidental modifications but does not protect against malicious intent.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/Evaneos/kubectl-readonly/kubepolicy"
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
	allowed, hint := kubepolicy.Check(filteredArgs)

	if checkMode {
		if allowed {
			fmt.Println("OK: This command is allowed by kubectl-readonly")
			return 0
		}
		fmt.Println("BLOCKED: This command is not allowed in read-only mode")
		if hint != "" {
			fmt.Printf("Hint: %s\n", hint)
		}
		return 1
	}

	if !allowed {
		fmt.Fprint(os.Stderr, "This command is not safe for read-only access; use kubectl directly instead.\n")
		if hint != "" {
			fmt.Fprintf(os.Stderr, "Hint: %s\n", hint)
		}
		fmt.Fprint(os.Stderr, "\nkubectl-readonly only allows read-only commands without side effects.\nFor a list of allowed commands, see: kubectl-readonly --help\n")
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
        config view, config get-contexts, config get-clusters,
        config get-users, config current-context, config use-context
        auth can-i, auth whoami
        rollout status, rollout history
        krew list, krew search, krew info

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
