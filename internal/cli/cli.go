// Package cli is the command-line front end shared by the kubectl-readonly
// binaries: each binary runs it with its own policy mode.
package cli

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

// Main runs the binary for mode and exits with its status.
func Main(mode kubepolicy.Mode) {
	os.Exit(Run(mode, os.Args[1:]))
}

// Run checks args against mode and, when allowed, replaces the process with
// kubectl. It returns the exit status only when kubectl is not executed.
func Run(mode kubepolicy.Mode, args []string) int {
	name := binaryName(mode)

	if len(args) == 0 || (len(args) == 1 && (args[0] == "-h" || args[0] == "--help")) {
		printHelp(mode)
		return 0
	}

	if len(args) == 1 && args[0] == versionFlag {
		profileInfo := ""
		if mode != kubepolicy.ModeModerate {
			profileInfo = "profile: " + mode.String() + ", "
		}
		fmt.Printf("%s %s (%scommit: %s, built: %s)\n", name, version, profileInfo, commit, date)
		return 0
	}

	checkMode := false
	var filteredArgs []string
	for _, arg := range args {
		if arg == checkFlag {
			checkMode = true
		} else {
			filteredArgs = append(filteredArgs, arg)
		}
	}

	d := kubepolicy.Evaluate(filteredArgs, mode)

	if checkMode {
		if d.Allowed {
			fmt.Printf("OK: This command is allowed by %s\n", name)
			return 0
		}
		fmt.Println("BLOCKED: This command is not allowed in read-only mode")
		if d.Hint != "" {
			fmt.Printf("Hint: %s\n", d.Hint)
		}
		return 1
	}

	if !d.Allowed {
		fmt.Fprint(os.Stderr, "This command is not safe for read-only access; use kubectl directly instead.\n")
		if d.Hint != "" {
			fmt.Fprintf(os.Stderr, "Hint: %s\n", d.Hint)
		}
		fmt.Fprintf(os.Stderr, "\n%s only allows read-only commands without side effects.\nFor a list of allowed commands, see: %s --help\n", name, name)
		return 1
	}

	env := os.Environ()
	if profiles[mode].sanitizesEnv {
		env = sanitizeEnvironment(env)
	}
	return execKubectl(filteredArgs, env)
}

func execKubectl(args, env []string) int {
	kubectlPath, err := exec.LookPath("kubectl")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: kubectl not found in PATH")
		return 127
	}

	// Use syscall.Exec to replace the current process (more efficient)
	execArgs := append([]string{"kubectl"}, args...)
	if err := syscall.Exec(kubectlPath, execArgs, env); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing kubectl: %v\n", err)
		return 1
	}
	return 0
}

func binaryName(mode kubepolicy.Mode) string {
	if mode == kubepolicy.ModeModerate {
		return "kubectl-readonly"
	}
	return "kubectl-readonly-" + mode.String()
}

// pluginName is the krew plugin name, as typed after `kubectl`.
func pluginName(mode kubepolicy.Mode) string {
	return binaryName(mode)[len("kubectl-"):]
}
