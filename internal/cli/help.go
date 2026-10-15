package cli

import (
	"fmt"
	"strings"

	"github.com/Evaneos/kubectl-readonly/kubepolicy"
)

const helpTemplate = `{{name}} - A kubectl wrapper that only allows read-only commands

PROFILE:
{{profileSummary}}

USAGE:
    {{name}} [kubectl args...]
    {{name}} --readonly-check-ok [kubectl args...]

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

{{secretsSection}}
EXAMPLES:
    {{name}} get pods
    {{name}} get pods -n kube-system
    {{name}} describe pod my-pod
    {{name}} logs my-pod -f
    {{name}} top nodes
    {{name}} config use-context production
    {{name}} --readonly-check-ok delete pod my-pod  # Returns 1

ALIAS:
    For convenience, you can create an alias:
        alias kro='{{name}}'

    Or use as a kubectl plugin (if installed via Krew):
        kubectl {{plugin}} get pods
`

const maskedSecretsSection = `SECRETS PROTECTION:
    You can list secrets (metadata) but not view their values:
        {{name}} get secrets              # OK - shows names only
        {{name}} describe secret X        # OK - shows size only
        {{name}} get secrets -o yaml      # BLOCKED - exposes values
        {{name}} get secrets -o json      # BLOCKED - exposes values
`

const strictEnvSection = `
ENVIRONMENT:
    kubectl runs without KUBECTL_EXTERNAL_DIFF (runs a program on diff)
    and with KUBERC=off (kuberc defaults can add flags such as -o yaml).
    Every other variable is passed through, so credential plugins and
    proxies keep working. A kubeconfig exec: entry still runs its command.
`

const leakySecretsSection = `SECRETS:
    Secret values are shown: get secret -o yaml, get --raw on secret
    paths, config view --raw and diff --show-secrets print credentials.
    Writes and exec stay blocked. Use kubectl-readonly to keep secret
    values hidden.
`

// profile holds what the CLI does differently for each mode.
type profile struct {
	summary      string
	secretsHelp  string
	sanitizesEnv bool
}

var profiles = map[kubepolicy.Mode]profile{
	kubepolicy.ModeModerate: {
		summary:     "    moderate: blocks writes and exec, masks secret values.",
		secretsHelp: maskedSecretsSection,
	},
	kubepolicy.ModeStrict: {
		summary:      "    strict: moderate, plus a sanitized environment for kubectl.",
		secretsHelp:  maskedSecretsSection + strictEnvSection,
		sanitizesEnv: true,
	},
	kubepolicy.ModeLeaky: {
		summary:     "    leaky: blocks writes and exec, shows secret values.",
		secretsHelp: leakySecretsSection,
	},
}

func printHelp(mode kubepolicy.Mode) {
	p := profiles[mode]
	r := strings.NewReplacer(
		"{{secretsSection}}", p.secretsHelp,
		"{{profileSummary}}", p.summary,
	)
	// Second pass: the sections inserted above carry {{name}} themselves.
	names := strings.NewReplacer("{{name}}", binaryName(mode), "{{plugin}}", pluginName(mode))
	fmt.Print(names.Replace(r.Replace(helpTemplate)))
}
