package cli

import (
	"slices"
	"strings"
)

// unsafeEnvVars make an allowed kubectl command run a program or change its
// behavior without any argument: KUBECTL_EXTERNAL_DIFF runs a program on
// `kubectl diff`, KUBERC points to a kuberc file whose defaults add flags
// (e.g. -o yaml on get secrets). Every other variable is kept: credential
// plugins (gcloud, aws, kubelogin) and proxies need them.
var unsafeEnvVars = []string{"KUBECTL_EXTERNAL_DIFF", "KUBERC"}

// sanitizeEnvironment drops unsafeEnvVars and disables kuberc, including the
// default ~/.kube/kuberc file.
func sanitizeEnvironment(environ []string) []string {
	safe := make([]string, 0, len(environ)+1)
	for _, entry := range environ {
		name, _, _ := strings.Cut(entry, "=")
		if !slices.Contains(unsafeEnvVars, name) {
			safe = append(safe, entry)
		}
	}
	return append(safe, "KUBERC=off")
}
