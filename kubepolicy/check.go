// Package kubepolicy provides a read-only policy check for kubectl commands.
//
// It implements a deny-by-default allowlist: only commands explicitly listed
// as safe are permitted. On secrets, only the name and wide output formats are
// allowed, so no format can print their values.
package kubepolicy

import "fmt"

// Check reports whether the given kubectl arguments are allowed
// under a read-only policy. The hint is a short corrective suggestion
// when the command can be adjusted to pass; it is empty when no
// actionable correction exists.
func Check(args []string) (bool, string) {
	if len(args) == 0 {
		return true, "" // allow: bare kubectl invocation shows help
	}

	if containsControlCharacters(args) {
		return false, "" // deny: potential injection via control characters
	}

	// Every check below reads norm, never args: norm has the flags as kubectl sees them.
	norm := normalizeArgs(args)

	command, subcommand := extractCommandAndSubcommand(norm)
	if command == "" {
		return true, "" // allow: only flags, no command — harmless
	}

	// Safe commands (no subcommand validation needed).
	if safeCommands[command] {
		if mayReadSecret(command, norm) && requestsExposingOutput(norm) {
			return false, "use -o name or -o wide to view secret metadata safely"
		}
		if containsRawSecretsAccess(norm) {
			return false, "use 'get secrets' without --raw to view secret metadata safely"
		}
		if command == "kustomize" {
			if flag := blockedKustomizeFlag(norm); flag != "" {
				return false, fmt.Sprintf("flag %s is not allowed in read-only mode", flag)
			}
		}
		return true, ""
	}

	// Commands requiring a specific subcommand.
	if allowedSubs, ok := safeSubcommands[command]; ok {
		if subcommand == "" {
			return false, fmt.Sprintf("allowed subcommands: %s", joinSorted(allowedSubs))
		}
		if !allowedSubs[subcommand] {
			return false, fmt.Sprintf("allowed subcommands for %s: %s", command, joinSorted(allowedSubs))
		}
		if command == "config" && subcommand == "view" && revealsKubeconfigSecrets(norm) {
			return false, "use 'config view' without --raw or --flatten; these reveal credentials"
		}
		return true, ""
	}

	return false, "" // deny: command not in any allowlist
}
