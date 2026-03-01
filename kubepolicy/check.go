// Package kubepolicy provides a read-only policy check for kubectl commands.
//
// It implements a deny-by-default allowlist: only commands explicitly listed
// as safe are permitted. Secret values are protected by blocking output formats
// that expose base64-decoded data.
package kubepolicy

// Check reports whether the given kubectl arguments are allowed
// under a read-only policy.
func Check(args []string) bool {
	if len(args) == 0 {
		return true // allow: bare kubectl invocation shows help
	}

	if containsControlCharacters(args) {
		return false // deny: potential injection via control characters
	}

	command, subcommand := extractCommandAndSubcommand(args)
	if command == "" {
		return true // deny: only flags, no command — harmless
	}

	// Safe commands (no subcommand validation needed).
	if safeCommands[command] {
		if containsSecretResource(args) {
			if isSecretExposingFormat(getOutputFormat(args)) {
				return false // deny: output format exposes secret values
			}
		}
		if containsRawSecretsAccess(args) {
			return false // deny: --raw access to secrets API
		}
		if command == "kustomize" {
			if containsBlockedKustomizeFlags(args) {
				return false // deny: kustomize flag enables execution/network/unrestricted reads
			}
		}
		return true
	}

	// Commands requiring a specific subcommand.
	if allowedSubs, ok := safeSubcommands[command]; ok {
		if subcommand == "" {
			return false // deny: command requires a subcommand
		}
		if allowedSubs[subcommand] {
			return true
		}
		return false // deny: subcommand not in allowlist
	}

	return false // deny: command not in any allowlist
}
