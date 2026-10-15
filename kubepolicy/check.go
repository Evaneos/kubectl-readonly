// Package kubepolicy provides a read-only policy check for kubectl commands.
//
// It implements a deny-by-default allowlist: only commands explicitly listed
// as safe are permitted. Under the moderate and strict modes, only the name
// and wide output formats are allowed on secrets, so no format can print their
// values. The leaky mode drops that secret masking and keeps everything else.
package kubepolicy

import "fmt"

// Hints of the secret-masking rules, the only rules ModeLeaky skips.
const (
	hintSecretOutput          = "use -o name or -o wide to view secret metadata safely"
	hintRawSecrets            = "use 'get secrets' without --raw to view secret metadata safely"
	hintKubeconfigCredentials = "use 'config view' without --raw or --flatten; these reveal credentials"
	hintDiffShowSecrets       = "use 'diff' without --show-secrets; it reveals secret values"
)

// Decision is the policy verdict on a kubectl command line.
type Decision struct {
	Allowed bool
	// Hint is a short corrective suggestion when the command can be adjusted
	// to pass; it is empty when no actionable correction exists.
	Hint string
}

func allow() Decision           { return Decision{Allowed: true} }
func deny(hint string) Decision { return Decision{Hint: hint} }

// Check reports whether the given kubectl arguments are allowed under the
// moderate mode, with the hint of Evaluate.
func Check(args []string) (bool, string) {
	d := Evaluate(args, ModeModerate)
	return d.Allowed, d.Hint
}

// Evaluate reports whether the given kubectl arguments are allowed under mode.
// Arguments are parsed the same way in every mode; the mode only selects
// which rules apply.
func Evaluate(args []string, mode Mode) Decision {
	if len(args) == 0 {
		return allow() // bare kubectl invocation shows help
	}

	if containsControlCharacters(args) {
		return deny("") // potential injection via control characters
	}

	// Every check below reads norm, never args: norm has the flags as kubectl sees them.
	norm := normalizeArgs(args)

	command, subcommand := extractCommandAndSubcommand(norm)
	if command == "" {
		return allow() // only flags, no command: harmless
	}

	// Safe commands (no subcommand validation needed).
	if safeCommands[command] {
		if mode.masksSecrets() {
			if mayReadSecret(command, norm) && requestsExposingOutput(norm) {
				return deny(hintSecretOutput)
			}
			if containsRawSecretsAccess(norm) {
				return deny(hintRawSecrets)
			}
			if command == "diff" && revealsSecretsInDiff(norm) {
				return deny(hintDiffShowSecrets)
			}
		}
		if command == "kustomize" {
			if flag := blockedKustomizeFlag(norm); flag != "" {
				return deny(fmt.Sprintf("flag %s is not allowed in read-only mode", flag))
			}
		}
		return allow()
	}

	// Commands requiring a specific subcommand.
	if allowedSubs, ok := safeSubcommands[command]; ok {
		if subcommand == "" {
			return deny(fmt.Sprintf("allowed subcommands: %s", joinSorted(allowedSubs)))
		}
		if !allowedSubs[subcommand] {
			return deny(fmt.Sprintf("allowed subcommands for %s: %s", command, joinSorted(allowedSubs)))
		}
		if mode.masksSecrets() && command == "config" && subcommand == "view" && revealsKubeconfigSecrets(norm) {
			return deny(hintKubeconfigCredentials)
		}
		return allow()
	}

	return deny("") // command not in any allowlist
}
