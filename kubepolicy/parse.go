package kubepolicy

import (
	"net/url"
	"strconv"
	"strings"
)

// shorthandValueFlags are the single-letter kubectl flags that take a value; a
// letter missing here mis-splits a cluster. Shorthands vary per command (-f is
// --follow on logs): exact for get, describe, wait and events, over-blocking elsewhere.
var shorthandValueFlags = map[byte]bool{
	'o': true, // output
	'n': true, // namespace
	'l': true, // selector
	'L': true, // label-columns (get)
	'v': true, // verbosity
	'c': true, // container
	's': true, // server
	'f': true, // filename
	'k': true, // kustomize
}

// normalizeArgs rewrites args so the policy sees the flags kubectl sees: grouped
// shorthand clusters are split (-Aoyaml -> -A -o yaml, -o=yaml -> -o yaml) and "_"
// in long flag names is folded to "-" (kubectl reads --profile_output as
// --profile-output). A bare "-", "--" and a non-letter cluster (-1) pass through.
func normalizeArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			name, value, hasValue := strings.Cut(arg[2:], "=")
			name = strings.ReplaceAll(name, "_", "-")
			if hasValue {
				out = append(out, "--"+name+"="+value)
			} else {
				out = append(out, "--"+name)
			}
			continue
		}
		if len(arg) < 2 || arg[0] != '-' || !isASCIILetter(arg[1]) {
			out = append(out, arg)
			continue
		}
		body := arg[1:]
		for j := 0; j < len(body); j++ {
			ch := body[j]
			if !shorthandValueFlags[ch] {
				if j+1 < len(body) && body[j+1] == '=' {
					// A boolean shorthand with an explicit value (-A=false) stays one flag.
					out = append(out, "-"+body[j:])
					break
				}
				out = append(out, "-"+string(ch))
				continue
			}
			raw := body[j+1:]
			switch {
			case strings.HasPrefix(raw, "="):
				// -o=value, and -o= for an explicit empty value: both in this token.
				out = append(out, "-"+string(ch), raw[1:])
			case raw != "":
				out = append(out, "-"+string(ch), raw)
			case i+1 < len(args):
				out = append(out, "-"+string(ch), args[i+1])
				i++
			default:
				out = append(out, "-"+string(ch))
			}
			break // the value flag consumes the remainder of the cluster
		}
	}
	return out
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func extractCommandAndSubcommand(args []string) (command, subcommand string) {
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

		for _, part := range strings.Split(arg, ",") {
			resourceType := part
			if idx := strings.Index(part, "/"); idx != -1 {
				resourceType = part[:idx]
			}
			// Strip API group qualifiers (e.g. secret.v1, secret.v1.core)
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

// outputFormats returns every -o/--output value in args (kubectl honours the
// last, so all are checked). Expects args already run through normalizeArgs.
func outputFormats(args []string) []string {
	var formats []string
	for i, arg := range args {
		switch {
		case (arg == "-o" || arg == "--output") && i+1 < len(args):
			formats = append(formats, args[i+1])
		case strings.HasPrefix(arg, "--output="):
			formats = append(formats, arg[len("--output="):])
		}
	}
	return formats
}

// requestsExposingOutput reports whether any output selector would print secret
// values. Only name and wide are metadata-safe; any other format counts as
// exposing. A bare --template also selects go-template output without any -o.
func requestsExposingOutput(args []string) bool {
	for i, arg := range args {
		if (arg == "--template" && i+1 < len(args)) || strings.HasPrefix(arg, "--template=") {
			return true
		}
	}
	for _, f := range outputFormats(args) {
		base := strings.ToLower(f)
		if idx := strings.IndexByte(base, '='); idx != -1 {
			base = base[:idx]
		}
		if base != "" && base != "name" && base != "wide" {
			return true
		}
	}
	return false
}

// mayReadSecret reports whether the command could print live Secret values:
// a named secret resource, or a get/wait pointed at a -f/-k file. The file is
// never inspected, so when it could name a secret we treat it as one.
func mayReadSecret(command string, args []string) bool {
	if containsSecretResource(args) {
		return true
	}
	if command == "get" || command == "wait" {
		return hasFileFlag(args)
	}
	return false
}

func hasFileFlag(args []string) bool {
	for _, a := range args {
		switch {
		case a == "-f" || a == "--filename" || a == "-k" || a == "--kustomize":
			return true
		case strings.HasPrefix(a, "--filename=") || strings.HasPrefix(a, "--kustomize="):
			return true
		}
	}
	return false
}

// revealsKubeconfigSecrets reports whether a 'config view' would print
// credentials in clear. Plain 'config view' redacts them; --raw and --flatten
// undo that redaction.
func revealsKubeconfigSecrets(args []string) bool {
	for _, a := range args {
		switch {
		case a == "--raw" || a == "--flatten":
			return true
		case strings.HasPrefix(a, "--raw=") || strings.HasPrefix(a, "--flatten="):
			_, v, _ := strings.Cut(a, "=")
			if on, err := strconv.ParseBool(v); err != nil || on {
				return true
			}
		}
	}
	return false
}

// revealsSecretsInDiff reports whether a 'diff' would print Secret values in
// clear. diff masks them by default; --show-secrets turns the masking off.
func revealsSecretsInDiff(args []string) bool {
	for _, a := range args {
		switch {
		case a == "--show-secrets":
			return true
		case strings.HasPrefix(a, "--show-secrets="):
			_, v, _ := strings.Cut(a, "=")
			if on, err := strconv.ParseBool(v); err != nil || on {
				return true
			}
		}
	}
	return false
}

func containsRawSecretsAccess(args []string) bool {
	for i, arg := range args {
		var rawValue string
		switch {
		case arg == "--raw" && i+1 < len(args):
			rawValue = args[i+1]
		case strings.HasPrefix(arg, "--raw="):
			rawValue = arg[len("--raw="):]
		default:
			continue
		}
		if rawPathHitsSecrets(rawValue) {
			return true
		}
	}
	return false
}

// rawPathHitsSecrets reports whether an API path addresses the secrets resource:
// "secret"/"secrets" as a path segment, except the namespace name after "namespaces".
// The path is parsed like client-go does (url.Parse, then Path), so percent-escapes
// are decoded and the query and fragment are dropped.
func rawPathHitsSecrets(rawValue string) bool {
	u, err := url.Parse(rawValue)
	if err != nil {
		return true // kubectl rejects what it cannot parse; deny is the safe side
	}
	segs := strings.Split(strings.ToLower(u.Path), "/")
	for i := 0; i < len(segs); i++ {
		if segs[i] == "namespaces" {
			i++ // the next segment is the namespace name, never a resource
			continue
		}
		if segs[i] == "secret" || segs[i] == "secrets" {
			return true
		}
	}
	return false
}

// blockedKustomizeFlag returns the name of the first blocked flag, or "" if none.
func blockedKustomizeFlag(args []string) string {
	for i, arg := range args {
		if kustomizeBlockedFlags[arg] {
			return arg
		}
		for flag := range kustomizeBlockedFlags {
			if strings.HasPrefix(arg, flag+"=") {
				return flag
			}
		}
		// --load-restrictor with non-default value
		if arg == "--load-restrictor" && i+1 < len(args) && args[i+1] != "LoadRestrictionsRootOnly" {
			return "--load-restrictor"
		}
		if strings.HasPrefix(arg, "--load-restrictor=") {
			val := arg[len("--load-restrictor="):]
			if val != "LoadRestrictionsRootOnly" {
				return "--load-restrictor"
			}
		}
	}
	return ""
}
