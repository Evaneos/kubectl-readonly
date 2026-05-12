package kubepolicy

import "strings"

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

// getOutputFormats returns every -o/--output value present in args.
// kubectl honours the LAST occurrence when more than one is given, so checking
// only the first allowed `-o name -o yaml` to bypass secret protection.
func getOutputFormats(args []string) []string {
	var formats []string
	for i, arg := range args {
		switch {
		case (arg == "-o" || arg == "--output") && i+1 < len(args):
			formats = append(formats, args[i+1])
		case strings.HasPrefix(arg, "-o="):
			formats = append(formats, arg[3:])
		case strings.HasPrefix(arg, "--output="):
			formats = append(formats, arg[9:])
		case strings.HasPrefix(arg, "-o") && len(arg) > 2:
			formats = append(formats, arg[2:])
		}
	}
	return formats
}

// hasSecretExposingOutput reports whether any -o/--output flag in args
// requests a format that would expose secret values.
func hasSecretExposingOutput(args []string) bool {
	for _, f := range getOutputFormats(args) {
		if isSecretExposingFormat(f) {
			return true
		}
	}
	return false
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
