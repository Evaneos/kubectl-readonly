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
