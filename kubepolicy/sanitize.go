package kubepolicy

func containsControlCharacters(args []string) bool {
	for _, arg := range args {
		for _, r := range arg {
			// Block null byte and other dangerous control characters.
			// Allow common whitespace: tab (0x09), newline (0x0A), carriage return (0x0D).
			if r == 0x00 ||
				(r >= 0x01 && r <= 0x08) ||
				(r >= 0x0E && r <= 0x1F) ||
				r == 0x0B ||
				r == 0x0C ||
				r == 0x7F {
				return true
			}
		}
	}
	return false
}
