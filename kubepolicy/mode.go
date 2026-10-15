package kubepolicy

// Mode selects a read-only profile. Every mode blocks writes, exec and the
// risky kustomize flags; only ModeLeaky changes the argument policy.
type Mode int

const (
	// ModeModerate masks secret values at the argument level.
	ModeModerate Mode = iota
	// ModeStrict applies the moderate policy; the CLI also sanitizes the
	// environment passed to kubectl.
	ModeStrict
	// ModeLeaky applies the moderate policy and lets secret values through.
	ModeLeaky
)

func (m Mode) String() string {
	switch m {
	case ModeModerate:
		return "moderate"
	case ModeStrict:
		return "strict"
	case ModeLeaky:
		return "leaky"
	}
	return "unknown"
}

func (m Mode) masksSecrets() bool { return m != ModeLeaky }
