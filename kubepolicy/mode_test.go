package kubepolicy

import (
	"strings"
	"testing"
)

// verdicts is the expected Allowed per mode.
type verdicts map[Mode]bool

var (
	allowedEverywhere = verdicts{ModeModerate: true, ModeStrict: true, ModeLeaky: true}
	blockedEverywhere = verdicts{ModeModerate: false, ModeStrict: false, ModeLeaky: false}
	allowedInLeaky    = verdicts{ModeModerate: false, ModeStrict: false, ModeLeaky: true}
)

// Every case of check_test.go also runs under all modes through
// assertModesConsistent; this table pins the verdicts that define each mode.
func TestEvaluatePerMode(t *testing.T) {
	cases := []struct {
		args []string
		want verdicts
	}{
		// Secret masking: the only rules leaky skips.
		{[]string{"get", "secrets", "-o", "yaml"}, allowedInLeaky},
		{[]string{"get", "secret", "my-secret", "-o", "json"}, allowedInLeaky},
		{[]string{"get", "secret/my-secret", "-ojsonpath={.data}"}, allowedInLeaky},
		{[]string{"get", "pods,secrets", "-o", "go-template={{.data}}"}, allowedInLeaky},
		{[]string{"get", "secrets", "-o", "custom-columns=DATA:.data"}, allowedInLeaky},
		{[]string{"get", "secret.v1.core", "-o", "yaml"}, allowedInLeaky},
		{[]string{"get", "--raw", "/api/v1/namespaces/default/secrets/my-secret"}, allowedInLeaky},
		{[]string{"get", "--raw=/api/v1/secrets"}, allowedInLeaky},
		{[]string{"config", "view", "--raw"}, allowedInLeaky},
		{[]string{"config", "view", "--flatten"}, allowedInLeaky},
		{[]string{"diff", "-f", "deploy.yaml", "--show-secrets"}, allowedInLeaky},

		// Writes, exec and risky kustomize flags.
		{[]string{"delete", "pod", "x"}, blockedEverywhere},
		{[]string{"apply", "-f", "deploy.yaml"}, blockedEverywhere},
		{[]string{"exec", "-it", "pod", "--", "sh"}, blockedEverywhere},
		{[]string{"port-forward", "svc/x", "8080:80"}, blockedEverywhere},
		{[]string{"config", "set-context", "evil"}, blockedEverywhere},
		{[]string{"rollout", "restart", "deployment/x"}, blockedEverywhere},
		{[]string{"krew", "install", "ctx"}, blockedEverywhere},
		{[]string{"kustomize", "--enable-helm", "."}, blockedEverywhere},
		{[]string{"kustomize", "--enable-alpha-plugins", "."}, blockedEverywhere},
		{[]string{"kustomize", "--network", "."}, blockedEverywhere},
		{[]string{"kustomize", "--load-restrictor=LoadRestrictionsNone", "."}, blockedEverywhere},
		{[]string{"get\x00delete", "pods"}, blockedEverywhere},
		{[]string{"debug", "pod/x"}, blockedEverywhere},

		// Strict keeps the moderate surface.
		{[]string{"get", "pods", "-o", "yaml"}, allowedEverywhere},
		{[]string{"get", "pods", "-o", "jsonpath={.items[*].spec}"}, allowedEverywhere},
		{[]string{"get", "pods", "--template", "{{.metadata.name}}"}, allowedEverywhere},
		{[]string{"get", "--raw", "/api/v1/pods"}, allowedEverywhere},
		{[]string{"get", "-f", "deploy.yaml"}, allowedEverywhere},
		{[]string{"get", "secrets", "-o", "name"}, allowedEverywhere},
		{[]string{"describe", "secret", "x"}, allowedEverywhere},
		{[]string{"diff", "-f", "deploy.yaml"}, allowedEverywhere},
		{[]string{"kustomize", "."}, allowedEverywhere},
		{[]string{"config", "use-context", "prod"}, allowedEverywhere},
		{[]string{"logs", "pod", "-f"}, allowedEverywhere},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, "_"), func(t *testing.T) {
			for mode, want := range c.want {
				t.Run(mode.String(), func(t *testing.T) {
					if d := Evaluate(c.args, mode); d.Allowed != want {
						t.Errorf("Allowed = %v, want %v (hint: %q)", d.Allowed, want, d.Hint)
					}
				})
			}
		})
	}
}

func TestCheckIsModerate(t *testing.T) {
	args := []string{"get", "secrets", "-o", "yaml"}
	allowed, hint := Check(args)
	if got := (Decision{Allowed: allowed, Hint: hint}); got != Evaluate(args, ModeModerate) {
		t.Errorf("Check = %+v, want Evaluate(moderate)", got)
	}
}

func TestModeNames(t *testing.T) {
	for _, mode := range []Mode{ModeModerate, ModeStrict, ModeLeaky} {
		if mode.String() == "unknown" {
			t.Errorf("mode %d has no name", mode)
		}
	}
}
