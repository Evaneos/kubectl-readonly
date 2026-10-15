package cli

import (
	"slices"
	"testing"

	"github.com/Evaneos/kubectl-readonly/kubepolicy"
)

func TestSanitizeEnvironment(t *testing.T) {
	environ := []string{
		"HOME=/home/user",
		"PATH=/usr/bin",
		"KUBECONFIG=/home/user/.kube/config",
		"CLOUDSDK_CONFIG=/home/user/.config/gcloud-ci",
		"AWS_PROFILE=prod",
		"HTTPS_PROXY=http://proxy:3128",
		"NO_PROXY=localhost",
		"SSL_CERT_FILE=/etc/ssl/corp.pem",
		"KUBECTL_EXTERNAL_DIFF=/tmp/evil.sh",
		"KUBERC=/tmp/kuberc",
		"KUBECTL_EXTERNAL_DIFF_X=kept",
	}
	want := slices.Concat(environ[:8], []string{"KUBECTL_EXTERNAL_DIFF_X=kept", "KUBERC=off"})

	got := sanitizeEnvironment(environ)
	if !slices.Equal(got, want) {
		t.Errorf("sanitizeEnvironment:\n got %v\nwant %v", got, want)
	}
}

func TestOnlyStrictSanitizesEnvironment(t *testing.T) {
	for _, mode := range []kubepolicy.Mode{kubepolicy.ModeModerate, kubepolicy.ModeStrict, kubepolicy.ModeLeaky} {
		p, ok := profiles[mode]
		if !ok {
			t.Fatalf("%s has no profile", mode)
		}
		if p.sanitizesEnv != (mode == kubepolicy.ModeStrict) {
			t.Errorf("%s: sanitizesEnv = %v", mode, p.sanitizesEnv)
		}
	}
}

func TestNames(t *testing.T) {
	cases := []struct {
		mode           kubepolicy.Mode
		binary, plugin string
	}{
		{kubepolicy.ModeModerate, "kubectl-readonly", "readonly"},
		{kubepolicy.ModeStrict, "kubectl-readonly-strict", "readonly-strict"},
		{kubepolicy.ModeLeaky, "kubectl-readonly-leaky", "readonly-leaky"},
	}
	for _, c := range cases {
		if got := binaryName(c.mode); got != c.binary {
			t.Errorf("binaryName(%s) = %q, want %q", c.mode, got, c.binary)
		}
		if got := pluginName(c.mode); got != c.plugin {
			t.Errorf("pluginName(%s) = %q, want %q", c.mode, got, c.plugin)
		}
	}
}

func TestRunCheckModePerMode(t *testing.T) {
	secretYAML := []string{"--readonly-check-ok", "get", "secret", "x", "-o", "yaml"}
	cases := []struct {
		mode kubepolicy.Mode
		args []string
		want int
	}{
		{kubepolicy.ModeModerate, secretYAML, 1},
		{kubepolicy.ModeStrict, secretYAML, 1},
		{kubepolicy.ModeLeaky, secretYAML, 0},
		{kubepolicy.ModeLeaky, []string{"--readonly-check-ok", "delete", "pod", "x"}, 1},
		{kubepolicy.ModeStrict, []string{"--readonly-check-ok", "diff", "-f", "x.yaml"}, 0},
	}
	for _, c := range cases {
		if got := Run(c.mode, c.args); got != c.want {
			t.Errorf("Run(%s, %v) = %d, want %d", c.mode, c.args, got, c.want)
		}
	}
}
