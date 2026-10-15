// kubectl-readonly is a kubectl wrapper that only allows read-only commands.
// It prevents accidental modifications but does not protect against malicious intent.
package main

import (
	"github.com/Evaneos/kubectl-readonly/internal/cli"
	"github.com/Evaneos/kubectl-readonly/kubepolicy"
)

func main() {
	cli.Main(kubepolicy.ModeModerate)
}
