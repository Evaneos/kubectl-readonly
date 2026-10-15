// kubectl-readonly-strict is kubectl-readonly with a sanitized environment
// passed to kubectl.
package main

import (
	"github.com/Evaneos/kubectl-readonly/internal/cli"
	"github.com/Evaneos/kubectl-readonly/kubepolicy"
)

func main() {
	cli.Main(kubepolicy.ModeStrict)
}
