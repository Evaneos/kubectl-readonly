// kubectl-readonly-leaky is kubectl-readonly with secret values shown: it still
// blocks writes and exec.
package main

import (
	"github.com/Evaneos/kubectl-readonly/internal/cli"
	"github.com/Evaneos/kubectl-readonly/kubepolicy"
)

func main() {
	cli.Main(kubepolicy.ModeLeaky)
}
