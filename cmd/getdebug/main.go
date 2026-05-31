package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/getdebug-ai/cli/internal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		// The CI threshold path in `analyze --ci` prints its own banner;
		// the sentinel just signals "exit non-zero" without doubling up
		// the message in CI logs.
		if errors.Is(err, cmd.ErrCIThresholdExceeded) {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
