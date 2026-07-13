package main

import (
	"errors"
	"fmt"
	"os"
)

var errNotInitialized = errors.New("command not initialized")

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: supergrok-api <serve|login|version>")
	}
	switch args[0] {
	case "serve", "login", "version":
		return fmt.Errorf("%s: %w", args[0], errNotInitialized)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
