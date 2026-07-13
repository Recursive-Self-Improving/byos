package main

import (
	"errors"
	"strings"
	"testing"
)

func TestRunPlaceholders(t *testing.T) {
	for _, command := range []string{"serve", "login", "version"} {
		err := run([]string{command})
		if !errors.Is(err, errNotInitialized) {
			t.Fatalf("run(%q) error = %v, want not initialized", command, err)
		}
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	if err := run([]string{"unknown"}); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("run unknown error = %v", err)
	}
}
