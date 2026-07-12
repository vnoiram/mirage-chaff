package main

import (
	"path/filepath"
	"testing"
)

func TestCmdCheckRejectsMissingConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.conf")

	if code := cmdCheck([]string{"-config", missing}); code != 1 {
		t.Fatalf("cmdCheck exit code = %d, want 1", code)
	}
}

func TestCmdCheckAcceptsExistingConfig(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "mirage-chaff.conf.sample")

	if code := cmdCheck([]string{"-config", path}); code != 0 {
		t.Fatalf("cmdCheck exit code = %d, want 0", code)
	}
}
