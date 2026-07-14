package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vnoiram/mirage-chaff/internal/admin"
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

func TestCmdAdminBootstrapSkipsWhenAdminDisabled(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeBootstrapConfig(t, dir, false)

	if code := cmdAdminBootstrap([]string{"-config", cfgPath}); code != 0 {
		t.Fatalf("cmdAdminBootstrap exit code = %d, want 0", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "admin", "admin.json")); !os.IsNotExist(err) {
		t.Fatalf("admin store stat error = %v, want not exist", err)
	}
}

func TestCmdAdminBootstrapCreatesInitialAdminOnce(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeBootstrapConfig(t, dir, true)

	if code := cmdAdminBootstrap([]string{"-config", cfgPath}); code != 0 {
		t.Fatalf("cmdAdminBootstrap exit code = %d, want 0", code)
	}
	store, err := admin.OpenStore(filepath.Join(dir, "state", "admin", "admin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if store.UserCount() != 1 {
		t.Fatalf("user count = %d, want 1", store.UserCount())
	}
	u, ok := store.Get("admin")
	if !ok {
		t.Fatal("admin user missing")
	}
	if u.Role != admin.RoleAdmin || !u.MustChange {
		t.Fatalf("admin user = %+v", u)
	}
	if len(store.AuditLog(10)) != 1 {
		t.Fatalf("audit log = %+v", store.AuditLog(10))
	}

	if code := cmdAdminBootstrap([]string{"-config", cfgPath}); code != 0 {
		t.Fatalf("second cmdAdminBootstrap exit code = %d, want 0", code)
	}
	store, err = admin.OpenStore(filepath.Join(dir, "state", "admin", "admin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if store.UserCount() != 1 || len(store.AuditLog(10)) != 1 {
		t.Fatalf("second bootstrap mutated store: users=%d audit=%+v", store.UserCount(), store.AuditLog(10))
	}
}

func writeBootstrapConfig(t *testing.T, dir string, adminEnabled bool) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "mirage-chaff.conf")
	body := strings.Join([]string{
		"version = 1",
		"[admin]",
		"enabled = " + mapBool(adminEnabled),
		"[paths]",
		`state_dir = "` + filepath.ToSlash(filepath.Join(dir, "state")) + `"`,
		"",
	}, "\n")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func mapBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
