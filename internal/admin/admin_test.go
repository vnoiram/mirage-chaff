package admin

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestArgon2RoundTrip(t *testing.T) {
	h := HashPassword("correct horse battery staple")
	if !VerifyPassword("correct horse battery staple", h) {
		t.Error("correct password should verify")
	}
	if VerifyPassword("wrong", h) {
		t.Error("wrong password must not verify")
	}
	if VerifyPassword("x", "not-a-hash") {
		t.Error("malformed hash must not verify")
	}
	// Salt randomization: two hashes of the same password differ.
	if h == HashPassword("correct horse battery staple") {
		t.Error("hashes should be salted (differ each time)")
	}
}

func TestRBACCapabilities(t *testing.T) {
	if !Can(RoleAdmin, "killswitch.execute") {
		t.Error("admin should have killswitch.execute")
	}
	if Can(RoleEditor, "config.edit") {
		t.Error("editor must NOT have config.edit")
	}
	if Can(RoleEditor, "users.manage") {
		t.Error("editor must NOT have users.manage")
	}
	if !Can(RoleEditor, "policy.edit") {
		t.Error("editor should have policy.edit")
	}
	if !Can(RoleEditor, "catalog.edit") {
		t.Error("editor should be able to review catalog entries")
	}
	if Can(RoleEditor, "agh.manage") {
		t.Error("editor must NOT run AGH sync")
	}
	if !Can(RoleAdmin, "agh.manage") {
		t.Error("admin should run AGH sync")
	}
	if Can(RoleViewer, "policy.edit") {
		t.Error("viewer must NOT have policy.edit")
	}
	if !Can(RoleViewer, "policy.view") {
		t.Error("viewer should have policy.view")
	}
	if Can(RoleViewer, "traffic.view_full") {
		t.Error("viewer must NOT have traffic.view_full (raw bodies)")
	}
}

func TestStoreCRUDAndAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert(User{Username: "a", Hash: HashPassword("pw"), Role: RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	if s.UserCount() != 1 {
		t.Fatal("expected 1 user")
	}
	// Upsert with empty hash preserves the existing password.
	if err := s.Upsert(User{Username: "a", Role: RoleViewer}); err != nil {
		t.Fatal(err)
	}
	u, _ := s.Get("a")
	if u.Role != RoleViewer || !VerifyPassword("pw", u.Hash) {
		t.Error("role should update; password should be preserved")
	}

	s.Audit("a", "test", "detail")
	if log := s.AuditLog(10); len(log) != 1 || log[0].Actor != "a" {
		t.Errorf("audit log = %+v", log)
	}

	// Persistence: reopen and confirm the user + audit survive.
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if s2.UserCount() != 1 {
		t.Error("user should persist across reopen")
	}
	if err := s2.Delete("a"); err != nil || s2.UserCount() != 0 {
		t.Error("delete failed")
	}
}

func TestSessionLockout(t *testing.T) {
	m := newSessionManager(0)
	for i := 0; i < lockThreshold; i++ {
		if m.locked("u") {
			t.Fatalf("locked too early at %d", i)
		}
		m.recordFailure("u")
	}
	if !m.locked("u") {
		t.Error("should be locked after threshold failures")
	}
	m.recordSuccess("u")
	if m.locked("u") {
		t.Error("success should clear the lock")
	}
}

func TestAdminUISmokeIncludesAnalyticsAndCatalogActions(t *testing.T) {
	b, err := fs.ReadFile(webFS, "web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	for _, want := range []string{
		"Analytics",
		"Rule Catalog",
		"/api/analytics/summary",
		"/api/rule-catalog/",
		"promoteRule",
		"downgradeRule",
		"rewriteCandidate",
		"permanentAllowDomain",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("admin UI missing %q", want)
		}
	}
}
