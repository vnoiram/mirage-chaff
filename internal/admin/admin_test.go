package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/aghmanaged"
	"github.com/vnoiram/mirage-chaff/internal/config"
	"github.com/vnoiram/mirage-chaff/internal/observability"
	"github.com/vnoiram/mirage-chaff/internal/policy"
	"golang.org/x/oauth2"
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
		"approveManagedSource",
		"rejectManagedSource",
		"pendingManagedSource",
		"previewManagedSource",
		"toggleManagedSource",
		"refreshManagedTarget",
		"filterManagedCatalog",
		"manual",
		"target_cache_used",
		"pending_sources",
		"unresolved conflicts",
		"/api/agh/managed-catalog/conflicts",
		"resolveManagedConflict",
		"disable rewrite",
		"needs test",
		"allow exception wins",
		"/api/agh/sources/'+id+'/approve",
		"/api/agh/sources/'+id+'/reject",
		"/api/agh/sources/'+id+'/pending-diff",
		"/api/agh/managed-catalog/conflicts/'+id+'/resolve",
		"/api/agh/rewrite-feed/refresh-target",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("admin UI missing %q", want)
		}
	}
	for _, bad := range []string{
		`onclick="triage('${`,
		`onclick="tempAllowDomain('${`,
		`onclick="permanentAllowDomain('${`,
		`onclick="resetPw('${`,
		`onclick="delUser('${`,
	} {
		if strings.Contains(html, bad) {
			t.Fatalf("admin UI still contains vulnerable dynamic action pattern %q", bad)
		}
	}
}

func TestAGHManagedConflictHandlersRBAC(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policy")
	catalogDir := filepath.Join(dir, "catalog")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(catalogDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rs, err := policy.Load(policyDir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(dir, "admin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(User{Username: "admin", Hash: HashPassword("password123"), Role: RoleAdmin, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(User{Username: "viewer", Hash: HashPassword("password123"), Role: RoleViewer, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	cfg := config.AGHManagedConfig{
		Enabled:       true,
		FeedPath:      "/agh/managed-rewrites.txt",
		TargetMode:    "static_ip",
		StaticIPv4:    []string{"192.0.2.10"},
		DefaultPreset: "balanced",
		Scheduler:     config.AGHManagedScheduler{DefaultSyncInterval: "12h", SyncTimeout: "1s"},
	}
	managed, err := aghmanaged.Open(filepath.Join(dir, "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	tracker, err := managed.UpsertSource(aghmanaged.Source{Type: aghmanaged.SourceManual, Name: "tracker", Enabled: true, Content: "||conflict.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	allow, err := managed.UpsertSource(aghmanaged.Source{Type: aghmanaged.SourceManual, Name: "allow", Enabled: true, Content: "@@||conflict.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managed.SyncSource(context.Background(), tracker.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.SyncSource(context.Background(), allow.ID); err != nil {
		t.Fatal(err)
	}
	s := New(store, Deps{
		Version:    "test",
		ConfigPath: filepath.Join(dir, "mirage-chaff.conf"),
		Paths:      config.PathsConfig{PolicyDir: policyDir, CatalogDir: catalogDir, StateDir: dir},
		Recorder:   observability.NewRecorder(true, 8),
		Engine:     policy.NewEngine(rs),
		AGHManaged: managed,
	})
	h := s.Handler()
	viewerCookie, viewerCSRF := loginForTest(t, h, "viewer", "password123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agh/managed-catalog/conflicts", nil)
	req.AddCookie(viewerCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("viewer conflicts status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var listed struct {
		Conflicts []struct {
			ID string `json:"id"`
		} `json:"conflicts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Conflicts) != 1 || listed.Conflicts[0].ID == "" {
		t.Fatalf("conflicts response = %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agh/managed-catalog/conflicts/"+listed.Conflicts[0].ID+"/resolve", strings.NewReader(`{"rewrite_enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", viewerCSRF)
	req.AddCookie(viewerCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer resolve status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	adminCookie, adminCSRF := loginForTest(t, h, "admin", "password123")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agh/managed-catalog/conflicts/"+listed.Conflicts[0].ID+"/resolve", strings.NewReader(`{"rewrite_enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", adminCSRF)
	req.AddCookie(adminCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin resolve status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if got := managed.ListConflicts(); len(got) != 0 {
		t.Fatalf("conflict still listed after admin resolve: %+v", got)
	}
}

func TestAdminOversizedLoginBodyReturns413(t *testing.T) {
	s := newTestAdminServer(t, false)
	body := bytes.Repeat([]byte("x"), adminMaxBodyBytes+1)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized login status = %d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestMustChangeUserBlockedExceptPasswordFlow(t *testing.T) {
	s := newTestAdminServer(t, false)
	if err := s.store.Upsert(User{
		Username:   "must",
		Hash:       HashPassword("oldpassword"),
		Role:       RoleAdmin,
		MustChange: true,
		Created:    time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	cookie, csrf := loginForTest(t, h, "must", "oldpassword")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(cookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/api/me status = %d, want %d", rr.Code, http.StatusOK)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	req.AddCookie(cookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("/api/dashboard status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/me/password", strings.NewReader(`{"old":"oldpassword","new":"newpassword"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(cookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/api/me/password status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
}

func TestSecureCookiesConfig(t *testing.T) {
	insecure := newTestAdminServer(t, false)
	cookie, _ := loginForTest(t, insecure.Handler(), "admin", "password123")
	if cookie.Secure {
		t.Fatal("login cookie should not be Secure when secure_cookies=false over plain HTTP")
	}

	secure := newTestAdminServer(t, true)
	cookie, _ = loginForTest(t, secure.Handler(), "admin", "password123")
	if !cookie.Secure {
		t.Fatal("login cookie should be Secure when secure_cookies=true")
	}

	secure.oidc = &oidcAuth{oauth: &oauth2.Config{
		ClientID:    "client",
		RedirectURL: "http://127.0.0.1/callback",
		Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.example.test/auth"},
	}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/oidc/login", nil)
	secure.handleOIDCLogin(rr, req)
	var stateSecure, nonceSecure bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == oidcStateCookie {
			stateSecure = c.Secure
		}
		if c.Name == oidcNonceCookie {
			nonceSecure = c.Secure
		}
	}
	if !stateSecure || !nonceSecure {
		t.Fatal("OIDC state and nonce cookies should be Secure when secure_cookies=true")
	}
}

func newTestAdminServer(t *testing.T, secureCookies bool) *Server {
	t.Helper()
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policy")
	catalogDir := filepath.Join(dir, "catalog")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(catalogDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rs, err := policy.Load(policyDir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(dir, "admin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(User{Username: "admin", Hash: HashPassword("password123"), Role: RoleAdmin, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return New(store, Deps{
		Version:       "test",
		ConfigPath:    filepath.Join(dir, "mirage-chaff.conf"),
		Paths:         config.PathsConfig{PolicyDir: policyDir, CatalogDir: catalogDir, StateDir: dir},
		Recorder:      observability.NewRecorder(true, 8),
		Engine:        policy.NewEngine(rs),
		SecureCookies: secureCookies,
	})
}

func loginForTest(t *testing.T, h http.Handler, username, password string) (*http.Cookie, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	bodyBytes, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("login response did not set session cookie")
	}
	var resp struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.CSRF == "" {
		t.Fatal("login response missing csrf")
	}
	return cookie, resp.CSRF
}
