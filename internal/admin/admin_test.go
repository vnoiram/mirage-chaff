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

func TestAGHManagedFeedURLUsesForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/agh/rewrite-feed/status", nil)
	req.Host = "admin.internal:8443"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "mirage.example.net")
	if got, want := aghManagedFeedURL(req, "/agh/managed-rewrites.txt"), "https://mirage.example.net/agh/managed-rewrites.txt"; got != want {
		t.Fatalf("feed URL = %q, want %q", got, want)
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
		"managedSourcePendingDiff",
		"managedPendingDiffTable",
		"managedPendingChangeSummary",
		"changed_fields",
		"previous",
		"managedFeedImpact",
		"feed_impact",
		"feed impact",
		"previewManagedSource",
		"managedSourcePreview",
		"managedSourceEntryTable",
		"managedSourceTrace",
		"managedSourceTraceSearch",
		"source trace",
		"toggleManagedSourceEntries",
		"showMoreManagedSourceEntries",
		"filterManagedSourceEntries",
		"renderManagedSourceEntries",
		"AGH_SOURCE_ENTRY_STATE",
		"filter source entries",
		"show more",
		"managedSourceEntriesRow",
		"editManagedSourceRow",
		"saveManagedSourceRow",
		"cancelManagedSourceRow",
		"managedSourceEditRow",
		"sync_interval",
		"save source",
		"toggleManagedSource",
		"saveManagedSourceSettings",
		"agh-src-stale-policy",
		"refreshManagedTarget",
		"Feed Setup",
		"Feed Generation History",
		"AGH Managed History",
		"managedHistoryCounts",
		"/api/agh/history",
		"added_count",
		"removed_count",
		"managedTargetState",
		"AGH feed URL",
		"DNS blocklists",
		"registration check",
		"AGH registration",
		"Check AGH registration",
		"checkManagedAGHStatus",
		"managedAGHCheckSummary",
		"agh-registration-result",
		"/api/agh/rewrite-feed/agh-status",
		"check_host",
		"fetch check",
		"manual list update",
		"AGH refresh",
		"force refresh",
		"Refresh AGH filters",
		"refreshAGHFilters",
		"agh-refresh-result",
		"/api/agh/rewrite-feed/refresh-agh",
		"curl -fsS",
		"! mirage-chaff managed rewrites",
		"filterManagedCatalog",
		"managedCatalogFilterSelect",
		"managedCatalogFilterValues",
		"agh-cat-source",
		"agh-cat-rewrite",
		"agh-cat-unsupported",
		"unsupported only",
		"supported only",
		"agh-src-priority",
		"manual",
		"source priority",
		"health",
		"never synced",
		"target_cache_used",
		"pending_sources",
		"default preset",
		"default_preset",
		"saveManagedPreset",
		"agh-preset",
		"last duration ms",
		"consecutive failures",
		"last_duration_ms",
		"consecutive_failures",
		"pending diff",
		"allow exceptions",
		"unresolved conflicts",
		"/api/agh/managed-catalog/conflicts",
		"/api/agh/managed-catalog/bulk",
		"/api/agh/managed-catalog/rollbacks",
		"/api/agh/rewrite-feed/export",
		"resolveManagedConflict",
		"resolveManagedConflictCustom",
		"managedConflictControls",
		"apply classification",
		"agh-conflict-category",
		"agh-conflict-resource",
		"agh-conflict-review",
		"agh-conflict-confidence",
		"agh-conflict-action",
		"agh-conflict-rewrite",
		"bulkManagedCatalog",
		"selectManagedCatalogVisible",
		"exportManagedFeedSnapshot",
		"applyManagedRollback",
		"editManagedCatalogRow",
		"saveManagedCatalogRow",
		"cancelManagedCatalogRow",
		"toggleManagedCatalogDetails",
		"managedCatalogDetailRow",
		"agh-edit-review",
		"agh-edit-confidence",
		"agh-edit-risk",
		"agh-edit-verified",
		"agh-edit-expected",
		"agh-edit-action",
		"agh-edit-notes",
		"agh-bulk-resource",
		"agh-bulk-risk",
		"agh-bulk-confidence",
		"agh-bulk-verified",
		"agh-bulk-expected",
		"agh-bulk-action",
		"agh-bulk-notes",
		"expected catalog",
		"original_rule",
		"unsupported",
		"details",
		"entries",
		"hide",
		"showing 100 of",
		"showing ${shown.length} of",
		"Rollback Candidates",
		"Apply bulk edit",
		"Export snapshot",
		"save",
		"cancel",
		"rollback",
		"disable rewrite",
		"needs test",
		"allow exception wins",
		"strategy:'source_priority'",
		"/api/agh/sources/'+id+'/approve",
		"/api/agh/sources/'+id+'/reject",
		"/api/agh/sources/'+id+'/pending-diff",
		"/api/agh/sources/'+id+'/entries",
		"/api/agh/managed-catalog/conflicts/'+id+'/resolve",
		"/api/agh/managed-catalog/rollbacks/'+id+'/apply",
		"/api/agh/rewrite-feed/refresh-target",
		"/api/agh/rewrite-feed/preset",
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

func TestAGHManagedFeedExportHandler(t *testing.T) {
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
	if err := store.Upsert(User{Username: "viewer", Hash: HashPassword("password123"), Role: RoleViewer, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(User{Username: "admin", Hash: HashPassword("password123"), Role: RoleAdmin, Created: time.Now()}); err != nil {
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
	src, err := managed.UpsertSource(aghmanaged.Source{Type: aghmanaged.SourceManual, Name: "manual", Enabled: true, Content: "||export.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managed.SyncSource(context.Background(), src.ID); err != nil {
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

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agh/rewrite-feed/export", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated export status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}

	cookie, _ := loginForTest(t, h, "viewer", "password123")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/agh/rewrite-feed/status", nil)
	req.AddCookie(cookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("viewer status status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var statusResp struct {
		DefaultPreset string `json:"default_preset"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &statusResp); err != nil {
		t.Fatal(err)
	}
	if statusResp.DefaultPreset != "balanced" {
		t.Fatalf("status default_preset = %q, want balanced", statusResp.DefaultPreset)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agh/rewrite-feed/preset", strings.NewReader(`{"preset":"aggressive"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer preset status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	adminCookie, adminCSRF := loginForTest(t, h, "admin", "password123")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agh/rewrite-feed/preset", strings.NewReader(`{"preset":"aggressive"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", adminCSRF)
	req.AddCookie(adminCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin preset status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &statusResp); err != nil {
		t.Fatal(err)
	}
	if statusResp.DefaultPreset != "aggressive" {
		t.Fatalf("preset response default_preset = %q, want aggressive", statusResp.DefaultPreset)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/agh/rewrite-feed/export", nil)
	req.AddCookie(cookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("viewer export status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type = %q", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, `attachment; filename="mirage-chaff-managed-rewrites-`) || !strings.HasSuffix(cd, `.txt"`) {
		t.Fatalf("content-disposition = %q", cd)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "! mirage-chaff managed rewrites") || !strings.Contains(body, "||export.example.net^$dnsrewrite=NOERROR;A;192.0.2.10") {
		t.Fatalf("export body =\n%s", body)
	}
}

func TestAGHManagedSourceSyncAuditDetail(t *testing.T) {
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
	src, err := managed.UpsertSource(aghmanaged.Source{Type: aghmanaged.SourceManual, Name: "manual", Enabled: true, Content: "||one.example.net^\n@@||allow.example.net^\n! unsupported\n"})
	if err != nil {
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
	adminCookie, adminCSRF := loginForTest(t, h, "admin", "password123")

	rr := httptest.NewRecorder()
	src.Priority = 9
	body, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/agh/sources/"+src.ID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", adminCSRF)
	req.AddCookie(adminCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin source upsert status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	entry, ok := auditEntryForAction(store, "agh_managed.source.upsert")
	if !ok {
		t.Fatalf("source upsert audit missing: %+v", store.AuditLog(20))
	}
	if !strings.Contains(entry.Detail, "priority=9") {
		t.Fatalf("source upsert audit detail = %q", entry.Detail)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agh/sources/"+src.ID+"/sync", nil)
	req.Header.Set("X-CSRF-Token", adminCSRF)
	req.AddCookie(adminCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin sync status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	entry, ok = auditEntryForAction(store, "agh_managed.source.sync")
	if !ok {
		t.Fatalf("source sync audit missing: %+v", store.AuditLog(20))
	}
	for _, want := range []string{
		"id=" + src.ID,
		"entries=",
		"added=",
		"removed=",
		"changed=",
		"pending=",
		"unsupported=",
		"allow_exceptions=",
	} {
		if !strings.Contains(entry.Detail, want) {
			t.Fatalf("source sync audit detail %q missing %q", entry.Detail, want)
		}
	}

	if _, err := managed.Generate(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/agh/history", nil)
	req.AddCookie(adminCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("history status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var history struct {
		Events []struct {
			Kind   string `json:"kind"`
			Action string `json:"action"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &history); err != nil {
		t.Fatal(err)
	}
	var sawAudit, sawFeed bool
	for _, event := range history.Events {
		if event.Kind == "audit" && event.Action == "agh_managed.source.sync" {
			sawAudit = true
		}
		if event.Kind == "feed_generation" {
			sawFeed = true
		}
	}
	if !sawAudit || !sawFeed {
		t.Fatalf("history events missing audit/feed: %+v", history.Events)
	}
}

func TestAGHManagedRefreshAGHHandlerRBACAndAudit(t *testing.T) {
	dir := t.TempDir()
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
	envPath := filepath.Join(dir, "agh.env")
	writeTestFile(t, envPath, "AGH_API_USER=admin\nAGH_API_PASS=secret\n")
	var sawRefresh bool
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sawRefresh = r.URL.Path == "/control/filtering/refresh"
		return stringResponse(http.StatusOK, `{"updated":1}`), nil
	})}
	s := New(store, Deps{
		AGHSyncConfig: config.AGHSyncConfig{BaseURL: "http://agh.test", EnvFile: envPath},
		AGHHTTPClient: httpClient,
	})
	h := s.Handler()

	viewerCookie, viewerCSRF := loginForTest(t, h, "viewer", "password123")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/agh/rewrite-feed/refresh-agh", strings.NewReader(`{"force":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", viewerCSRF)
	req.AddCookie(viewerCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer refresh status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	adminCookie, adminCSRF := loginForTest(t, h, "admin", "password123")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agh/rewrite-feed/refresh-agh", strings.NewReader(`{"force":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", adminCSRF)
	req.AddCookie(adminCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin refresh status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if !sawRefresh {
		t.Fatal("refresh endpoint was not called")
	}
	entry, ok := auditEntryForAction(store, "agh_managed.agh_refresh")
	if !ok || !strings.Contains(entry.Detail, "base_url=http://agh.test") || !strings.Contains(entry.Detail, "force=true") || strings.Contains(entry.Detail, "secret") {
		t.Fatalf("refresh audit = %+v ok=%v", entry, ok)
	}
}

func TestAGHManagedRefreshAGHHandlerConfigError(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "admin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(User{Username: "admin", Hash: HashPassword("password123"), Role: RoleAdmin, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	s := New(store, Deps{AGHSyncConfig: config.AGHSyncConfig{BaseURL: "http://agh.test"}})
	h := s.Handler()
	adminCookie, adminCSRF := loginForTest(t, h, "admin", "password123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/agh/rewrite-feed/refresh-agh", strings.NewReader(`{"force":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", adminCSRF)
	req.AddCookie(adminCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("config error status = %d, want %d: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
	entry, ok := auditEntryForAction(store, "agh_managed.agh_refresh")
	if !ok || !strings.Contains(entry.Detail, "credentials required") {
		t.Fatalf("refresh failure audit = %+v ok=%v", entry, ok)
	}
}

func TestAGHManagedAGHStatusHandlerChecksRegistrationAndHost(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "admin.json"))
	if err != nil {
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
	src, err := managed.UpsertSource(aghmanaged.Source{Type: aghmanaged.SourceManual, Name: "manual", Enabled: true, Content: "||status.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managed.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(dir, "agh.env")
	writeTestFile(t, envPath, "AGH_API_USER=admin\nAGH_API_PASS=secret\n")
	var sawStatus, sawCheckHost bool
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/control/filtering/status":
			sawStatus = true
			return stringResponse(http.StatusOK, `{"filters":[{"id":9,"name":"mirage","url":"https://managed.example/agh/managed-rewrites.txt/","enabled":true}]}`), nil
		case "/control/filtering/check_host":
			sawCheckHost = true
			if got := r.URL.Query().Get("name"); got != "status.example.net" {
				t.Fatalf("check_host name = %q, want status.example.net", got)
			}
			return stringResponse(http.StatusOK, `{"reason":"RewriteRule","rule":"||status.example.net^$dnsrewrite=NOERROR;A;192.0.2.10"}`), nil
		default:
			t.Fatalf("unexpected AGH request path %s", r.URL.Path)
			return nil, nil
		}
	})}
	s := New(store, Deps{
		AGHManaged:    managed,
		AGHSyncConfig: config.AGHSyncConfig{BaseURL: "http://agh.test", EnvFile: envPath},
		AGHHTTPClient: httpClient,
	})
	h := s.Handler()
	cookie, _ := loginForTest(t, h, "viewer", "password123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agh/rewrite-feed/agh-status", nil)
	req.Host = "managed.example"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.AddCookie(cookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("agh status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if !sawStatus || !sawCheckHost {
		t.Fatalf("AGH status/check_host called = %v/%v", sawStatus, sawCheckHost)
	}
	var resp struct {
		FeedURL       string          `json:"feed_url"`
		Registered    bool            `json:"registered"`
		Enabled       bool            `json:"enabled"`
		CheckDomain   string          `json:"check_domain"`
		MatchedFilter *aghFilterMatch `json:"matched_filter"`
		CheckResult   struct {
			Raw map[string]any `json:"raw"`
		} `json:"check_result"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.FeedURL != "https://managed.example/agh/managed-rewrites.txt" || !resp.Registered || !resp.Enabled || resp.MatchedFilter == nil || resp.MatchedFilter.ID != 9 {
		t.Fatalf("registration response = %+v", resp)
	}
	if resp.CheckDomain != "status.example.net" || resp.CheckResult.Raw["reason"] != "RewriteRule" {
		t.Fatalf("check_host response = %+v", resp)
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
	entry, ok := auditEntryForAction(store, "agh_managed.conflict.resolve")
	if !ok {
		t.Fatalf("conflict resolve audit missing: %+v", store.AuditLog(20))
	}
	if !strings.Contains(entry.Detail, "id=") || !strings.Contains(entry.Detail, "fields=rewrite_enabled") {
		t.Fatalf("conflict resolve audit detail = %q", entry.Detail)
	}

	tracker2, err := managed.UpsertSource(aghmanaged.Source{Type: aghmanaged.SourceManual, Name: "tracker-priority", Enabled: true, Priority: 10, Content: "||priority-handler.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	allow2, err := managed.UpsertSource(aghmanaged.Source{Type: aghmanaged.SourceManual, Name: "allow-priority", Enabled: true, Priority: 1, Content: "@@||priority-handler.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managed.SyncSource(context.Background(), tracker2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.SyncSource(context.Background(), allow2.ID); err != nil {
		t.Fatal(err)
	}
	priorityConflicts := managed.ListConflicts()
	if len(priorityConflicts) != 1 {
		t.Fatalf("priority conflicts = %+v", priorityConflicts)
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agh/managed-catalog/conflicts/"+priorityConflicts[0].ID+"/resolve", strings.NewReader(`{"strategy":"source_priority"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", adminCSRF)
	req.AddCookie(adminCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin source priority resolve status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if got := managed.ListConflicts(); len(got) != 0 {
		t.Fatalf("priority conflict still listed after admin resolve: %+v", got)
	}
	entry, ok = auditEntryForAction(store, "agh_managed.conflict.resolve")
	if !ok || !strings.Contains(entry.Detail, "strategy=source_priority") {
		t.Fatalf("source priority resolve audit detail = %q ok=%v", entry.Detail, ok)
	}
}

func TestAGHManagedBulkCatalogHandlerRBAC(t *testing.T) {
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
	src, err := managed.UpsertSource(aghmanaged.Source{Type: aghmanaged.SourceManual, Name: "manual", Enabled: true, Content: "||one.example.net^\n||two.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managed.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	rows := managed.CatalogRows()
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	bodyBytes, err := json.Marshal(map[string]any{
		"ids": []string{rows[0].ID, rows[1].ID},
		"override": map[string]any{
			"resource_type":    "script",
			"risk":             "high",
			"confidence":       "low",
			"verified":         true,
			"expected_catalog": "noop-sdk",
			"action":           "stub",
			"rewrite_enabled":  false,
			"rewrite_reason":   "bulk disable",
			"notes":            "bulk note",
			"last_changed_by":  "payload-user",
		},
	})
	if err != nil {
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
	req := httptest.NewRequest(http.MethodPost, "/api/agh/managed-catalog/bulk", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", viewerCSRF)
	req.AddCookie(viewerCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer bulk status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	adminCookie, adminCSRF := loginForTest(t, h, "admin", "password123")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agh/managed-catalog/bulk", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", adminCSRF)
	req.AddCookie(adminCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin bulk status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp struct {
		Updated int `json:"updated"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Updated != 2 {
		t.Fatalf("bulk response = %s", rr.Body.String())
	}
	for _, row := range managed.CatalogRows() {
		if row.ResourceType != "script" ||
			row.Risk != "high" ||
			row.Confidence != "low" ||
			!row.Verified ||
			row.ExpectedCatalog != "noop-sdk" ||
			row.Action != "stub" ||
			row.RewriteEnabled ||
			row.RewriteReason != "bulk disable" ||
			row.Notes != "bulk note" ||
			row.LastChangedBy != "admin" {
			t.Fatalf("row after bulk handler = %+v", row)
		}
	}
	entry, ok := auditEntryForAction(store, "agh_managed.catalog.bulk_patch")
	if !ok {
		t.Fatalf("bulk patch audit missing: %+v", store.AuditLog(20))
	}
	for _, want := range []string{"updated=2", "resource_type", "risk", "confidence", "verified", "expected_catalog", "action", "rewrite_enabled", "rewrite_reason", "notes"} {
		if !strings.Contains(entry.Detail, want) {
			t.Fatalf("bulk patch audit detail %q missing %q", entry.Detail, want)
		}
	}
}

func TestAGHManagedSourceEntriesHandlerAllowsViewer(t *testing.T) {
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
	sourceA, err := managed.UpsertSource(aghmanaged.Source{Type: aghmanaged.SourceManual, Name: "manual-a", Enabled: true, Content: "||a.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	sourceB, err := managed.UpsertSource(aghmanaged.Source{Type: aghmanaged.SourceManual, Name: "manual-b", Enabled: true, Content: "||b.example.net^\nb.example.net##.ad\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managed.SyncSource(context.Background(), sourceA.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.SyncSource(context.Background(), sourceB.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := managed.SourceEntries(sourceA.ID)
	if err != nil {
		t.Fatal(err)
	}
	off := false
	if _, err := managed.PatchEntry(rows[0].ID, aghmanaged.CatalogOverride{RewriteEnabled: &off, RewriteReason: "viewer read"}); err != nil {
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
	viewerCookie, _ := loginForTest(t, h, "viewer", "password123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agh/sources/"+sourceA.ID+"/entries", nil)
	req.AddCookie(viewerCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("viewer source entries status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp struct {
		Source  aghmanaged.Source       `json:"source"`
		Entries []aghmanaged.CatalogRow `json:"entries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Source.ID != sourceA.ID || len(resp.Entries) != 1 {
		t.Fatalf("source entries response = %s", rr.Body.String())
	}
	if resp.Entries[0].Match.Domain != "a.example.net" || resp.Entries[0].RewriteEnabled || resp.Entries[0].RewriteReason != "viewer read" {
		t.Fatalf("source entry = %+v", resp.Entries[0])
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/agh/managed-catalog", nil)
	req.AddCookie(viewerCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("viewer managed catalog status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var catalogResp struct {
		Entries []aghmanaged.CatalogRow `json:"entries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &catalogResp); err != nil {
		t.Fatal(err)
	}
	var sawUnsupported bool
	for _, row := range catalogResp.Entries {
		if row.Unsupported && row.Match.Domain == "b.example.net" && len(row.SourceIDs) == 1 && row.SourceIDs[0] == sourceB.ID {
			sawUnsupported = true
		}
	}
	if !sawUnsupported {
		t.Fatalf("managed catalog response missing unsupported row: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/agh/sources/missing/entries", nil)
	req.AddCookie(viewerCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing source entries status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestAGHManagedRollbackHandlersRBAC(t *testing.T) {
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
	src, err := managed.UpsertSource(aghmanaged.Source{Type: aghmanaged.SourceManual, Name: "manual", Enabled: true, Content: "||rollback.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managed.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	rows := managed.CatalogRows()
	if len(rows) != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	off := false
	if _, err := managed.PatchEntry(rows[0].ID, aghmanaged.CatalogOverride{RewriteEnabled: &off, RewriteReason: "manual disable"}); err != nil {
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
	req := httptest.NewRequest(http.MethodGet, "/api/agh/managed-catalog/rollbacks", nil)
	req.AddCookie(viewerCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("viewer rollbacks status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var listed struct {
		Rollbacks []struct {
			ID string `json:"id"`
		} `json:"rollbacks"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Rollbacks) != 1 || listed.Rollbacks[0].ID == "" {
		t.Fatalf("rollbacks response = %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agh/managed-catalog/rollbacks/"+listed.Rollbacks[0].ID+"/apply", nil)
	req.Header.Set("X-CSRF-Token", viewerCSRF)
	req.AddCookie(viewerCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer rollback status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	adminCookie, adminCSRF := loginForTest(t, h, "admin", "password123")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agh/managed-catalog/rollbacks/"+listed.Rollbacks[0].ID+"/apply", nil)
	req.Header.Set("X-CSRF-Token", adminCSRF)
	req.AddCookie(adminCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin rollback status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp struct {
		Updated int `json:"updated"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Updated != 1 {
		t.Fatalf("rollback response = %s", rr.Body.String())
	}
	row := managed.CatalogRows()[0]
	if !row.RewriteEnabled || row.RewriteReason != "" {
		t.Fatalf("row after rollback = %+v", row)
	}
	entry, ok := auditEntryForAction(store, "agh_managed.rollback")
	if !ok {
		t.Fatalf("rollback audit missing: %+v", store.AuditLog(20))
	}
	if !strings.Contains(entry.Detail, "rollback_id="+listed.Rollbacks[0].ID) || !strings.Contains(entry.Detail, "updated=1") {
		t.Fatalf("rollback audit detail = %q", entry.Detail)
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

func auditEntryForAction(store *Store, action string) (AuditEntry, bool) {
	for _, entry := range store.AuditLog(50) {
		if entry.Action == action {
			return entry, true
		}
	}
	return AuditEntry{}, false
}
