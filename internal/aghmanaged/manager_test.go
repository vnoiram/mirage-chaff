package aghmanaged

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/config"
	"github.com/vnoiram/mirage-chaff/internal/rulecatalog"
)

type fakeResolver struct {
	ips []net.IP
	err error
}

func (f fakeResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.ips, nil
}

func testConfig() config.AGHManagedConfig {
	return config.AGHManagedConfig{
		Enabled:       true,
		FeedPath:      "/agh/managed-rewrites.txt",
		TargetName:    "mirage-chaff.lan",
		TargetMode:    "resolved_ip",
		DefaultPreset: "balanced",
		Scheduler: config.AGHManagedScheduler{
			Enabled: true, DefaultSyncInterval: "12h", SyncTimeout: "1s",
			LargeChangeThresholdPercent: 25, LargeChangeThresholdCount: 500, LargeChangeRequiresReview: true,
		},
	}
}

func TestManagedFeedResolvedIP(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), testConfig(), fakeResolver{ips: []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")}})
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||tracker.example.com^\n@@||allowed.example.com^\nexample.com##.ad\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	p, err := m.Generate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"||tracker.example.com^$dnsrewrite=NOERROR;A;192.0.2.10",
		"||tracker.example.com^$dnsrewrite=NOERROR;AAAA;2001:db8::10",
	} {
		if !strings.Contains(p.Lines, want) {
			t.Fatalf("feed missing %q:\n%s", want, p.Lines)
		}
	}
	if strings.Contains(p.Lines, "allowed.example.com") {
		t.Fatalf("allow exception must not be included:\n%s", p.Lines)
	}
	if p.Status.ItemCount != 1 || p.Status.ExcludedCount != 2 {
		t.Fatalf("status = %+v", p.Status)
	}
}

func TestManagedFeedCNAME(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "cname"
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, fakeResolver{})
	if err != nil {
		t.Fatal(err)
	}
	src, _ := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "0.0.0.0 ads.example.net\n"})
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	p, err := m.Generate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Lines, "||ads.example.net^$dnsrewrite=NOERROR;CNAME;mirage-chaff.lan") {
		t.Fatalf("feed =\n%s", p.Lines)
	}
}

func TestSourcePriorityPersistsAndAppearsOnRows(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	path := filepath.Join(t.TempDir(), "managed.json")
	m, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Priority: 7, Content: "||priority.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	rows := m.CatalogRows()
	if len(rows) != 1 || rows[0].SourcePriority != 7 {
		t.Fatalf("rows = %+v", rows)
	}

	reopened, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	sources := reopened.ListSources()
	if len(sources) != 1 || sources[0].Priority != 7 {
		t.Fatalf("sources = %+v", sources)
	}
	rows = reopened.CatalogRows()
	if len(rows) != 1 || rows[0].SourcePriority != 7 {
		t.Fatalf("reopened rows = %+v", rows)
	}
}

func TestUpsertSourceSettingsPreservesSyncMetadata(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{
		Type:            SourceManual,
		Name:            "manual",
		Enabled:         true,
		SyncInterval:    "12h",
		Priority:        1,
		StaleFeedPolicy: StaleFeedPolicyExclude,
		Content:         "||source-settings.example.net^\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	synced, err := m.SyncSource(context.Background(), src.ID)
	if err != nil {
		t.Fatal(err)
	}
	synced.Name = "renamed"
	synced.SyncInterval = "30m"
	synced.Priority = 9
	synced.StaleFeedPolicy = StaleFeedPolicyKeep
	synced.Content = "||source-settings.example.net^\n||second.example.net^\n"
	updated, err := m.UpsertSource(synced)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "renamed" || updated.SyncInterval != "30m" || updated.Priority != 9 || updated.StaleFeedPolicy != StaleFeedPolicyKeep {
		t.Fatalf("updated source settings = %+v", updated)
	}
	if updated.LastSuccess.IsZero() || updated.LastSyncStarted.IsZero() || updated.Entries != 1 {
		t.Fatalf("sync metadata was not preserved: %+v", updated)
	}
	if updated.Content != "||source-settings.example.net^\n||second.example.net^\n" {
		t.Fatalf("content was not updated: %q", updated.Content)
	}
}

func TestPresetOverridePersistsAndAffectsFeed(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	path := filepath.Join(t.TempDir(), "managed.json")
	m, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||preset.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.SetPreset("conservative"); err != nil {
		t.Fatal(err)
	}
	p, err := m.Generate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Status.DefaultPreset != "conservative" || strings.Contains(p.Lines, "preset.example.net") {
		t.Fatalf("conservative preset should exclude candidate: status=%+v\n%s", p.Status, p.Lines)
	}
	if err := m.SetPreset("aggressive"); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err = reopened.Generate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Status.DefaultPreset != "aggressive" || !strings.Contains(p.Lines, "preset.example.net") {
		t.Fatalf("aggressive preset override not persisted/applied: status=%+v\n%s", p.Status, p.Lines)
	}
	if err := reopened.SetPreset("reckless"); err == nil {
		t.Fatal("invalid preset should fail")
	}
}

func TestCatalogPatchTracksLastChangedBy(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	path := filepath.Join(t.TempDir(), "managed.json")
	m, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||changed-by.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	rows := m.CatalogRows()
	if len(rows) != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	if _, err := m.PatchEntry(rows[0].ID, CatalogOverride{Notes: "reviewed"}, "alice"); err != nil {
		t.Fatal(err)
	}
	rows = m.CatalogRows()
	if rows[0].LastChangedBy != "alice" {
		t.Fatalf("last_changed_by = %q", rows[0].LastChangedBy)
	}
	reopened, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows = reopened.CatalogRows()
	if rows[0].LastChangedBy != "alice" {
		t.Fatalf("reopened last_changed_by = %q", rows[0].LastChangedBy)
	}
}

func TestManagedFeedExcludesHTTPPathRules(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||ads.example.net/sdk.js$script\n||dns.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	p, err := m.Generate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Lines, "ads.example.net") {
		t.Fatalf("HTTP/path scoped rule should not be emitted:\n%s", p.Lines)
	}
	if !strings.Contains(p.Lines, "dns.example.net") {
		t.Fatalf("DNS domain rule should be emitted:\n%s", p.Lines)
	}
	var sawHTTP bool
	for _, item := range p.Items {
		if item.Domain == "ads.example.net" && (item.Reason == "http layer" || item.Reason == "path scoped rule") {
			sawHTTP = true
		}
	}
	if !sawHTTP {
		t.Fatalf("preview items did not explain HTTP/path exclusion: %+v", p.Items)
	}
}

func TestManagedFeedTracksLastIncludedAt(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	path := filepath.Join(t.TempDir(), "managed.json")
	m, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||included.example.net^\n@@||excluded.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Generate(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	rows := m.CatalogRows()
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	var includedSeen, excludedSeen time.Time
	for _, row := range rows {
		switch row.Match.Domain {
		case "included.example.net":
			includedSeen = row.LastFeedIncludedAt
		case "excluded.example.net":
			excludedSeen = row.LastFeedIncludedAt
		}
	}
	if includedSeen.IsZero() {
		t.Fatalf("included row missing LastFeedIncludedAt: %+v", rows)
	}
	if !excludedSeen.IsZero() {
		t.Fatalf("excluded row should not have LastFeedIncludedAt: %+v", rows)
	}
	reopened, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows = reopened.CatalogRows()
	for _, row := range rows {
		if row.Match.Domain == "included.example.net" && row.LastFeedIncludedAt.IsZero() {
			t.Fatalf("reopened row missing LastFeedIncludedAt: %+v", rows)
		}
	}
}

func TestManagedFeedRecordsGenerationHistory(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	path := filepath.Join(t.TempDir(), "managed.json")
	m, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||included.example.net^\n@@||excluded.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Generate(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if got := len(m.ListFeedHistory()); got != 0 {
		t.Fatalf("preview recorded history len = %d", got)
	}
	if _ = m.Status(context.Background()); len(m.ListFeedHistory()) != 0 {
		t.Fatalf("status should not record history: %+v", m.ListFeedHistory())
	}
	p, err := m.Generate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Status.History) != 1 {
		t.Fatalf("history = %+v", p.Status.History)
	}
	rec := p.Status.History[0]
	if rec.IncludedCount != 1 || rec.ExcludedCount != 1 || rec.AddedCount != 1 || rec.RemovedCount != 0 || rec.TargetMode != "static_ip" || rec.EmergencyEmpty {
		t.Fatalf("history record = %+v", rec)
	}
	src.Content = "||included.example.net^\n||new.example.net^\n"
	if _, err := m.UpsertSource(src); err != nil {
		t.Fatal(err)
	}
	synced, err := m.SyncSource(context.Background(), src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if synced.PendingReview {
		if _, err := m.ApproveSource(src.ID); err != nil {
			t.Fatal(err)
		}
	}
	p, err = m.Generate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Status.History) != 2 {
		t.Fatalf("history after second generation = %+v", p.Status.History)
	}
	rec = p.Status.History[0]
	if rec.IncludedCount != 2 || rec.ExcludedCount != 0 || rec.AddedCount != 1 || rec.RemovedCount != 0 {
		t.Fatalf("second history record = %+v", rec)
	}
	off := false
	for _, row := range m.CatalogRows() {
		if row.Match.Domain == "included.example.net" {
			if _, err := m.PatchEntry(row.ID, CatalogOverride{RewriteEnabled: &off}); err != nil {
				t.Fatal(err)
			}
		}
	}
	p, err = m.Generate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	rec = p.Status.History[0]
	if rec.IncludedCount != 1 || rec.ExcludedCount != 1 || rec.AddedCount != 0 || rec.RemovedCount != 1 {
		t.Fatalf("third history record = %+v", rec)
	}
	reopened, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.ListFeedHistory(); len(got) != 3 || got[0].IncludedCount != 1 || got[0].RemovedCount != 1 {
		t.Fatalf("reopened history = %+v", got)
	}
}

func TestBalancedPresetRequiresMediumConfidenceCandidate(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||low.example.net^\n||medium.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	for _, row := range m.CatalogRows() {
		if row.Match.Domain == "low.example.net" {
			if _, err := m.PatchEntry(row.ID, CatalogOverride{Confidence: "low"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	p, err := m.Generate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Lines, "low.example.net") {
		t.Fatalf("low confidence candidate should be excluded:\n%s", p.Lines)
	}
	if !strings.Contains(p.Lines, "medium.example.net") {
		t.Fatalf("medium confidence candidate should be included:\n%s", p.Lines)
	}
}

func TestSourceURLSync(t *testing.T) {
	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("||ads.example.net/sdk.js$script\n"))
	}))
	defer filter.Close()

	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), testConfig(), fakeResolver{ips: []net.IP{net.ParseIP("192.0.2.10")}})
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceFilterURL, Name: "remote", URL: filter.URL, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.SyncSource(context.Background(), src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Entries != 1 || got.Added != 1 {
		t.Fatalf("source = %+v", got)
	}
	rows := m.CatalogRows()
	if len(rows) != 1 || rows[0].Match.Domain != "ads.example.net" || rows[0].ResourceType != "script" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestAGHCustomRulesSourceSync(t *testing.T) {
	agh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/control/filtering/status" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user_rules":["||custom.example.net^"],"allowlist_rules":["@@||allowed.example.net^"]}`))
	}))
	defer agh.Close()

	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceAGHCustomRules, Name: "agh-custom", URL: agh.URL, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.SyncSource(context.Background(), src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Entries != 2 || got.Added != 2 || got.AllowExceptions != 1 {
		t.Fatalf("source = %+v", got)
	}
	byDomain := map[string]CatalogRow{}
	for _, row := range m.CatalogRows() {
		byDomain[row.Match.Domain] = row
	}
	if got := byDomain["custom.example.net"]; got.Source.Type != "adguard_custom" || !got.RewriteEnabled {
		t.Fatalf("custom row = %+v", got)
	}
	if got := byDomain["allowed.example.net"]; got.Category != "allow_exception" {
		t.Fatalf("allow row = %+v", got)
	}
}

func TestAGHQueryLogCNAMESourceSync(t *testing.T) {
	var sawQueryLog bool
	agh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/control/filtering/status" {
			t.Fatal("query log source must not fetch filtering status")
		}
		if r.URL.Path != "/control/querylog" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		sawQueryLog = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"question":{"name":"cloak.example.net."},"answer":[{"type":"CNAME","value":"tracker.vendor.net."}],"reason":"Filtered"}]}`))
	}))
	defer agh.Close()

	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceAGHQueryLogCNAME, Name: "agh-querylog", URL: agh.URL, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	if !sawQueryLog {
		t.Fatal("query log endpoint was not called")
	}
	rows := m.CatalogRows()
	if len(rows) != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	row := rows[0]
	if row.Match.Domain != "cloak.example.net" || row.CNAMETarget != "tracker.vendor.net" || !row.CloakingDetected || row.Source.Type != "adguard_query_log" {
		t.Fatalf("query log row = %+v", row)
	}
	p, err := m.Generate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Lines, "||cloak.example.net^$dnsrewrite=NOERROR;A;192.0.2.10") {
		t.Fatalf("feed missing CNAME candidate rewrite:\n%s", p.Lines)
	}
}

func TestSyncDueSyncsAGHSourceTypes(t *testing.T) {
	agh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/control/filtering/status":
			_, _ = w.Write([]byte(`{"user_rules":["||custom.example.net^"]}`))
		case "/control/querylog":
			_, _ = w.Write([]byte(`{"data":[{"question":{"name":"cloak.example.net."},"answer":[{"type":"CNAME","value":"tracker.vendor.net."}],"reason":"Filtered"}]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer agh.Close()

	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	cfg.Scheduler.MaxParallelSyncs = 1
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpsertSource(Source{Type: SourceAGHCustomRules, Name: "agh-custom", URL: agh.URL, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpsertSource(Source{Type: SourceAGHQueryLogCNAME, Name: "agh-querylog", URL: agh.URL, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	m.SyncDue(context.Background())

	byDomain := map[string]CatalogRow{}
	for _, row := range m.CatalogRows() {
		byDomain[row.Match.Domain] = row
	}
	if _, ok := byDomain["custom.example.net"]; !ok {
		t.Fatalf("custom source was not synced: %+v", byDomain)
	}
	if _, ok := byDomain["cloak.example.net"]; !ok {
		t.Fatalf("query log source was not synced: %+v", byDomain)
	}
}

func TestPendingReviewApproveRejectAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.json")
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	cfg.Scheduler.LargeChangeThresholdCount = 1
	m, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||old.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	if rows := m.CatalogRows(); len(rows) != 1 || rows[0].Match.Domain != "old.example.net" {
		t.Fatalf("initial rows = %+v", rows)
	}

	src.Content = "||new.example.net^\n"
	if _, err := m.UpsertSource(src); err != nil {
		t.Fatal(err)
	}
	pending, err := m.SyncSource(context.Background(), src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !pending.PendingReview {
		t.Fatalf("source should require review: %+v", pending)
	}
	if rows := m.CatalogRows(); len(rows) != 1 || rows[0].Match.Domain != "old.example.net" {
		t.Fatalf("pending sync should not replace active rows: %+v", rows)
	}
	diff, err := m.PendingDiff(src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Added) != 1 || len(diff.Removed) != 1 || len(diff.Changed) != 0 {
		t.Fatalf("pending diff = %+v", diff)
	}
	if !diff.Added[0].FeedImpact.WouldInclude || diff.Added[0].FeedImpact.Reason != "included" || diff.Added[0].FeedImpact.LineCount != 1 {
		t.Fatalf("added feed impact = %+v", diff.Added[0].FeedImpact)
	}
	if len(diff.Added[0].SourceRefs) != 1 || diff.Added[0].SourceRefs[0].ID != src.ID || diff.Added[0].SourceRefs[0].Name != "manual" {
		t.Fatalf("added source refs = %+v", diff.Added[0].SourceRefs)
	}
	if !diff.Removed[0].FeedImpact.WouldInclude || diff.Removed[0].FeedImpact.Reason != "included" || diff.Removed[0].FeedImpact.LineCount != 1 {
		t.Fatalf("removed feed impact = %+v", diff.Removed[0].FeedImpact)
	}

	reopened, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.pending[src.ID]) != 1 {
		t.Fatalf("pending entries were not restored: %+v", reopened.pending)
	}
	approved, err := reopened.ApproveSource(src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if approved.PendingReview || approved.Entries != 1 {
		t.Fatalf("approved source = %+v", approved)
	}
	if rows := reopened.CatalogRows(); len(rows) != 1 || rows[0].Match.Domain != "new.example.net" {
		t.Fatalf("approved rows = %+v", rows)
	}
	if len(reopened.pending) != 0 {
		t.Fatalf("pending not cleared after approve: %+v", reopened.pending)
	}

	src.Content = "||third.example.net^\n"
	if _, err := reopened.UpsertSource(src); err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.SyncSource(context.Background(), src.ID); err != nil || !got.PendingReview {
		t.Fatalf("second pending sync source=%+v err=%v", got, err)
	}
	rejected, err := reopened.RejectSource(src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rejected.PendingReview {
		t.Fatalf("rejected source still pending: %+v", rejected)
	}
	if rows := reopened.CatalogRows(); len(rows) != 1 || rows[0].Match.Domain != "new.example.net" {
		t.Fatalf("reject should keep active rows: %+v", rows)
	}
	if len(reopened.pending) != 0 {
		t.Fatalf("pending not cleared after reject: %+v", reopened.pending)
	}
}

func TestPendingDiffChangedEntriesIncludePreviousAndFields(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||changed.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	prev := rulecatalog.Entry{
		ID:           "same-id",
		Source:       rulecatalog.Source{Name: src.ID},
		OriginalRule: "||changed.example.net^",
		Match:        rulecatalog.Match{Domain: "changed.example.net"},
		Layer:        rulecatalog.LayerDNS,
		Category:     "tracker",
		ResourceType: "domain",
	}
	next := prev
	next.Category = "ad_sdk"
	next.ResourceType = "script"
	diff := m.pendingDiffLocked(src, []rulecatalog.Entry{prev}, []rulecatalog.Entry{next})
	if len(diff.Changed) != 1 {
		t.Fatalf("changed diff = %+v", diff)
	}
	got := diff.Changed[0]
	if got.Previous == nil || got.Previous.Category != "tracker" || got.Previous.ResourceType != "domain" {
		t.Fatalf("previous entry = %+v", got.Previous)
	}
	if strings.Join(got.ChangedFields, ",") != "category,resource_type" {
		t.Fatalf("changed fields = %+v", got.ChangedFields)
	}
	if got.Category != "ad_sdk" || got.ResourceType != "script" {
		t.Fatalf("next entry = %+v", got.Entry)
	}
}

func TestStaleTargetTTLRejectsExpiredCachedIPs(t *testing.T) {
	cfg := testConfig()
	cfg.StaleTargetTTL = "1h"
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, fakeResolver{err: errors.New("dns down")})
	if err != nil {
		t.Fatal(err)
	}
	m.targetIPs = []net.IP{net.ParseIP("192.0.2.10")}
	m.lastResolve = time.Now().Add(-2 * time.Hour)
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||ads.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	p, err := m.Generate(context.Background(), false)
	if err == nil {
		t.Fatalf("Generate should fail with expired cached IPs: status=%+v lines=\n%s", p.Status, p.Lines)
	}
	if strings.Contains(p.Lines, "192.0.2.10") {
		t.Fatalf("expired cached IP should not be used:\n%s", p.Lines)
	}
}

func TestFreshCachedTargetIsMarkedStaleCache(t *testing.T) {
	cfg := testConfig()
	cfg.StaleTargetTTL = "1h"
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, fakeResolver{err: errors.New("dns down")})
	if err != nil {
		t.Fatal(err)
	}
	m.targetIPs = []net.IP{net.ParseIP("192.0.2.10")}
	m.lastResolve = time.Now().Add(-10 * time.Minute)
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||ads.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	p, err := m.Generate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Status.TargetCacheUsed || !strings.Contains(p.Lines, "target_resolution=stale-cache") {
		t.Fatalf("cached target use was not marked: status=%+v lines=\n%s", p.Status, p.Lines)
	}
}

func TestStaleSourceTTLDefaultAndDisable(t *testing.T) {
	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("||remote.example.net^\n"))
	}))
	defer filter.Close()

	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := m.UpsertSource(Source{Type: SourceFilterURL, Name: "remote", URL: filter.URL, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), remote.ID); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	src := m.sources[remote.ID]
	src.LastSuccess = time.Now().Add(-73 * time.Hour)
	m.sources[remote.ID] = src
	m.mu.Unlock()
	p, err := m.Generate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Lines, "remote.example.net") || p.Status.StaleSources != 1 {
		t.Fatalf("default stale_source_ttl should exclude old remote source: status=%+v lines=\n%s", p.Status, p.Lines)
	}
	src.StaleFeedPolicy = StaleFeedPolicyKeep
	if _, err := m.UpsertSource(src); err != nil {
		t.Fatal(err)
	}
	p, err = m.Generate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Lines, "remote.example.net") || p.Status.StaleSources != 1 {
		t.Fatalf("keep stale policy should include old remote source while warning: status=%+v lines=\n%s", p.Status, p.Lines)
	}
	cfg.Scheduler.StaleSourceTTL = "0"
	m.SetConfig(cfg)
	p, err = m.Generate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Lines, "remote.example.net") {
		t.Fatalf("stale_source_ttl=0 should disable exclusion:\n%s", p.Lines)
	}
}

func TestStaleSourceTTLExcludesOnlyRemoteSources(t *testing.T) {
	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("||remote.example.net^\n"))
	}))
	defer filter.Close()

	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	cfg.Scheduler.StaleSourceTTL = "1h"
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := m.UpsertSource(Source{Type: SourceFilterURL, Name: "remote", URL: filter.URL, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	manual, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||manual.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), remote.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), manual.ID); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	src := m.sources[remote.ID]
	src.LastSuccess = time.Now().Add(-2 * time.Hour)
	m.sources[remote.ID] = src
	src = m.sources[manual.ID]
	src.LastSuccess = time.Now().Add(-2 * time.Hour)
	m.sources[manual.ID] = src
	m.mu.Unlock()

	p, err := m.Generate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Lines, "remote.example.net") {
		t.Fatalf("stale remote source should be excluded:\n%s", p.Lines)
	}
	if !strings.Contains(p.Lines, "manual.example.net") {
		t.Fatalf("manual source should not be stale-excluded:\n%s", p.Lines)
	}
	if p.Status.ItemCount != 1 || p.Status.ExcludedCount != 1 {
		t.Fatalf("status = %+v", p.Status)
	}
}

func TestConflictsListExcludeAndResolve(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	tracker, err := m.UpsertSource(Source{Type: SourceManual, Name: "tracker", Enabled: true, Content: "||conflict.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	allow, err := m.UpsertSource(Source{Type: SourceManual, Name: "allow", Enabled: true, Content: "@@||conflict.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), tracker.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), allow.ID); err != nil {
		t.Fatal(err)
	}

	conflicts := m.ListConflicts()
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %+v", conflicts)
	}
	if conflicts[0].Domain != "conflict.example.net" || len(conflicts[0].Entries) != 2 {
		t.Fatalf("conflict = %+v", conflicts[0])
	}
	if !strings.Contains(strings.Join(conflicts[0].Reasons, ","), "allow_exception conflicts with rewrite candidate") {
		t.Fatalf("conflict reasons = %+v", conflicts[0].Reasons)
	}

	p, err := m.Generate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Status.ConflictCount != 1 {
		t.Fatalf("status = %+v", p.Status)
	}
	var sawUnresolved bool
	for _, item := range p.Items {
		if item.Domain == "conflict.example.net" && item.Reason == "conflict unresolved" {
			sawUnresolved = true
		}
	}
	if !sawUnresolved {
		t.Fatalf("preview items did not explain unresolved conflict: %+v", p.Items)
	}
	if strings.Contains(p.Lines, "conflict.example.net") {
		t.Fatalf("unresolved conflict should not be emitted:\n%s", p.Lines)
	}

	off := false
	if _, err := m.ResolveConflict(conflicts[0].ID, CatalogOverride{RewriteEnabled: &off, RewriteReason: "manual disable"}); err != nil {
		t.Fatal(err)
	}
	if got := m.ListConflicts(); len(got) != 0 {
		t.Fatalf("resolved conflict still listed: %+v", got)
	}
	p, err = m.Generate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Status.ConflictCount != 0 {
		t.Fatalf("status after resolve = %+v", p.Status)
	}
	var sawDisabled, sawStillUnresolved bool
	for _, item := range p.Items {
		if item.Domain != "conflict.example.net" {
			continue
		}
		if item.Reason == "disabled by preset or user" {
			sawDisabled = true
		}
		if item.Reason == "conflict unresolved" {
			sawStillUnresolved = true
		}
	}
	if !sawDisabled || sawStillUnresolved {
		t.Fatalf("preview items after resolve = %+v", p.Items)
	}
}

func TestRewriteActionConflictsExcludeAndResolve(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||missing-action.example.net^\n||unsafe-action.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	var missingID, unsafeID string
	for _, row := range m.CatalogRows() {
		switch row.Match.Domain {
		case "missing-action.example.net":
			missingID = row.ID
			m.mu.Lock()
			e := m.entries[row.ID]
			e.ActionCandidates = nil
			m.entries[row.ID] = e
			m.mu.Unlock()
		case "unsafe-action.example.net":
			unsafeID = row.ID
			if _, err := m.PatchEntry(row.ID, CatalogOverride{Action: "forward-asis"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if missingID == "" || unsafeID == "" {
		t.Fatalf("test rows not found: missing=%q unsafe=%q", missingID, unsafeID)
	}
	conflicts := m.ListConflicts()
	if len(conflicts) != 2 {
		t.Fatalf("conflicts = %+v", conflicts)
	}
	reasons := map[string]string{}
	for _, conflict := range conflicts {
		reasons[conflict.Domain] = strings.Join(conflict.Reasons, ",")
	}
	if !strings.Contains(reasons["missing-action.example.net"], "missing mirage action") {
		t.Fatalf("missing action reasons = %+v", conflicts)
	}
	if !strings.Contains(reasons["unsafe-action.example.net"], "unsafe mirage action") {
		t.Fatalf("unsafe action reasons = %+v", conflicts)
	}
	p, err := m.Generate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Status.ConflictCount != 2 || strings.Contains(p.Lines, "missing-action.example.net") || strings.Contains(p.Lines, "unsafe-action.example.net") {
		t.Fatalf("conflicting actions should be excluded: status=%+v\n%s", p.Status, p.Lines)
	}
	off := false
	for _, conflict := range conflicts {
		if _, err := m.ResolveConflict(conflict.ID, CatalogOverride{RewriteEnabled: &off, RewriteReason: "action conflict"}); err != nil {
			t.Fatal(err)
		}
	}
	if got := m.ListConflicts(); len(got) != 0 {
		t.Fatalf("resolved action conflicts still listed: %+v", got)
	}
}

func TestResolveConflictByPriorityAppliesWinnerClassification(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	low, err := m.UpsertSource(Source{Type: SourceManual, Name: "low", Enabled: true, Priority: 1, Content: "@@||priority-conflict.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	high, err := m.UpsertSource(Source{Type: SourceManual, Name: "high", Enabled: true, Priority: 10, Content: "||priority-conflict.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), low.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), high.ID); err != nil {
		t.Fatal(err)
	}
	rows := m.CatalogRows()
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	verified := true
	for _, row := range rows {
		if row.SourcePriority == 10 {
			if _, err := m.PatchEntry(row.ID, CatalogOverride{Category: "winner_category", ResourceType: "script", Risk: "high", Confidence: "high", ReviewStatus: "approved", Verified: &verified, ExpectedCatalog: "winner-catalog", Action: "stub"}); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := m.PatchEntry(row.ID, CatalogOverride{Category: "loser_category", ReviewStatus: "needs_test"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	conflicts := m.ListConflicts()
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %+v", conflicts)
	}
	updated, err := m.ResolveConflictByPriority(conflicts[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 1 {
		t.Fatalf("updated = %+v", updated)
	}
	if got := m.ListConflicts(); len(got) != 0 {
		t.Fatalf("conflict still listed: %+v", got)
	}
	var loser CatalogRow
	for _, row := range m.CatalogRows() {
		if row.SourcePriority == 1 {
			loser = row
		}
	}
	if loser.Category != "winner_category" || loser.ResourceType != "script" || loser.Risk != "high" || loser.Confidence != "high" || loser.ReviewStatus != "approved" || !loser.Verified || loser.ExpectedCatalog != "winner-catalog" || loser.Action != "stub" {
		t.Fatalf("loser did not receive winner classification: %+v", loser)
	}
	rollbacks := m.ListRollbacks()
	if len(rollbacks) == 0 || rollbacks[0].Action != "conflict source priority resolve" || !strings.Contains(rollbacks[0].Summary, high.ID) {
		t.Fatalf("rollbacks = %+v", rollbacks)
	}
}

func TestResolveConflictByPriorityAllowExceptionWinsAndExcludesFeed(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	tracker, err := m.UpsertSource(Source{Type: SourceManual, Name: "tracker", Enabled: true, Priority: 1, Content: "||priority-allow.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	allow, err := m.UpsertSource(Source{Type: SourceManual, Name: "allow", Enabled: true, Priority: 5, Content: "@@||priority-allow.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), tracker.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), allow.ID); err != nil {
		t.Fatal(err)
	}
	conflicts := m.ListConflicts()
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %+v", conflicts)
	}
	if _, err := m.ResolveConflictByPriority(conflicts[0].ID); err != nil {
		t.Fatal(err)
	}
	if got := m.ListConflicts(); len(got) != 0 {
		t.Fatalf("conflict still listed: %+v", got)
	}
	p, err := m.Generate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Lines, "priority-allow.example.net") {
		t.Fatalf("allow-priority conflict should be excluded:\n%s", p.Lines)
	}
	for _, row := range m.CatalogRows() {
		if row.Category != "allow_exception" {
			t.Fatalf("row should align to allow_exception: %+v", row)
		}
	}
}

func TestResolveConflictByPriorityTieDoesNotMutate(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	tracker, err := m.UpsertSource(Source{Type: SourceManual, Name: "tracker", Enabled: true, Priority: 3, Content: "||priority-tie.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	allow, err := m.UpsertSource(Source{Type: SourceManual, Name: "allow", Enabled: true, Priority: 3, Content: "@@||priority-tie.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), tracker.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), allow.ID); err != nil {
		t.Fatal(err)
	}
	conflicts := m.ListConflicts()
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %+v", conflicts)
	}
	if _, err := m.ResolveConflictByPriority(conflicts[0].ID); err == nil || !strings.Contains(err.Error(), "tie") {
		t.Fatalf("ResolveConflictByPriority error = %v, want tie", err)
	}
	if len(m.ListRollbacks()) != 0 {
		t.Fatalf("tie should not record rollback: %+v", m.ListRollbacks())
	}
	if got := m.ListConflicts(); len(got) != 1 {
		t.Fatalf("tie should leave conflict unchanged: %+v", got)
	}
}

func TestRollbackRestoresPriorityConflictResolution(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	tracker, err := m.UpsertSource(Source{Type: SourceManual, Name: "tracker", Enabled: true, Priority: 1, Content: "||priority-rollback.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	allow, err := m.UpsertSource(Source{Type: SourceManual, Name: "allow", Enabled: true, Priority: 5, Content: "@@||priority-rollback.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), tracker.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), allow.ID); err != nil {
		t.Fatal(err)
	}
	conflicts := m.ListConflicts()
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %+v", conflicts)
	}
	if _, err := m.ResolveConflictByPriority(conflicts[0].ID); err != nil {
		t.Fatal(err)
	}
	rollbacks := m.ListRollbacks()
	if len(rollbacks) == 0 {
		t.Fatal("expected rollback")
	}
	if _, err := m.Rollback(rollbacks[0].ID); err != nil {
		t.Fatal(err)
	}
	if got := m.ListConflicts(); len(got) != 1 {
		t.Fatalf("rollback should restore conflict: %+v", got)
	}
}

func TestBulkPatchEntriesAppliesOverridesAtomically(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||one.example.net^\n||two.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	rows := m.CatalogRows()
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	ids := []string{rows[0].ID, rows[1].ID}

	off := false
	verified := true
	updated, err := m.BulkPatchEntries(ids, CatalogOverride{
		Category:        "ad_sdk",
		ResourceType:    "script",
		Risk:            "high",
		Confidence:      "low",
		ReviewStatus:    "needs_test",
		Verified:        &verified,
		ExpectedCatalog: "noop-sdk",
		Action:          "stub",
		RewriteEnabled:  &off,
		RewriteReason:   "bulk disable",
		Notes:           "bulk note",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 2 {
		t.Fatalf("updated = %+v", updated)
	}
	for _, row := range m.CatalogRows() {
		if row.Category != "ad_sdk" ||
			row.ResourceType != "script" ||
			row.Risk != "high" ||
			row.Confidence != "low" ||
			row.ReviewStatus != "needs_test" ||
			!row.Verified ||
			row.ExpectedCatalog != "noop-sdk" ||
			row.Action != "stub" ||
			row.RewriteEnabled ||
			row.RewriteReason != "bulk disable" ||
			row.Notes != "bulk note" {
			t.Fatalf("row after bulk patch = %+v", row)
		}
	}
	p, err := m.Generate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range p.Items {
		if item.Reason != "disabled by preset or user" {
			t.Fatalf("item after bulk patch = %+v", item)
		}
	}

	on := true
	if _, err := m.BulkPatchEntries([]string{ids[0], "missing"}, CatalogOverride{RewriteEnabled: &on, RewriteReason: "should not apply", Risk: "low", Action: "allow"}); err == nil {
		t.Fatal("BulkPatchEntries should reject missing IDs")
	}
	for _, row := range m.CatalogRows() {
		if row.RewriteEnabled || row.RewriteReason != "bulk disable" || row.Risk != "high" || row.Action != "stub" {
			t.Fatalf("bulk patch was not atomic: %+v", row)
		}
	}
}

func TestPatchEntryPersistsClassificationMetadata(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	path := filepath.Join(t.TempDir(), "managed.json")
	m, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||one.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	rows := m.CatalogRows()
	if len(rows) != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	verified := true
	row, err := m.PatchEntry(rows[0].ID, CatalogOverride{
		Risk:            "high",
		Verified:        &verified,
		ExpectedCatalog: "noop-sdk",
		Action:          "stub",
		Notes:           "verified manually",
	})
	if err != nil {
		t.Fatal(err)
	}
	if row.Risk != "high" || !row.Verified || row.ExpectedCatalog != "noop-sdk" || row.Action != "stub" || row.Notes != "verified manually" {
		t.Fatalf("patched row = %+v", row)
	}

	reopened, err := Open(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows = reopened.CatalogRows()
	if len(rows) != 1 {
		t.Fatalf("reopened rows = %+v", rows)
	}
	if rows[0].Risk != "high" || !rows[0].Verified || rows[0].ExpectedCatalog != "noop-sdk" || rows[0].Action != "stub" || rows[0].Notes != "verified manually" {
		t.Fatalf("reopened row = %+v", rows[0])
	}
}

func TestSourceEntriesFiltersAndAppliesOverrides(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceA, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual-a", Enabled: true, Content: "||b.example.net^\n||a.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	sourceB, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual-b", Enabled: true, Content: "||c.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), sourceA.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), sourceB.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := m.SourceEntries(sourceA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("sourceA rows = %+v", rows)
	}
	if rows[0].Match.Domain != "a.example.net" || rows[1].Match.Domain != "b.example.net" {
		t.Fatalf("sourceA rows not sorted by domain: %+v", rows)
	}
	for _, row := range rows {
		if row.Source.Name != sourceA.ID || len(row.SourceIDs) != 1 || row.SourceIDs[0] != sourceA.ID {
			t.Fatalf("sourceA row has wrong source: %+v", row)
		}
		if len(row.SourceRefs) != 1 || row.SourceRefs[0].ID != sourceA.ID || row.SourceRefs[0].Name != "manual-a" || row.SourceRefs[0].Type != SourceManual {
			t.Fatalf("sourceA row has wrong source refs: %+v", row.SourceRefs)
		}
	}
	off := false
	if _, err := m.PatchEntry(rows[0].ID, CatalogOverride{RewriteEnabled: &off, RewriteReason: "source override"}); err != nil {
		t.Fatal(err)
	}
	rows, err = m.SourceEntries(sourceA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].RewriteEnabled || rows[0].RewriteReason != "source override" {
		t.Fatalf("override not reflected in source entries: %+v", rows[0])
	}
	sourceBRows, err := m.SourceEntries(sourceB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sourceBRows) != 1 || sourceBRows[0].Match.Domain != "c.example.net" {
		t.Fatalf("sourceB rows = %+v", sourceBRows)
	}
	p, err := m.Generate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	var sawItemRef bool
	for _, item := range p.Items {
		if item.Domain == "a.example.net" && len(item.SourceRefs) == 1 && item.SourceRefs[0].ID == sourceA.ID {
			sawItemRef = true
		}
	}
	if !sawItemRef {
		t.Fatalf("feed items missing source refs: %+v", p.Items)
	}
	if _, err := m.SourceEntries("missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing source error = %v, want os.ErrNotExist", err)
	}
}

func TestUnsupportedCatalogRowsRemainVisibleAndExcludedFromFeed(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||dns.example.net^\nexample.net##.ad\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	rows := m.CatalogRows()
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	var unsupported CatalogRow
	for _, row := range rows {
		if row.Unsupported {
			unsupported = row
		}
	}
	if unsupported.ID == "" || unsupported.Layer != rulecatalog.LayerDOM || unsupported.Match.Domain != "example.net" {
		t.Fatalf("unsupported row not exposed: %+v", rows)
	}
	p, err := m.Generate(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	var sawUnsupported bool
	for _, item := range p.Items {
		if item.EntryID == unsupported.ID {
			sawUnsupported = item.Reason == "unsupported layer" && !item.Included
		}
	}
	if !sawUnsupported {
		t.Fatalf("unsupported feed item missing/exposed incorrectly: %+v", p.Items)
	}
	if strings.Contains(p.Lines, "||example.net^") {
		t.Fatalf("unsupported row should not be emitted:\n%s", p.Lines)
	}
}

func TestRollbackRestoresCatalogOverrides(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||one.example.net^\n||two.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	rows := m.CatalogRows()
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	off := false
	if _, err := m.PatchEntry(rows[0].ID, CatalogOverride{RewriteEnabled: &off, RewriteReason: "manual disable"}); err != nil {
		t.Fatal(err)
	}
	rollbacks := m.ListRollbacks()
	if len(rollbacks) != 1 {
		t.Fatalf("rollbacks = %+v", rollbacks)
	}
	restored, err := m.Rollback(rollbacks[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 || restored[0].ID != rows[0].ID || !restored[0].RewriteEnabled || restored[0].RewriteReason != "" {
		t.Fatalf("restored = %+v", restored)
	}
	if _, ok := m.overrides[rows[0].ID]; ok {
		t.Fatalf("override should be removed after rollback: %+v", m.overrides[rows[0].ID])
	}
	if got := m.ListRollbacks(); len(got) != 0 {
		t.Fatalf("rollback record should be removed: %+v", got)
	}

	off = false
	verified := true
	if _, err := m.BulkPatchEntries([]string{rows[0].ID, rows[1].ID}, CatalogOverride{
		Category:        "ad_sdk",
		ResourceType:    "script",
		Risk:            "high",
		Confidence:      "low",
		Verified:        &verified,
		ExpectedCatalog: "noop-sdk",
		Action:          "stub",
		RewriteEnabled:  &off,
		RewriteReason:   "bulk disable",
		Notes:           "bulk note",
	}); err != nil {
		t.Fatal(err)
	}
	rollbacks = m.ListRollbacks()
	if len(rollbacks) != 1 || len(rollbacks[0].EntryIDs) != 2 {
		t.Fatalf("bulk rollbacks = %+v", rollbacks)
	}
	restored, err = m.Rollback(rollbacks[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 2 {
		t.Fatalf("bulk restored = %+v", restored)
	}
	for _, row := range restored {
		if row.Category == "ad_sdk" ||
			row.ResourceType == "script" ||
			row.Risk == "high" ||
			row.Confidence == "low" ||
			row.Verified ||
			row.ExpectedCatalog == "noop-sdk" ||
			row.Action == "stub" ||
			!row.RewriteEnabled ||
			row.RewriteReason != "" ||
			row.Notes == "bulk note" {
			t.Fatalf("row after bulk rollback = %+v", row)
		}
	}
}

func TestRollbackRejectsOverlappingNewerChangeAndCapsHistory(t *testing.T) {
	cfg := testConfig()
	cfg.TargetMode = "static_ip"
	cfg.StaticIPv4 = []string{"192.0.2.10"}
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(Source{Type: SourceManual, Name: "manual", Enabled: true, Content: "||one.example.net^\n||two.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	rows := m.CatalogRows()
	off := false
	if _, err := m.PatchEntry(rows[0].ID, CatalogOverride{RewriteEnabled: &off, RewriteReason: "first"}); err != nil {
		t.Fatal(err)
	}
	first := m.ListRollbacks()[0]
	if _, err := m.PatchEntry(rows[0].ID, CatalogOverride{RewriteReason: "second"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Rollback(first.ID); err == nil {
		t.Fatal("expected older overlapping rollback to be rejected")
	}
	if got := m.overrides[rows[0].ID].RewriteReason; got != "second" {
		t.Fatalf("rollback changed state despite overlap error: %q", got)
	}

	for i := 0; i < 55; i++ {
		if _, err := m.PatchEntry(rows[1].ID, CatalogOverride{RewriteReason: fmt.Sprintf("cap-%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(m.ListRollbacks()); got != 50 {
		t.Fatalf("rollback history len = %d, want 50", got)
	}
}

func TestManualSourceIDIncludesContent(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.UpsertSource(Source{Type: SourceManual, Enabled: true, Content: "||a.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.UpsertSource(Source{Type: SourceManual, Enabled: true, Content: "||b.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID {
		t.Fatalf("manual source IDs collided: %s", a.ID)
	}
	if got := m.ListSources(); len(got) != 2 {
		t.Fatalf("sources = %+v", got)
	}
}

func TestListSourcesIncludesDerivedHealth(t *testing.T) {
	cfg := testConfig()
	cfg.Scheduler.StaleSourceTTL = "1h"
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	paused, err := m.UpsertSource(Source{Type: SourceManual, Name: "paused", Enabled: false, Content: "||paused.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	never, err := m.UpsertSource(Source{Type: SourceManual, Name: "never", Enabled: true, Content: "||never.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	failing, err := m.UpsertSource(Source{Type: SourceManual, Name: "failing", Enabled: true, Content: "||failing.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := m.UpsertSource(Source{Type: SourceManual, Name: "pending", Enabled: true, Content: "||pending.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	stale, err := m.UpsertSource(Source{Type: SourceFilterURL, Name: "stale", URL: "https://example.test/stale.txt", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	staleAGH, err := m.UpsertSource(Source{Type: SourceAGHCustomRules, Name: "stale-agh", URL: "https://example.test", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	healthy, err := m.UpsertSource(Source{Type: SourceManual, Name: "healthy", Enabled: true, Content: "||healthy.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	src := m.sources[failing.ID]
	src.LastError = "boom"
	m.sources[failing.ID] = src
	src = m.sources[pending.ID]
	src.PendingReview = true
	m.sources[pending.ID] = src
	src = m.sources[stale.ID]
	src.LastSuccess = time.Now().Add(-2 * time.Hour)
	m.sources[stale.ID] = src
	src = m.sources[staleAGH.ID]
	src.LastSuccess = time.Now().Add(-2 * time.Hour)
	m.sources[staleAGH.ID] = src
	src = m.sources[healthy.ID]
	src.LastSuccess = time.Now()
	m.sources[healthy.ID] = src
	m.mu.Unlock()

	got := map[string]string{}
	for _, src := range m.ListSources() {
		got[src.Name] = src.Health
		if src.ID == paused.ID || src.ID == never.ID || src.ID == failing.ID || src.ID == pending.ID || src.ID == stale.ID || src.ID == staleAGH.ID || src.ID == healthy.ID {
			if src.Health == "" {
				t.Fatalf("source missing health: %+v", src)
			}
		}
	}
	want := map[string]string{
		"paused":    "paused",
		"never":     "never synced",
		"failing":   "failing",
		"pending":   "pending",
		"stale":     "stale",
		"stale-agh": "stale",
		"healthy":   "healthy",
	}
	for name, health := range want {
		if got[name] != health {
			t.Fatalf("health[%s] = %q, want %q; all=%+v", name, got[name], health, got)
		}
	}
}

func TestEmergencyEmptySurvivesConfigReloadAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.json")
	cfg := testConfig()
	m, err := Open(path, cfg, fakeResolver{ips: []net.IP{net.ParseIP("192.0.2.10")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetEmergencyEmpty(true); err != nil {
		t.Fatal(err)
	}
	reloaded := testConfig()
	reloaded.EmergencyEmpty = false
	m.SetConfig(reloaded)
	p, err := m.Generate(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Status.EmergencyEmpty || !strings.Contains(p.Lines, "emergency_empty=true") {
		t.Fatalf("emergency state lost after SetConfig: status=%+v lines=\n%s", p.Status, p.Lines)
	}

	reopened, err := Open(path, cfg, fakeResolver{ips: []net.IP{net.ParseIP("192.0.2.10")}})
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Config().EmergencyEmpty {
		t.Fatal("emergency state was not restored from state file")
	}
}

func TestSyncDueHonorsMaxParallelSyncs(t *testing.T) {
	var active int32
	var maxActive int32
	bothStarted := make(chan struct{})
	release := make(chan struct{})
	var closed int32
	filter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt32(&active, 1)
		defer atomic.AddInt32(&active, -1)
		for {
			max := atomic.LoadInt32(&maxActive)
			if cur <= max || atomic.CompareAndSwapInt32(&maxActive, max, cur) {
				break
			}
		}
		if cur == 2 && atomic.CompareAndSwapInt32(&closed, 0, 1) {
			close(bothStarted)
		}
		select {
		case <-release:
		case <-time.After(2 * time.Second):
			t.Error("timed out waiting for release")
		}
		_, _ = w.Write([]byte("||ads.example.net^\n"))
	}))
	defer filter.Close()

	cfg := testConfig()
	cfg.Scheduler.MaxParallelSyncs = 2
	m, err := Open(filepath.Join(t.TempDir(), "managed.json"), cfg, fakeResolver{ips: []net.IP{net.ParseIP("192.0.2.10")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"remote-a", "remote-b"} {
		if _, err := m.UpsertSource(Source{Type: SourceFilterURL, Name: name, URL: filter.URL, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}

	done := make(chan struct{})
	go func() {
		m.SyncDue(context.Background())
		close(done)
	}()
	select {
	case <-bothStarted:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("expected two source syncs to run concurrently")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SyncDue did not finish")
	}
	if got := atomic.LoadInt32(&maxActive); got < 2 {
		t.Fatalf("max active syncs = %d, want at least 2", got)
	}
}
