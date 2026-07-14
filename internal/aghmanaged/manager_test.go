package aghmanaged

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/config"
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
