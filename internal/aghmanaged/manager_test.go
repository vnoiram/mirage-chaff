package aghmanaged

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
