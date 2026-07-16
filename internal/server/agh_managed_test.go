package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vnoiram/mirage-chaff/internal/aghmanaged"
	"github.com/vnoiram/mirage-chaff/internal/config"
	"github.com/vnoiram/mirage-chaff/internal/observability"
)

func TestManagedRewriteFeedRegisteredWithoutAdmin(t *testing.T) {
	cfg := config.Defaults()
	cfg.Admin.Enabled = false
	cfg.AGHManaged.Enabled = true
	cfg.AGHManaged.FeedPath = "/agh/managed-rewrites.txt"
	cfg.AGHManaged.TargetMode = "static_ip"
	cfg.AGHManaged.StaticIPv4 = []string{"192.0.2.44"}

	m, err := aghmanaged.Open(filepath.Join(t.TempDir(), "managed.json"), cfg.AGHManaged, nil)
	if err != nil {
		t.Fatal(err)
	}
	src, err := m.UpsertSource(aghmanaged.Source{Type: aghmanaged.SourceManual, Name: "manual", Enabled: true, Content: "||ads.example.net^\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SyncSource(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}

	s := &Server{cfg: cfg, managed: m}
	obs := observability.New("127.0.0.1:0", false, &observability.Health{}, nil)
	s.registerManagedRewriteFeed(obs)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agh/managed-rewrites.txt", nil)
	obs.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if body := rr.Body.String(); !strings.Contains(body, "||ads.example.net^$dnsrewrite=NOERROR;A;192.0.2.44") {
		t.Fatalf("feed missing rewrite line:\n%s", body)
	}

	next := cfg.AGHManaged
	next.FeedPath = "/agh/new-managed-rewrites.txt"
	m.SetConfig(next)

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/agh/managed-rewrites.txt", nil)
	obs.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("old feed path status = %d, want %d", rr.Code, http.StatusNotFound)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/agh/new-managed-rewrites.txt", nil)
	obs.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("new feed path status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if body := rr.Body.String(); !strings.Contains(body, "||ads.example.net^$dnsrewrite=NOERROR;A;192.0.2.44") {
		t.Fatalf("new feed path missing rewrite line:\n%s", body)
	}
}
