package observability

import (
	"strings"
	"testing"
	"time"
)

func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"/collect":          "/collect",
		"/c?uid=secret&x=1": "/c?uid=REDACTED&x=REDACTED",
		"/p?a=1":            "/p?a=REDACTED",
	}
	for in, want := range cases {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRecorderRingAndCounters(t *testing.T) {
	r := NewRecorder(true, 2)
	r.Log(Record{Time: time.Now(), Domain: "a", Path: "/x?uid=1", Action: "stub", Status: 204})
	r.Log(Record{Time: time.Now(), Domain: "b", Path: "/y", Action: "forward-scrubbed", Status: 200})
	r.Log(Record{Time: time.Now(), Domain: "c", Path: "/z", Action: "stub", Status: 204})

	// Ring holds only the last 2.
	snap := r.Snapshot(0)
	if len(snap) != 2 || snap[0].Domain != "b" || snap[1].Domain != "c" {
		t.Fatalf("ring snapshot = %+v", snap)
	}
	// Redaction applied in snapshots.
	if strings.Contains(snap[0].Path, "uid=1") {
		t.Error("snapshot path should be redacted")
	}

	var sb strings.Builder
	r.WriteMetrics(&sb)
	out := sb.String()
	if !strings.Contains(out, `mirage_chaff_requests_total{action="stub"} 2`) {
		t.Errorf("metrics missing stub counter:\n%s", out)
	}
	if !strings.Contains(out, `mirage_chaff_requests_total{action="forward-scrubbed"} 1`) {
		t.Errorf("metrics missing forward-scrubbed counter:\n%s", out)
	}
}

func TestRecorderLogModesAndCatalogMetrics(t *testing.T) {
	stats := NewRecorderWithOptions(Options{Redact: true, Mode: "stats", CatalogMetrics: true, EmitCatalogLog: true}, 4)
	stats.Log(Record{
		Time: time.Now(), Domain: "ads.example", Path: "/collect?uid=1", Method: "GET",
		Action: "stub", Status: 204, Category: "ad_sdk", Risk: "high",
		ReviewStatus: "candidate", CatalogSource: "adguard_filter",
	})
	snap := stats.Snapshot(1)
	if len(snap) != 1 {
		t.Fatal("missing snapshot")
	}
	if snap[0].Path != "" || snap[0].Method != "" {
		t.Fatalf("stats mode should not retain per-request path/method: %+v", snap[0])
	}
	var sb strings.Builder
	stats.WriteMetrics(&sb)
	out := sb.String()
	if strings.Contains(out, "ads.example") || strings.Contains(out, "/collect") {
		t.Fatalf("metrics leaked high-cardinality fields:\n%s", out)
	}
	if !strings.Contains(out, `mirage_chaff_catalog_requests_total{category="ad_sdk",risk="high",verified="false",review_status="candidate",source_type="adguard_filter"} 1`) {
		t.Fatalf("missing catalog metric:\n%s", out)
	}

	full := NewRecorderWithOptions(Options{Redact: true, Mode: "full"}, 2)
	full.Log(Record{Time: time.Now(), Domain: "x", Path: "/p?token=secret", Action: "forward-asis", Status: 200})
	if got := full.Snapshot(1)[0].Path; got != "/p?token=secret" {
		t.Fatalf("full mode path = %q", got)
	}
}

func TestCatalogMetricsCanBeDisabled(t *testing.T) {
	r := NewRecorderWithOptions(Options{Redact: true, Mode: "redacted", CatalogMetrics: false}, 2)
	r.Log(Record{Time: time.Now(), Domain: "ads.example", Path: "/x", Action: "stub", Status: 204, Category: "ad_sdk", Risk: "high"})
	var sb strings.Builder
	r.WriteMetrics(&sb)
	if strings.Contains(sb.String(), "mirage_chaff_catalog_requests_total") {
		t.Fatalf("catalog metric should be disabled:\n%s", sb.String())
	}
}
