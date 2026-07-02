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
