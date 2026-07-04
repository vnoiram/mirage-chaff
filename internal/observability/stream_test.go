package observability

import (
	"testing"
	"time"
)

// TestSnapshotSinceContinuesAfterWrap verifies the SSE cursor keeps delivering
// new records after the ring buffer has wrapped. The previous length-based
// cursor stalled permanently once the ring filled.
func TestSnapshotSinceContinuesAfterWrap(t *testing.T) {
	r := NewRecorder(false, 2) // tiny ring to force wrapping

	log := func(dom string) {
		r.Log(Record{Time: time.Now(), Domain: dom, Action: "stub", Status: 204})
	}

	seq := r.Seq()
	log("a")
	log("b")
	log("c") // ring (size 2) has now wrapped once; total = 3

	recs, seq := r.SnapshotSince(seq)
	if len(recs) != 2 { // only the last 2 are retained (b, c)
		t.Fatalf("after wrap got %d records, want 2", len(recs))
	}
	if recs[len(recs)-1].Domain != "c" {
		t.Fatalf("newest = %q, want c", recs[len(recs)-1].Domain)
	}

	// Nothing new yet.
	if recs, _ := r.SnapshotSince(seq); len(recs) != 0 {
		t.Fatalf("expected no new records, got %d", len(recs))
	}

	// Keep logging well past the ring size; delivery must continue.
	log("d")
	log("e")
	recs, _ = r.SnapshotSince(seq)
	if len(recs) != 2 || recs[0].Domain != "d" || recs[1].Domain != "e" {
		t.Fatalf("post-wrap delivery = %+v, want [d e]", recs)
	}
}
