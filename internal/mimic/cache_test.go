package mimic

import (
	"fmt"
	"net/http/httptest"
	"testing"
)

// TestDecoyCacheBounded verifies the decoy lookup cache respects CacheMax and
// evicts LRU entries, so a long-running process cannot grow it without bound
// (A-5: previously an unbounded sync.Map with CacheMax never wired in).
func TestDecoyCacheBounded(t *testing.T) {
	h := New(nil, Options{CacheMax: 4})

	for i := 0; i < 50; i++ {
		h.storeDecoy(fmt.Sprintf("https://ads.test/%d", i), CachedDecoy{Seed: fmt.Sprintf("s%d", i)})
	}

	h.mu.Lock()
	n := len(h.cache)
	h.mu.Unlock()
	if n > 4 {
		t.Fatalf("cache holds %d entries, want <= 4", n)
	}

	// The most recently stored entry must still be present.
	if _, ok := h.Lookup("https://ads.test/49"); !ok {
		t.Fatal("most-recent decoy was evicted")
	}
	// An old entry must have been evicted.
	if _, ok := h.Lookup("https://ads.test/0"); ok {
		t.Fatal("oldest decoy should have been evicted")
	}
}

// TestServeUsesCachedShapeWithoutProbe verifies that when a URL is already in
// the decoy cache, Serve reuses the cached shape and does not probe the origin
// (D-5). The handler is built with a nil resolver, so any HEAD probe would fail
// and fall back to defaults — proving reuse by serving the cached content-type.
func TestServeUsesCachedShapeWithoutProbe(t *testing.T) {
	h := New(nil, Options{})

	r := httptest.NewRequest("GET", "https://ads.test/pixel", nil)
	// Pre-seed a cached decoy with a distinctive content-type the probe/defaults
	// would never produce for this extension-less path.
	h.storeDecoy(r.URL.String(), CachedDecoy{Shape: Shape{ContentType: "image/gif", Length: 100, Media: MediaImage}})

	w := httptest.NewRecorder()
	if !h.Serve(w, r) {
		t.Fatal("Serve returned false for a cached decoy")
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/gif" {
		t.Fatalf("Content-Type = %q, want image/gif (cached shape not reused)", ct)
	}
}

// TestDecoyCacheDefault confirms CacheMax <= 0 falls back to a sane default
// rather than an unbounded (or zero-size) cache.
func TestDecoyCacheDefault(t *testing.T) {
	h := New(nil, Options{})
	if h.cacheMax <= 0 {
		t.Fatalf("cacheMax = %d, want a positive default", h.cacheMax)
	}
}
