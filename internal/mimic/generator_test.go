package mimic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// deadResolver always fails, so probe() returns a zero Shape and defaults are used.
type deadResolver struct{}

func (deadResolver) LookupIP(context.Context, string) ([]net.IP, error) {
	return nil, fmt.Errorf("no resolver")
}

func TestGenerateExactLengthAndDeterminism(t *testing.T) {
	shapes := []Shape{
		{ContentType: "application/javascript", Length: 500, Media: MediaJS},
		{ContentType: "image/gif", Length: 300, Media: MediaImage},
		{ContentType: "image/png", Length: 300, Media: MediaImage},
		{ContentType: "application/octet-stream", Length: 777, Media: MediaBinary},
		{ContentType: "video/mp4", Length: 777, Media: MediaVideo},
	}
	for _, sh := range shapes {
		a, err := Generate("https://x/seed", sh)
		if err != nil {
			t.Fatalf("%s: %v", sh.Media, err)
		}
		if int64(len(a)) != sh.Length {
			t.Errorf("%s: len=%d want %d", sh.Media, len(a), sh.Length)
		}
		b, _ := Generate("https://x/seed", sh)
		if !bytes.Equal(a, b) {
			t.Errorf("%s: not deterministic", sh.Media)
		}
		c, _ := Generate("https://x/other", sh)
		if bytes.Equal(a, c) {
			t.Errorf("%s: different seeds produced identical bytes", sh.Media)
		}
	}
}

func TestGenerateImageValidHeader(t *testing.T) {
	gif, _ := Generate("s", Shape{ContentType: "image/gif", Length: 100, Media: MediaImage})
	if !bytes.HasPrefix(gif, []byte("GIF89a")) {
		t.Error("gif decoy must start with GIF89a")
	}
	png, _ := Generate("s", Shape{ContentType: "image/png", Length: 100, Media: MediaImage})
	if !bytes.HasPrefix(png, []byte{0x89, 0x50, 0x4e, 0x47}) {
		t.Error("png decoy must start with PNG magic")
	}
}

func TestGenerateJSNoUnsafeCommentClose(t *testing.T) {
	js, _ := Generate("s", Shape{ContentType: "application/javascript", Length: 2000, Media: MediaJS})
	// The padding lives inside /* ... */; it must not contain a premature */.
	inner := js[3 : len(js)-len("*/\nvar __mc=0;\n")]
	if bytes.Contains(inner, []byte("*/")) {
		t.Error("js padding contains a comment terminator")
	}
}

func TestRangeConsistency(t *testing.T) {
	sh := Shape{ContentType: "application/octet-stream", Length: 1000, Media: MediaBinary}
	full, _ := Generate("seed", sh)
	part, err := GenerateRange("seed", sh, 100, 199)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(part, full[100:200]) {
		t.Error("range slice mismatch")
	}
}

func TestGenerateVideoOpaqueDeterministic(t *testing.T) {
	shape := Shape{ContentType: "video/mp4", Length: 100, Media: MediaVideo}
	a, err := Generate("https://ads.test/clip.mp4", shape)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate("https://ads.test/clip.mp4", shape)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != int(shape.Length) {
		t.Fatalf("len=%d want %d", len(a), shape.Length)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("video decoy is not deterministic")
	}
}

func TestServeFallsBackForVideo(t *testing.T) {
	h := New(deadResolver{}, Options{AllowVideo: false})
	r := httptest.NewRequest(http.MethodGet, "https://ads.test/clip.mp4", nil)
	r.Host = "ads.test"
	rec := httptest.NewRecorder()
	// probe will fail (nil resolver) but classification by .mp4 is video -> false.
	if h.Serve(rec, r) {
		t.Fatal("video should not be served by mimic")
	}
}

func TestServeGeneratesOptInVideoWithoutProbe(t *testing.T) {
	h := New(deadResolver{}, Options{AllowVideo: true})
	r := httptest.NewRequest(http.MethodGet, "https://ads.test/clip.mp4", nil)
	r.Host = "ads.test"
	rec := httptest.NewRecorder()
	if !h.Serve(rec, r) {
		t.Fatal("video should be served when allow_video is true")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "video/mp4" {
		t.Errorf("content-type = %q", ct)
	}
	if rec.Header().Get("Accept-Ranges") != "bytes" {
		t.Error("expected Accept-Ranges: bytes")
	}
	if rec.Body.Len() == 0 {
		t.Fatal("expected non-empty body")
	}
	if rec.Header().Get("Content-Length") != fmt.Sprint(rec.Body.Len()) {
		t.Errorf("content-length = %q want %d", rec.Header().Get("Content-Length"), rec.Body.Len())
	}
	cached, ok := h.Lookup(r.URL.String())
	if !ok {
		t.Fatal("expected cached video decoy")
	}
	if cached.Shape.Media != MediaVideo {
		t.Fatalf("cached media = %q want %q", cached.Shape.Media, MediaVideo)
	}
	if sum := sha256.Sum256(rec.Body.Bytes()); sum != cached.Hash {
		t.Fatal("cached hash does not match served body")
	}
}

func TestServeOptInVideoRange(t *testing.T) {
	h := New(deadResolver{}, Options{AllowVideo: true})
	fullReq := httptest.NewRequest(http.MethodGet, "https://ads.test/clip.mp4", nil)
	fullReq.Host = "ads.test"
	fullRec := httptest.NewRecorder()
	if !h.Serve(fullRec, fullReq) {
		t.Fatal("video should be served when allow_video is true")
	}

	rangeReq := httptest.NewRequest(http.MethodGet, "https://ads.test/clip.mp4", nil)
	rangeReq.Host = "ads.test"
	rangeReq.Header.Set("Range", "bytes=10-19")
	rangeRec := httptest.NewRecorder()
	if !h.Serve(rangeRec, rangeReq) {
		t.Fatal("video range should be served when allow_video is true")
	}
	if rangeRec.Code != http.StatusPartialContent {
		t.Fatalf("status=%d want %d", rangeRec.Code, http.StatusPartialContent)
	}
	if got := rangeRec.Body.Len(); got != 10 {
		t.Fatalf("range body len=%d want 10", got)
	}
	if !bytes.Equal(rangeRec.Body.Bytes(), fullRec.Body.Bytes()[10:20]) {
		t.Fatal("range body does not match full response slice")
	}
	if got := rangeRec.Header().Get("Content-Range"); got != "bytes 10-19/1024" {
		t.Errorf("content-range = %q", got)
	}
	if got := rangeRec.Header().Get("Content-Length"); got != "10" {
		t.Errorf("content-length = %q", got)
	}
	if got := rangeRec.Header().Get("Content-Type"); got != "video/mp4" {
		t.Errorf("content-type = %q", got)
	}
}

func TestServeGeneratesJSWithoutProbe(t *testing.T) {
	// nil resolver => probe fails => defaults used; .js still served.
	h := New(deadResolver{}, Options{AllowVideo: false})
	r := httptest.NewRequest(http.MethodGet, "https://ads.test/tag.js", nil)
	r.Host = "ads.test"
	rec := httptest.NewRecorder()
	if !h.Serve(rec, r) {
		t.Fatal("js should be served")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/javascript" {
		t.Errorf("content-type = %q", ct)
	}
	if rec.Header().Get("Accept-Ranges") != "bytes" {
		t.Error("expected Accept-Ranges: bytes")
	}
}

func BenchmarkGenerateBinary1MiB(b *testing.B) {
	shape := Shape{ContentType: "application/octet-stream", Length: 1 << 20, Media: MediaBinary}
	for i := 0; i < b.N; i++ {
		if _, err := Generate("https://example.test/asset.bin", shape); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateJS1MiB(b *testing.B) {
	shape := Shape{ContentType: "application/javascript", Length: 1 << 20, Media: MediaJS}
	for i := 0; i < b.N; i++ {
		if _, err := Generate("https://example.test/app.js", shape); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServeBinary1MiB(b *testing.B) {
	h := New(nil, Options{MaxBytes: 2 << 20})
	urlKey := "/asset.bin"
	h.storeDecoy(urlKey, CachedDecoy{Shape: Shape{ContentType: "application/octet-stream", Length: 1 << 20, Media: MediaBinary}})
	req := httptest.NewRequest(http.MethodGet, urlKey, nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		if !h.Serve(rec, req) {
			b.Fatal("Serve returned false")
		}
	}
}
