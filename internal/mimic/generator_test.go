package mimic

import (
	"bytes"
	"context"
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

func TestVideoRefused(t *testing.T) {
	if _, err := Generate("s", Shape{Media: MediaVideo, Length: 100}); err == nil {
		t.Fatal("expected video to be refused")
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
