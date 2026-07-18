package forward

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// staticResolver resolves every host to loopback (tests point origins at 127.0.0.1).
type staticResolver struct{ ip net.IP }

func (s staticResolver) LookupIP(_ context.Context, _ string) ([]net.IP, error) {
	return []net.IP{s.ip}, nil
}

type seen struct {
	UA     string
	Cookie string
	XFF    string
	XTrack string
	RawQ   string
}

func newOrigin(t *testing.T) (*httptest.Server, *seen) {
	t.Helper()
	got := &seen{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.UA = r.Header.Get("User-Agent")
		got.Cookie = r.Header.Get("Cookie")
		got.XFF = r.Header.Get("X-Forwarded-For")
		got.XTrack = r.Header.Get("X-Track-Id")
		got.RawQ = r.URL.RawQuery
		w.Header().Set("Set-Cookie", "sid=abc; Path=/")
		json.NewEncoder(w).Encode(map[string]string{"ok": "1"})
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func newForwarder(t *testing.T) *Forwarder {
	return New(staticResolver{net.IPv4(127, 0, 0, 1)}, Options{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test origin cert
	})
}

func request(t *testing.T, origin *httptest.Server, target string) *http.Request {
	t.Helper()
	u, _ := url.Parse(origin.URL)
	authority := "ads.test.example:" + u.Port() // resolver maps host -> 127.0.0.1
	r := httptest.NewRequest(http.MethodGet, "https://"+authority+target, nil)
	r.Host = authority
	r.Header.Set("User-Agent", "SecretBrowser/1.0 identifiable")
	r.Header.Set("Cookie", "sid=tracking-me")
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Set("X-Track-Id", "abc123")
	r.Header.Set("Referer", "https://private.example/page")
	return r
}

func TestScrubbedRemovesIdentifiers(t *testing.T) {
	origin, got := newOrigin(t)
	f := newForwarder(t)

	rec := httptest.NewRecorder()
	f.Scrubbed(rec, request(t, origin, "/collect?uid=123&keep=1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got.Cookie != "" {
		t.Errorf("cookie should be scrubbed, origin saw %q", got.Cookie)
	}
	if got.UA != defaultScrubbedUA {
		t.Errorf("UA = %q, want generic", got.UA)
	}
	if got.XFF != "" {
		t.Errorf("X-Forwarded-For should be gone, saw %q", got.XFF)
	}
	if got.XTrack != "" {
		t.Errorf("X-Track-Id should be scrubbed, saw %q", got.XTrack)
	}
	if strings.Contains(got.RawQ, "uid") {
		t.Errorf("uid should be stripped, query = %q", got.RawQ)
	}
	if !strings.Contains(got.RawQ, "keep=1") {
		t.Errorf("keep=1 should survive, query = %q", got.RawQ)
	}
	if sc := rec.Header().Get("Set-Cookie"); sc != "" {
		t.Errorf("response Set-Cookie should be scrubbed, saw %q", sc)
	}
}

func TestAsisPreservesRequest(t *testing.T) {
	origin, got := newOrigin(t)
	f := newForwarder(t)

	rec := httptest.NewRecorder()
	f.Asis(rec, request(t, origin, "/x?uid=123"))

	if got.Cookie != "sid=tracking-me" {
		t.Errorf("asis should keep cookie, saw %q", got.Cookie)
	}
	if got.UA != "SecretBrowser/1.0 identifiable" {
		t.Errorf("asis should keep UA, saw %q", got.UA)
	}
	if !strings.Contains(got.RawQ, "uid=123") {
		t.Errorf("asis should keep uid, query = %q", got.RawQ)
	}
	// asis still must not leak the proxy hop's client IP.
	if got.XFF != "" {
		t.Errorf("X-Forwarded-For should not be added, saw %q", got.XFF)
	}
}

func TestOnErrorFailSafe(t *testing.T) {
	called := false
	f := New(staticResolver{net.IPv4(127, 0, 0, 1)}, Options{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		OnError: func(w http.ResponseWriter, r *http.Request, err error) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		},
	})
	// Point at a closed port so the dial fails.
	r := httptest.NewRequest(http.MethodGet, "https://dead.test.example:1/x", nil)
	r.Host = "dead.test.example:1"
	rec := httptest.NewRecorder()
	f.Asis(rec, r)
	if !called || rec.Code != http.StatusNoContent {
		t.Fatalf("expected fail-safe OnError, called=%v code=%d", called, rec.Code)
	}
}
