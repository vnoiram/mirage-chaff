package observability

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdditionalPublicRoute(t *testing.T) {
	s := New("127.0.0.1:0", false, &Health{}, nil)
	s.Handle("GET /agh/managed-rewrites.txt", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("managed feed"))
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agh/managed-rewrites.txt", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if rr.Body.String() != "managed feed" {
		t.Fatalf("body = %q", rr.Body.String())
	}
}
