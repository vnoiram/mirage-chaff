package catalog

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCatalog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pixel.gif"), []byte("GIF89a"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := `
beacon-204:
  status: 204
noop-js:
  status: 200
  headers:
    Content-Type: application/javascript
  body:
    inline: "/*noop*/"
pixel:
  status: 200
  headers:
    Content-Type: image/gif
  body:
    file: pixel.gif
mp:
  status: 200
  multipart:
    type: multipart/mixed
    parts:
      - headers: { Content-Type: application/json }
        body: { inline: "{}" }
      - headers: { Content-Type: image/gif }
        body: { file: pixel.gif }
`
	if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRender(t *testing.T) {
	cat, err := Load(writeCatalog(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	cases := []struct {
		name        string
		wantStatus  int
		wantCTHas   string
		wantBodyHas string
	}{
		{"beacon-204", 204, "", ""},
		{"noop-js", 200, "application/javascript", "noop"},
		{"pixel", 200, "image/gif", "GIF89a"},
		{"mp", 200, "multipart/mixed; boundary=", "GIF89a"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if err := cat.Render(rec, c.name); err != nil {
				t.Fatalf("render: %v", err)
			}
			if rec.Code != c.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, c.wantStatus)
			}
			if c.wantCTHas != "" && !strings.Contains(rec.Header().Get("Content-Type"), c.wantCTHas) {
				t.Errorf("content-type = %q, want contains %q", rec.Header().Get("Content-Type"), c.wantCTHas)
			}
			if c.wantBodyHas != "" && !strings.Contains(rec.Body.String(), c.wantBodyHas) {
				t.Errorf("body missing %q", c.wantBodyHas)
			}
		})
	}
}

func TestRenderUnknownErrors(t *testing.T) {
	cat, err := Load(writeCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := cat.Render(httptest.NewRecorder(), "nope"); err == nil {
		t.Fatal("expected error for unknown entry")
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	dir := t.TempDir()
	yaml := "bad:\n  body:\n    file: does-not-exist.js\n"
	os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte(yaml), 0o600)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected load to fail on missing body file")
	}
}
