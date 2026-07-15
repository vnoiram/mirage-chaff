package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vnoiram/mirage-chaff/internal/config"
)

func TestParseAGHEnv(t *testing.T) {
	env := parseAGHEnv(strings.NewReader(`
# comment
AGH_API_URL="http://agh.example:3000"
export AGH_API_USER='admin'
AGH_API_PASS=secret
ignored
`))
	if env["AGH_API_URL"] != "http://agh.example:3000" || env["AGH_API_USER"] != "admin" || env["AGH_API_PASS"] != "secret" {
		t.Fatalf("env = %+v", env)
	}
}

func TestRefreshAGHFilters(t *testing.T) {
	var sawAuth bool
	var sawForce bool
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/control/filtering/refresh" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		user, pass, ok := r.BasicAuth()
		sawAuth = ok && user == "admin" && pass == "secret"
		var body struct {
			Force bool `json:"force"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		sawForce = body.Force
		return stringResponse(http.StatusOK, `{"updated":1}`), nil
	})}

	dir := t.TempDir()
	envPath := filepath.Join(dir, "agh.env")
	writeTestFile(t, envPath, "AGH_API_USER=admin\nAGH_API_PASS=secret\n")
	got, err := refreshAGHFilters(context.Background(), client, config.AGHSyncConfig{BaseURL: "http://agh.test", EnvFile: envPath}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.BaseURL != "http://agh.test" || !got.Force || !sawAuth || !sawForce {
		t.Fatalf("result=%+v sawAuth=%v sawForce=%v", got, sawAuth, sawForce)
	}
}

func TestRefreshAGHFiltersConfigErrors(t *testing.T) {
	if _, err := refreshAGHFilters(context.Background(), nil, config.AGHSyncConfig{BaseURL: "http://agh"}, false); err == nil || !strings.Contains(err.Error(), "credentials required") {
		t.Fatalf("missing credentials err = %v", err)
	}
}

func TestRefreshAGHFiltersHTTPErrorRedactsCredentials(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return stringResponse(http.StatusBadGateway, "bad refresh"), nil
	})}

	dir := t.TempDir()
	envPath := filepath.Join(dir, "agh.env")
	writeTestFile(t, envPath, "AGH_API_USER=admin\nAGH_API_PASS=supersecret\n")
	_, err := refreshAGHFilters(context.Background(), client, config.AGHSyncConfig{BaseURL: "http://agh.test", EnvFile: envPath}, false)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("error leaked credential: %v", err)
	}
	if !strings.Contains(err.Error(), "status 502") {
		t.Fatalf("error = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func stringResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
