package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadDir(t *testing.T, yaml string) *Ruleset {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return rs
}

func TestMatchPriorityAndFields(t *testing.T) {
	rs := loadDir(t, `
rules:
  - name: broad
    priority: 100
    match: { domain: "*.example.com" }
    action: stub
    catalog: beacon-204
  - name: specific
    priority: 10
    match: { domain: "ads.example.com", path: "*/gpt/*", method: ["GET"] }
    action: stub
    catalog: noop-js
default:
  action: stub
  catalog: empty-json
`)
	// specific (priority 10) wins over broad (100) for the gpt GET path.
	if d := rs.Match("ads.example.com", "/x/gpt/y", "GET"); d.Rule != "specific" {
		t.Errorf("expected specific, got %q", d.Rule)
	}
	// POST does not match specific's method -> falls to broad.
	if d := rs.Match("ads.example.com", "/x/gpt/y", "POST"); d.Rule != "broad" {
		t.Errorf("expected broad for POST, got %q", d.Rule)
	}
	// Different subdomain, non-gpt path -> broad by domain glob.
	if d := rs.Match("cdn.example.com", "/foo", "GET"); d.Rule != "broad" {
		t.Errorf("expected broad, got %q", d.Rule)
	}
	// Unrelated domain -> default (unmatched).
	d := rs.Match("other.test", "/", "GET")
	if d.Matched || d.Catalog != "empty-json" {
		t.Errorf("expected default empty-json unmatched, got %+v", d)
	}
}

func TestLoadRejectsBadAction(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "p.yaml"), []byte("rules:\n  - name: x\n    action: bogus\n"), 0o600)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected invalid action error")
	}
}

func TestLoadRejectsStubWithoutCatalog(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "p.yaml"), []byte("rules:\n  - name: x\n    action: stub\n"), 0o600)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected stub-without-catalog error")
	}
}

func TestCatalogRefs(t *testing.T) {
	rs := loadDir(t, `
rules:
  - name: a
    action: stub
    catalog: noop-js
  - name: b
    action: passthrough
default:
  action: stub
  catalog: beacon-204
`)
	refs := map[string]bool{}
	for _, r := range rs.CatalogRefs() {
		refs[r] = true
	}
	if !refs["noop-js"] || !refs["beacon-204"] {
		t.Errorf("expected noop-js + beacon-204 refs, got %v", rs.CatalogRefs())
	}
	if refs["b"] {
		t.Error("passthrough rule should not contribute a catalog ref")
	}
}

func TestEngineUnmatchedAggregation(t *testing.T) {
	rs := loadDir(t, `
rules:
  - name: a
    match: { domain: "known.test" }
    action: stub
    catalog: beacon-204
default: { action: stub, catalog: beacon-204 }
`)
	e := NewEngine(rs)
	e.Decide("known.test", "/", "GET")        // matched, not aggregated
	e.Decide("new.test", "/track", "GET")     // unmatched
	e.Decide("new.test", "/track", "GET")     // unmatched again
	e.Decide("other.test", "/beacon", "POST") // unmatched

	top := e.UnmatchedTop(10)
	if len(top) != 2 {
		t.Fatalf("expected 2 unmatched keys, got %d: %+v", len(top), top)
	}
	if top[0].Domain != "new.test" || top[0].Count != 2 {
		t.Errorf("expected new.test x2 first, got %+v", top[0])
	}
}

func TestTempRuleSweepsExpiredOnList(t *testing.T) {
	e := NewEngine(&Ruleset{})
	e.AddTempRule("expired.example", "forward-asis", "", time.Millisecond)
	e.AddTempRule("alive.example", "forward-asis", "", time.Hour)
	time.Sleep(10 * time.Millisecond)

	got := e.TempRules()
	if _, ok := got["expired.example"]; ok {
		t.Error("expired rule should not appear in TempRules result")
	}
	if _, ok := got["alive.example"]; !ok {
		t.Error("live rule should appear in TempRules result")
	}

	// Verify the expired entry was swept from the internal map.
	e.tmu.Lock()
	_, stillThere := e.temps["expired.example"]
	e.tmu.Unlock()
	if stillThere {
		t.Error("expired rule should have been deleted from temps map by TempRules sweep")
	}
}
