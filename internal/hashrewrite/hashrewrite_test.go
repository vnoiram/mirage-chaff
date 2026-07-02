package hashrewrite

import (
	"strings"
	"testing"
)

func TestRewriteSRI(t *testing.T) {
	html := []byte(`<html><head>
<script src="https://cdn.ads/tag.js" integrity="sha256-OLDHASHVALUE" crossorigin="anonymous"></script>
<link rel="stylesheet" href="/style.css" integrity="sha384-KEEPME">
<script src="/no-integrity.js"></script>
</head></html>`)

	hasher := func(url string) (string, bool) {
		if url == "https://cdn.ads/tag.js" {
			return "sha256-DECOYHASH", true
		}
		return "", false // /style.css not decoyed -> leave as-is
	}

	out, n := RewriteSRI(html, hasher)
	if n != 1 {
		t.Fatalf("rewritten = %d, want 1", n)
	}
	s := string(out)
	if !strings.Contains(s, `integrity="sha256-DECOYHASH"`) {
		t.Error("decoy integrity not written")
	}
	if strings.Contains(s, "OLDHASHVALUE") {
		t.Error("old hash should be gone")
	}
	if !strings.Contains(s, `integrity="sha384-KEEPME"`) {
		t.Error("non-decoyed integrity must be preserved")
	}
	if !strings.Contains(s, `src="https://cdn.ads/tag.js"`) {
		t.Error("src must be preserved")
	}
}

func TestRewriteSRINoChangeWhenUnknown(t *testing.T) {
	html := []byte(`<script src="/x.js" integrity="sha256-A"></script>`)
	out, n := RewriteSRI(html, func(string) (string, bool) { return "", false })
	if n != 0 || string(out) != string(html) {
		t.Fatal("unknown URLs must be left untouched")
	}
}

func TestRewriteJSONIntegrity(t *testing.T) {
	body := []byte(`{"segments":[{"url":"seg1.m4s","integrity":"sha256-OLD","dur":6}]}`)
	out, n := RewriteJSONIntegrity(body, func(url string) (string, bool) {
		if url == "seg1.m4s" {
			return "sha256-NEW", true
		}
		return "", false
	})
	if n != 1 {
		t.Fatalf("rewritten = %d, want 1", n)
	}
	if !strings.Contains(string(out), `"integrity":"sha256-NEW"`) {
		t.Errorf("integrity not rewritten: %s", out)
	}
}

func TestIntegrityOf(t *testing.T) {
	if got := IntegrityOf([]byte("abc")); !strings.HasPrefix(got, "sha256-") {
		t.Errorf("IntegrityOf = %q", got)
	}
}
