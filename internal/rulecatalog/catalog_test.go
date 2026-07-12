package rulecatalog

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseRulesClassifiesCommonFormats(t *testing.T) {
	src := Source{Type: "adguard_filter", Name: "test"}
	rules := strings.NewReader(`
0.0.0.0 tracker.example.net
||ads.example.net/sdk.js$script
example.com##.ad-banner
cloak.example.net CNAME real-tracker.example.org.
@@||allowed.example.net^$script
`)
	entries, err := ParseRules(rules, src)
	if err != nil {
		t.Fatal(err)
	}
	byDomain := map[string]Entry{}
	for _, e := range entries {
		byDomain[e.Match.Domain] = e
	}
	if got := byDomain["tracker.example.net"]; got.Layer != LayerDNS || got.ResourceType != "domain" {
		t.Fatalf("hosts entry = %+v", got)
	}
	if got := byDomain["ads.example.net"]; got.Layer != LayerHTTP || got.ResourceType != "script" || got.ExpectedCatalog != "noop-sdk" {
		t.Fatalf("script entry = %+v", got)
	}
	if got := byDomain["example.com"]; got.Layer != LayerDOM || !got.Unsupported {
		t.Fatalf("DOM entry = %+v", got)
	}
	if got := byDomain["cloak.example.net"]; !got.CloakingDetected || got.CNAMETarget != "real-tracker.example.org" {
		t.Fatalf("RPZ CNAME entry = %+v", got)
	}
	if got := byDomain["allowed.example.net"]; got.Category != "allow_exception" || !got.Verified {
		t.Fatalf("allow entry = %+v", got)
	}
}

func TestStoreLookupReviewAndAnalytics(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	e := Entry{Match: Match{Domain: "ads.example.net", Path: "/sdk.js"}, Layer: LayerHTTP, ResourceType: "script", Risk: "high", Source: Source{Type: "adguard_filter"}}
	if err := s.Upsert(e); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Lookup("sub.ads.example.net", "/sdk.js?v=1")
	if !ok {
		t.Fatal("expected lookup hit")
	}
	yes := true
	reviewed, err := s.Review(got.ID, ReviewApproved, &yes)
	if err != nil {
		t.Fatal(err)
	}
	if reviewed.ReviewStatus != ReviewApproved || !reviewed.Verified {
		t.Fatalf("reviewed = %+v", reviewed)
	}
	a := s.Analytics()
	if a["total"].(int) != 1 {
		t.Fatalf("analytics = %+v", a)
	}
}

func TestPromoteDowngradeCNAMEAndRewriteCandidate(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	e := Entry{Match: Match{Domain: "metrics.example.com"}, Source: Source{Type: "adguard_filter"}, Risk: "high"}
	if err := s.Upsert(e); err != nil {
		t.Fatal(err)
	}
	list := s.List(nil)
	id := list[0].ID

	promoted, err := s.Promote(id)
	if err != nil {
		t.Fatal(err)
	}
	if !promoted.Verified || promoted.ReviewStatus != ReviewApproved || promoted.PromotionCount != 1 {
		t.Fatalf("promoted = %+v", promoted)
	}

	cname, err := s.MarkCNAME(id, []string{"metrics.example.com.", "tracker.vendor.net."}, "tracker.vendor.net.", "Vendor", "high", "ql-1")
	if err != nil {
		t.Fatal(err)
	}
	if !cname.CloakingDetected || cname.CNAMETarget != "tracker.vendor.net" || cname.TrackerVendor != "Vendor" {
		t.Fatalf("cname = %+v", cname)
	}
	candidate, err := s.RewriteCandidate(id)
	if err != nil {
		t.Fatal(err)
	}
	if candidate["custom_rule"] != "||metrics.example.com^" {
		t.Fatalf("candidate = %+v", candidate)
	}

	down, err := s.Downgrade(id)
	if err != nil {
		t.Fatal(err)
	}
	if down.Verified || down.ReviewStatus != ReviewDisabled || down.FalsePositiveCount != 1 {
		t.Fatalf("downgraded = %+v", down)
	}
}

func TestVerifiedStubCatalogRequiresVerifiedScriptAndSiteMatch(t *testing.T) {
	e := Entry{ResourceType: "script", ExpectedCatalog: "noop-advendor-v1", Verified: true, TestedSites: []string{"news.example"}}
	if got, ok := e.VerifiedStubCatalog("www.news.example"); !ok || got != "noop-advendor-v1" {
		t.Fatalf("expected verified catalog match, got %q %v", got, ok)
	}
	if _, ok := e.VerifiedStubCatalog("shop.example"); ok {
		t.Fatal("site mismatch must not use SDK noop")
	}
	e.Verified = false
	if _, ok := e.VerifiedStubCatalog("www.news.example"); ok {
		t.Fatal("unverified JS must not use SDK noop")
	}
}

func TestBuildFetchesAGHFilteringStatus(t *testing.T) {
	var filterURL string
	filterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("||ads.example.net/sdk.js$script\n"))
	}))
	defer filterSrv.Close()
	filterURL = filterSrv.URL

	agh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/control/filtering/status" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"filters":[{"enabled":true,"url":"` + filterURL + `"},{"enabled":false,"url":"https://disabled.example/list.txt"}],
			"user_rules":["0.0.0.0 tracker.example.net"],
			"allowlist_rules":["@@||allowed.example.net^"]
		}`))
	}))
	defer agh.Close()

	entries, sources, err := Build(SyncConfig{
		Enabled: true, BaseURL: agh.URL, SyncFilters: true, SyncCustomRules: true,
		Client: agh.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if sources != 2 {
		t.Fatalf("sources = %d, want filter + custom", sources)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Match.Domain] = true
	}
	for _, want := range []string{"ads.example.net", "tracker.example.net", "allowed.example.net"} {
		if !seen[want] {
			t.Fatalf("missing %s in %+v", want, entries)
		}
	}
}
