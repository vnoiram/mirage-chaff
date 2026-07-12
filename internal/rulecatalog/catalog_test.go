package rulecatalog

import (
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
