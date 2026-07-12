package server

import (
	"testing"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/catalog"
	"github.com/vnoiram/mirage-chaff/internal/config"
	"github.com/vnoiram/mirage-chaff/internal/policy"
	"github.com/vnoiram/mirage-chaff/internal/rulecatalog"
)

func TestBreakerOpensAndRecovers(t *testing.T) {
	b := newBreaker(3, 50*time.Millisecond)
	const d = "ads.example"

	if !b.Allow(d) {
		t.Fatal("should allow initially")
	}
	b.RecordFailure(d)
	b.RecordFailure(d)
	if !b.Allow(d) {
		t.Fatal("should still allow below threshold")
	}
	b.RecordFailure(d) // 3rd failure -> open
	if b.Allow(d) {
		t.Fatal("should be open after threshold failures")
	}
	if !b.Open(d) {
		t.Fatal("Open() should report open")
	}

	// After cooldown, half-open allows a probe.
	time.Sleep(60 * time.Millisecond)
	if !b.Allow(d) {
		t.Fatal("should half-open after cooldown")
	}
	// A success fully closes it.
	b.RecordSuccess(d)
	if b.Open(d) {
		t.Fatal("should be closed after success")
	}
}

func TestBreakerSuccessResetsCount(t *testing.T) {
	b := newBreaker(3, time.Second)
	const d = "x"
	b.RecordFailure(d)
	b.RecordFailure(d)
	b.RecordSuccess(d)
	b.RecordFailure(d)
	b.RecordFailure(d)
	if !b.Allow(d) {
		t.Fatal("success should have reset the failure count")
	}
}

func TestUnknownFallbackKeepsJavascriptForwarded(t *testing.T) {
	cfg := config.Defaults()
	cfg.UnknownProfile.Default = "aggressive"
	s := &Server{cfg: cfg}
	d, changed := s.unknownFallback(policy.Decision{Action: policy.ActionStub, Catalog: "beacon-204"}, rulecatalog.Entry{}, false, "/sdk.js")
	if !changed {
		t.Fatal("expected fallback decision")
	}
	if d.Action != policy.ActionForwardAsis {
		t.Fatalf("unknown JS must not auto-mimic/stub, got %+v", d)
	}
	if d.Rule != "unknown:aggressive:script" {
		t.Fatalf("unexpected reason: %+v", d)
	}
}

func TestUnknownFallbackBalancedPixelStubs(t *testing.T) {
	cfg := config.Defaults()
	cfg.UnknownProfile.Default = "balanced"
	s := &Server{cfg: cfg}
	d, changed := s.unknownFallback(policy.Decision{Action: policy.ActionStub, Catalog: "beacon-204"}, rulecatalog.Entry{}, false, "/pixel.gif")
	if !changed {
		t.Fatal("expected fallback decision")
	}
	if d.Action != policy.ActionStub || d.Catalog != "pixel" {
		t.Fatalf("balanced pixel should use pixel stub, got %+v", d)
	}
}

func TestVerifiedJSStubDecisionOnlyForVerifiedMetadata(t *testing.T) {
	cat := &catalog.Catalog{}
	// Build a tiny catalog through Load would need files; this checks fallback
	// when the expected SDK catalog is not installed.
	meta := rulecatalog.Entry{
		ID:              "rc_test",
		ResourceType:    "script",
		ExpectedCatalog: "noop-advendor-v1",
		Verified:        true,
		TestedSites:     []string{"news.example"},
	}
	d, changed := verifiedJSStubDecision(policy.Decision{}, meta, true, "www.news.example", cat)
	if !changed {
		t.Fatal("expected verified JS stub decision")
	}
	if d.Action != policy.ActionStub || d.Catalog != safeDefaultStub || d.Rule != "catalog:rc_test" {
		t.Fatalf("decision = %+v", d)
	}
	meta.Verified = false
	if _, changed := verifiedJSStubDecision(policy.Decision{}, meta, true, "www.news.example", cat); changed {
		t.Fatal("unverified JS metadata must not auto-stub")
	}
}
