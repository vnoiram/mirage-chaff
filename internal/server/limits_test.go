package server

import (
	"testing"

	"github.com/vnoiram/mirage-chaff/internal/policy"
)

func TestStubOnlyGate(t *testing.T) {
	// Non-stub actions are downgraded to a safe stub in stub-only mode.
	for _, act := range []string{policy.ActionForwardAsis, policy.ActionForwardScrubbed, policy.ActionForwardMimic, policy.ActionPassthrough} {
		d := policy.Decision{Action: act, Rule: "r"}
		got, changed := stubOnlyGate("stub-only", d)
		if !changed || got.Action != policy.ActionStub {
			t.Fatalf("%s in stub-only: got action=%q changed=%v, want stub/true", act, got.Action, changed)
		}
		if got.Catalog == "" {
			t.Fatalf("%s: expected a fallback catalog", act)
		}
	}
	// Stub decisions pass through unchanged.
	d := policy.Decision{Action: policy.ActionStub, Catalog: "beacon-204"}
	if got, changed := stubOnlyGate("stub-only", d); changed || got.Catalog != "beacon-204" {
		t.Fatalf("stub decision must be unchanged, got %+v changed=%v", got, changed)
	}
	// In full mode nothing is gated.
	fwd := policy.Decision{Action: policy.ActionForwardAsis}
	if _, changed := stubOnlyGate("full", fwd); changed {
		t.Fatal("full mode must not gate")
	}
}

func TestRateLimiterNilAllowsAll(t *testing.T) {
	var l *rateLimiter // rate_limit <= 0 => nil
	for i := 0; i < 100; i++ {
		if !l.Allow() {
			t.Fatal("nil limiter must allow everything")
		}
	}
}

func TestRateLimiterEnforcesBurst(t *testing.T) {
	l := newRateLimiter(5) // 5 rps, burst 5
	allowed := 0
	for i := 0; i < 20; i++ {
		if l.Allow() {
			allowed++
		}
	}
	// The initial burst is bounded by the rate; well under 20.
	if allowed == 0 || allowed > 6 {
		t.Fatalf("allowed %d requests in a burst, want ~5", allowed)
	}
}
