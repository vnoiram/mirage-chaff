package server

import (
	"testing"
	"time"
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
